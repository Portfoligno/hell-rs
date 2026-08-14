use std::collections::{BTreeMap, BTreeSet};

use super::evidence::{
    EvidenceIndex, EvidenceRepository, ObligationVerdict, TrustedEvidenceBindings,
    exploratory_mismatches,
};
use super::ledger::{
    Blocker, ConformancePlan, DerivedPartition, ExemptionKind, FailureClass, FinalDisposition,
    PlannedCell, ScopeDisposition, VerificationMode,
};

pub(crate) fn derive_partition(
    plan: &ConformancePlan,
    expected_universe: &[super::CellKey],
    evidence: &EvidenceRepository,
    trusted: &TrustedEvidenceBindings,
) -> Result<DerivedPartition, String> {
    plan.validate(expected_universe)?;
    trusted.validate()?;
    if trusted.conformance_plan_sha256 != plan.plan_sha256
        || trusted.candidate_sha != plan.candidate_sha
        || trusted.source_inventory_sha256 != plan.source_inventory_sha256
    {
        return Err("trusted evidence bindings differ from the conformance plan".to_owned());
    }

    let mut index = EvidenceIndex::build(evidence)?;
    let mut cells = BTreeMap::new();
    let mut consumed_obligations = BTreeSet::new();
    let mut consumed_exemptions = BTreeSet::new();
    for cell in &plan.cells {
        let disposition = derive_cell(
            cell,
            &mut index,
            trusted,
            &mut consumed_obligations,
            &mut consumed_exemptions,
        )?;
        if cells.insert(cell.key.clone(), disposition).is_some() {
            return Err(format!("duplicate planned cell {}", cell.key));
        }
    }
    index.require_empty()?;
    let partition = DerivedPartition {
        cells,
        unclassified_mismatches: exploratory_mismatches(evidence, trusted)?,
        consumed_obligations,
        consumed_exemptions,
    };
    partition.validate_complete_against(plan)?;
    Ok(partition)
}

fn derive_cell(
    cell: &PlannedCell,
    evidence: &mut EvidenceIndex<'_>,
    trusted: &TrustedEvidenceBindings,
    consumed_obligations: &mut BTreeSet<(super::CellKey, String)>,
    consumed_exemptions: &mut BTreeSet<String>,
) -> Result<FinalDisposition, String> {
    match &cell.scope {
        ScopeDisposition::Excluded { scope_id, .. } => Ok(FinalDisposition::Excluded {
            scope_id: scope_id.clone(),
        }),
        ScopeDisposition::NotApplicable { decision_id, .. } => {
            Ok(FinalDisposition::NotApplicable {
                decision_id: decision_id.clone(),
            })
        }
        ScopeDisposition::Required { .. } => {
            let mut verdicts = Vec::new();
            for obligation in &cell.obligations {
                if !consumed_obligations.insert((cell.key.clone(), obligation.id.clone())) {
                    return Err(format!("obligation {} was evaluated twice", obligation.id));
                }
                verdicts.push((
                    obligation.id.as_str(),
                    evidence.evaluate_obligation(cell, obligation, trusted),
                ));
            }
            reduce_required_cell(cell, &verdicts, consumed_exemptions)
        }
    }
}

fn reduce_required_cell(
    cell: &PlannedCell,
    verdicts: &[(&str, ObligationVerdict)],
    consumed_exemptions: &mut BTreeSet<String>,
) -> Result<FinalDisposition, String> {
    let failures = verdicts
        .iter()
        .filter(|(_, verdict)| !matches!(verdict, ObligationVerdict::Verified { .. }))
        .collect::<Vec<_>>();
    if super::mutant_active("applicable-unverified-accepted")
        && failures
            .iter()
            .all(|(_, verdict)| matches!(verdict, ObligationVerdict::Missing))
    {
        return Ok(FinalDisposition::Verified {
            mode: VerificationMode::Exact,
            evidence_ids: Vec::new(),
        });
    }
    if failures.is_empty() {
        if cell.exemption.is_some() && !super::mutant_active("unused-exemption-accepted") {
            return Err(format!(
                "verified cell {} has an unused exemption",
                cell.key
            ));
        }
        let mut evidence_ids = Vec::new();
        let mut mode = VerificationMode::Exact;
        for (_, verdict) in verdicts {
            let ObligationVerdict::Verified {
                mode: obligation_mode,
                evidence_ids: obligation_evidence,
            } = verdict
            else {
                return Err("verified reduction contains a failure".to_owned());
            };
            mode = strongest_mode(mode, *obligation_mode);
            evidence_ids.extend(obligation_evidence.iter().cloned());
        }
        return Ok(FinalDisposition::Verified { mode, evidence_ids });
    }

    if failures.len() == 1 {
        let (obligation_id, verdict) = failures[0];
        if let Some(exemption) = cell.exemption.as_ref().filter(|exemption| {
            exemption.obligation_id == *obligation_id
                && match (exemption.kind, verdict) {
                    (ExemptionKind::EvidenceGap, ObligationVerdict::Missing) => true,
                    (
                        ExemptionKind::KnownDivergence,
                        ObligationVerdict::Mismatch { mismatch_sha256 },
                    ) => {
                        super::mutant_active("exemption-mismatch-fingerprint-ignored")
                            || exemption.expected_mismatch_sha256.as_ref() == Some(mismatch_sha256)
                    }
                    _ => false,
                }
        }) {
            if !consumed_exemptions.insert(exemption.id.clone()) {
                return Err(format!("exemption {} was consumed twice", exemption.id));
            }
            let underlying = match verdict {
                ObligationVerdict::Missing => FailureClass::MissingEvidence,
                ObligationVerdict::Mismatch { .. } => FailureClass::Mismatch,
                ObligationVerdict::Invalid { .. } | ObligationVerdict::Verified { .. } => {
                    return Err("invalid evidence cannot be exempted".to_owned());
                }
            };
            return Ok(FinalDisposition::Exempted {
                exemption_id: exemption.id.clone(),
                underlying,
            });
        }
    }

    let (obligation_id, failure) = failures
        .iter()
        .find(|(_, verdict)| matches!(verdict, ObligationVerdict::Invalid { .. }))
        .or_else(|| {
            failures
                .iter()
                .find(|(_, verdict)| matches!(verdict, ObligationVerdict::Mismatch { .. }))
        })
        .unwrap_or(&failures[0]);
    let blocker = match failure {
        ObligationVerdict::Missing => Blocker::MissingEvidence {
            obligation_id: (*obligation_id).to_owned(),
        },
        ObligationVerdict::Mismatch { mismatch_sha256 } => Blocker::Mismatch {
            obligation_id: (*obligation_id).to_owned(),
            mismatch_sha256: mismatch_sha256.clone(),
        },
        ObligationVerdict::Invalid { code } => Blocker::InvalidEvidence { code: *code },
        ObligationVerdict::Verified { .. } => {
            return Err("failure reduction selected verified evidence".to_owned());
        }
    };
    Ok(FinalDisposition::Blocked { blocker })
}

const fn strongest_mode(left: VerificationMode, right: VerificationMode) -> VerificationMode {
    match (left, right) {
        (VerificationMode::PlatformEquivalent, _) | (_, VerificationMode::PlatformEquivalent) => {
            VerificationMode::PlatformEquivalent
        }
        (VerificationMode::Normalized, _) | (_, VerificationMode::Normalized) => {
            VerificationMode::Normalized
        }
        (VerificationMode::Exact, VerificationMode::Exact) => VerificationMode::Exact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hell_builtins::CompatibilityDimension;

    use crate::conformance::evidence::{
        CaseSource, EvidenceRecord, EvidenceTarget, Observation, OracleBinding,
    };
    use crate::conformance::ledger::{
        ConformanceAcceptance, ConformancePlan, EvidenceStrategy, PlannedExemption,
        PlannedObligation,
    };
    use crate::conformance::{ConformancePlatform, ProfileId};

    fn cell_key() -> super::super::CellKey {
        super::super::CellKey::new(
            "Text.all",
            CompatibilityDimension::Presentation,
            ProfileId::Upstream,
            ConformancePlatform::LinuxX86_64,
        )
        .unwrap()
    }

    fn raw_observation_case() -> hell_testkit::DifferentialCase {
        hell_testkit::committed_differential_cases()
            .into_iter()
            .find(|case| {
                case.claim_evidence.as_ref().is_some_and(|descriptor| {
                    descriptor.semantic_targets.iter().any(|target| {
                        target.builtin.as_ref() == "Text.all"
                            && target.dimension == CompatibilityDimension::Presentation
                            && target
                                .obligations
                                .iter()
                                .any(|obligation| obligation.0.as_ref() == "raw-observation")
                    })
                })
            })
            .expect("committed Text.all presentation case")
    }

    fn fixture(exemption: Option<PlannedExemption>) -> (ConformancePlan, TrustedEvidenceBindings) {
        let key = cell_key();
        let case = raw_observation_case();
        let case_id = case.id.to_string();
        let plan = ConformancePlan {
            standard: super::super::RELEASE_STANDARD.to_owned(),
            candidate_sha: "a".repeat(40),
            workflow_sha: "b".repeat(40),
            release_evaluation_instant: "2026-08-13T00:00:00Z".to_owned(),
            trusted_inputs_sha256: "1".repeat(64),
            source_inventory_sha256: "2".repeat(64),
            baseline: "2026-05-29".to_owned(),
            exploratory_generator_version: super::super::EXPLORATORY_GENERATOR_VERSION.to_owned(),
            exploratory_generator_seed: super::super::EXPLORATORY_GENERATOR_SEED,
            exploratory_generator_count_per_platform: 32,
            generated_agreement_may_verify: super::super::GENERATED_AGREEMENT_MAY_VERIFY,
            generated_mismatch_blocks: super::super::GENERATED_MISMATCH_BLOCKS,
            cells: vec![PlannedCell {
                key,
                scope: ScopeDisposition::Required {
                    decision_id: "applicable".to_owned(),
                },
                obligations: vec![PlannedObligation {
                    id: "raw-observation".to_owned(),
                    strategy: EvidenceStrategy::NativeOracle,
                    case_ids: vec![case_id.clone()],
                    case_descriptor_sha256: BTreeMap::from([(
                        case_id,
                        hell_testkit::case_descriptor_sha256(&case).hex(),
                    )]),
                    allowed_normalizers: Vec::new(),
                }],
                exemption,
            }],
            plan_sha256: "3".repeat(64),
        };
        let oracle = OracleBinding {
            repository: "chrisdone/hell".to_owned(),
            commit: "c".repeat(40),
            executable_sha256: "4".repeat(64),
            source_sha256: "5".repeat(64),
        };
        let trusted = TrustedEvidenceBindings {
            release_plan_sha256: "6".repeat(64),
            conformance_plan_sha256: plan.plan_sha256.clone(),
            candidate_sha: plan.candidate_sha.clone(),
            candidate_executable_sha256: BTreeMap::from([
                (ConformancePlatform::LinuxX86_64, "7".repeat(64)),
                (ConformancePlatform::MacosAarch64, "8".repeat(64)),
                (ConformancePlatform::WindowsX86_64, "9".repeat(64)),
            ]),
            source_inventory_sha256: plan.source_inventory_sha256.clone(),
            oracle: BTreeMap::from([
                (ConformancePlatform::LinuxX86_64, oracle.clone()),
                (ConformancePlatform::MacosAarch64, oracle.clone()),
                (ConformancePlatform::WindowsX86_64, oracle),
            ]),
        };
        (plan, trusted)
    }

    fn evidence(
        plan: &ConformancePlan,
        trusted: &TrustedEvidenceBindings,
        candidate_bytes: &[u8],
        oracle_bytes: &[u8],
    ) -> EvidenceRepository {
        let candidate = Observation::from_bytes(candidate_bytes.to_vec());
        let oracle = Observation::from_bytes(oracle_bytes.to_vec());
        let case = raw_observation_case();
        let mut record = EvidenceRecord {
            record_id: String::new(),
            release_plan_sha256: trusted.release_plan_sha256.clone(),
            conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
            candidate_sha: trusted.candidate_sha.clone(),
            candidate_executable_sha256: trusted.candidate_executable_sha256
                [&ConformancePlatform::LinuxX86_64]
                .clone(),
            candidate_build_info_schema_version: 2,
            candidate_compat_tracing: true,
            source_inventory_sha256: trusted.source_inventory_sha256.clone(),
            oracle: trusted.oracle[&ConformancePlatform::LinuxX86_64].clone(),
            platform: ConformancePlatform::LinuxX86_64,
            profile: ProfileId::Upstream,
            target: EvidenceTarget {
                cell: plan.cells[0].key.clone(),
                obligation_id: "raw-observation".to_owned(),
                case_id: case.id.to_string(),
            },
            descriptor_sha256: hell_testkit::case_descriptor_sha256(&case).hex(),
            case_source: CaseSource::Committed,
            candidate_observation_sha256: candidate.sha256.clone(),
            oracle_observation_sha256: oracle.sha256.clone(),
            requested_normalizers: Vec::new(),
        };
        record.record_id = record.canonical_id().unwrap();
        EvidenceRepository {
            records: vec![record],
            observations: BTreeMap::from([
                (candidate.sha256.clone(), candidate),
                (oracle.sha256.clone(), oracle),
            ]),
            exploratory_records: Vec::new(),
        }
    }

    fn raw_presentation_evidence(
        plan: &ConformancePlan,
        trusted: &TrustedEvidenceBindings,
        candidate_context: &str,
        oracle_context: &str,
    ) -> EvidenceRepository {
        let case = raw_observation_case();
        let observation = |context: &str| {
            let semantic = hell_testkit::SemanticObservation {
                typed_result_sha256: Some(hell_testkit::sha256_bytes(
                    b"{\"type\":\"Bool\",\"value\":true}",
                )),
                typed_result_builtin: hell_builtins::lookup("Text.all").map(|spec| spec.id),
                typed_result_canonical: Some("{\"type\":\"Bool\",\"value\":true}".into()),
                causal_event_order: vec![
                    (1, "parsed-builtin".into()),
                    (2, "resolved-builtin".into()),
                    (3, "specialized-builtin".into()),
                    (4, "entered-adapter".into()),
                    (5, "typed-result".into()),
                    (6, "presentation-field".into()),
                    (7, "obligation-event".into()),
                ],
                coverage: vec![
                    hell_testkit::CoverageEvent::ParsedBuiltin(
                        hell_builtins::lookup("Text.all").unwrap().id,
                    ),
                    hell_testkit::CoverageEvent::ResolvedBuiltin(
                        hell_builtins::lookup("Text.all").unwrap().id,
                    ),
                    hell_testkit::CoverageEvent::SpecializedBuiltin(
                        hell_builtins::lookup("Text.all").unwrap().id,
                    ),
                    hell_testkit::CoverageEvent::EnteredAdapter(
                        hell_builtins::lookup("Text.all").unwrap().id,
                    ),
                    hell_testkit::CoverageEvent::PresentedField(
                        hell_builtins::lookup("Text.all").unwrap().id,
                        "rendered-output".into(),
                    ),
                ],
                obligation_trace: vec![hell_testkit::ObligationTraceEvent {
                    builtin: hell_builtins::lookup("Text.all").unwrap().id,
                    instance_target: None,
                    instance_premises: Vec::new(),
                    owner_task: None,
                    sequence: 1,
                    parent_sequence: None,
                    outcome: "value".into(),
                    nested_adapters: 0,
                    materialized_before: 0,
                    materialized_after: 0,
                    callbacks: Vec::new(),
                    comparators: Vec::new(),
                }],
                ..hell_testkit::SemanticObservation::default()
            };
            let observation = hell_testkit::Observation {
                case_id: case.id.clone(),
                identity: hell_testkit::ExecutableIdentity {
                    path: "hell".into(),
                    sha256: hell_testkit::sha256_bytes(b"hell"),
                    reported_version: "test".into(),
                    build_info: None,
                    role: hell_testkit::ExecutableRole::Candidate,
                    assurance_epoch_sha256: None,
                    acquisition_receipt_id: None,
                    acquisition_receipt_sha256: None,
                    acquisition_attestation_sha256: None,
                },
                environment_profile: hell_testkit::EnvironmentProfile::Explicit,
                process_helper_sha256: None,
                mode: hell_testkit::DifferentialMode::Run,
                status: hell_testkit::ProcessStatus {
                    success: true,
                    code: Some(0),
                },
                stdout: hell_testkit::BoundedCapture::from_bytes(b"True\n".to_vec()),
                stderr: hell_testkit::BoundedCapture::from_bytes(Vec::new()),
                raw_stderr: hell_testkit::BoundedCapture::from_bytes(Vec::new()),
                claim_input_stderr: hell_testkit::BoundedCapture::from_bytes(Vec::new()),
                normalizer_sandbox: context.into(),
                normalizer_script: std::path::Path::new(context).join("case.hell"),
                timed_out: false,
                diagnostic: None,
                filesystem: Vec::new(),
                harness_normalizers: Vec::new(),
                claim_normalizers: Vec::new(),
                semantic: Some(semantic),
                resource_audit: Some(hell_testkit::ResourceAudit::default()),
            };
            let bytes = hell_testkit::canonical_conformance_observation_json(&observation).unwrap();
            let value = crate::json::parse_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
            let canonical = crate::json::canonical_json_bytes(&value).unwrap();
            if bytes != canonical {
                let index = bytes
                    .iter()
                    .zip(&canonical)
                    .position(|(left, right)| left != right)
                    .unwrap_or(bytes.len().min(canonical.len()));
                panic!(
                    "testkit observation is noncanonical at {index}: produced={:?} expected={:?}",
                    String::from_utf8_lossy(
                        &bytes[index.saturating_sub(80)..bytes.len().min(index + 160)]
                    ),
                    String::from_utf8_lossy(
                        &canonical[index.saturating_sub(80)..canonical.len().min(index + 160)]
                    ),
                );
            }
            let document = crate::json::json_member(value.object().unwrap(), "semanticTrace")
                .unwrap()
                .array()
                .unwrap()[0]
                .string()
                .unwrap();
            hell_testkit::validate_conformance_semantic_obligation(
                document,
                &case,
                "Text.all",
                CompatibilityDimension::Presentation,
                "raw-observation",
            )
            .unwrap();
            Observation::parse_canonical(bytes).unwrap()
        };
        let candidate = observation(candidate_context);
        let oracle = observation(oracle_context);
        let mut record = EvidenceRecord {
            record_id: String::new(),
            release_plan_sha256: trusted.release_plan_sha256.clone(),
            conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
            candidate_sha: trusted.candidate_sha.clone(),
            candidate_executable_sha256: trusted.candidate_executable_sha256
                [&ConformancePlatform::LinuxX86_64]
                .clone(),
            candidate_build_info_schema_version: 2,
            candidate_compat_tracing: true,
            source_inventory_sha256: trusted.source_inventory_sha256.clone(),
            oracle: trusted.oracle[&ConformancePlatform::LinuxX86_64].clone(),
            platform: ConformancePlatform::LinuxX86_64,
            profile: ProfileId::Upstream,
            target: EvidenceTarget {
                cell: plan.cells[0].key.clone(),
                obligation_id: "raw-observation".to_owned(),
                case_id: case.id.to_string(),
            },
            descriptor_sha256: hell_testkit::case_descriptor_sha256(&case).hex(),
            case_source: CaseSource::Committed,
            candidate_observation_sha256: candidate.sha256.clone(),
            oracle_observation_sha256: oracle.sha256.clone(),
            requested_normalizers: Vec::new(),
        };
        record.record_id = record.canonical_id().unwrap();
        EvidenceRepository {
            records: vec![record],
            observations: BTreeMap::from([
                (candidate.sha256.clone(), candidate),
                (oracle.sha256.clone(), oracle),
            ]),
            exploratory_records: Vec::new(),
        }
    }

    #[test]
    fn exact_missing_mismatch_and_invalid_bindings_are_derived() {
        let (plan, trusted) = fixture(None);
        let universe = [cell_key()];
        let exact = derive_partition(
            &plan,
            &universe,
            &raw_presentation_evidence(&plan, &trusted, "/same", "/same"),
            &trusted,
        )
        .unwrap();
        assert!(
            matches!(
                exact.cells.values().next().unwrap(),
                FinalDisposition::Verified {
                    mode: VerificationMode::Exact,
                    ..
                }
            ),
            "{:?}",
            exact.cells.values().next().unwrap()
        );

        let missing =
            derive_partition(&plan, &universe, &EvidenceRepository::default(), &trusted).unwrap();
        assert!(matches!(
            missing.cells.values().next().unwrap(),
            FinalDisposition::Blocked {
                blocker: Blocker::MissingEvidence { .. }
            }
        ));

        let mismatch = derive_partition(
            &plan,
            &universe,
            &raw_presentation_evidence(&plan, &trusted, "/candidate", "/oracle"),
            &trusted,
        )
        .unwrap();
        assert!(matches!(
            mismatch.cells.values().next().unwrap(),
            FinalDisposition::Blocked {
                blocker: Blocker::Mismatch { .. }
            }
        ));

        let mut invalid = raw_presentation_evidence(&plan, &trusted, "/same", "/same");
        invalid.records[0].candidate_sha = "e".repeat(40);
        invalid.records[0].record_id = invalid.records[0].canonical_id().unwrap();
        let invalid = derive_partition(&plan, &universe, &invalid, &trusted).unwrap();
        assert!(matches!(
            invalid.cells.values().next().unwrap(),
            FinalDisposition::Blocked {
                blocker: Blocker::InvalidEvidence { .. }
            }
        ));
    }

    #[test]
    fn mismatch_exemptions_require_exact_fingerprint() {
        let exemption = PlannedExemption {
            id: "EX-MISMATCH-1".to_owned(),
            kind: ExemptionKind::KnownDivergence,
            candidate_sha: "a".repeat(40),
            standard: super::super::RELEASE_STANDARD.to_owned(),
            baseline: "2026-05-29".to_owned(),
            cell: cell_key(),
            obligation_id: "raw-observation".to_owned(),
            expected_mismatch_sha256: Some("f".repeat(64)),
            issue: "COMPAT-1".to_owned(),
            rationale: "Exact reviewed mismatch only.".to_owned(),
            review_group: "release-conformance".to_owned(),
            expires_on: "2026-08-14".to_owned(),
        };
        let (plan, trusted) = fixture(Some(exemption.clone()));
        assert!(
            derive_partition(
                &plan,
                &[cell_key()],
                &raw_presentation_evidence(&plan, &trusted, "/candidate", "/oracle"),
                &trusted,
            )
            .is_err()
        );
    }

    #[test]
    fn unused_exemption_is_rejected() {
        let exemption = PlannedExemption {
            id: "EX-UNUSED-1".to_owned(),
            kind: ExemptionKind::EvidenceGap,
            candidate_sha: "a".repeat(40),
            standard: super::super::RELEASE_STANDARD.to_owned(),
            baseline: "2026-05-29".to_owned(),
            cell: cell_key(),
            obligation_id: "raw-observation".to_owned(),
            expected_mismatch_sha256: None,
            issue: "COMPAT-1".to_owned(),
            rationale: "Temporary exact evidence gap.".to_owned(),
            review_group: "release-conformance".to_owned(),
            expires_on: "2026-08-14".to_owned(),
        };
        let (plan, trusted) = fixture(Some(exemption));
        assert!(
            derive_partition(
                &plan,
                &[cell_key()],
                &raw_presentation_evidence(&plan, &trusted, "/same", "/same"),
                &trusted,
            )
            .is_err()
        );
    }

    #[test]
    fn generic_observation_agreement_cannot_verify_a_semantic_obligation() {
        let (mut plan, trusted) = fixture(None);
        plan.cells[0].obligations[0].id = "typed-result".to_owned();
        let mut repository = evidence(&plan, &trusted, b"same\n", b"same\n");
        repository.records[0].target.obligation_id = "typed-result".to_owned();
        repository.records[0].record_id = repository.records[0].canonical_id().unwrap();
        let partition = derive_partition(&plan, &[cell_key()], &repository, &trusted).unwrap();
        assert!(matches!(
            partition.cells.values().next().unwrap(),
            FinalDisposition::Blocked {
                blocker: Blocker::InvalidEvidence { code }
            } if matches!(
                *code,
                crate::conformance::ledger::InvalidEvidenceCode::TrustedCaseUnavailable
                    | crate::conformance::ledger::InvalidEvidenceCode::CandidateSemanticObligationInvalid
            )
        ));
    }

    #[test]
    fn generated_agreement_never_verifies_and_generated_mismatch_blocks_acceptance() {
        let (plan, trusted) = fixture(None);
        let mut generated_claim = raw_presentation_evidence(&plan, &trusted, "/same", "/same");
        generated_claim.records[0].case_source = CaseSource::Generated {
            generator_version: super::super::EXPLORATORY_GENERATOR_VERSION.to_owned(),
            seed: super::super::EXPLORATORY_GENERATOR_SEED,
        };
        generated_claim.records[0].record_id = generated_claim.records[0].canonical_id().unwrap();
        assert!(derive_partition(&plan, &[cell_key()], &generated_claim, &trusted).is_err());
        let mut repository = raw_presentation_evidence(&plan, &trusted, "/same", "/same");
        let agreement = Observation::from_bytes(b"same\n".to_vec());
        repository
            .observations
            .insert(agreement.sha256.clone(), agreement.clone());
        let generated = hell_testkit::generated_typed_cases(1, 1).remove(0);
        repository
            .exploratory_records
            .push(super::super::ExploratoryRecord {
                generated_case_id: generated.id.to_string(),
                platform: ConformancePlatform::LinuxX86_64,
                generator_version: "typed-generator-v1".to_owned(),
                seed: 1,
                source_sha256: hell_testkit::sha256_bytes(generated.source.as_bytes()).hex(),
                ast_sha256: generated.ast_sha256.hex(),
                release_plan_sha256: trusted.release_plan_sha256.clone(),
                conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
                source_inventory_sha256: trusted.source_inventory_sha256.clone(),
                candidate_sha: trusted.candidate_sha.clone(),
                candidate_executable_sha256: trusted.candidate_executable_sha256
                    [&ConformancePlatform::LinuxX86_64]
                    .clone(),
                candidate_build_info_schema_version: 2,
                candidate_compat_tracing: true,
                oracle: trusted.oracle[&ConformancePlatform::LinuxX86_64].clone(),
                candidate_observation_sha256: agreement.sha256.clone(),
                oracle_observation_sha256: agreement.sha256,
            });
        let partition = derive_partition(&plan, &[cell_key()], &repository, &trusted).unwrap();
        assert_eq!(partition.counts().unwrap().verified(), 1);
        assert!(partition.unclassified_mismatches.is_empty());

        let original_ast = repository.exploratory_records[0].ast_sha256.clone();
        repository.exploratory_records[0].ast_sha256 = "0".repeat(64);
        assert!(derive_partition(&plan, &[cell_key()], &repository, &trusted).is_err());
        repository.exploratory_records[0].ast_sha256 = original_ast;

        let disagreement = Observation::from_bytes(b"different\n".to_vec());
        let digest = disagreement.sha256.clone();
        repository.observations.insert(digest.clone(), disagreement);
        repository.exploratory_records[0].oracle_observation_sha256 = digest;
        let partition = derive_partition(&plan, &[cell_key()], &repository, &trusted).unwrap();
        let acceptance =
            ConformanceAcceptance::derive(&plan, &partition, "a".repeat(64), "b".repeat(64))
                .unwrap();
        assert!(!acceptance.admitted);
        assert_eq!(acceptance.counts.verified(), 1);
        assert_eq!(acceptance.unclassified_mismatch_count, 1);
    }
}
