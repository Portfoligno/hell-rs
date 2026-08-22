use std::collections::{BTreeMap, BTreeSet};

use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};
use crate::release::schema::{number, object, string};
use crate::release::schema::{require_digest, require_sha};

use super::key::{CellKey, ConformancePlatform};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceStrategy {
    NativeOracle,
    PortableStatic,
    StructuralInvariant,
    CommittedDifferentialCorpus,
    CrossPlatformRelation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlannedObligation {
    pub(crate) id: String,
    pub(crate) strategy: EvidenceStrategy,
    pub(crate) case_ids: Vec<String>,
    pub(crate) case_descriptor_sha256: BTreeMap<String, String>,
    pub(crate) allowed_normalizers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScopeDisposition {
    Required {
        decision_id: String,
    },
    NotApplicable {
        decision_id: String,
        rationale: String,
    },
    Excluded {
        scope_id: String,
        rationale: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExemptionKind {
    EvidenceGap,
    KnownDivergence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlannedExemption {
    pub(crate) id: String,
    pub(crate) kind: ExemptionKind,
    pub(crate) candidate_sha: String,
    pub(crate) standard: String,
    pub(crate) baseline: String,
    pub(crate) cell: CellKey,
    pub(crate) obligation_id: String,
    pub(crate) expected_mismatch_sha256: Option<String>,
    pub(crate) issue: String,
    pub(crate) rationale: String,
    pub(crate) review_group: String,
    pub(crate) expires_on: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PlannedCell {
    pub(crate) key: CellKey,
    pub(crate) scope: ScopeDisposition,
    pub(crate) obligations: Vec<PlannedObligation>,
    pub(crate) exemption: Option<PlannedExemption>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConformancePlan {
    pub(crate) standard: String,
    pub(crate) candidate_sha: String,
    pub(crate) workflow_sha: String,
    pub(crate) release_evaluation_instant: String,
    pub(crate) trusted_inputs_sha256: String,
    pub(crate) source_inventory_sha256: String,
    pub(crate) baseline: String,
    pub(crate) exploratory_generator_version: String,
    pub(crate) exploratory_generator_seed: u64,
    pub(crate) exploratory_generator_count_per_platform: u64,
    pub(crate) generated_agreement_may_verify: bool,
    pub(crate) generated_mismatch_blocks: bool,
    pub(crate) cells: Vec<PlannedCell>,
    pub(crate) plan_sha256: String,
}

impl ConformancePlan {
    pub(crate) fn json_without_digest(&self) -> JsonValue {
        object([
            ("baseline", string(&self.baseline)),
            ("candidateSha", string(&self.candidate_sha)),
            (
                "cells",
                JsonValue::Array(self.cells.iter().map(PlannedCell::json).collect()),
            ),
            (
                "exploratoryGenerator",
                object([
                    (
                        "countPerPlatform",
                        number(self.exploratory_generator_count_per_platform),
                    ),
                    ("rootSeed", number(self.exploratory_generator_seed)),
                    ("version", string(&self.exploratory_generator_version)),
                ]),
            ),
            (
                "exploratoryPolicy",
                object([
                    (
                        "generatedAgreementMayVerify",
                        JsonValue::Bool(self.generated_agreement_may_verify),
                    ),
                    (
                        "generatedMismatchBlocks",
                        JsonValue::Bool(self.generated_mismatch_blocks),
                    ),
                ]),
            ),
            (
                "releaseEvaluationInstant",
                string(&self.release_evaluation_instant),
            ),
            ("schemaVersion", number(1)),
            (
                "sourceInventorySha256",
                string(&self.source_inventory_sha256),
            ),
            ("standard", string(&self.standard)),
            ("trustedInputsSha256", string(&self.trusted_inputs_sha256)),
            ("workflowSha", string(&self.workflow_sha)),
        ])
    }

    pub(crate) fn json(&self) -> JsonValue {
        let mut value = self.json_without_digest().object().expect("object").clone();
        value.insert("planSha256".to_owned(), string(&self.plan_sha256));
        JsonValue::Object(value)
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "baseline",
                "candidateSha",
                "cells",
                "exploratoryGenerator",
                "exploratoryPolicy",
                "planSha256",
                "releaseEvaluationInstant",
                "schemaVersion",
                "sourceInventorySha256",
                "standard",
                "trustedInputsSha256",
                "workflowSha",
            ],
        )?;
        if json_member(fields, "schemaVersion")?.number()? != 1 {
            return Err("unsupported conformance plan schema".to_owned());
        }
        let exploratory = json_member(fields, "exploratoryGenerator")?.object()?;
        require_exact_json_keys(exploratory, &["countPerPlatform", "rootSeed", "version"])?;
        let exploratory_policy = json_member(fields, "exploratoryPolicy")?.object()?;
        require_exact_json_keys(
            exploratory_policy,
            &["generatedAgreementMayVerify", "generatedMismatchBlocks"],
        )?;
        let mut plan = Self {
            standard: text(fields, "standard")?,
            candidate_sha: text(fields, "candidateSha")?,
            workflow_sha: text(fields, "workflowSha")?,
            release_evaluation_instant: text(fields, "releaseEvaluationInstant")?,
            trusted_inputs_sha256: text(fields, "trustedInputsSha256")?,
            source_inventory_sha256: text(fields, "sourceInventorySha256")?,
            baseline: text(fields, "baseline")?,
            exploratory_generator_version: text(exploratory, "version")?,
            exploratory_generator_seed: json_member(exploratory, "rootSeed")?.number()?,
            exploratory_generator_count_per_platform: json_member(exploratory, "countPerPlatform")?
                .number()?,
            generated_agreement_may_verify: json_member(
                exploratory_policy,
                "generatedAgreementMayVerify",
            )?
            .boolean()?,
            generated_mismatch_blocks: json_member(exploratory_policy, "generatedMismatchBlocks")?
                .boolean()?,
            cells: json_member(fields, "cells")?
                .array()?
                .iter()
                .map(PlannedCell::parse)
                .collect::<Result<_, _>>()?,
            plan_sha256: text(fields, "planSha256")?,
        };
        let stated = std::mem::take(&mut plan.plan_sha256);
        let observed =
            hell_testkit::sha256_bytes(&canonical_json_bytes(&plan.json_without_digest())?).hex();
        plan.plan_sha256 = stated;
        if observed != plan.plan_sha256 {
            return Err("conformance plan self-digest mismatch".to_owned());
        }
        plan.validate(&super::canonical_universe()?)?;
        Ok(plan)
    }

    pub(crate) fn validate(&self, expected_universe: &[CellKey]) -> Result<(), String> {
        if self.standard != super::RELEASE_STANDARD {
            return Err("conformance standard differs from release policy".to_owned());
        }
        require_sha(&self.candidate_sha, "conformance candidate SHA")?;
        require_sha(&self.workflow_sha, "conformance workflow SHA")?;
        for (digest, label) in [
            (&self.trusted_inputs_sha256, "trusted inputs digest"),
            (&self.source_inventory_sha256, "source inventory digest"),
            (&self.plan_sha256, "conformance plan digest"),
        ] {
            require_digest(digest, label)?;
        }
        validate_utc_instant(&self.release_evaluation_instant)?;
        if self.exploratory_generator_version != super::EXPLORATORY_GENERATOR_VERSION
            || self.exploratory_generator_seed != super::EXPLORATORY_GENERATOR_SEED
            || self.exploratory_generator_count_per_platform
                != u64::try_from(super::EXPLORATORY_GENERATOR_COUNT)
                    .map_err(|_| "exploratory generator count overflow")?
            || self.generated_agreement_may_verify != super::GENERATED_AGREEMENT_MAY_VERIFY
            || self.generated_mismatch_blocks != super::GENERATED_MISMATCH_BLOCKS
        {
            return Err(
                "conformance plan exploratory schedule differs from trusted code".to_owned(),
            );
        }
        if self.baseline.is_empty() {
            return Err("conformance baseline is empty".to_owned());
        }
        let observed = self.cells.iter().map(|cell| &cell.key).collect::<Vec<_>>();
        let omitted_final = super::mutant_active("required-cell-omitted-from-plan")
            && observed.len().checked_add(1) == Some(expected_universe.len())
            && observed
                .iter()
                .copied()
                .eq(expected_universe[..observed.len()].iter());
        let accepted_duplicate = super::mutant_active("duplicate-cell-accepted")
            && one_duplicate_from_universe(&observed, expected_universe);
        if !observed.iter().copied().eq(expected_universe.iter())
            && !omitted_final
            && !accepted_duplicate
        {
            return Err("conformance plan does not equal the exact canonical universe".to_owned());
        }

        let mut exemption_ids = BTreeSet::new();
        for cell in &self.cells {
            validate_cell(self, cell, &mut exemption_ids)?;
        }
        Ok(())
    }
}

fn one_duplicate_from_universe(observed: &[&CellKey], expected: &[CellKey]) -> bool {
    if observed.len() != expected.len().saturating_add(1) {
        return false;
    }
    (1..observed.len()).any(|duplicate_index| {
        observed[duplicate_index] == observed[duplicate_index - 1]
            && observed
                .iter()
                .enumerate()
                .filter_map(|(index, value)| (index != duplicate_index).then_some(*value))
                .eq(expected.iter())
    })
}

pub(crate) fn assurance_final_cell_omission() -> Result<(), String> {
    let first = assurance_cell("Bool.bool")?;
    let second = assurance_cell("Bool.not")?;
    assurance_plan(vec![first.clone()]).validate(&[first.key, second.key])
}

pub(crate) fn assurance_duplicate_cell() -> Result<(), String> {
    let cell = assurance_cell("Bool.bool")?;
    assurance_plan(vec![cell.clone(), cell.clone()]).validate(&[cell.key])
}

pub(crate) fn assurance_exemption_selector_mismatch() -> Result<(), String> {
    let mut plan = assurance_exemption_plan("2026-08-14")?;
    let selector = &mut plan
        .cells
        .first_mut()
        .and_then(|cell| cell.exemption.as_mut())
        .ok_or_else(|| "assurance exemption fixture is incomplete".to_owned())?
        .candidate_sha;
    hell_builtins::UPSTREAM_COMMIT.clone_into(selector);
    let expected = vec![plan.cells[0].key.clone()];
    plan.validate(&expected)
}

pub(crate) fn assurance_exemption_expired_at_plan_time() -> Result<(), String> {
    let plan = assurance_exemption_plan("2026-08-13")?;
    let expected = vec![plan.cells[0].key.clone()];
    plan.validate(&expected)
}

fn assurance_exemption_plan(expires_on: &str) -> Result<ConformancePlan, String> {
    let mut cell = assurance_cell("Bool.bool")?;
    let obligation = PlannedObligation {
        id: "bool-native".to_owned(),
        strategy: EvidenceStrategy::NativeOracle,
        case_ids: vec!["bool-false".to_owned()],
        case_descriptor_sha256: BTreeMap::from([(
            "bool-false".to_owned(),
            hell_testkit::sha256_bytes(b"bool-false assurance descriptor").hex(),
        )]),
        allowed_normalizers: Vec::new(),
    };
    cell.scope = ScopeDisposition::Required {
        decision_id: "applicable".to_owned(),
    };
    cell.obligations = vec![obligation.clone()];
    let candidate_sha = assurance_candidate_sha();
    cell.exemption = Some(PlannedExemption {
        id: "EX-ASSURANCE".to_owned(),
        kind: ExemptionKind::EvidenceGap,
        candidate_sha: candidate_sha.clone(),
        standard: super::RELEASE_STANDARD.to_owned(),
        baseline: "2026-05-29".to_owned(),
        cell: cell.key.clone(),
        obligation_id: obligation.id,
        expected_mismatch_sha256: None,
        issue: "COMPAT-ASSURANCE".to_owned(),
        rationale: "Focused exact-selector mutation assurance.".to_owned(),
        review_group: "release-conformance".to_owned(),
        expires_on: expires_on.to_owned(),
    });
    let mut plan = assurance_plan(vec![cell]);
    plan.candidate_sha = candidate_sha;
    Ok(plan)
}

fn assurance_cell(builtin: &str) -> Result<PlannedCell, String> {
    Ok(PlannedCell {
        key: CellKey::new(
            builtin,
            hell_builtins::CompatibilityDimension::PureRuntime,
            super::ProfileId::Upstream,
            ConformancePlatform::LinuxX86_64,
        )?,
        scope: ScopeDisposition::NotApplicable {
            decision_id: "assurance-not-applicable".to_owned(),
            rationale: "Focused ledger inventory assurance.".to_owned(),
        },
        obligations: Vec::new(),
        exemption: None,
    })
}

fn assurance_plan(cells: Vec<PlannedCell>) -> ConformancePlan {
    ConformancePlan {
        standard: super::RELEASE_STANDARD.to_owned(),
        candidate_sha: assurance_candidate_sha(),
        workflow_sha: hell_builtins::UPSTREAM_COMMIT.to_owned(),
        release_evaluation_instant: "2026-08-13T00:00:00Z".to_owned(),
        trusted_inputs_sha256: hell_testkit::sha256_bytes(b"assurance trusted inputs").hex(),
        source_inventory_sha256: hell_testkit::sha256_bytes(b"assurance source inventory").hex(),
        baseline: "2026-05-29".to_owned(),
        exploratory_generator_version: super::EXPLORATORY_GENERATOR_VERSION.to_owned(),
        exploratory_generator_seed: super::EXPLORATORY_GENERATOR_SEED,
        exploratory_generator_count_per_platform: u64::try_from(super::EXPLORATORY_GENERATOR_COUNT)
            .expect("exploratory count is bounded"),
        generated_agreement_may_verify: super::GENERATED_AGREEMENT_MAY_VERIFY,
        generated_mismatch_blocks: super::GENERATED_MISMATCH_BLOCKS,
        cells,
        plan_sha256: hell_testkit::sha256_bytes(b"assurance conformance plan").hex(),
    }
}

fn assurance_candidate_sha() -> String {
    let digest = hell_testkit::sha256_bytes(b"assurance candidate commit").hex();
    digest
        .strip_suffix(&digest[hell_builtins::UPSTREAM_COMMIT.len()..])
        .expect("digest has at least one Git SHA worth of bytes")
        .to_owned()
}

impl PlannedCell {
    fn json(&self) -> JsonValue {
        let scope = match &self.scope {
            ScopeDisposition::Required { decision_id } => object([
                ("decisionId", string(decision_id)),
                ("kind", string("required")),
                ("rationale", string("")),
            ]),
            ScopeDisposition::NotApplicable {
                decision_id,
                rationale,
            } => object([
                ("decisionId", string(decision_id)),
                ("kind", string("not-applicable")),
                ("rationale", string(rationale)),
            ]),
            ScopeDisposition::Excluded {
                scope_id,
                rationale,
            } => object([
                ("decisionId", string(scope_id)),
                ("kind", string("excluded")),
                ("rationale", string(rationale)),
            ]),
        };
        object([
            (
                "exemptions",
                JsonValue::Array(self.exemption.iter().map(PlannedExemption::json).collect()),
            ),
            ("key", self.key.json()),
            (
                "obligations",
                JsonValue::Array(
                    self.obligations
                        .iter()
                        .map(PlannedObligation::json)
                        .collect(),
                ),
            ),
            ("scope", scope),
        ])
    }

    fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(fields, &["exemptions", "key", "obligations", "scope"])?;
        let scope = json_member(fields, "scope")?.object()?;
        require_exact_json_keys(scope, &["decisionId", "kind", "rationale"])?;
        let decision_id = text(scope, "decisionId")?;
        let rationale = text(scope, "rationale")?;
        let scope = match json_member(scope, "kind")?.string()? {
            "required" if rationale.is_empty() => ScopeDisposition::Required { decision_id },
            "not-applicable" => ScopeDisposition::NotApplicable {
                decision_id,
                rationale,
            },
            "excluded" => ScopeDisposition::Excluded {
                scope_id: decision_id,
                rationale,
            },
            kind => return Err(format!("invalid conformance scope kind {kind:?}")),
        };
        let exemptions = json_member(fields, "exemptions")?.array()?;
        if exemptions.len() > 1 {
            return Err("a planned cell has multiple exemptions".to_owned());
        }
        Ok(Self {
            key: CellKey::parse(json_member(fields, "key")?)?,
            scope,
            obligations: json_member(fields, "obligations")?
                .array()?
                .iter()
                .map(PlannedObligation::parse)
                .collect::<Result<_, _>>()?,
            exemption: exemptions
                .first()
                .map(PlannedExemption::parse)
                .transpose()?,
        })
    }
}

impl PlannedObligation {
    fn json(&self) -> JsonValue {
        object([
            ("allowedNormalizers", strings(&self.allowed_normalizers)),
            (
                "caseDescriptorSha256",
                JsonValue::Object(
                    self.case_descriptor_sha256
                        .iter()
                        .map(|(key, value)| (key.clone(), string(value)))
                        .collect(),
                ),
            ),
            ("caseIds", strings(&self.case_ids)),
            ("id", string(&self.id)),
            ("strategy", string(strategy_id(self.strategy))),
        ])
    }

    fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "allowedNormalizers",
                "caseDescriptorSha256",
                "caseIds",
                "id",
                "strategy",
            ],
        )?;
        Ok(Self {
            id: text(fields, "id")?,
            strategy: parse_strategy(json_member(fields, "strategy")?.string()?)?,
            case_ids: parse_strings(json_member(fields, "caseIds")?)?,
            case_descriptor_sha256: json_member(fields, "caseDescriptorSha256")?
                .object()?
                .iter()
                .map(|(key, value)| Ok((key.clone(), value.string()?.to_owned())))
                .collect::<Result<_, String>>()?,
            allowed_normalizers: parse_strings(json_member(fields, "allowedNormalizers")?)?,
        })
    }
}

impl PlannedExemption {
    fn json(&self) -> JsonValue {
        object([
            ("baseline", string(&self.baseline)),
            ("candidateSha", string(&self.candidate_sha)),
            ("cell", self.cell.json()),
            ("expiresOn", string(&self.expires_on)),
            (
                "expectedMismatchSha256",
                self.expected_mismatch_sha256
                    .as_ref()
                    .map_or(JsonValue::Null, |value| string(value)),
            ),
            ("id", string(&self.id)),
            ("issue", string(&self.issue)),
            (
                "kind",
                string(match self.kind {
                    ExemptionKind::EvidenceGap => "evidence-gap",
                    ExemptionKind::KnownDivergence => "known-divergence",
                }),
            ),
            ("obligationId", string(&self.obligation_id)),
            ("rationale", string(&self.rationale)),
            ("reviewGroup", string(&self.review_group)),
            ("standard", string(&self.standard)),
        ])
    }

    fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "baseline",
                "candidateSha",
                "cell",
                "expiresOn",
                "expectedMismatchSha256",
                "id",
                "issue",
                "kind",
                "obligationId",
                "rationale",
                "reviewGroup",
                "standard",
            ],
        )?;
        Ok(Self {
            id: text(fields, "id")?,
            kind: match json_member(fields, "kind")?.string()? {
                "evidence-gap" => ExemptionKind::EvidenceGap,
                "known-divergence" => ExemptionKind::KnownDivergence,
                value => return Err(format!("unknown exemption kind {value:?}")),
            },
            candidate_sha: text(fields, "candidateSha")?,
            standard: text(fields, "standard")?,
            baseline: text(fields, "baseline")?,
            cell: CellKey::parse(json_member(fields, "cell")?)?,
            obligation_id: text(fields, "obligationId")?,
            expected_mismatch_sha256: match json_member(fields, "expectedMismatchSha256")? {
                JsonValue::Null => None,
                value => Some(value.string()?.to_owned()),
            },
            issue: text(fields, "issue")?,
            rationale: text(fields, "rationale")?,
            review_group: text(fields, "reviewGroup")?,
            expires_on: text(fields, "expiresOn")?,
        })
    }
}

fn text(fields: &BTreeMap<String, JsonValue>, key: &str) -> Result<String, String> {
    Ok(json_member(fields, key)?.string()?.to_owned())
}

fn strings(values: &[String]) -> JsonValue {
    JsonValue::Array(values.iter().map(|value| string(value)).collect())
}

fn parse_strings(value: &JsonValue) -> Result<Vec<String>, String> {
    value
        .array()?
        .iter()
        .map(|value| Ok(value.string()?.to_owned()))
        .collect()
}

const fn strategy_id(strategy: EvidenceStrategy) -> &'static str {
    match strategy {
        EvidenceStrategy::NativeOracle => "native-oracle",
        EvidenceStrategy::PortableStatic => "portable-static",
        EvidenceStrategy::StructuralInvariant => "structural-invariant",
        EvidenceStrategy::CommittedDifferentialCorpus => "committed-differential-corpus",
        EvidenceStrategy::CrossPlatformRelation => "cross-platform-relation",
    }
}

fn parse_strategy(value: &str) -> Result<EvidenceStrategy, String> {
    match value {
        "native-oracle" => Ok(EvidenceStrategy::NativeOracle),
        "portable-static" => Ok(EvidenceStrategy::PortableStatic),
        "structural-invariant" => Ok(EvidenceStrategy::StructuralInvariant),
        "committed-differential-corpus" => Ok(EvidenceStrategy::CommittedDifferentialCorpus),
        "cross-platform-relation" => Ok(EvidenceStrategy::CrossPlatformRelation),
        _ => Err(format!("unknown evidence strategy {value:?}")),
    }
}

fn validate_cell(
    plan: &ConformancePlan,
    cell: &PlannedCell,
    exemption_ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    match &cell.scope {
        ScopeDisposition::Required { decision_id } => {
            require_nonempty_token(decision_id, "required decision ID")?;
            if cell.obligations.is_empty() {
                return Err(format!("required cell {} has no obligation", cell.key));
            }
            let mut obligation_ids = BTreeSet::new();
            for obligation in &cell.obligations {
                require_nonempty_token(&obligation.id, "obligation ID")?;
                if !obligation_ids.insert(obligation.id.as_str()) {
                    return Err(format!("cell {} repeats an obligation ID", cell.key));
                }
                require_unique_tokens(&obligation.case_ids, "case IDs")?;
                let descriptor_ids = obligation
                    .case_descriptor_sha256
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                let case_ids = obligation
                    .case_ids
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                if descriptor_ids != case_ids {
                    return Err(format!(
                        "obligation {} case descriptor inventory differs",
                        obligation.id
                    ));
                }
                for digest in obligation.case_descriptor_sha256.values() {
                    require_digest(digest, "case descriptor digest")?;
                }
                require_unique_tokens(&obligation.allowed_normalizers, "normalizer IDs")?;
                for normalizer in &obligation.allowed_normalizers {
                    let id = hell_builtins::NormalizerId::ALL
                        .iter()
                        .copied()
                        .find(|id| id.as_str() == normalizer)
                        .ok_or_else(|| format!("unknown normalizer ID {normalizer:?}"))?;
                    let contract = hell_builtins::normalizer_contract(id)
                        .ok_or_else(|| format!("missing normalizer contract {normalizer:?}"))?;
                    let platform_allowed = contract.requires_platforms.iter().any(|platform| {
                        matches!(
                            (platform, cell.key.platform),
                            (hell_builtins::ClaimPlatform::All, _)
                                | (
                                    hell_builtins::ClaimPlatform::Linux,
                                    ConformancePlatform::LinuxX86_64
                                )
                                | (
                                    hell_builtins::ClaimPlatform::MacOs,
                                    ConformancePlatform::MacosAarch64
                                )
                                | (
                                    hell_builtins::ClaimPlatform::Windows,
                                    ConformancePlatform::WindowsX86_64
                                )
                        )
                    });
                    if contract.version == 0
                        || contract.implementation.is_empty()
                        || require_digest(
                            contract.implementation_sha256,
                            "normalizer implementation digest",
                        )
                        .is_err()
                        || !contract.allowed_dimensions.contains(&cell.key.dimension)
                        || !platform_allowed
                        || !contract.idempotent
                    {
                        return Err(format!(
                            "normalizer {normalizer:?} is not authorized for {}",
                            cell.key
                        ));
                    }
                }
            }
            if let Some(exemption) = &cell.exemption {
                validate_exemption(plan, cell, exemption, exemption_ids)?;
            }
        }
        ScopeDisposition::NotApplicable {
            decision_id,
            rationale,
        } => {
            require_nonempty_token(decision_id, "not-applicable decision ID")?;
            require_nonempty_text(rationale, "not-applicable rationale")?;
            require_no_required_metadata(cell)?;
        }
        ScopeDisposition::Excluded {
            scope_id,
            rationale,
        } => {
            require_nonempty_token(scope_id, "exclusion scope ID")?;
            require_nonempty_text(rationale, "exclusion rationale")?;
            require_no_required_metadata(cell)?;
        }
    }
    Ok(())
}

fn require_no_required_metadata(cell: &PlannedCell) -> Result<(), String> {
    if !cell.obligations.is_empty() || cell.exemption.is_some() {
        return Err(format!(
            "non-required cell {} carries an obligation or exemption",
            cell.key
        ));
    }
    Ok(())
}

fn validate_exemption(
    plan: &ConformancePlan,
    cell: &PlannedCell,
    exemption: &PlannedExemption,
    exemption_ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    for (value, label) in [
        (&exemption.id, "exemption ID"),
        (&exemption.baseline, "exemption baseline"),
        (&exemption.obligation_id, "exemption obligation"),
        (&exemption.issue, "exemption issue"),
        (&exemption.rationale, "exemption rationale"),
        (&exemption.review_group, "exemption review group"),
    ] {
        require_nonempty_text(value, label)?;
    }
    if !super::mutant_active("exemption-wildcard-accepted")
        && (contains_wildcard(&exemption.id)
            || contains_wildcard(&exemption.candidate_sha)
            || contains_wildcard(&exemption.obligation_id)
            || contains_wildcard(&exemption.cell.canonical_id()))
    {
        return Err("release exemption contains wildcard syntax".to_owned());
    }
    require_sha(&exemption.candidate_sha, "exemption candidate SHA")?;
    validate_date(&exemption.expires_on)?;
    let selector_matches = (super::mutant_active("exemption-candidate-sha-ignored")
        || exemption.candidate_sha == plan.candidate_sha)
        && exemption.standard == plan.standard
        && exemption.baseline == plan.baseline
        && exemption.cell == cell.key
        && cell
            .obligations
            .iter()
            .any(|obligation| obligation.id == exemption.obligation_id);
    if !super::mutant_active("compare-exemption-id-only") && !selector_matches {
        return Err(format!(
            "exemption {} does not exactly target its cell",
            exemption.id
        ));
    }
    let (evaluation_date, _) = plan
        .release_evaluation_instant
        .split_once('T')
        .ok_or_else(|| "trusted evaluation instant has no date".to_owned())?;
    if !super::mutant_active("exemption-expiry-bypassed")
        && exemption.expires_on.as_str() <= evaluation_date
    {
        return Err(format!("exemption {} is expired", exemption.id));
    }
    match exemption.kind {
        ExemptionKind::EvidenceGap if exemption.expected_mismatch_sha256.is_some() => {
            return Err("evidence-gap exemption carries a mismatch digest".to_owned());
        }
        ExemptionKind::KnownDivergence => {
            require_digest(
                exemption
                    .expected_mismatch_sha256
                    .as_deref()
                    .ok_or_else(|| "known-divergence exemption lacks mismatch digest".to_owned())?,
                "expected mismatch digest",
            )?;
        }
        ExemptionKind::EvidenceGap => {}
    }
    if !exemption_ids.insert(exemption.id.clone()) {
        return Err(format!("duplicate release exemption ID {}", exemption.id));
    }
    Ok(())
}

fn contains_wildcard(value: &str) -> bool {
    value.contains(['*', '?', '[', ']']) || matches!(value, "all" | "ALL") || value.ends_with('-')
}

fn require_unique_tokens(values: &[String], label: &str) -> Result<(), String> {
    let mut observed = BTreeSet::new();
    for value in values {
        require_nonempty_token(value, label)?;
        if !observed.insert(value) {
            return Err(format!("{label} contain a duplicate"));
        }
    }
    Ok(())
}

fn require_nonempty_token(value: &str, label: &str) -> Result<(), String> {
    require_nonempty_text(value, label)?;
    if value.contains(char::is_whitespace) || value.contains(['\0', '*', '?']) {
        return Err(format!("{label} is not a canonical token"));
    }
    Ok(())
}

fn require_nonempty_text(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.contains(['\0', '\r']) {
        return Err(format!("{label} is empty or malformed"));
    }
    Ok(())
}

pub(super) fn validate_date(value: &str) -> Result<(), String> {
    const YEAR_PATTERN: &str = "YYYY";
    const MONTH_PATTERN: &str = "MM";
    const DAY_PATTERN: &str = "DD";
    let mut components = value.split('-');
    let year_text = components
        .next()
        .ok_or_else(|| "date must be canonical YYYY-MM-DD".to_owned())?;
    let month_text = components
        .next()
        .ok_or_else(|| "date must be canonical YYYY-MM-DD".to_owned())?;
    let day_text = components
        .next()
        .ok_or_else(|| "date must be canonical YYYY-MM-DD".to_owned())?;
    if components.next().is_some()
        || year_text.len() != YEAR_PATTERN.len()
        || month_text.len() != MONTH_PATTERN.len()
        || day_text.len() != DAY_PATTERN.len()
    {
        return Err("date must be canonical YYYY-MM-DD".to_owned());
    }
    let year = parse_decimal(year_text.as_bytes())?;
    let month = parse_decimal(month_text.as_bytes())?;
    let day = parse_decimal(day_text.as_bytes())?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err("date month is out of range".to_owned()),
    };
    if day == 0 || day > maximum {
        return Err("date day is out of range".to_owned());
    }
    let canonical = format!(
        "{year:0year_width$}-{month:0month_width$}-{day:0day_width$}",
        year_width = YEAR_PATTERN.len(),
        month_width = MONTH_PATTERN.len(),
        day_width = DAY_PATTERN.len(),
    );
    if canonical != value {
        return Err("date must be canonical YYYY-MM-DD".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_utc_instant(value: &str) -> Result<(), String> {
    const HOUR_PATTERN: &str = "hh";
    const MINUTE_PATTERN: &str = "mm";
    const SECOND_PATTERN: &str = "ss";
    let without_zone = value
        .strip_suffix('Z')
        .ok_or_else(|| "trusted evaluation instant must be canonical UTC".to_owned())?;
    let (date, time) = without_zone
        .split_once('T')
        .ok_or_else(|| "trusted evaluation instant must be canonical UTC".to_owned())?;
    if time.contains('T') {
        return Err("trusted evaluation instant must be canonical UTC".to_owned());
    }
    validate_date(date)?;
    let mut components = time.split(':');
    let hour_text = components
        .next()
        .ok_or_else(|| "trusted evaluation instant must be canonical UTC".to_owned())?;
    let minute_text = components
        .next()
        .ok_or_else(|| "trusted evaluation instant must be canonical UTC".to_owned())?;
    let second_text = components
        .next()
        .ok_or_else(|| "trusted evaluation instant must be canonical UTC".to_owned())?;
    if components.next().is_some()
        || hour_text.len() != HOUR_PATTERN.len()
        || minute_text.len() != MINUTE_PATTERN.len()
        || second_text.len() != SECOND_PATTERN.len()
    {
        return Err("trusted evaluation instant must be canonical UTC".to_owned());
    }
    let hour = parse_decimal(hour_text.as_bytes())?;
    let minute = parse_decimal(minute_text.as_bytes())?;
    let second = parse_decimal(second_text.as_bytes())?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err("trusted evaluation instant time is out of range".to_owned());
    }
    let canonical = format!(
        "{date}T{hour:0hour_width$}:{minute:0minute_width$}:{second:0second_width$}Z",
        hour_width = HOUR_PATTERN.len(),
        minute_width = MINUTE_PATTERN.len(),
        second_width = SECOND_PATTERN.len(),
    );
    if canonical != value {
        return Err("trusted evaluation instant must be canonical UTC".to_owned());
    }
    Ok(())
}

fn parse_decimal(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err("decimal value contains a non-digit".to_owned());
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*byte - b'0')))
            .ok_or_else(|| "decimal value overflow".to_owned())
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VerificationMode {
    Exact,
    Normalized,
    PlatformEquivalent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureClass {
    MissingEvidence,
    Mismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Blocker {
    MissingEvidence {
        obligation_id: String,
    },
    Mismatch {
        obligation_id: String,
        mismatch_sha256: String,
    },
    InvalidEvidence {
        code: InvalidEvidenceCode,
    },
    UnclassifiedMismatch {
        platform: super::ConformancePlatform,
        generated_case_id: String,
        candidate_observation_sha256: String,
        oracle_observation_sha256: String,
        mismatch_sha256: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvalidEvidenceCode {
    UnsupportedStrategy,
    EvidenceBinding,
    NormalizerClosure,
    NativePlatformSubstitution,
    MissingCandidateObservation,
    MissingOracleObservation,
    TrustedCaseUnavailable,
    CandidateSemanticObligationInvalid,
    OracleSemanticObligationInvalid,
    NormalizerReplayUnavailable,
    UnauthorizedNormalizer,
}

impl InvalidEvidenceCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedStrategy => "unsupported-strategy-evidence-shape",
            Self::EvidenceBinding => "evidence-binding-invalid",
            Self::NormalizerClosure => "normalizer-closure-invalid",
            Self::NativePlatformSubstitution => "native-platform-substitution",
            Self::MissingCandidateObservation => "candidate-observation-missing",
            Self::MissingOracleObservation => "oracle-observation-missing",
            Self::TrustedCaseUnavailable => "trusted-case-unavailable",
            Self::CandidateSemanticObligationInvalid => "candidate-semantic-obligation-invalid",
            Self::OracleSemanticObligationInvalid => "oracle-semantic-obligation-invalid",
            Self::NormalizerReplayUnavailable => "normalizer-replay-unavailable",
            Self::UnauthorizedNormalizer => "normalizer-unauthorized",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FinalDisposition {
    Verified {
        mode: VerificationMode,
        evidence_ids: Vec<String>,
    },
    NotApplicable {
        decision_id: String,
    },
    Excluded {
        scope_id: String,
    },
    Exempted {
        exemption_id: String,
        underlying: FailureClass,
    },
    Blocked {
        blocker: Blocker,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PartitionCounts {
    pub(crate) verified_exact: u64,
    pub(crate) verified_normalized: u64,
    pub(crate) verified_platform_equivalent: u64,
    pub(crate) not_applicable: u64,
    pub(crate) excluded: u64,
    pub(crate) exempted: u64,
    pub(crate) blocked_missing_evidence: u64,
    pub(crate) blocked_mismatch: u64,
    pub(crate) blocked_invalid_evidence: u64,
}

impl PartitionCounts {
    pub(crate) fn verified(&self) -> u64 {
        self.verified_exact
            .saturating_add(self.verified_normalized)
            .saturating_add(self.verified_platform_equivalent)
    }

    pub(crate) fn blocked(&self) -> u64 {
        self.blocked_missing_evidence
            .saturating_add(self.blocked_mismatch)
            .saturating_add(self.blocked_invalid_evidence)
    }

    pub(crate) fn total(&self) -> u64 {
        self.verified()
            .saturating_add(self.not_applicable)
            .saturating_add(self.excluded)
            .saturating_add(self.exempted)
            .saturating_add(self.blocked())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DerivedPartition {
    pub(crate) cells: BTreeMap<CellKey, FinalDisposition>,
    pub(crate) unclassified_mismatches: Vec<Blocker>,
    pub(crate) consumed_obligations: BTreeSet<(CellKey, String)>,
    pub(crate) consumed_exemptions: BTreeSet<String>,
}

impl DerivedPartition {
    pub(crate) fn validate_complete_against(&self, plan: &ConformancePlan) -> Result<(), String> {
        let planned_cells = plan
            .cells
            .iter()
            .map(|cell| cell.key.clone())
            .collect::<BTreeSet<_>>();
        if self.cells.len() != plan.cells.len()
            || self.cells.keys().cloned().collect::<BTreeSet<_>>() != planned_cells
        {
            return Err("derived partition does not cover the planned universe exactly".to_owned());
        }
        let expected_obligations = plan
            .cells
            .iter()
            .flat_map(|cell| {
                cell.obligations
                    .iter()
                    .map(move |obligation| (cell.key.clone(), obligation.id.clone()))
            })
            .collect::<BTreeSet<_>>();
        if self.consumed_obligations != expected_obligations {
            return Err("not every planned obligation was consumed exactly once".to_owned());
        }
        let expected_exemptions = plan
            .cells
            .iter()
            .filter_map(|cell| cell.exemption.as_ref().map(|value| value.id.clone()))
            .collect::<BTreeSet<_>>();
        if !super::mutant_active("unused-exemption-accepted")
            && self.consumed_exemptions != expected_exemptions
        {
            return Err("not every planned exemption was consumed exactly once".to_owned());
        }
        Ok(())
    }

    pub(crate) fn counts(&self) -> Result<PartitionCounts, String> {
        let mut counts = PartitionCounts::default();
        for disposition in self.cells.values() {
            let counter = match disposition {
                FinalDisposition::Verified {
                    mode: VerificationMode::Exact,
                    ..
                } => &mut counts.verified_exact,
                FinalDisposition::Verified {
                    mode: VerificationMode::Normalized,
                    ..
                } => &mut counts.verified_normalized,
                FinalDisposition::Verified {
                    mode: VerificationMode::PlatformEquivalent,
                    ..
                } => &mut counts.verified_platform_equivalent,
                FinalDisposition::NotApplicable { .. }
                    if super::mutant_active("not-applicable-counted-as-verified") =>
                {
                    &mut counts.verified_exact
                }
                FinalDisposition::NotApplicable { .. } => &mut counts.not_applicable,
                FinalDisposition::Excluded { .. }
                    if super::mutant_active("excluded-counted-as-verified") =>
                {
                    &mut counts.verified_exact
                }
                FinalDisposition::Excluded { .. } => &mut counts.excluded,
                FinalDisposition::Exempted { .. }
                    if super::mutant_active("exemption-counted-as-verified") =>
                {
                    &mut counts.verified_exact
                }
                FinalDisposition::Exempted { .. } => &mut counts.exempted,
                FinalDisposition::Blocked {
                    blocker: Blocker::MissingEvidence { .. },
                } => &mut counts.blocked_missing_evidence,
                FinalDisposition::Blocked {
                    blocker: Blocker::Mismatch { .. },
                } => &mut counts.blocked_mismatch,
                FinalDisposition::Blocked {
                    blocker: Blocker::InvalidEvidence { .. },
                } => &mut counts.blocked_invalid_evidence,
                FinalDisposition::Blocked {
                    blocker: Blocker::UnclassifiedMismatch { .. },
                } => return Err("unclassified mismatch cannot be a cell disposition".to_owned()),
            };
            *counter = counter
                .checked_add(1)
                .ok_or_else(|| "partition count overflow".to_owned())?;
        }
        let observed = u64::try_from(self.cells.len()).map_err(|_| "cell count overflow")?;
        if counts.total() != observed {
            return Err("derived partition counters do not cover the ledger".to_owned());
        }
        Ok(counts)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConformanceAcceptance {
    pub(crate) standard: String,
    pub(crate) candidate_sha: String,
    pub(crate) conformance_plan_sha256: String,
    pub(crate) evidence_archive_sha256: String,
    pub(crate) report_sha256: String,
    pub(crate) counts: PartitionCounts,
    pub(crate) unclassified_mismatch_count: u64,
    pub(crate) admitted: bool,
    pub(crate) decision_sha256: String,
}

impl ConformanceAcceptance {
    pub(crate) fn derive(
        plan: &ConformancePlan,
        partition: &DerivedPartition,
        evidence_archive_sha256: String,
        report_sha256: String,
    ) -> Result<Self, String> {
        partition.validate_complete_against(plan)?;
        require_digest(&evidence_archive_sha256, "evidence archive digest")?;
        require_digest(&report_sha256, "conformance report digest")?;
        let counts = partition.counts()?;
        let unclassified_mismatch_count = u64::try_from(partition.unclassified_mismatches.len())
            .map_err(|_| "unclassified mismatch count overflow".to_owned())?;
        let admitted = counts.blocked() == 0 && unclassified_mismatch_count == 0;
        let mut acceptance = Self {
            standard: plan.standard.clone(),
            candidate_sha: plan.candidate_sha.clone(),
            conformance_plan_sha256: plan.plan_sha256.clone(),
            evidence_archive_sha256,
            report_sha256,
            counts,
            unclassified_mismatch_count,
            admitted,
            decision_sha256: String::new(),
        };
        acceptance.decision_sha256 =
            hell_testkit::sha256_bytes(&canonical_json_bytes(&acceptance.json_without_digest())?)
                .hex();
        Ok(acceptance)
    }

    fn json_without_digest(&self) -> JsonValue {
        object([
            ("admitted", JsonValue::Bool(self.admitted)),
            ("candidateSha", string(&self.candidate_sha)),
            (
                "conformancePlanSha256",
                string(&self.conformance_plan_sha256),
            ),
            (
                "evidenceArchiveSha256",
                string(&self.evidence_archive_sha256),
            ),
            ("partition", counts_json(&self.counts)),
            ("reportSha256", string(&self.report_sha256)),
            ("schemaVersion", number(1)),
            ("standard", string(&self.standard)),
            (
                "unclassifiedMismatchCount",
                number(self.unclassified_mismatch_count),
            ),
        ])
    }

    pub(crate) fn json(&self) -> JsonValue {
        let mut fields = self
            .json_without_digest()
            .object()
            .expect("acceptance object")
            .clone();
        fields.insert("decisionSha256".to_owned(), string(&self.decision_sha256));
        JsonValue::Object(fields)
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "admitted",
                "candidateSha",
                "conformancePlanSha256",
                "decisionSha256",
                "evidenceArchiveSha256",
                "partition",
                "reportSha256",
                "schemaVersion",
                "standard",
                "unclassifiedMismatchCount",
            ],
        )?;
        if json_member(fields, "schemaVersion")?.number()? != 1 {
            return Err("unsupported conformance acceptance schema".to_owned());
        }
        let mut acceptance = Self {
            standard: text(fields, "standard")?,
            candidate_sha: text(fields, "candidateSha")?,
            conformance_plan_sha256: text(fields, "conformancePlanSha256")?,
            evidence_archive_sha256: text(fields, "evidenceArchiveSha256")?,
            report_sha256: text(fields, "reportSha256")?,
            counts: parse_counts(json_member(fields, "partition")?)?,
            unclassified_mismatch_count: json_member(fields, "unclassifiedMismatchCount")?
                .number()?,
            admitted: json_member(fields, "admitted")?.boolean()?,
            decision_sha256: text(fields, "decisionSha256")?,
        };
        for (digest, label) in [
            (
                &acceptance.conformance_plan_sha256,
                "acceptance plan digest",
            ),
            (
                &acceptance.evidence_archive_sha256,
                "acceptance evidence digest",
            ),
            (&acceptance.report_sha256, "acceptance report digest"),
            (&acceptance.decision_sha256, "acceptance decision digest"),
        ] {
            require_digest(digest, label)?;
        }
        require_sha(&acceptance.candidate_sha, "acceptance candidate SHA")?;
        if !super::mutant_active("partition-counter-forgery")
            && (acceptance.standard != super::RELEASE_STANDARD
                || ((acceptance.counts.blocked() == 0
                    && acceptance.unclassified_mismatch_count == 0)
                    != acceptance.admitted))
        {
            return Err("conformance acceptance decision is contradictory".to_owned());
        }
        let stated = std::mem::take(&mut acceptance.decision_sha256);
        let observed =
            hell_testkit::sha256_bytes(&canonical_json_bytes(&acceptance.json_without_digest())?)
                .hex();
        acceptance.decision_sha256 = stated;
        if acceptance.decision_sha256 != observed {
            return Err("conformance acceptance self-digest mismatch".to_owned());
        }
        Ok(acceptance)
    }
}

pub(crate) fn conformance_report(
    plan: &ConformancePlan,
    partition: &DerivedPartition,
    evidence_archive_sha256: &str,
) -> Result<JsonValue, String> {
    partition.validate_complete_against(plan)?;
    require_digest(evidence_archive_sha256, "report evidence archive digest")?;
    let counts = partition.counts()?;
    let cells = plan
        .cells
        .iter()
        .map(|cell| {
            let disposition = partition
                .cells
                .get(&cell.key)
                .ok_or_else(|| "report partition cell is missing".to_owned())?;
            let exemption = match (disposition, cell.exemption.as_ref()) {
                (FinalDisposition::Exempted { exemption_id, .. }, Some(exemption))
                    if exemption.id == *exemption_id =>
                {
                    JsonValue::Array(vec![object([
                        ("expiresOn", string(&exemption.expires_on)),
                        ("id", string(&exemption.id)),
                        ("issue", string(&exemption.issue)),
                        ("obligationId", string(&exemption.obligation_id)),
                        ("rationale", string(&exemption.rationale)),
                        ("reviewGroup", string(&exemption.review_group)),
                    ])])
                }
                (FinalDisposition::Exempted { .. }, _) => {
                    return Err(
                        "report exempted disposition lacks exact reviewed metadata".to_owned()
                    );
                }
                (_, _) => JsonValue::Array(Vec::new()),
            };
            Ok(object([
                ("disposition", disposition_json(disposition)),
                ("exemptions", exemption),
                ("key", cell.key.json()),
            ]))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let blockers = partition
        .unclassified_mismatches
        .iter()
        .map(blocker_json)
        .collect::<Vec<_>>();
    let admitted = counts.blocked() == 0 && blockers.is_empty();
    let without = object([
        ("admitted", JsonValue::Bool(admitted)),
        ("candidateSha", string(&plan.candidate_sha)),
        ("cells", JsonValue::Array(cells)),
        ("conformancePlanSha256", string(&plan.plan_sha256)),
        ("evidenceArchiveSha256", string(evidence_archive_sha256)),
        ("partition", counts_json(&counts)),
        ("schemaVersion", number(2)),
        ("standard", string(&plan.standard)),
        ("trustedInputsSha256", string(&plan.trusted_inputs_sha256)),
        ("unclassifiedMismatches", JsonValue::Array(blockers)),
    ]);
    let digest = hell_testkit::sha256_bytes(&canonical_json_bytes(&without)?).hex();
    let mut fields = without.object()?.clone();
    fields.insert("reportSha256".to_owned(), string(&digest));
    Ok(JsonValue::Object(fields))
}

fn counts_json(counts: &PartitionCounts) -> JsonValue {
    object([
        (
            "blockedInvalidEvidence",
            number(counts.blocked_invalid_evidence),
        ),
        ("blockedMismatch", number(counts.blocked_mismatch)),
        (
            "blockedMissingEvidence",
            number(counts.blocked_missing_evidence),
        ),
        ("excluded", number(counts.excluded)),
        ("exempted", number(counts.exempted)),
        ("notApplicable", number(counts.not_applicable)),
        ("verifiedExact", number(counts.verified_exact)),
        ("verifiedNormalized", number(counts.verified_normalized)),
        (
            "verifiedPlatformEquivalent",
            number(counts.verified_platform_equivalent),
        ),
    ])
}

fn parse_counts(value: &JsonValue) -> Result<PartitionCounts, String> {
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &[
            "blockedInvalidEvidence",
            "blockedMismatch",
            "blockedMissingEvidence",
            "excluded",
            "exempted",
            "notApplicable",
            "verifiedExact",
            "verifiedNormalized",
            "verifiedPlatformEquivalent",
        ],
    )?;
    Ok(PartitionCounts {
        verified_exact: json_member(fields, "verifiedExact")?.number()?,
        verified_normalized: json_member(fields, "verifiedNormalized")?.number()?,
        verified_platform_equivalent: json_member(fields, "verifiedPlatformEquivalent")?
            .number()?,
        not_applicable: json_member(fields, "notApplicable")?.number()?,
        excluded: json_member(fields, "excluded")?.number()?,
        exempted: json_member(fields, "exempted")?.number()?,
        blocked_missing_evidence: json_member(fields, "blockedMissingEvidence")?.number()?,
        blocked_mismatch: json_member(fields, "blockedMismatch")?.number()?,
        blocked_invalid_evidence: json_member(fields, "blockedInvalidEvidence")?.number()?,
    })
}

fn disposition_json(disposition: &FinalDisposition) -> JsonValue {
    match disposition {
        FinalDisposition::Verified { mode, evidence_ids } => object([
            ("evidenceIds", strings(evidence_ids)),
            (
                "kind",
                string(match mode {
                    VerificationMode::Exact => "verified-exact",
                    VerificationMode::Normalized => "verified-normalized",
                    VerificationMode::PlatformEquivalent => "verified-platform-equivalent",
                }),
            ),
        ]),
        FinalDisposition::NotApplicable { decision_id } => object([
            ("decisionId", string(decision_id)),
            ("kind", string("not-applicable")),
        ]),
        FinalDisposition::Excluded { scope_id } => {
            object([("kind", string("excluded")), ("scopeId", string(scope_id))])
        }
        FinalDisposition::Exempted {
            exemption_id,
            underlying,
        } => object([
            ("exemptionId", string(exemption_id)),
            ("kind", string("exempted")),
            (
                "underlying",
                string(match underlying {
                    FailureClass::MissingEvidence => "missing-evidence",
                    FailureClass::Mismatch => "mismatch",
                }),
            ),
        ]),
        FinalDisposition::Blocked { blocker } => object([
            ("blocker", blocker_json(blocker)),
            ("kind", string("blocked")),
        ]),
    }
}

fn blocker_json(blocker: &Blocker) -> JsonValue {
    match blocker {
        Blocker::MissingEvidence { obligation_id } => object([
            ("kind", string("missing-evidence")),
            ("obligationId", string(obligation_id)),
        ]),
        Blocker::Mismatch {
            obligation_id,
            mismatch_sha256,
        } => object([
            ("kind", string("mismatch")),
            ("mismatchSha256", string(mismatch_sha256)),
            ("obligationId", string(obligation_id)),
        ]),
        Blocker::InvalidEvidence { code } => object([
            ("code", string(code.as_str())),
            ("kind", string("invalid-evidence")),
        ]),
        Blocker::UnclassifiedMismatch {
            platform,
            generated_case_id,
            candidate_observation_sha256,
            oracle_observation_sha256,
            mismatch_sha256,
        } => object([
            (
                "candidateObservationSha256",
                string(candidate_observation_sha256),
            ),
            ("generatedCaseId", string(generated_case_id)),
            ("kind", string("unclassified-mismatch")),
            ("mismatchSha256", string(mismatch_sha256)),
            ("oracleObservationSha256", string(oracle_observation_sha256)),
            ("platform", string(platform.as_str())),
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hell_builtins::CompatibilityDimension;

    use crate::conformance::{ConformancePlatform, ProfileId};

    fn key(profile: ProfileId) -> CellKey {
        CellKey::new(
            "Bool.bool",
            CompatibilityDimension::PureRuntime,
            profile,
            ConformancePlatform::LinuxX86_64,
        )
        .unwrap()
    }

    fn plan(cells: Vec<PlannedCell>) -> ConformancePlan {
        ConformancePlan {
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
            cells,
            plan_sha256: "3".repeat(64),
        }
    }

    #[test]
    fn nonverified_dispositions_never_increment_verified_counts() {
        let cells = vec![
            PlannedCell {
                key: key(ProfileId::Upstream),
                scope: ScopeDisposition::NotApplicable {
                    decision_id: "rule-one".to_owned(),
                    rationale: "No meaningful runtime behavior.".to_owned(),
                },
                obligations: Vec::new(),
                exemption: None,
            },
            PlannedCell {
                key: key(ProfileId::Sandboxed),
                scope: ScopeDisposition::Excluded {
                    scope_id: "upstream-release-v1-sandboxed".to_owned(),
                    rationale: "Sandboxed is outside this standard.".to_owned(),
                },
                obligations: Vec::new(),
                exemption: None,
            },
        ];
        let plan = plan(cells);
        let universe = vec![key(ProfileId::Upstream), key(ProfileId::Sandboxed)];
        plan.validate(&universe).unwrap();
        let partition = DerivedPartition {
            cells: BTreeMap::from([
                (
                    universe[0].clone(),
                    FinalDisposition::NotApplicable {
                        decision_id: "rule-one".to_owned(),
                    },
                ),
                (
                    universe[1].clone(),
                    FinalDisposition::Excluded {
                        scope_id: "upstream-release-v1-sandboxed".to_owned(),
                    },
                ),
                (
                    CellKey::new(
                        "Bool.not",
                        CompatibilityDimension::PureRuntime,
                        ProfileId::Upstream,
                        ConformancePlatform::LinuxX86_64,
                    )
                    .unwrap(),
                    FinalDisposition::Exempted {
                        exemption_id: "EX-COUNT".to_owned(),
                        underlying: FailureClass::MissingEvidence,
                    },
                ),
            ]),
            unclassified_mismatches: Vec::new(),
            consumed_obligations: BTreeSet::new(),
            consumed_exemptions: BTreeSet::new(),
        };
        let counts = partition.counts().unwrap();
        assert_eq!(counts.verified(), 0);
        assert_eq!(counts.not_applicable, 1);
        assert_eq!(counts.excluded, 1);
        assert_eq!(counts.exempted, 1);
    }

    #[test]
    fn malformed_or_expired_exemptions_fail_plan_validation() {
        let required_key = key(ProfileId::Upstream);
        let obligation = PlannedObligation {
            id: "bool-native".to_owned(),
            strategy: EvidenceStrategy::NativeOracle,
            case_ids: vec!["bool-false".to_owned()],
            case_descriptor_sha256: BTreeMap::from([("bool-false".to_owned(), "5".repeat(64))]),
            allowed_normalizers: Vec::new(),
        };
        let mut exemption = PlannedExemption {
            id: "EX-1".to_owned(),
            kind: ExemptionKind::EvidenceGap,
            candidate_sha: "a".repeat(40),
            standard: super::super::RELEASE_STANDARD.to_owned(),
            baseline: "2026-05-29".to_owned(),
            cell: required_key.clone(),
            obligation_id: obligation.id.clone(),
            expected_mismatch_sha256: None,
            issue: "COMPAT-1".to_owned(),
            rationale: "Temporary native fixture gap.".to_owned(),
            review_group: "release-conformance".to_owned(),
            expires_on: "2026-08-13".to_owned(),
        };
        let make = |exemption: PlannedExemption| {
            plan(vec![PlannedCell {
                key: required_key.clone(),
                scope: ScopeDisposition::Required {
                    decision_id: "applicable".to_owned(),
                },
                obligations: vec![obligation.clone()],
                exemption: Some(exemption),
            }])
        };
        assert!(
            make(exemption.clone())
                .validate(std::slice::from_ref(&required_key))
                .is_err()
        );
        exemption.expires_on = "2026-08-14".to_owned();
        make(exemption).validate(&[required_key]).unwrap();
    }

    #[test]
    fn exemption_mutations_are_rejected() {
        let required_key = key(ProfileId::Upstream);
        let obligation = PlannedObligation {
            id: "adapter-success".to_owned(),
            strategy: EvidenceStrategy::NativeOracle,
            case_ids: Vec::new(),
            case_descriptor_sha256: BTreeMap::new(),
            allowed_normalizers: Vec::new(),
        };
        let valid = PlannedExemption {
            id: "EX-STRICT-1".to_owned(),
            kind: ExemptionKind::EvidenceGap,
            candidate_sha: "a".repeat(40),
            standard: super::super::RELEASE_STANDARD.to_owned(),
            baseline: "2026-05-29".to_owned(),
            cell: required_key.clone(),
            obligation_id: obligation.id.clone(),
            expected_mismatch_sha256: None,
            issue: "COMPAT-1".to_owned(),
            rationale: "Temporary exact evidence gap.".to_owned(),
            review_group: "release-conformance".to_owned(),
            expires_on: "2026-08-14".to_owned(),
        };
        let make = |exemption: PlannedExemption| {
            plan(vec![PlannedCell {
                key: required_key.clone(),
                scope: ScopeDisposition::Required {
                    decision_id: "applicable".to_owned(),
                },
                obligations: vec![obligation.clone()],
                exemption: Some(exemption),
            }])
        };
        let mut wildcard = valid.clone();
        wildcard.id = "EX-*".to_owned();
        assert!(
            make(wildcard)
                .validate(std::slice::from_ref(&required_key))
                .is_err()
        );
        let mut expired = valid.clone();
        expired.expires_on = "2026-08-13".to_owned();
        assert!(
            make(expired)
                .validate(std::slice::from_ref(&required_key))
                .is_err()
        );
        let mut wrong_candidate = valid;
        wrong_candidate.candidate_sha = "b".repeat(40);
        assert!(make(wrong_candidate).validate(&[required_key]).is_err());
    }

    #[test]
    fn utc_instant_is_delimiter_parsed_and_canonical() {
        validate_utc_instant("2026-08-13T23:59:59Z").unwrap();
        for malformed in [
            "2026-08-13T!!:!!:!!Z",
            "2026-08-13T7:00:00Z",
            "2026-8-13T07:00:00Z",
            "2026-08-13 07:00:00Z",
            "2026-08-13T07:00:00+00:00",
            "2026-08-13T07:00:00Ｚ",
            "２０２６-08-13T07:00:00Z",
        ] {
            assert!(
                validate_utc_instant(malformed).is_err(),
                "accepted malformed instant {malformed:?}"
            );
        }
    }

    #[test]
    fn exploratory_policy_is_an_exact_plan_binding() {
        let mut plan = plan(Vec::new());
        plan.generated_agreement_may_verify = true;
        assert!(plan.validate(&[]).is_err());
        plan.generated_agreement_may_verify = super::super::GENERATED_AGREEMENT_MAY_VERIFY;
        plan.generated_mismatch_blocks = false;
        assert!(plan.validate(&[]).is_err());
    }

    #[test]
    fn report_and_acceptance_are_canonical_derived_outputs() {
        let cell = PlannedCell {
            key: key(ProfileId::Sandboxed),
            scope: ScopeDisposition::Excluded {
                scope_id: "upstream-release-v1-sandboxed".to_owned(),
                rationale: "Sandboxed is outside this standard.".to_owned(),
            },
            obligations: Vec::new(),
            exemption: None,
        };
        let plan = plan(vec![cell.clone()]);
        let partition = DerivedPartition {
            cells: BTreeMap::from([(
                cell.key,
                FinalDisposition::Excluded {
                    scope_id: "upstream-release-v1-sandboxed".to_owned(),
                },
            )]),
            unclassified_mismatches: Vec::new(),
            consumed_obligations: BTreeSet::new(),
            consumed_exemptions: BTreeSet::new(),
        };
        let report = conformance_report(&plan, &partition, &"4".repeat(64)).unwrap();
        let report_sha256 = json_member(report.object().unwrap(), "reportSha256")
            .unwrap()
            .string()
            .unwrap()
            .to_owned();
        assert_eq!(
            canonical_json_bytes(&report).unwrap(),
            canonical_json_bytes(
                &crate::json::parse_json(
                    std::str::from_utf8(&canonical_json_bytes(&report).unwrap()).unwrap()
                )
                .unwrap()
            )
            .unwrap()
        );
        let acceptance =
            ConformanceAcceptance::derive(&plan, &partition, "4".repeat(64), report_sha256)
                .unwrap();
        assert_eq!(
            ConformanceAcceptance::parse(&acceptance.json()).unwrap(),
            acceptance
        );
        let mut forged = acceptance.json().object().unwrap().clone();
        forged.insert("admitted".to_owned(), JsonValue::Bool(!acceptance.admitted));
        assert!(ConformanceAcceptance::parse(&JsonValue::Object(forged)).is_err());
    }

    #[test]
    fn partition_counter_forgery_is_rejected() {
        let plan = plan(Vec::new());
        let partition = DerivedPartition {
            cells: BTreeMap::new(),
            unclassified_mismatches: Vec::new(),
            consumed_obligations: BTreeSet::new(),
            consumed_exemptions: BTreeSet::new(),
        };
        let report = conformance_report(&plan, &partition, &"4".repeat(64)).unwrap();
        let report_sha256 = json_member(report.object().unwrap(), "reportSha256")
            .unwrap()
            .string()
            .unwrap();
        let acceptance = ConformanceAcceptance::derive(
            &plan,
            &partition,
            "4".repeat(64),
            report_sha256.to_owned(),
        )
        .unwrap();
        let mut forged = acceptance;
        forged.admitted = false;
        forged.decision_sha256 = hell_testkit::sha256_bytes(
            &canonical_json_bytes(&forged.json_without_digest()).unwrap(),
        )
        .hex();
        assert!(ConformanceAcceptance::parse(&forged.json()).is_err());
    }

    #[test]
    fn invalid_evidence_report_uses_a_finite_stable_code() {
        let cell = PlannedCell {
            key: key(ProfileId::Upstream),
            scope: ScopeDisposition::Required {
                decision_id: "applicable".to_owned(),
            },
            obligations: vec![PlannedObligation {
                id: "adapter-success".to_owned(),
                strategy: EvidenceStrategy::NativeOracle,
                case_ids: Vec::new(),
                case_descriptor_sha256: BTreeMap::new(),
                allowed_normalizers: Vec::new(),
            }],
            exemption: None,
        };
        let plan = plan(vec![cell.clone()]);
        let partition = DerivedPartition {
            cells: BTreeMap::from([(
                cell.key.clone(),
                FinalDisposition::Blocked {
                    blocker: Blocker::InvalidEvidence {
                        code: InvalidEvidenceCode::CandidateSemanticObligationInvalid,
                    },
                },
            )]),
            unclassified_mismatches: Vec::new(),
            consumed_obligations: BTreeSet::from([(cell.key, "adapter-success".to_owned())]),
            consumed_exemptions: BTreeSet::new(),
        };
        let bytes =
            canonical_json_bytes(&conformance_report(&plan, &partition, &"4".repeat(64)).unwrap())
                .unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.contains("candidate-semantic-obligation-invalid"));
        assert!(!text.contains("std::io"));
        assert!(!text.contains("Custom {"));
    }

    #[test]
    fn report_retains_exact_reviewed_exemption_metadata() {
        let cell_key = key(ProfileId::Upstream);
        let obligation_id = "catalog-gap".to_owned();
        let exemption = PlannedExemption {
            id: "EX-REPORT-1".to_owned(),
            kind: ExemptionKind::EvidenceGap,
            candidate_sha: "a".repeat(40),
            standard: super::super::RELEASE_STANDARD.to_owned(),
            baseline: "2026-05-29".to_owned(),
            cell: cell_key.clone(),
            obligation_id: obligation_id.clone(),
            expected_mismatch_sha256: None,
            issue: "COMPAT-42".to_owned(),
            rationale: "Reviewed temporary evidence gap.".to_owned(),
            review_group: "release-conformance".to_owned(),
            expires_on: "2026-08-14".to_owned(),
        };
        let conformance_plan = plan(vec![PlannedCell {
            key: cell_key.clone(),
            scope: ScopeDisposition::Required {
                decision_id: "applicable".to_owned(),
            },
            obligations: vec![PlannedObligation {
                id: obligation_id.clone(),
                strategy: EvidenceStrategy::NativeOracle,
                case_ids: Vec::new(),
                case_descriptor_sha256: BTreeMap::new(),
                allowed_normalizers: Vec::new(),
            }],
            exemption: Some(exemption),
        }]);
        let partition = DerivedPartition {
            cells: BTreeMap::from([(
                cell_key.clone(),
                FinalDisposition::Exempted {
                    exemption_id: "EX-REPORT-1".to_owned(),
                    underlying: FailureClass::MissingEvidence,
                },
            )]),
            unclassified_mismatches: Vec::new(),
            consumed_obligations: BTreeSet::from([(cell_key, obligation_id)]),
            consumed_exemptions: BTreeSet::from(["EX-REPORT-1".to_owned()]),
        };

        let report = conformance_report(&conformance_plan, &partition, &"4".repeat(64)).unwrap();
        let reported = json_member(report.object().unwrap(), "cells")
            .unwrap()
            .array()
            .unwrap()[0]
            .object()
            .unwrap();
        let exemption = json_member(reported, "exemptions")
            .unwrap()
            .array()
            .unwrap()[0]
            .object()
            .unwrap();
        assert_eq!(
            json_member(exemption, "issue").unwrap().string().unwrap(),
            "COMPAT-42"
        );
        assert_eq!(
            json_member(exemption, "rationale")
                .unwrap()
                .string()
                .unwrap(),
            "Reviewed temporary evidence gap."
        );
        assert_eq!(
            json_member(exemption, "expiresOn")
                .unwrap()
                .string()
                .unwrap(),
            "2026-08-14"
        );
    }
}
