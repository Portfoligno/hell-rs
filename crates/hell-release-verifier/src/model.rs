use std::collections::{BTreeMap, BTreeSet};

use crate::digest;
use crate::json::{self, Value};

pub(crate) const ADMISSION_PROTOCOL: &str = "release-admission-v1";
const GIT_SHA_SHAPE: &str = "0000000000000000000000000000000000000000";
const DIGEST_SHAPE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug)]
pub(crate) struct ReleasePlan {
    pub candidate_sha: String,
    pub candidate_branch: String,
    pub workflow_sha: String,
    pub workflow_ref: String,
    pub repository: String,
    pub repository_id: u64,
    pub run_id: u64,
    pub run_attempt: u64,
    pub version: String,
    pub tag: String,
    pub source_date_epoch: u64,
    pub evaluation_instant: String,
    pub source_inventory_sha256: String,
    pub governance_declaration_sha256: String,
    pub governance_profile_sha256: String,
    pub residual_assumption_set_sha256: String,
    pub external_inputs_sha256: String,
    pub conformance_plan_sha256: String,
    pub trusted_inputs_sha256: String,
    pub plan_sha256: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct CellKey {
    pub builtin: String,
    pub dimension: String,
    pub profile: String,
    pub platform: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Obligation {
    pub id: String,
    pub strategy: String,
    pub case_ids: BTreeSet<String>,
    pub descriptors: BTreeMap<String, String>,
    pub allowed_normalizers: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum Scope {
    Required,
    NotApplicable,
    Excluded,
}

#[derive(Clone, Debug)]
pub(crate) struct Exemption {
    pub id: String,
    pub kind: String,
    pub candidate_sha: String,
    pub standard: String,
    pub baseline: String,
    pub cell: CellKey,
    pub obligation_id: String,
    pub expected_mismatch_sha256: Option<String>,
    pub expires_on: String,
    pub issue: String,
    pub rationale: String,
    pub review_group: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PlannedCell {
    pub key: CellKey,
    pub scope: Scope,
    pub decision_id: String,
    pub obligations: Vec<Obligation>,
    pub exemption: Option<Exemption>,
}

#[derive(Clone, Debug)]
pub(crate) struct ConformancePlan {
    pub standard: String,
    pub candidate_sha: String,
    pub workflow_sha: String,
    pub evaluation_instant: String,
    pub source_inventory_sha256: String,
    pub trusted_inputs_sha256: String,
    pub baseline: String,
    pub generator_version: String,
    pub generator_seed: u64,
    pub generator_count_per_platform: u64,
    pub cells: Vec<PlannedCell>,
    pub plan_sha256: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Counts {
    pub verified_exact: u64,
    pub verified_normalized: u64,
    pub verified_platform_equivalent: u64,
    pub not_applicable: u64,
    pub excluded: u64,
    pub exempted: u64,
    pub blocked_missing: u64,
    pub blocked_mismatch: u64,
    pub blocked_invalid: u64,
}

impl Counts {
    pub(crate) fn verified(&self) -> Result<u64, String> {
        self.verified_exact
            .checked_add(self.verified_normalized)
            .and_then(|count| count.checked_add(self.verified_platform_equivalent))
            .ok_or_else(|| "verified cell count overflow".to_owned())
    }

    pub(crate) fn blocked(&self) -> Result<u64, String> {
        self.blocked_missing
            .checked_add(self.blocked_mismatch)
            .and_then(|count| count.checked_add(self.blocked_invalid))
            .ok_or_else(|| "blocked cell count overflow".to_owned())
    }

    pub(crate) fn total(&self) -> Result<u64, String> {
        self.verified()?
            .checked_add(self.not_applicable)
            .and_then(|count| count.checked_add(self.excluded))
            .and_then(|count| count.checked_add(self.exempted))
            .and_then(|count| {
                self.blocked()
                    .ok()
                    .and_then(|blocked| count.checked_add(blocked))
            })
            .ok_or_else(|| "partition cell count overflow".to_owned())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ReportCell {
    pub key: CellKey,
    pub disposition: Value,
    pub exemptions: Vec<Value>,
}

#[derive(Clone, Debug)]
pub(crate) struct ConformanceReport {
    pub cells: Vec<ReportCell>,
    pub counts: Counts,
    pub admitted: bool,
    pub report_sha256: String,
    pub cells_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Decision {
    pub implementation: String,
    pub protocol_sha256: String,
    pub candidate_sha: String,
    pub workflow_sha: String,
    pub release_plan_sha256: String,
    pub conformance_plan_sha256: String,
    pub source_inventory_sha256: String,
    pub trusted_inputs_sha256: String,
    pub obligation_rules_sha256: String,
    pub governance_declaration_sha256: String,
    pub governance_profile_sha256: String,
    pub governance_resolve_sha256: String,
    pub governance_post_assembly_sha256: String,
    pub governance_pre_attestation_sha256: String,
    pub residual_assumption_set_sha256: String,
    pub external_inputs_sha256: String,
    pub native_environment_set_sha256: String,
    pub cell_ledger_sha256: String,
    pub subject_manifest_sha256: String,
    pub release_gate_sha256: String,
    pub required_cell_count: u64,
    pub verified_cell_count: u64,
    pub exempted_cell_count: u64,
    pub blocked_cell_count: u64,
    pub admitted: bool,
}

impl ReleasePlan {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let fields = value.object()?;
        let schema = json::member(fields, "schemaVersion")?.number()?;
        if schema != 2 {
            return Err("independent verifier supports release plan schema 2".to_owned());
        }
        require_release_plan_keys(fields)?;
        if json::member(fields, "releaseBinary")?.string()? != "hell"
            || json::member(fields, "releasePackage")?.string()? != "hell-cli"
        {
            return Err("release plan package identity differs".to_owned());
        }
        require_platforms(json::member(fields, "expectedPlatforms")?)?;
        let mut without = fields.clone();
        let stated = text(fields, "planSha256")?;
        without.remove("planSha256");
        if digest::sha256_hex(&json::canonical(&Value::Object(without))?) != stated {
            return Err("release plan self-digest mismatch".to_owned());
        }
        let plan = Self {
            candidate_sha: text(fields, "candidateSha")?,
            candidate_branch: text(fields, "candidateBranch")?,
            workflow_sha: text(fields, "workflowSha")?,
            workflow_ref: text(fields, "workflowRef")?,
            repository: text(fields, "repository")?,
            repository_id: json::member(fields, "repositoryId")?.number()?,
            run_id: json::member(fields, "runId")?.number()?,
            run_attempt: json::member(fields, "runAttempt")?.number()?,
            version: text(fields, "version")?,
            tag: text(fields, "tag")?,
            source_date_epoch: json::member(fields, "sourceDateEpoch")?.number()?,
            evaluation_instant: text(fields, "releaseEvaluationInstant")?,
            source_inventory_sha256: text(fields, "sourceInventorySha256")?,
            governance_declaration_sha256: text(fields, "governanceDeclarationSha256")?,
            governance_profile_sha256: text(fields, "governanceProfileSha256")?,
            residual_assumption_set_sha256: text(fields, "residualAssumptionSetSha256")?,
            external_inputs_sha256: text(fields, "externalInputsSha256")?,
            conformance_plan_sha256: text(fields, "conformancePlanSha256")?,
            trusted_inputs_sha256: text(fields, "trustedConformanceInputsSha256")?,
            plan_sha256: stated,
        };
        validate_release_plan(&plan)?;
        Ok(plan)
    }
}

fn require_release_plan_keys(fields: &BTreeMap<String, Value>) -> Result<(), String> {
    json::exact_keys(
        fields,
        &[
            "actor",
            "actorId",
            "buildInputsSha256",
            "candidateBranch",
            "candidateSha",
            "changelogSha256",
            "commitAuthor",
            "commitCommitter",
            "conformancePlanSha256",
            "conformanceStandard",
            "defaultBranch",
            "externalInputsSha256",
            "expectedPlatforms",
            "governanceDeclarationSha256",
            "governanceProfileSha256",
            "planSha256",
            "policySha256",
            "prerelease",
            "releaseBinary",
            "releaseEvaluationInstant",
            "releasePackage",
            "repository",
            "repositoryId",
            "residualAssumptionSetSha256",
            "runAttempt",
            "runId",
            "schemaVersion",
            "sourceDateEpoch",
            "sourceInventorySha256",
            "tag",
            "trustedConformanceInputsSha256",
            "version",
            "workflowRef",
            "workflowSha",
        ],
    )
}

fn validate_release_plan(plan: &ReleasePlan) -> Result<(), String> {
    require_sha(&plan.candidate_sha, "release candidate SHA")?;
    require_sha(&plan.workflow_sha, "release workflow SHA")?;
    for (digest, label) in [
        (&plan.source_inventory_sha256, "source inventory digest"),
        (
            &plan.governance_declaration_sha256,
            "governance declaration digest",
        ),
        (&plan.governance_profile_sha256, "governance profile digest"),
        (
            &plan.residual_assumption_set_sha256,
            "residual assumption set digest",
        ),
        (&plan.external_inputs_sha256, "external-input lock digest"),
        (&plan.conformance_plan_sha256, "conformance plan digest"),
        (&plan.trusted_inputs_sha256, "release trusted-input digest"),
        (&plan.plan_sha256, "release plan digest"),
    ] {
        require_digest(digest, label)?;
    }
    validate_instant(&plan.evaluation_instant)?;
    if plan.repository.split_once('/').is_none()
        || plan.version.is_empty()
        || plan.tag.is_empty()
        || plan.repository_id == 0
    {
        return Err("release plan has an empty or invalid release identity".to_owned());
    }
    Ok(())
}

impl ConformancePlan {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let fields = value.object()?;
        json::exact_keys(
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
        if json::member(fields, "schemaVersion")?.number()? != 1 {
            return Err("unsupported conformance plan schema".to_owned());
        }
        let generator = json::member(fields, "exploratoryGenerator")?.object()?;
        json::exact_keys(generator, &["countPerPlatform", "rootSeed", "version"])?;
        let generator_count_per_platform = json::member(generator, "countPerPlatform")?.number()?;
        let generator_seed = json::member(generator, "rootSeed")?.number()?;
        let generator_version = json::member(generator, "version")?.string()?.to_owned();
        nonempty(&generator_version, "generator version")?;
        let policy = json::member(fields, "exploratoryPolicy")?.object()?;
        json::exact_keys(
            policy,
            &["generatedAgreementMayVerify", "generatedMismatchBlocks"],
        )?;
        let generated_agreement_may_verify =
            json::member(policy, "generatedAgreementMayVerify")?.boolean()?;
        let generated_mismatch_blocks =
            json::member(policy, "generatedMismatchBlocks")?.boolean()?;
        if generated_agreement_may_verify || !generated_mismatch_blocks {
            return Err("exploratory policy weakens release admission".to_owned());
        }
        let stated = text(fields, "planSha256")?;
        let mut without = fields.clone();
        without.remove("planSha256");
        if digest::sha256_hex(&json::canonical(&Value::Object(without))?) != stated {
            return Err("conformance plan self-digest mismatch".to_owned());
        }
        let cells = json::member(fields, "cells")?
            .array()?
            .iter()
            .map(parse_cell)
            .collect::<Result<Vec<_>, _>>()?;
        if cells.is_empty() || cells.windows(2).any(|pair| pair[0].key >= pair[1].key) {
            return Err("conformance plan cells are empty, duplicated, or unsorted".to_owned());
        }
        let plan = Self {
            standard: text(fields, "standard")?,
            candidate_sha: text(fields, "candidateSha")?,
            workflow_sha: text(fields, "workflowSha")?,
            evaluation_instant: text(fields, "releaseEvaluationInstant")?,
            source_inventory_sha256: text(fields, "sourceInventorySha256")?,
            trusted_inputs_sha256: text(fields, "trustedInputsSha256")?,
            baseline: text(fields, "baseline")?,
            generator_version,
            generator_seed,
            generator_count_per_platform,
            cells,
            plan_sha256: stated,
        };
        require_sha(&plan.candidate_sha, "conformance candidate SHA")?;
        require_sha(&plan.workflow_sha, "conformance workflow SHA")?;
        for (value, label) in [
            (
                &plan.source_inventory_sha256,
                "conformance source inventory digest",
            ),
            (&plan.trusted_inputs_sha256, "trusted inputs digest"),
            (&plan.plan_sha256, "conformance plan digest"),
        ] {
            require_digest(value, label)?;
        }
        nonempty(&plan.standard, "conformance standard")?;
        nonempty(&plan.baseline, "conformance baseline")?;
        validate_instant(&plan.evaluation_instant)?;
        validate_exemptions(&plan)?;
        Ok(plan)
    }
}

impl ConformanceReport {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let fields = value.object()?;
        json::exact_keys(
            fields,
            &[
                "admitted",
                "candidateSha",
                "cells",
                "conformancePlanSha256",
                "evidenceArchiveSha256",
                "partition",
                "reportSha256",
                "schemaVersion",
                "standard",
                "trustedInputsSha256",
                "unclassifiedMismatches",
            ],
        )?;
        if json::member(fields, "schemaVersion")?.number()? != 2 {
            return Err("unsupported conformance report schema".to_owned());
        }
        let stated = text(fields, "reportSha256")?;
        let mut without = fields.clone();
        without.remove("reportSha256");
        if digest::sha256_hex(&json::canonical(&Value::Object(without))?) != stated {
            return Err("conformance report self-digest mismatch".to_owned());
        }
        let cells_value = json::member(fields, "cells")?;
        let cells = cells_value
            .array()?
            .iter()
            .map(|value| {
                let fields = value.object()?;
                json::exact_keys(fields, &["disposition", "exemptions", "key"])?;
                Ok(ReportCell {
                    key: CellKey::parse(json::member(fields, "key")?)?,
                    disposition: json::member(fields, "disposition")?.clone(),
                    exemptions: json::member(fields, "exemptions")?.array()?.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        if cells.windows(2).any(|pair| pair[0].key >= pair[1].key) {
            return Err("conformance report cells are duplicated or unsorted".to_owned());
        }
        let counts = Counts::parse(json::member(fields, "partition")?)?;
        if counts.total()?
            != u64::try_from(cells.len()).map_err(|_| "report cell count overflow".to_owned())?
        {
            return Err("conformance report counts do not cover cells".to_owned());
        }
        if !json::member(fields, "unclassifiedMismatches")?
            .array()?
            .is_empty()
        {
            return Err("conformance report has unclassified mismatches".to_owned());
        }
        let admitted = json::member(fields, "admitted")?.boolean()?;
        if admitted != (counts.blocked()? == 0) {
            return Err("conformance report admitted state contradicts counts".to_owned());
        }
        Ok(Self {
            cells,
            counts,
            admitted,
            report_sha256: stated,
            cells_bytes: json::canonical(cells_value)?,
        })
    }
}

impl Counts {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let fields = value.object()?;
        json::exact_keys(
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
        Ok(Self {
            verified_exact: json::member(fields, "verifiedExact")?.number()?,
            verified_normalized: json::member(fields, "verifiedNormalized")?.number()?,
            verified_platform_equivalent: json::member(fields, "verifiedPlatformEquivalent")?
                .number()?,
            not_applicable: json::member(fields, "notApplicable")?.number()?,
            excluded: json::member(fields, "excluded")?.number()?,
            exempted: json::member(fields, "exempted")?.number()?,
            blocked_missing: json::member(fields, "blockedMissingEvidence")?.number()?,
            blocked_mismatch: json::member(fields, "blockedMismatch")?.number()?,
            blocked_invalid: json::member(fields, "blockedInvalidEvidence")?.number()?,
        })
    }
}

impl Decision {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let fields = value.object()?;
        require_decision_keys(fields)?;
        if json::member(fields, "schemaVersion")?.number()? != 1
            || json::member(fields, "protocolVersion")?.string()? != ADMISSION_PROTOCOL
        {
            return Err("unsupported verifier decision schema or protocol".to_owned());
        }
        let decision = Self {
            implementation: text(fields, "implementation")?,
            protocol_sha256: text(fields, "protocolSha256")?,
            candidate_sha: text(fields, "candidateSha")?,
            workflow_sha: text(fields, "workflowSha")?,
            release_plan_sha256: text(fields, "releasePlanSha256")?,
            conformance_plan_sha256: text(fields, "conformancePlanSha256")?,
            source_inventory_sha256: text(fields, "sourceInventorySha256")?,
            trusted_inputs_sha256: text(fields, "trustedInputsSha256")?,
            obligation_rules_sha256: text(fields, "obligationRulesSha256")?,
            governance_declaration_sha256: text(fields, "governanceDeclarationSha256")?,
            governance_profile_sha256: text(fields, "governanceProfileSha256")?,
            governance_resolve_sha256: text(fields, "governanceResolveSha256")?,
            governance_post_assembly_sha256: text(fields, "governancePostAssemblySha256")?,
            governance_pre_attestation_sha256: text(fields, "governancePreAttestationSha256")?,
            residual_assumption_set_sha256: text(fields, "residualAssumptionSetSha256")?,
            external_inputs_sha256: text(fields, "externalInputsSha256")?,
            native_environment_set_sha256: text(fields, "nativeEnvironmentSetSha256")?,
            cell_ledger_sha256: text(fields, "cellLedgerSha256")?,
            subject_manifest_sha256: text(fields, "subjectManifestSha256")?,
            release_gate_sha256: text(fields, "releaseGateSha256")?,
            required_cell_count: json::member(fields, "requiredCellCount")?.number()?,
            verified_cell_count: json::member(fields, "verifiedCellCount")?.number()?,
            exempted_cell_count: json::member(fields, "exemptedCellCount")?.number()?,
            blocked_cell_count: json::member(fields, "blockedCellCount")?.number()?,
            admitted: json::member(fields, "admitted")?.boolean()?,
        };
        validate_decision(&decision)?;
        Ok(decision)
    }

    pub(crate) fn json(&self) -> Value {
        json::object([
            ("admitted", Value::Bool(self.admitted)),
            ("blockedCellCount", json::number(self.blocked_cell_count)),
            ("candidateSha", json::string(&self.candidate_sha)),
            ("cellLedgerSha256", json::string(&self.cell_ledger_sha256)),
            (
                "conformancePlanSha256",
                json::string(&self.conformance_plan_sha256),
            ),
            ("exemptedCellCount", json::number(self.exempted_cell_count)),
            (
                "externalInputsSha256",
                json::string(&self.external_inputs_sha256),
            ),
            (
                "governanceDeclarationSha256",
                json::string(&self.governance_declaration_sha256),
            ),
            (
                "governanceProfileSha256",
                json::string(&self.governance_profile_sha256),
            ),
            (
                "governancePostAssemblySha256",
                json::string(&self.governance_post_assembly_sha256),
            ),
            (
                "governancePreAttestationSha256",
                json::string(&self.governance_pre_attestation_sha256),
            ),
            (
                "governanceResolveSha256",
                json::string(&self.governance_resolve_sha256),
            ),
            ("implementation", json::string(&self.implementation)),
            (
                "nativeEnvironmentSetSha256",
                json::string(&self.native_environment_set_sha256),
            ),
            (
                "obligationRulesSha256",
                json::string(&self.obligation_rules_sha256),
            ),
            ("protocolSha256", json::string(&self.protocol_sha256)),
            ("protocolVersion", json::string(ADMISSION_PROTOCOL)),
            ("releaseGateSha256", json::string(&self.release_gate_sha256)),
            ("releasePlanSha256", json::string(&self.release_plan_sha256)),
            (
                "residualAssumptionSetSha256",
                json::string(&self.residual_assumption_set_sha256),
            ),
            ("requiredCellCount", json::number(self.required_cell_count)),
            ("schemaVersion", json::number(1)),
            (
                "sourceInventorySha256",
                json::string(&self.source_inventory_sha256),
            ),
            (
                "subjectManifestSha256",
                json::string(&self.subject_manifest_sha256),
            ),
            (
                "trustedInputsSha256",
                json::string(&self.trusted_inputs_sha256),
            ),
            ("verifiedCellCount", json::number(self.verified_cell_count)),
            ("workflowSha", json::string(&self.workflow_sha)),
        ])
    }
}

fn require_decision_keys(fields: &BTreeMap<String, Value>) -> Result<(), String> {
    json::exact_keys(
        fields,
        &[
            "admitted",
            "blockedCellCount",
            "candidateSha",
            "cellLedgerSha256",
            "conformancePlanSha256",
            "externalInputsSha256",
            "exemptedCellCount",
            "governanceDeclarationSha256",
            "governancePostAssemblySha256",
            "governancePreAttestationSha256",
            "governanceProfileSha256",
            "governanceResolveSha256",
            "implementation",
            "nativeEnvironmentSetSha256",
            "obligationRulesSha256",
            "protocolSha256",
            "protocolVersion",
            "releaseGateSha256",
            "releasePlanSha256",
            "residualAssumptionSetSha256",
            "requiredCellCount",
            "schemaVersion",
            "sourceInventorySha256",
            "subjectManifestSha256",
            "trustedInputsSha256",
            "verifiedCellCount",
            "workflowSha",
        ],
    )
}

fn validate_decision(decision: &Decision) -> Result<(), String> {
    for (value, label) in [
        (&decision.protocol_sha256, "decision protocol digest"),
        (
            &decision.release_plan_sha256,
            "decision release plan digest",
        ),
        (
            &decision.conformance_plan_sha256,
            "decision conformance plan digest",
        ),
        (
            &decision.source_inventory_sha256,
            "decision source inventory digest",
        ),
        (
            &decision.trusted_inputs_sha256,
            "decision trusted inputs digest",
        ),
        (
            &decision.obligation_rules_sha256,
            "decision obligation rules digest",
        ),
        (
            &decision.governance_declaration_sha256,
            "decision governance declaration digest",
        ),
        (
            &decision.governance_profile_sha256,
            "decision governance profile digest",
        ),
        (
            &decision.governance_resolve_sha256,
            "decision governance resolve receipt digest",
        ),
        (
            &decision.governance_post_assembly_sha256,
            "decision governance post-assembly receipt digest",
        ),
        (
            &decision.governance_pre_attestation_sha256,
            "decision governance pre-attestation receipt digest",
        ),
        (
            &decision.residual_assumption_set_sha256,
            "decision residual assumption set digest",
        ),
        (
            &decision.external_inputs_sha256,
            "decision external inputs digest",
        ),
        (
            &decision.native_environment_set_sha256,
            "decision native environment set digest",
        ),
        (&decision.cell_ledger_sha256, "decision cell ledger digest"),
        (
            &decision.subject_manifest_sha256,
            "decision subject manifest digest",
        ),
        (
            &decision.release_gate_sha256,
            "decision release gate digest",
        ),
    ] {
        require_digest(value, label)?;
    }
    require_sha(&decision.candidate_sha, "decision candidate SHA")?;
    require_sha(&decision.workflow_sha, "decision workflow SHA")?;
    let classified = decision
        .verified_cell_count
        .checked_add(decision.exempted_cell_count)
        .and_then(|value| value.checked_add(decision.blocked_cell_count))
        .ok_or_else(|| "decision cell count overflow".to_owned())?;
    if classified != decision.required_cell_count
        || decision.admitted != (decision.blocked_cell_count == 0)
    {
        return Err("decision counts or admission state are contradictory".to_owned());
    }
    Ok(())
}

impl CellKey {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let fields = value.object()?;
        json::exact_keys(fields, &["builtin", "dimension", "platform", "profile"])?;
        let key = Self {
            builtin: text(fields, "builtin")?,
            dimension: text(fields, "dimension")?,
            profile: text(fields, "profile")?,
            platform: text(fields, "platform")?,
        };
        if key.builtin.is_empty()
            || key.builtin.contains("::")
            || key.dimension.is_empty()
            || !matches!(key.profile.as_str(), "upstream" | "sandboxed")
            || !matches!(
                key.platform.as_str(),
                "linux-x86_64" | "macos-aarch64" | "windows-x86_64"
            )
        {
            return Err("conformance cell key is invalid".to_owned());
        }
        Ok(key)
    }
}

fn parse_cell(value: &Value) -> Result<PlannedCell, String> {
    let fields = value.object()?;
    json::exact_keys(fields, &["exemptions", "key", "obligations", "scope"])?;
    let key = CellKey::parse(json::member(fields, "key")?)?;
    let scope_fields = json::member(fields, "scope")?.object()?;
    json::exact_keys(scope_fields, &["decisionId", "kind", "rationale"])?;
    let decision_id = text(scope_fields, "decisionId")?;
    nonempty(&decision_id, "scope decision ID")?;
    let rationale = json::member(scope_fields, "rationale")?.string()?;
    let scope = match json::member(scope_fields, "kind")?.string()? {
        "required" if rationale.is_empty() => Scope::Required,
        "not-applicable" if !rationale.is_empty() => Scope::NotApplicable,
        "excluded" if !rationale.is_empty() => Scope::Excluded,
        _ => return Err("conformance cell scope is invalid".to_owned()),
    };
    let obligations = json::member(fields, "obligations")?
        .array()?
        .iter()
        .map(parse_obligation)
        .collect::<Result<Vec<_>, _>>()?;
    if obligations.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return Err("cell obligations are duplicated or unsorted".to_owned());
    }
    let exemptions = json::member(fields, "exemptions")?.array()?;
    if exemptions.len() > 1 {
        return Err("conformance cell has multiple exemptions".to_owned());
    }
    let exemption = exemptions.first().map(parse_exemption).transpose()?;
    match scope {
        Scope::Required if obligations.is_empty() => {
            return Err("required cell has no obligation".to_owned());
        }
        Scope::NotApplicable | Scope::Excluded
            if !obligations.is_empty() || exemption.is_some() =>
        {
            return Err("non-required cell carries an obligation or exemption".to_owned());
        }
        Scope::Required | Scope::NotApplicable | Scope::Excluded => {}
    }
    Ok(PlannedCell {
        key,
        scope,
        decision_id,
        obligations,
        exemption,
    })
}

fn parse_obligation(value: &Value) -> Result<Obligation, String> {
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
            "allowedNormalizers",
            "caseDescriptorSha256",
            "caseIds",
            "id",
            "strategy",
        ],
    )?;
    let id = text(fields, "id")?;
    nonempty(&id, "obligation ID")?;
    let strategy = text(fields, "strategy")?;
    if !matches!(
        strategy.as_str(),
        "native-oracle"
            | "portable-static"
            | "structural-invariant"
            | "committed-differential-corpus"
            | "cross-platform-relation"
    ) {
        return Err("unknown evidence strategy".to_owned());
    }
    let allowed_normalizers = json::member(fields, "allowedNormalizers")?
        .array()?
        .iter()
        .map(|value| {
            let value = value.string()?.to_owned();
            nonempty(&value, "normalizer ID")?;
            Ok(value)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if allowed_normalizers
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err("normalizers are duplicated or unsorted".to_owned());
    }
    let cases = json::member(fields, "caseIds")?
        .array()?
        .iter()
        .map(|value| Ok(value.string()?.to_owned()))
        .collect::<Result<Vec<_>, String>>()?;
    if cases.is_empty() || cases.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("obligation cases are empty, duplicated, or unsorted".to_owned());
    }
    let case_ids = cases.into_iter().collect::<BTreeSet<_>>();
    let descriptors = json::member(fields, "caseDescriptorSha256")?
        .object()?
        .iter()
        .map(|(case, value)| {
            let digest = value.string()?.to_owned();
            require_digest(&digest, "case descriptor digest")?;
            Ok((case.clone(), digest))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if descriptors.keys().cloned().collect::<BTreeSet<_>>() != case_ids {
        return Err("obligation case descriptor set differs from case IDs".to_owned());
    }
    Ok(Obligation {
        id,
        strategy,
        case_ids,
        descriptors,
        allowed_normalizers,
    })
}

fn parse_exemption(value: &Value) -> Result<Exemption, String> {
    let fields = value.object()?;
    json::exact_keys(
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
    if !matches!(
        json::member(fields, "kind")?.string()?,
        "evidence-gap" | "known-divergence"
    ) {
        return Err("unknown exemption kind".to_owned());
    }
    for field in ["id", "issue", "rationale", "reviewGroup"] {
        nonempty(json::member(fields, field)?.string()?, field)?;
    }
    let expected_mismatch_sha256 = match json::member(fields, "expectedMismatchSha256")? {
        Value::Null => None,
        value => {
            let digest = value.string()?.to_owned();
            require_digest(&digest, "expected mismatch digest")?;
            Some(digest)
        }
    };
    Ok(Exemption {
        id: text(fields, "id")?,
        kind: text(fields, "kind")?,
        candidate_sha: text(fields, "candidateSha")?,
        standard: text(fields, "standard")?,
        baseline: text(fields, "baseline")?,
        cell: CellKey::parse(json::member(fields, "cell")?)?,
        obligation_id: text(fields, "obligationId")?,
        expected_mismatch_sha256,
        expires_on: text(fields, "expiresOn")?,
        issue: text(fields, "issue")?,
        rationale: text(fields, "rationale")?,
        review_group: text(fields, "reviewGroup")?,
    })
}

fn validate_exemptions(plan: &ConformancePlan) -> Result<(), String> {
    let evaluation_date = plan
        .evaluation_instant
        .split_once('T')
        .map(|(date, _)| date)
        .ok_or_else(|| "release evaluation instant has no date separator".to_owned())?;
    let mut ids = BTreeSet::new();
    for cell in &plan.cells {
        let Some(exemption) = &cell.exemption else {
            continue;
        };
        if !ids.insert(exemption.id.as_str())
            || exemption.candidate_sha != plan.candidate_sha
            || exemption.standard != plan.standard
            || exemption.baseline != plan.baseline
            || exemption.cell != cell.key
            || !cell
                .obligations
                .iter()
                .any(|obligation| obligation.id == exemption.obligation_id)
            || !canonical_date(&exemption.expires_on)
            || exemption.expires_on.as_str() <= evaluation_date
            || (exemption.kind == "evidence-gap" && exemption.expected_mismatch_sha256.is_some())
            || (exemption.kind == "known-divergence"
                && exemption.expected_mismatch_sha256.is_none())
        {
            return Err("exemption selector or evaluation-instant binding differs".to_owned());
        }
    }
    Ok(())
}

fn require_platforms(value: &Value) -> Result<(), String> {
    let observed = value
        .array()?
        .iter()
        .map(Value::string)
        .collect::<Result<Vec<_>, _>>()?;
    if observed != ["linux-x86_64", "macos-aarch64", "windows-x86_64"] {
        return Err("release plan platform inventory differs".to_owned());
    }
    Ok(())
}

pub(crate) fn require_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() != GIT_SHA_SHAPE.len()
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} is not a lowercase full Git SHA"));
    }
    Ok(())
}

pub(crate) fn require_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != DIGEST_SHAPE.len()
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} is not a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_instant(value: &str) -> Result<(), String> {
    let (date, time) = value
        .strip_suffix('Z')
        .and_then(|value| value.split_once('T'))
        .ok_or_else(|| "evaluation instant is not canonical UTC".to_owned())?;
    let components = time.split(':').collect::<Vec<_>>();
    if !canonical_date(date) || components.len() != 3 {
        return Err("evaluation instant is not canonical UTC".to_owned());
    }
    let values = components
        .iter()
        .map(|component| {
            if component.len() != "00".len() || !component.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            component.parse::<u64>().ok()
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "evaluation instant is not canonical UTC".to_owned())?;
    if values[0] > 23 || values[1] > 59 || values[2] > 59 {
        return Err("evaluation instant time is out of range".to_owned());
    }
    Ok(())
}

fn canonical_date(value: &str) -> bool {
    let parts = value.split('-').collect::<Vec<_>>();
    if !(parts.len() == 3
        && parts[0].len() == "0000".len()
        && parts[1].len() == "00".len()
        && parts[2].len() == "00".len()
        && parts
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit())))
    {
        return false;
    }
    let Ok(year) = parts[0].parse::<u64>() else {
        return false;
    };
    let Ok(month) = parts[1].parse::<u64>() else {
        return false;
    };
    let Ok(day) = parts[2].parse::<u64>() else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day != 0 && day <= maximum
}

fn nonempty(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty() || value.contains(['\0', '\n', '\r']) {
        Err(format!("{label} is empty or unsafe"))
    } else {
        Ok(())
    }
}

fn text(fields: &BTreeMap<String, Value>, name: &str) -> Result<String, String> {
    Ok(json::member(fields, name)?.string()?.to_owned())
}
