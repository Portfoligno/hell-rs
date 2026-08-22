use std::path::{Path, PathBuf};

use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};

use super::manifest::{read_json, read_regular, write_json};
use super::schema::{number, object, require_digest, require_sha, string, text};

pub(crate) const ADMISSION_PROTOCOL_VERSION: &str = "release-admission-v1";
const ADMISSION_INPUT_DOMAIN: &[u8] = b"hell-rs:release-admission-inputs:1\0";

const COMPARED_FIELDS: [&str; 25] = [
    "protocolVersion",
    "protocolSha256",
    "candidateSha",
    "workflowSha",
    "releasePlanSha256",
    "conformancePlanSha256",
    "sourceInventorySha256",
    "trustedInputsSha256",
    "obligationRulesSha256",
    "governanceDeclarationSha256",
    "governanceProfileSha256",
    "governanceResolveSha256",
    "governancePostAssemblySha256",
    "governancePreAttestationSha256",
    "residualAssumptionSetSha256",
    "externalInputsSha256",
    "nativeEnvironmentSetSha256",
    "cellLedgerSha256",
    "subjectManifestSha256",
    "releaseGateSha256",
    "requiredCellCount",
    "verifiedCellCount",
    "exemptedCellCount",
    "blockedCellCount",
    "admitted",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifierDecision {
    pub implementation: String,
    pub protocol_version: String,
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

impl VerifierDecision {
    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "admitted",
                "blockedCellCount",
                "candidateSha",
                "cellLedgerSha256",
                "conformancePlanSha256",
                "externalInputsSha256",
                "exemptedCellCount",
                "implementation",
                "governanceDeclarationSha256",
                "governancePostAssemblySha256",
                "governancePreAttestationSha256",
                "governanceProfileSha256",
                "governanceResolveSha256",
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
        )?;
        if json_member(fields, "schemaVersion")?.number()? != 1 {
            return Err("unsupported verifier decision schema".to_owned());
        }
        let decision = Self {
            implementation: text(fields, "implementation")?,
            protocol_version: text(fields, "protocolVersion")?,
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
            required_cell_count: json_member(fields, "requiredCellCount")?.number()?,
            verified_cell_count: json_member(fields, "verifiedCellCount")?.number()?,
            exempted_cell_count: json_member(fields, "exemptedCellCount")?.number()?,
            blocked_cell_count: json_member(fields, "blockedCellCount")?.number()?,
            admitted: json_member(fields, "admitted")?.boolean()?,
        };
        decision.validate()?;
        Ok(decision)
    }

    pub(crate) fn json(&self) -> JsonValue {
        object([
            ("admitted", JsonValue::Bool(self.admitted)),
            ("blockedCellCount", number(self.blocked_cell_count)),
            ("candidateSha", string(&self.candidate_sha)),
            ("cellLedgerSha256", string(&self.cell_ledger_sha256)),
            (
                "conformancePlanSha256",
                string(&self.conformance_plan_sha256),
            ),
            ("exemptedCellCount", number(self.exempted_cell_count)),
            ("externalInputsSha256", string(&self.external_inputs_sha256)),
            (
                "governanceDeclarationSha256",
                string(&self.governance_declaration_sha256),
            ),
            (
                "governanceProfileSha256",
                string(&self.governance_profile_sha256),
            ),
            (
                "governancePostAssemblySha256",
                string(&self.governance_post_assembly_sha256),
            ),
            (
                "governancePreAttestationSha256",
                string(&self.governance_pre_attestation_sha256),
            ),
            (
                "governanceResolveSha256",
                string(&self.governance_resolve_sha256),
            ),
            ("implementation", string(&self.implementation)),
            (
                "nativeEnvironmentSetSha256",
                string(&self.native_environment_set_sha256),
            ),
            (
                "obligationRulesSha256",
                string(&self.obligation_rules_sha256),
            ),
            ("protocolSha256", string(&self.protocol_sha256)),
            ("protocolVersion", string(&self.protocol_version)),
            ("releaseGateSha256", string(&self.release_gate_sha256)),
            ("releasePlanSha256", string(&self.release_plan_sha256)),
            (
                "residualAssumptionSetSha256",
                string(&self.residual_assumption_set_sha256),
            ),
            ("requiredCellCount", number(self.required_cell_count)),
            ("schemaVersion", number(1)),
            (
                "sourceInventorySha256",
                string(&self.source_inventory_sha256),
            ),
            (
                "subjectManifestSha256",
                string(&self.subject_manifest_sha256),
            ),
            ("trustedInputsSha256", string(&self.trusted_inputs_sha256)),
            ("verifiedCellCount", number(self.verified_cell_count)),
            ("workflowSha", string(&self.workflow_sha)),
        ])
    }

    fn validate(&self) -> Result<(), String> {
        if self.protocol_version != ADMISSION_PROTOCOL_VERSION {
            return Err("unsupported release-admission protocol".to_owned());
        }
        if !matches!(
            self.implementation.as_str(),
            "hell-ci" | "hell-release-verifier"
        ) {
            return Err("unknown verifier implementation".to_owned());
        }
        require_sha(&self.candidate_sha, "verifier candidate SHA")?;
        require_sha(&self.workflow_sha, "verifier workflow SHA")?;
        for (digest, label) in [
            (&self.protocol_sha256, "admission protocol digest"),
            (&self.release_plan_sha256, "release plan digest"),
            (&self.conformance_plan_sha256, "conformance plan digest"),
            (&self.source_inventory_sha256, "source inventory digest"),
            (&self.trusted_inputs_sha256, "trusted-input digest"),
            (&self.obligation_rules_sha256, "obligation-rule digest"),
            (
                &self.governance_declaration_sha256,
                "governance declaration digest",
            ),
            (&self.governance_profile_sha256, "governance profile digest"),
            (
                &self.governance_resolve_sha256,
                "governance resolve receipt digest",
            ),
            (
                &self.governance_post_assembly_sha256,
                "governance post-assembly receipt digest",
            ),
            (
                &self.governance_pre_attestation_sha256,
                "governance pre-attestation receipt digest",
            ),
            (
                &self.residual_assumption_set_sha256,
                "residual assumption set digest",
            ),
            (&self.external_inputs_sha256, "external-input lock digest"),
            (
                &self.native_environment_set_sha256,
                "native environment set digest",
            ),
            (&self.cell_ledger_sha256, "cell ledger digest"),
            (&self.subject_manifest_sha256, "subject manifest digest"),
            (&self.release_gate_sha256, "release gate digest"),
        ] {
            require_digest(digest, label)?;
        }
        let classified = self
            .verified_cell_count
            .checked_add(self.exempted_cell_count)
            .and_then(|count| count.checked_add(self.blocked_cell_count))
            .ok_or_else(|| "verifier decision cell count overflow".to_owned())?;
        if classified != self.required_cell_count {
            return Err("verifier decision counts do not cover required cells".to_owned());
        }
        if self.admitted != (self.blocked_cell_count == 0) {
            return Err("verifier admitted state differs from blocked cell count".to_owned());
        }
        Ok(())
    }

    fn authoritative_values(&self) -> [JsonValue; COMPARED_FIELDS.len()] {
        [
            string(&self.protocol_version),
            string(&self.protocol_sha256),
            string(&self.candidate_sha),
            string(&self.workflow_sha),
            string(&self.release_plan_sha256),
            string(&self.conformance_plan_sha256),
            string(&self.source_inventory_sha256),
            string(&self.trusted_inputs_sha256),
            string(&self.obligation_rules_sha256),
            string(&self.governance_declaration_sha256),
            string(&self.governance_profile_sha256),
            string(&self.governance_resolve_sha256),
            string(&self.governance_post_assembly_sha256),
            string(&self.governance_pre_attestation_sha256),
            string(&self.residual_assumption_set_sha256),
            string(&self.external_inputs_sha256),
            string(&self.native_environment_set_sha256),
            string(&self.cell_ledger_sha256),
            string(&self.subject_manifest_sha256),
            string(&self.release_gate_sha256),
            number(self.required_cell_count),
            number(self.verified_cell_count),
            number(self.exempted_cell_count),
            number(self.blocked_cell_count),
            JsonValue::Bool(self.admitted),
        ]
    }
}

pub(crate) fn read(path: &Path) -> Result<VerifierDecision, String> {
    VerifierDecision::parse(&read_json(path)?)
}

pub(crate) fn protocol_sha256(
    projection_path: &Path,
    obligation_rules_path: &Path,
    specification_path: &Path,
) -> Result<String, String> {
    let projection_bytes = read_regular(projection_path)?;
    let projection_text = std::str::from_utf8(&projection_bytes)
        .map_err(|_| "release protocol projection is not UTF-8".to_owned())?;
    let projection = crate::json::parse_json(projection_text)?;
    let mut projection_fields = projection.object()?.clone();
    let stated = projection_fields
        .remove("protocolSha256")
        .ok_or_else(|| "release protocol projection lacks protocolSha256".to_owned())?
        .string()?
        .to_owned();
    require_digest(&stated, "release admission protocol digest")?;
    let projection = canonical_json_bytes(&JsonValue::Object(projection_fields))?;

    let rules_bytes = read_regular(obligation_rules_path)?;
    let rules_text = std::str::from_utf8(&rules_bytes)
        .map_err(|_| "release obligation rules are not UTF-8".to_owned())?;
    let rules = canonical_json_bytes(&crate::json::parse_json(rules_text)?)?;
    let specification = read_regular(specification_path)?;
    let mut bound = ADMISSION_INPUT_DOMAIN.to_vec();
    bound.extend_from_slice(projection.strip_suffix(b"\n").unwrap_or(&projection));
    bound.push(0);
    bound.extend_from_slice(rules.strip_suffix(b"\n").unwrap_or(&rules));
    bound.push(0);
    bound.extend_from_slice(&specification);
    let observed = hell_testkit::sha256_bytes(&bound).hex();
    if observed != stated {
        return Err(format!(
            "release protocol projection contains stale normative digest {stated}; recomputed {observed}"
        ));
    }
    Ok(observed)
}

pub(crate) fn protocol_sha256_from_projection(projection: &Path) -> Result<String, String> {
    let repository_root = projection
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| "release projection is not under ci/release-protocol/v1".to_owned())?;
    let expected = repository_root.join("ci/release-protocol/v1/projection.json");
    if std::fs::canonicalize(projection).ok() != std::fs::canonicalize(expected).ok() {
        return Err("release projection path differs from trusted repository path".to_owned());
    }
    protocol_sha256(
        projection,
        &repository_root.join("compat/release-obligation-rules-v1.json"),
        &repository_root.join("spec/release-admission-protocol-v1.md"),
    )
}

pub(crate) fn write_protocol_digest(
    projection: PathBuf,
    obligation_rules: PathBuf,
    specification: PathBuf,
    output: PathBuf,
) -> Result<String, String> {
    let projection = projection.into_boxed_path();
    let obligation_rules = obligation_rules.into_boxed_path();
    let specification = specification.into_boxed_path();
    let output = output.into_boxed_path();
    if output.exists() {
        return Err("release protocol digest output already exists".to_owned());
    }
    let digest = protocol_sha256(&projection, &obligation_rules, &specification)?;
    write_json(
        &output,
        &object([
            ("protocolSha256", string(&digest)),
            ("protocolVersion", string(ADMISSION_PROTOCOL_VERSION)),
            ("schemaVersion", number(1)),
        ]),
    )?;
    Ok("release admission protocol inputs are content-bound".to_owned())
}

pub(crate) fn domain_digest(object_type: &str, schema_version: u64, bytes: &[u8]) -> String {
    let mut separated = b"hell-rs:".to_vec();
    separated.extend_from_slice(object_type.as_bytes());
    separated.push(b':');
    separated.extend_from_slice(schema_version.to_string().as_bytes());
    separated.push(0);
    separated.extend_from_slice(bytes);
    hell_testkit::sha256_bytes(&separated).hex()
}

pub(crate) fn agree(
    primary: PathBuf,
    independent: PathBuf,
    output: PathBuf,
) -> Result<String, String> {
    let primary = primary.into_boxed_path();
    let independent = independent.into_boxed_path();
    let output = output.into_boxed_path();
    if output.exists() {
        return Err("verifier agreement output already exists".to_owned());
    }
    let primary_decision = read_agreement_input(&primary, &output, "primary")?;
    let independent_decision = read_agreement_input(&independent, &output, "independent")?;
    if primary_decision.implementation != "hell-ci"
        || independent_decision.implementation != "hell-release-verifier"
    {
        write_blocked(
            &output,
            "release.verifier-implementation-invalid",
            "implementation",
            "agreement inputs do not have the required implementation identities",
        )?;
        return Err("verifier implementation identities differ from policy".to_owned());
    }
    let mut mismatches = COMPARED_FIELDS
        .iter()
        .zip(
            primary_decision
                .authoritative_values()
                .into_iter()
                .zip(independent_decision.authoritative_values()),
        )
        .filter_map(|(name, (primary, independent))| (primary != independent).then_some(*name))
        .collect::<Vec<_>>();
    if crate::mutation::active("digest-binding-inverted") && mismatches.is_empty() {
        mismatches.push("protocolSha256");
    }
    let primary_bytes = canonical_json_bytes(&primary_decision.json())?;
    let independent_bytes = canonical_json_bytes(&independent_decision.json())?;
    let primary_sha256 = hell_testkit::sha256_bytes(&primary_bytes).hex();
    let independent_sha256 = hell_testkit::sha256_bytes(&independent_bytes).hex();
    let compared = JsonValue::Array(COMPARED_FIELDS.iter().map(|field| string(field)).collect());
    if !mismatches.is_empty() {
        write_json(
            &output,
            &object([
                ("admitted", JsonValue::Bool(false)),
                ("comparedFields", compared),
                ("diagnosticCode", string("release.verifier-disagreement")),
                ("equal", JsonValue::Bool(false)),
                ("independentDecisionSha256", string(&independent_sha256)),
                (
                    "mismatchedFields",
                    JsonValue::Array(mismatches.iter().map(|field| string(field)).collect()),
                ),
                ("primaryDecisionSha256", string(&primary_sha256)),
                ("protocolVersion", string(ADMISSION_PROTOCOL_VERSION)),
                ("schemaVersion", number(1)),
                ("state", string("blocked")),
            ]),
        )?;
        return Err(format!(
            "release.verifier-disagreement: authoritative fields differ: {}",
            mismatches.join(", ")
        ));
    }
    if !primary_decision.admitted {
        write_json(
            &output,
            &object([
                ("admitted", JsonValue::Bool(false)),
                ("comparedFields", compared),
                ("diagnosticCode", string("release.verifiers-did-not-admit")),
                ("equal", JsonValue::Bool(true)),
                ("independentDecisionSha256", string(&independent_sha256)),
                ("mismatchedFields", JsonValue::Array(Vec::new())),
                ("primaryDecisionSha256", string(&primary_sha256)),
                ("protocolVersion", string(ADMISSION_PROTOCOL_VERSION)),
                ("schemaVersion", number(1)),
                ("state", string("blocked")),
            ]),
        )?;
        return Err("matching verifier decisions did not admit the release".to_owned());
    }
    write_json(
        &output,
        &object([
            ("admitted", JsonValue::Bool(true)),
            ("comparedFields", compared),
            ("diagnosticCode", JsonValue::Null),
            ("equal", JsonValue::Bool(true)),
            ("independentDecisionSha256", string(&independent_sha256)),
            ("mismatchedFields", JsonValue::Array(Vec::new())),
            ("primaryDecisionSha256", string(&primary_sha256)),
            ("protocolVersion", string(ADMISSION_PROTOCOL_VERSION)),
            ("schemaVersion", number(1)),
            ("state", string("admitted")),
        ]),
    )?;
    Ok("release verifiers independently admitted and agree".to_owned())
}

fn read_agreement_input(
    path: &Path,
    output: &Path,
    implementation: &str,
) -> Result<VerifierDecision, String> {
    match read(path) {
        Ok(decision) => Ok(decision),
        Err(error) => {
            write_blocked(
                output,
                "release.verifier-decision-invalid",
                implementation,
                &error,
            )?;
            Err(format!(
                "{implementation} verifier decision is invalid: {error}"
            ))
        }
    }
}

fn write_blocked(output: &Path, code: &str, path: &str, message: &str) -> Result<(), String> {
    write_json(
        output,
        &object([
            ("admitted", JsonValue::Bool(false)),
            ("diagnosticCode", string(code)),
            ("diagnosticMessage", string(message)),
            ("diagnosticPath", string(path)),
            ("equal", JsonValue::Bool(false)),
            ("protocolVersion", string(ADMISSION_PROTOCOL_VERSION)),
            ("schemaVersion", number(1)),
            ("state", string("blocked")),
        ]),
    )?;
    Ok(())
}
