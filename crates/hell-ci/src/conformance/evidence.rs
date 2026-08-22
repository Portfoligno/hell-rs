use std::collections::{BTreeMap, BTreeSet};

use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};
use crate::release::schema::{number, object, string};
use crate::release::schema::{require_digest, require_sha};

use super::key::{CellKey, ConformancePlatform, ProfileId};
use super::ledger::{
    EvidenceStrategy, InvalidEvidenceCode, PlannedCell, PlannedObligation, VerificationMode,
};

const MAX_OBSERVATION_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const EXPLORATORY_GENERATOR_VERSION: &str = "typed-generator-v1";
pub(crate) const EXPLORATORY_GENERATOR_SEED: u64 = 0x4845_4c4c;
pub(crate) const EXPLORATORY_GENERATOR_COUNT: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) sha256: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) overflow: bool,
}

impl Observation {
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        let sha256 = hell_testkit::sha256_bytes(&bytes).hex();
        Self {
            sha256,
            bytes,
            overflow: false,
        }
    }

    fn validate(&self) -> Result<(), String> {
        require_digest(&self.sha256, "observation digest")?;
        if self.overflow || self.bytes.len() > MAX_OBSERVATION_BYTES {
            return Err("observation overflowed the retained evidence limit".to_owned());
        }
        if hell_testkit::sha256_bytes(&self.bytes).hex() != self.sha256 {
            return Err("observation digest does not match its retained bytes".to_owned());
        }
        Ok(())
    }

    pub(crate) fn parse_canonical(bytes: Vec<u8>) -> Result<Self, String> {
        let value = parse_canonical_json(&bytes)?;
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "diagnostic",
                "exit",
                "filesystem",
                "mode",
                "normalizerContext",
                "rawStderr",
                "resourceAudit",
                "schemaVersion",
                "semanticTrace",
                "stderr",
                "statusSuccess",
                "stdout",
                "termination",
            ],
        )?;
        if json_member(fields, "schemaVersion")?.number()? != 4 {
            return Err("unsupported observation schema".to_owned());
        }
        let context = json_member(fields, "normalizerContext")?.object()?;
        require_exact_json_keys(context, &["executable", "sandbox", "script"])?;
        let executable = json_member(context, "executable")?.string()?;
        let sandbox = json_member(context, "sandbox")?.string()?;
        let script = json_member(context, "script")?.string()?;
        if executable.is_empty()
            || std::path::Path::new(executable).file_name().is_none()
            || sandbox.is_empty()
            || script.is_empty()
            || executable.contains('\0')
            || sandbox.contains('\0')
            || script.contains('\0')
            || executable.len() > MAX_OBSERVATION_BYTES
            || sandbox.len() > MAX_OBSERVATION_BYTES
            || script.len() > MAX_OBSERVATION_BYTES
        {
            return Err("observation normalizer context is malformed".to_owned());
        }
        let structured_size = ["diagnostic", "filesystem", "mode", "resourceAudit"]
            .into_iter()
            .try_fold(0_usize, |size, field| {
                let value = json_member(fields, field)?.string()?;
                if value.len() > MAX_OBSERVATION_BYTES || value.contains('\0') {
                    return Err(format!("observation {field} exceeds its exact bound"));
                }
                size.checked_add(value.len())
                    .ok_or_else(|| "observation structured size overflow".to_owned())
            })?;
        let exit_kind = validate_exit(json_member(fields, "exit")?)?;
        let stdout = validate_base64_field(json_member(fields, "stdout")?, "stdout")?;
        let stderr = validate_base64_field(json_member(fields, "stderr")?, "stderr")?;
        let raw_stderr = validate_base64_field(json_member(fields, "rawStderr")?, "raw stderr")?;
        let status_success = json_member(fields, "statusSuccess")?.boolean()?;
        let trace = json_member(fields, "semanticTrace")?.array()?;
        if trace.len() > 64
            || trace.iter().any(|item| {
                item.string().map_or(true, |text| {
                    text.len() > MAX_OBSERVATION_BYTES || text.contains('\0')
                })
            })
        {
            return Err("observation semantic trace exceeds its exact bound".to_owned());
        }
        match (exit_kind, json_member(fields, "termination")?.string()?) {
            (ExitKind::Code(code), "exited") if status_success == (code == 0) => {}
            (ExitKind::Signal, "signaled") if !status_success => {}
            (_, "timed-out" | "overflow" | "truncated") => {
                return Err("observation is incomplete or overflowed".to_owned());
            }
            (_, value) => {
                return Err(format!(
                    "observation exit and termination are contradictory: {value:?}"
                ));
            }
        }
        let retained_size = stdout
            .len()
            .checked_add(stderr.len())
            .and_then(|size| size.checked_add(raw_stderr.len()))
            .and_then(|size| size.checked_add(structured_size))
            .and_then(|size| size.checked_add(sandbox.len()))
            .and_then(|size| size.checked_add(script.len()))
            .and_then(|size| {
                trace.iter().try_fold(size, |size, item| {
                    size.checked_add(item.string().ok()?.len())
                })
            })
            .ok_or_else(|| "observation retained size overflow".to_owned())?;
        if retained_size > MAX_OBSERVATION_BYTES {
            return Err("observation exceeds the retained evidence limit".to_owned());
        }
        let observation = Self::from_bytes(bytes);
        observation.validate()?;
        Ok(observation)
    }
}

enum ExitKind {
    Code(u64),
    Signal,
}

fn validate_exit(value: &JsonValue) -> Result<ExitKind, String> {
    let fields = value.object()?;
    require_exact_json_keys(fields, &["kind", "value"])?;
    match json_member(fields, "kind")?.string()? {
        "code" => Ok(ExitKind::Code(json_member(fields, "value")?.number()?)),
        "signal" => {
            let signal = json_member(fields, "value")?.string()?;
            if signal.is_empty() || signal.len() > 64 || signal.contains(char::is_whitespace) {
                return Err("observation signal is not canonical".to_owned());
            }
            Ok(ExitKind::Signal)
        }
        value => Err(format!("unknown observation exit kind {value:?}")),
    }
}

fn validate_base64_field(value: &JsonValue, label: &str) -> Result<Vec<u8>, String> {
    let fields = value.object()?;
    require_exact_json_keys(fields, &["encoding", "value"])?;
    if json_member(fields, "encoding")?.string()? != "base64" {
        return Err(format!("observation {label} encoding is not base64"));
    }
    decode_base64(json_member(fields, "value")?.string()?)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(4) || value.len() > MAX_OBSERVATION_BYTES.saturating_mul(2) {
        return Err("observation base64 is truncated or oversized".to_owned());
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for (chunk_index, chunk) in value.as_bytes().chunks_exact(4).enumerate() {
        let last = chunk_index + 1 == value.len() / 4;
        let padding = usize::from(chunk[3] == b'=') + usize::from(chunk[2] == b'=');
        if (!last && padding != 0) || padding > 2 || (chunk[2] == b'=' && chunk[3] != b'=') {
            return Err("observation base64 padding is invalid".to_owned());
        }
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_value(chunk[3])?
        };
        if (padding == 2 && b & 0x0f != 0) || (padding == 1 && c & 0x03 != 0) {
            return Err("observation base64 has noncanonical trailing bits".to_owned());
        }
        output.push((a << 2) | (b >> 4));
        if padding < 2 {
            output.push((b << 4) | (c >> 2));
        }
        if padding == 0 {
            output.push((c << 6) | d);
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("observation base64 contains an invalid byte".to_owned()),
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct EvidenceTarget {
    pub(crate) cell: CellKey,
    pub(crate) obligation_id: String,
    pub(crate) case_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CaseSource {
    Committed,
    Generated {
        generator_version: String,
        seed: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OracleBinding {
    pub(crate) repository: String,
    pub(crate) commit: String,
    pub(crate) executable_sha256: String,
    pub(crate) source_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrustedEvidenceBindings {
    pub(crate) release_plan_sha256: String,
    pub(crate) conformance_plan_sha256: String,
    pub(crate) candidate_sha: String,
    pub(crate) candidate_executable_sha256: BTreeMap<ConformancePlatform, String>,
    pub(crate) source_inventory_sha256: String,
    pub(crate) oracle: BTreeMap<ConformancePlatform, OracleBinding>,
}

impl TrustedEvidenceBindings {
    pub(crate) fn from_manifests(
        plan: &super::ConformancePlan,
        manifests: &[EvidenceManifest],
    ) -> Result<Self, String> {
        if manifests.len() != ConformancePlatform::ALL.len() {
            return Err("evidence manifests do not cover each platform exactly once".to_owned());
        }
        let release_plan_sha256 = manifests
            .first()
            .ok_or_else(|| "evidence manifest set is empty".to_owned())?
            .release_plan_sha256
            .clone();
        let mut candidate_executable_sha256 = BTreeMap::new();
        let mut oracle = BTreeMap::new();
        for manifest in manifests {
            manifest.validate()?;
            if hell_testkit::sha256_bytes(&canonical_json_bytes(&manifest.json_without_digest())?)
                .hex()
                != manifest.manifest_sha256
            {
                return Err("evidence manifest self-digest mismatch".to_owned());
            }
            if manifest.candidate_sha != plan.candidate_sha
                || manifest.conformance_plan_sha256 != plan.plan_sha256
                || manifest.release_plan_sha256 != release_plan_sha256
                || candidate_executable_sha256
                    .insert(
                        manifest.platform,
                        manifest.candidate_executable_sha256.clone(),
                    )
                    .is_some()
                || oracle
                    .insert(manifest.platform, manifest.oracle.clone())
                    .is_some()
            {
                return Err("evidence manifest identity set is contradictory".to_owned());
            }
        }
        Self::from_platform_identities(
            release_plan_sha256,
            plan,
            candidate_executable_sha256,
            oracle,
        )
    }

    pub(crate) fn from_platform_identities(
        release_plan_sha256: String,
        plan: &super::ConformancePlan,
        candidate_executable_sha256: BTreeMap<ConformancePlatform, String>,
        oracle: BTreeMap<ConformancePlatform, OracleBinding>,
    ) -> Result<Self, String> {
        let bindings = Self {
            release_plan_sha256,
            conformance_plan_sha256: plan.plan_sha256.clone(),
            candidate_sha: plan.candidate_sha.clone(),
            candidate_executable_sha256,
            source_inventory_sha256: plan.source_inventory_sha256.clone(),
            oracle,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        require_digest(&self.release_plan_sha256, "release plan digest")?;
        require_digest(&self.conformance_plan_sha256, "conformance plan digest")?;
        require_sha(&self.candidate_sha, "evidence candidate SHA")?;
        require_digest(&self.source_inventory_sha256, "source inventory digest")?;
        if self.candidate_executable_sha256.len() != ConformancePlatform::ALL.len() {
            return Err("trusted bindings do not name every platform executable".to_owned());
        }
        for platform in ConformancePlatform::ALL {
            require_digest(
                self.candidate_executable_sha256
                    .get(&platform)
                    .ok_or_else(|| {
                        format!("missing executable digest for {}", platform.as_str())
                    })?,
                "candidate executable digest",
            )?;
        }
        if self.oracle.len() != ConformancePlatform::ALL.len() {
            return Err("trusted bindings do not name every platform oracle".to_owned());
        }
        for platform in ConformancePlatform::ALL {
            let oracle = self
                .oracle
                .get(&platform)
                .ok_or_else(|| format!("missing oracle binding for {}", platform.as_str()))?;
            if oracle.repository.is_empty() {
                return Err("oracle repository is empty".to_owned());
            }
            require_sha(&oracle.commit, "oracle commit")?;
            require_digest(&oracle.executable_sha256, "oracle executable digest")?;
            require_digest(&oracle.source_sha256, "oracle source digest")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceRecord {
    pub(crate) record_id: String,
    pub(crate) release_plan_sha256: String,
    pub(crate) conformance_plan_sha256: String,
    pub(crate) candidate_sha: String,
    pub(crate) candidate_executable_sha256: String,
    pub(crate) candidate_build_info_schema_version: u64,
    pub(crate) candidate_compat_tracing: bool,
    pub(crate) source_inventory_sha256: String,
    pub(crate) oracle: OracleBinding,
    pub(crate) platform: ConformancePlatform,
    pub(crate) profile: ProfileId,
    pub(crate) target: EvidenceTarget,
    pub(crate) descriptor_sha256: String,
    pub(crate) case_source: CaseSource,
    pub(crate) candidate_observation_sha256: String,
    pub(crate) oracle_observation_sha256: String,
    pub(crate) requested_normalizers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExploratoryRecord {
    pub(crate) generated_case_id: String,
    pub(crate) platform: ConformancePlatform,
    pub(crate) generator_version: String,
    pub(crate) seed: u64,
    pub(crate) source_sha256: String,
    pub(crate) ast_sha256: String,
    pub(crate) release_plan_sha256: String,
    pub(crate) conformance_plan_sha256: String,
    pub(crate) source_inventory_sha256: String,
    pub(crate) candidate_sha: String,
    pub(crate) candidate_executable_sha256: String,
    pub(crate) candidate_build_info_schema_version: u64,
    pub(crate) candidate_compat_tracing: bool,
    pub(crate) oracle: OracleBinding,
    pub(crate) candidate_observation_sha256: String,
    pub(crate) oracle_observation_sha256: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct EvidenceRepository {
    pub(crate) records: Vec<EvidenceRecord>,
    pub(crate) observations: BTreeMap<String, Observation>,
    pub(crate) exploratory_records: Vec<ExploratoryRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceMember {
    pub(crate) id: Option<String>,
    pub(crate) path: String,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EvidenceManifest {
    pub(crate) platform: ConformancePlatform,
    pub(crate) candidate_sha: String,
    pub(crate) candidate_executable_sha256: String,
    pub(crate) release_plan_sha256: String,
    pub(crate) conformance_plan_sha256: String,
    pub(crate) oracle: OracleBinding,
    pub(crate) records: Vec<EvidenceMember>,
    pub(crate) exploratory_records: Vec<EvidenceMember>,
    pub(crate) observations: Vec<EvidenceMember>,
    pub(crate) assigned_obligations: u64,
    pub(crate) produced_records: u64,
    pub(crate) manifest_sha256: String,
}

pub(crate) struct EvidenceManifestInput {
    pub(crate) platform: ConformancePlatform,
    pub(crate) candidate_sha: String,
    pub(crate) candidate_executable_sha256: String,
    pub(crate) release_plan_sha256: String,
    pub(crate) conformance_plan_sha256: String,
    pub(crate) oracle: OracleBinding,
    pub(crate) records: Vec<EvidenceMember>,
    pub(crate) exploratory_records: Vec<EvidenceMember>,
    pub(crate) observations: Vec<EvidenceMember>,
    pub(crate) assigned_obligations: u64,
}

impl EvidenceManifest {
    pub(crate) fn new(input: EvidenceManifestInput) -> Result<Self, String> {
        let EvidenceManifestInput {
            platform,
            candidate_sha,
            candidate_executable_sha256,
            release_plan_sha256,
            conformance_plan_sha256,
            oracle,
            records,
            exploratory_records,
            observations,
            assigned_obligations,
        } = input;
        let produced_records = u64::try_from(records.len()).map_err(|_| "record count overflow")?;
        let mut manifest = Self {
            platform,
            candidate_sha,
            candidate_executable_sha256,
            release_plan_sha256,
            conformance_plan_sha256,
            oracle,
            records,
            exploratory_records,
            observations,
            assigned_obligations,
            produced_records,
            manifest_sha256: "1".repeat(64),
        };
        manifest.manifest_sha256 =
            hell_testkit::sha256_bytes(&canonical_json_bytes(&manifest.json_without_digest())?)
                .hex();
        manifest.validate()?;
        Ok(manifest)
    }

    fn json_without_digest(&self) -> JsonValue {
        object([
            ("assignedObligations", number(self.assigned_obligations)),
            (
                "candidateExecutableSha256",
                string(&self.candidate_executable_sha256),
            ),
            ("candidateSha", string(&self.candidate_sha)),
            (
                "conformancePlanSha256",
                string(&self.conformance_plan_sha256),
            ),
            (
                "exploratoryRecords",
                JsonValue::Array(
                    self.exploratory_records
                        .iter()
                        .map(EvidenceMember::json)
                        .collect(),
                ),
            ),
            (
                "observations",
                JsonValue::Array(self.observations.iter().map(EvidenceMember::json).collect()),
            ),
            ("oracle", oracle_json(&self.oracle)),
            ("platform", string(self.platform.as_str())),
            ("producedRecords", number(self.produced_records)),
            (
                "records",
                JsonValue::Array(self.records.iter().map(EvidenceMember::json).collect()),
            ),
            ("releasePlanSha256", string(&self.release_plan_sha256)),
            ("schemaVersion", number(1)),
        ])
    }

    pub(crate) fn json(&self) -> JsonValue {
        let mut fields = self
            .json_without_digest()
            .object()
            .expect("manifest object")
            .clone();
        fields.insert("manifestSha256".to_owned(), string(&self.manifest_sha256));
        JsonValue::Object(fields)
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "assignedObligations",
                "candidateExecutableSha256",
                "candidateSha",
                "conformancePlanSha256",
                "exploratoryRecords",
                "manifestSha256",
                "observations",
                "oracle",
                "platform",
                "producedRecords",
                "records",
                "releasePlanSha256",
                "schemaVersion",
            ],
        )?;
        if json_member(fields, "schemaVersion")?.number()? != 1 {
            return Err("unsupported evidence manifest schema".to_owned());
        }
        let mut manifest = Self {
            platform: ConformancePlatform::parse(json_member(fields, "platform")?.string()?)?,
            candidate_sha: json_member(fields, "candidateSha")?.string()?.to_owned(),
            candidate_executable_sha256: json_member(fields, "candidateExecutableSha256")?
                .string()?
                .to_owned(),
            release_plan_sha256: json_member(fields, "releasePlanSha256")?
                .string()?
                .to_owned(),
            conformance_plan_sha256: json_member(fields, "conformancePlanSha256")?
                .string()?
                .to_owned(),
            oracle: parse_oracle(json_member(fields, "oracle")?)?,
            records: parse_members(json_member(fields, "records")?, true, "ev-")?,
            exploratory_records: parse_members(
                json_member(fields, "exploratoryRecords")?,
                true,
                "gx-",
            )?,
            observations: parse_members(json_member(fields, "observations")?, false, "")?,
            assigned_obligations: json_member(fields, "assignedObligations")?.number()?,
            produced_records: json_member(fields, "producedRecords")?.number()?,
            manifest_sha256: json_member(fields, "manifestSha256")?.string()?.to_owned(),
        };
        manifest.validate()?;
        let stated = std::mem::take(&mut manifest.manifest_sha256);
        let observed =
            hell_testkit::sha256_bytes(&canonical_json_bytes(&manifest.json_without_digest())?)
                .hex();
        manifest.manifest_sha256 = stated;
        if manifest.manifest_sha256 != observed {
            return Err("evidence manifest self-digest mismatch".to_owned());
        }
        Ok(manifest)
    }

    pub(crate) fn validate_against(&self, trusted: &TrustedEvidenceBindings) -> Result<(), String> {
        self.validate()?;
        if self.candidate_sha != trusted.candidate_sha
            || self.release_plan_sha256 != trusted.release_plan_sha256
            || self.conformance_plan_sha256 != trusted.conformance_plan_sha256
            || self.candidate_executable_sha256
                != trusted.candidate_executable_sha256[&self.platform]
            || self.oracle != trusted.oracle[&self.platform]
        {
            return Err("evidence manifest binding differs from trusted release inputs".to_owned());
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        require_sha(&self.candidate_sha, "manifest candidate SHA")?;
        require_digest(
            &self.candidate_executable_sha256,
            "manifest candidate executable digest",
        )?;
        require_digest(&self.release_plan_sha256, "manifest release plan digest")?;
        require_digest(
            &self.conformance_plan_sha256,
            "manifest conformance plan digest",
        )?;
        require_digest(&self.manifest_sha256, "evidence manifest digest")?;
        if self.oracle.repository.is_empty() {
            return Err("manifest oracle repository is empty".to_owned());
        }
        require_sha(&self.oracle.commit, "manifest oracle commit")?;
        require_digest(
            &self.oracle.executable_sha256,
            "manifest oracle executable digest",
        )?;
        require_digest(&self.oracle.source_sha256, "manifest oracle source digest")?;
        if self.produced_records
            != u64::try_from(self.records.len()).map_err(|_| "record count overflow")?
        {
            return Err("evidence manifest produced-record count is forged".to_owned());
        }
        let mut paths = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for members in [&self.records, &self.exploratory_records, &self.observations] {
            if members.windows(2).any(|pair| pair[0].path >= pair[1].path) {
                return Err("evidence manifest members are not in canonical path order".to_owned());
            }
        }
        for member in self
            .records
            .iter()
            .chain(&self.exploratory_records)
            .chain(&self.observations)
        {
            require_digest(&member.sha256, "evidence member digest")?;
            if !paths.insert(member.path.as_str()) {
                return Err("evidence manifest repeats a path".to_owned());
            }
            if let Some(id) = &member.id
                && !ids.insert(id.as_str())
            {
                return Err("evidence manifest repeats an ID".to_owned());
            }
        }
        if self.records.iter().any(|member| {
            member
                .id
                .as_ref()
                .is_none_or(|id| member.path != format!("conformance-evidence/{id}.json"))
        }) || self.exploratory_records.iter().any(|member| {
            member
                .id
                .as_ref()
                .is_none_or(|id| member.path != format!("conformance-evidence/{id}.json"))
        }) || self.observations.iter().any(|member| {
            member.id.is_some()
                || member.path != format!("conformance-observations/{}.json", member.sha256)
        }) {
            return Err(
                "evidence manifest member path does not match its content identity".to_owned(),
            );
        }
        Ok(())
    }
}

impl ExploratoryRecord {
    fn json_without_id(&self) -> JsonValue {
        object([
            (
                "candidateBuildInfoSchemaVersion",
                number(self.candidate_build_info_schema_version),
            ),
            (
                "candidateCompatTracing",
                JsonValue::Bool(self.candidate_compat_tracing),
            ),
            (
                "candidateExecutableSha256",
                string(&self.candidate_executable_sha256),
            ),
            (
                "candidateObservationSha256",
                string(&self.candidate_observation_sha256),
            ),
            ("candidateSha", string(&self.candidate_sha)),
            (
                "conformancePlanSha256",
                string(&self.conformance_plan_sha256),
            ),
            ("generatedCaseId", string(&self.generated_case_id)),
            ("generatorVersion", string(&self.generator_version)),
            ("astSha256", string(&self.ast_sha256)),
            ("oracle", oracle_json(&self.oracle)),
            (
                "oracleObservationSha256",
                string(&self.oracle_observation_sha256),
            ),
            ("platform", string(self.platform.as_str())),
            ("releasePlanSha256", string(&self.release_plan_sha256)),
            ("schemaVersion", number(2)),
            ("seed", number(self.seed)),
            (
                "sourceInventorySha256",
                string(&self.source_inventory_sha256),
            ),
            ("sourceSha256", string(&self.source_sha256)),
        ])
    }

    pub(crate) fn canonical_id(&self) -> Result<String, String> {
        Ok(format!(
            "gx-{}",
            hell_testkit::sha256_bytes(&canonical_json_bytes(&self.json_without_id())?).hex()
        ))
    }

    pub(crate) fn json(&self) -> Result<JsonValue, String> {
        let mut fields = self
            .json_without_id()
            .object()
            .expect("exploratory object")
            .clone();
        fields.insert("recordId".to_owned(), string(&self.canonical_id()?));
        Ok(JsonValue::Object(fields))
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "candidateBuildInfoSchemaVersion",
                "candidateCompatTracing",
                "candidateExecutableSha256",
                "candidateObservationSha256",
                "candidateSha",
                "astSha256",
                "conformancePlanSha256",
                "generatedCaseId",
                "generatorVersion",
                "oracle",
                "oracleObservationSha256",
                "platform",
                "recordId",
                "releasePlanSha256",
                "schemaVersion",
                "seed",
                "sourceInventorySha256",
                "sourceSha256",
            ],
        )?;
        if json_member(fields, "schemaVersion")?.number()? != 2 {
            return Err("unsupported exploratory record schema".to_owned());
        }
        let record = Self {
            generated_case_id: json_member(fields, "generatedCaseId")?.string()?.to_owned(),
            platform: ConformancePlatform::parse(json_member(fields, "platform")?.string()?)?,
            generator_version: json_member(fields, "generatorVersion")?
                .string()?
                .to_owned(),
            seed: json_member(fields, "seed")?.number()?,
            source_sha256: json_member(fields, "sourceSha256")?.string()?.to_owned(),
            ast_sha256: json_member(fields, "astSha256")?.string()?.to_owned(),
            release_plan_sha256: json_member(fields, "releasePlanSha256")?
                .string()?
                .to_owned(),
            conformance_plan_sha256: json_member(fields, "conformancePlanSha256")?
                .string()?
                .to_owned(),
            source_inventory_sha256: json_member(fields, "sourceInventorySha256")?
                .string()?
                .to_owned(),
            candidate_sha: json_member(fields, "candidateSha")?.string()?.to_owned(),
            candidate_build_info_schema_version: json_member(
                fields,
                "candidateBuildInfoSchemaVersion",
            )?
            .number()?,
            candidate_compat_tracing: json_member(fields, "candidateCompatTracing")?.boolean()?,
            candidate_executable_sha256: json_member(fields, "candidateExecutableSha256")?
                .string()?
                .to_owned(),
            oracle: parse_oracle(json_member(fields, "oracle")?)?,
            candidate_observation_sha256: json_member(fields, "candidateObservationSha256")?
                .string()?
                .to_owned(),
            oracle_observation_sha256: json_member(fields, "oracleObservationSha256")?
                .string()?
                .to_owned(),
        };
        if record.candidate_build_info_schema_version != 2 || !record.candidate_compat_tracing {
            return Err(
                "exploratory record candidate compatibility tracing attestation is invalid"
                    .to_owned(),
            );
        }
        if json_member(fields, "recordId")?.string()? != record.canonical_id()? {
            return Err("exploratory record content-derived ID mismatch".to_owned());
        }
        Ok(record)
    }
}

impl EvidenceRepository {
    pub(crate) fn from_archive_members(
        manifests: &[EvidenceManifest],
        members: &BTreeMap<String, Vec<u8>>,
        trusted: &TrustedEvidenceBindings,
        plan: &super::ConformancePlan,
    ) -> Result<Self, String> {
        trusted.validate()?;
        plan.validate(&super::canonical_universe()?)?;
        let platforms = manifests
            .iter()
            .map(|manifest| manifest.platform)
            .collect::<BTreeSet<_>>();
        if manifests.len() != ConformancePlatform::ALL.len()
            || platforms
                != ConformancePlatform::ALL
                    .into_iter()
                    .collect::<BTreeSet<_>>()
        {
            return Err("evidence manifests do not cover each platform exactly once".to_owned());
        }
        let mut repository = Self::default();
        let mut consumed = BTreeSet::new();
        for manifest in manifests {
            ingest_evidence_manifest(
                &mut repository,
                &mut consumed,
                manifest,
                members,
                trusted,
                plan,
            )?;
        }
        let evidence_members = members
            .keys()
            .filter(|path| path.starts_with("records/") || path.starts_with("observations/"))
            .cloned()
            .collect::<BTreeSet<_>>();
        if consumed != evidence_members {
            return Err(
                "evidence archive contains unconsumed record or observation members".to_owned(),
            );
        }
        EvidenceIndex::build(&repository)?;
        Ok(repository)
    }
}

fn ingest_evidence_manifest(
    repository: &mut EvidenceRepository,
    consumed: &mut BTreeSet<String>,
    manifest: &EvidenceManifest,
    members: &BTreeMap<String, Vec<u8>>,
    trusted: &TrustedEvidenceBindings,
    plan: &super::ConformancePlan,
) -> Result<(), String> {
    manifest.validate_against(trusted)?;
    validate_evidence_manifest_bytes(manifest, members, plan)?;
    let declared = manifest
        .observations
        .iter()
        .map(|member| member.sha256.clone())
        .collect::<BTreeSet<_>>();
    let mut referenced = BTreeSet::new();
    ingest_evidence_records(
        repository,
        consumed,
        manifest,
        members,
        &declared,
        &mut referenced,
    )?;
    let exploratory = ingest_exploratory_records(
        repository,
        consumed,
        manifest,
        members,
        &declared,
        &mut referenced,
    )?;
    validate_exact_exploratory_schedule(manifest.platform, &exploratory)?;
    if referenced != declared {
        return Err("platform manifest contains a locally unreferenced observation".to_owned());
    }
    ingest_observations(repository, consumed, manifest, members)
}

fn validate_evidence_manifest_bytes(
    manifest: &EvidenceManifest,
    members: &BTreeMap<String, Vec<u8>>,
    plan: &super::ConformancePlan,
) -> Result<(), String> {
    let path = format!("platform-manifests/{}.json", manifest.platform.as_str());
    let bytes = members
        .get(&path)
        .ok_or_else(|| "platform evidence manifest is missing from archive".to_owned())?;
    if canonical_json_bytes(&manifest.json())? != *bytes
        || hell_testkit::sha256_bytes(&canonical_json_bytes(&manifest.json_without_digest())?).hex()
            != manifest.manifest_sha256
    {
        return Err("platform evidence manifest bytes or digest differ".to_owned());
    }
    if manifest.assigned_obligations != assigned_obligation_count(plan, manifest.platform)? {
        return Err("evidence manifest assigned-obligation count is forged".to_owned());
    }
    Ok(())
}

fn ingest_evidence_records(
    repository: &mut EvidenceRepository,
    consumed: &mut BTreeSet<String>,
    manifest: &EvidenceManifest,
    members: &BTreeMap<String, Vec<u8>>,
    declared: &BTreeSet<String>,
    referenced: &mut BTreeSet<String>,
) -> Result<(), String> {
    for member in &manifest.records {
        let bytes = consume_archive_member(member, members, consumed, false)?;
        let record = EvidenceRecord::parse(&parse_canonical_json(bytes)?)?;
        if record.record_id != member.id.as_deref().unwrap_or_default()
            || record.platform != manifest.platform
        {
            return Err("evidence record identity differs from its manifest".to_owned());
        }
        retain_referenced_observations(
            declared,
            referenced,
            &record.candidate_observation_sha256,
            &record.oracle_observation_sha256,
            "evidence record",
        )?;
        repository.records.push(record);
    }
    Ok(())
}

fn ingest_exploratory_records(
    repository: &mut EvidenceRepository,
    consumed: &mut BTreeSet<String>,
    manifest: &EvidenceManifest,
    members: &BTreeMap<String, Vec<u8>>,
    declared: &BTreeSet<String>,
    referenced: &mut BTreeSet<String>,
) -> Result<Vec<ExploratoryRecord>, String> {
    let mut platform_records = Vec::new();
    for member in &manifest.exploratory_records {
        let bytes = consume_archive_member(member, members, consumed, false)?;
        let record = ExploratoryRecord::parse(&parse_canonical_json(bytes)?)?;
        if record.canonical_id()? != member.id.as_deref().unwrap_or_default()
            || record.platform != manifest.platform
        {
            return Err("exploratory record identity differs from its manifest".to_owned());
        }
        retain_referenced_observations(
            declared,
            referenced,
            &record.candidate_observation_sha256,
            &record.oracle_observation_sha256,
            "exploratory record",
        )?;
        platform_records.push(record.clone());
        repository.exploratory_records.push(record);
    }
    Ok(platform_records)
}

fn retain_referenced_observations(
    declared: &BTreeSet<String>,
    referenced: &mut BTreeSet<String>,
    candidate: &str,
    oracle: &str,
    label: &str,
) -> Result<(), String> {
    for digest in [candidate, oracle] {
        if !declared.contains(digest) {
            return Err(format!(
                "{label} references an observation outside its platform manifest"
            ));
        }
        referenced.insert(digest.to_owned());
    }
    Ok(())
}

fn ingest_observations(
    repository: &mut EvidenceRepository,
    consumed: &mut BTreeSet<String>,
    manifest: &EvidenceManifest,
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    for member in &manifest.observations {
        let bytes = consume_archive_member(member, members, consumed, true)?;
        let observation = Observation::parse_canonical(bytes.clone())?;
        if observation.sha256 != member.sha256 {
            return Err("observation identity is duplicated or differs from manifest".to_owned());
        }
        match repository.observations.entry(observation.sha256.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(observation);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &observation => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err("observation digest has contradictory bytes".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_exact_exploratory_schedule(
    platform: ConformancePlatform,
    records: &[ExploratoryRecord],
) -> Result<(), String> {
    let expected = hell_testkit::generated_typed_cases(
        EXPLORATORY_GENERATOR_SEED,
        EXPLORATORY_GENERATOR_COUNT,
    )
    .into_iter()
    .map(|generated| {
        (
            generated.id.to_string(),
            (
                generated.seed,
                hell_testkit::sha256_bytes(generated.source.as_bytes()).hex(),
                generated.ast_sha256.hex(),
            ),
        )
    })
    .collect::<BTreeMap<_, _>>();
    if records.len() != expected.len() {
        return Err(format!(
            "{platform:?} exploratory evidence does not equal the exact trusted schedule"
        ));
    }
    let mut observed = BTreeMap::new();
    for record in records {
        if record.platform != platform
            || record.generator_version != EXPLORATORY_GENERATOR_VERSION
            || observed
                .insert(
                    record.generated_case_id.clone(),
                    (
                        record.seed,
                        record.source_sha256.clone(),
                        record.ast_sha256.clone(),
                    ),
                )
                .is_some()
        {
            return Err("exploratory evidence schedule is substituted or duplicated".to_owned());
        }
    }
    if observed != expected {
        return Err("exploratory evidence schedule differs from trusted regeneration".to_owned());
    }
    Ok(())
}

pub(crate) fn assigned_obligation_count(
    plan: &super::ConformancePlan,
    producer: ConformancePlatform,
) -> Result<u64, String> {
    let assigned = plan
        .cells
        .iter()
        .flat_map(|cell| {
            cell.obligations
                .iter()
                .map(move |obligation| (cell, obligation))
        })
        .filter(|(cell, obligation)| obligation_assigned_to(cell, obligation, producer))
        .count();
    u64::try_from(assigned).map_err(|_| "assigned obligation count overflow".to_owned())
}

fn obligation_assigned_to(
    cell: &PlannedCell,
    obligation: &PlannedObligation,
    producer: ConformancePlatform,
) -> bool {
    match obligation.strategy {
        EvidenceStrategy::NativeOracle | EvidenceStrategy::CommittedDifferentialCorpus => {
            cell.key.platform == producer
        }
        EvidenceStrategy::PortableStatic | EvidenceStrategy::StructuralInvariant => {
            producer == ConformancePlatform::LinuxX86_64
        }
        EvidenceStrategy::CrossPlatformRelation => false,
    }
}

fn consume_archive_member<'a>(
    member: &EvidenceMember,
    members: &'a BTreeMap<String, Vec<u8>>,
    consumed: &mut BTreeSet<String>,
    allow_shared: bool,
) -> Result<&'a Vec<u8>, String> {
    let archive_path = if let Some(tail) = member.path.strip_prefix("conformance-evidence/") {
        format!("records/{tail}")
    } else if let Some(tail) = member.path.strip_prefix("conformance-observations/") {
        format!("observations/{tail}")
    } else {
        return Err("evidence manifest member path has an unknown class".to_owned());
    };
    if !canonical_member_path(&archive_path)
        || (!consumed.insert(archive_path.clone()) && !allow_shared)
    {
        return Err("evidence member path is unsafe or duplicated".to_owned());
    }
    let bytes = members
        .get(&archive_path)
        .ok_or_else(|| "manifest evidence member is missing".to_owned())?;
    if hell_testkit::sha256_bytes(bytes).hex() != member.sha256 {
        return Err("manifest evidence member digest mismatch".to_owned());
    }
    Ok(bytes)
}

fn canonical_member_path(path: &str) -> bool {
    let (prefix, tail) = path.split_once('/').unwrap_or_default();
    matches!(prefix, "records" | "observations")
        && !tail.is_empty()
        && !tail.contains(['/', '\\'])
        && std::path::Path::new(tail)
            .extension()
            .is_some_and(|extension| extension == "json")
        && !tail.starts_with('.')
}

fn parse_canonical_json(bytes: &[u8]) -> Result<JsonValue, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "evidence JSON is not UTF-8".to_owned())?;
    let value = crate::json::parse_json(text)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err("evidence JSON is not canonical with one LF".to_owned());
    }
    Ok(value)
}

impl EvidenceMember {
    fn json(&self) -> JsonValue {
        match &self.id {
            Some(id) => object([
                ("id", string(id)),
                ("path", string(&self.path)),
                ("sha256", string(&self.sha256)),
            ]),
            None => object([
                ("path", string(&self.path)),
                ("sha256", string(&self.sha256)),
            ]),
        }
    }
}

fn parse_members(
    value: &JsonValue,
    has_id: bool,
    id_prefix: &str,
) -> Result<Vec<EvidenceMember>, String> {
    value
        .array()?
        .iter()
        .map(|value| {
            let fields = value.object()?;
            require_exact_json_keys(
                fields,
                if has_id {
                    &["id", "path", "sha256"]
                } else {
                    &["path", "sha256"]
                },
            )?;
            let id = has_id
                .then(|| {
                    json_member(fields, "id")
                        .and_then(JsonValue::string)
                        .map(str::to_owned)
                })
                .transpose()?;
            if id.as_ref().is_some_and(|id| !id.starts_with(id_prefix)) {
                return Err("evidence manifest member ID has the wrong class".to_owned());
            }
            Ok(EvidenceMember {
                id,
                path: json_member(fields, "path")?.string()?.to_owned(),
                sha256: json_member(fields, "sha256")?.string()?.to_owned(),
            })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ObligationVerdict {
    Verified {
        mode: VerificationMode,
        evidence_ids: Vec<String>,
    },
    Missing,
    Mismatch {
        mismatch_sha256: String,
    },
    Invalid {
        code: InvalidEvidenceCode,
    },
}

pub(super) struct EvidenceIndex<'a> {
    records: BTreeMap<EvidenceTarget, &'a EvidenceRecord>,
    observations: &'a BTreeMap<String, Observation>,
    referenced_observations: BTreeSet<String>,
}

impl<'a> EvidenceIndex<'a> {
    pub(super) fn build(repository: &'a EvidenceRepository) -> Result<Self, String> {
        let mut record_ids = BTreeSet::new();
        let mut records = BTreeMap::new();
        for record in &repository.records {
            if record.record_id != record.canonical_id()?
                || !record_ids.insert(record.record_id.as_str())
            {
                return Err("evidence record IDs are empty or duplicated".to_owned());
            }
            if !matches!(record.case_source, CaseSource::Committed)
                && !super::mutant_active("generated-agreement-verifies-claim")
            {
                return Err("generated evidence record appears in committed evidence".to_owned());
            }
            if records.insert(record.target.clone(), record).is_some() {
                return Err(format!(
                    "duplicate evidence target for {}",
                    record.target.cell
                ));
            }
        }
        let referenced_observations = repository
            .records
            .iter()
            .flat_map(|record| {
                [
                    record.candidate_observation_sha256.clone(),
                    record.oracle_observation_sha256.clone(),
                ]
            })
            .chain(repository.exploratory_records.iter().flat_map(|record| {
                [
                    record.candidate_observation_sha256.clone(),
                    record.oracle_observation_sha256.clone(),
                ]
            }))
            .collect::<BTreeSet<_>>();
        for (digest, observation) in &repository.observations {
            if digest != &observation.sha256 {
                return Err("observation map key differs from content digest".to_owned());
            }
            observation.validate()?;
        }
        Ok(Self {
            records,
            observations: &repository.observations,
            referenced_observations,
        })
    }

    pub(super) fn evaluate_obligation(
        &mut self,
        cell: &PlannedCell,
        obligation: &PlannedObligation,
        trusted: &TrustedEvidenceBindings,
    ) -> ObligationVerdict {
        if obligation.case_ids.is_empty() {
            return ObligationVerdict::Missing;
        }
        let unsupported_strategy = matches!(
            obligation.strategy,
            EvidenceStrategy::PortableStatic
                | EvidenceStrategy::StructuralInvariant
                | EvidenceStrategy::CrossPlatformRelation
        );
        let mut evidence_ids = Vec::new();
        let mut mode = VerificationMode::Exact;
        let mut missing = false;
        let mut mismatch = None;
        let mut invalid = unsupported_strategy.then_some(InvalidEvidenceCode::UnsupportedStrategy);
        for case_id in &obligation.case_ids {
            let target = EvidenceTarget {
                cell: cell.key.clone(),
                obligation_id: obligation.id.clone(),
                case_id: case_id.clone(),
            };
            let Some(record) = self.records.remove(&target) else {
                missing = true;
                continue;
            };
            if let Err(code) = validate_record_binding(record, cell, obligation, trusted) {
                invalid.get_or_insert(code);
                continue;
            }
            let Some(candidate) = self.observations.get(&record.candidate_observation_sha256)
            else {
                invalid.get_or_insert(InvalidEvidenceCode::MissingCandidateObservation);
                continue;
            };
            let Some(oracle) = self.observations.get(&record.oracle_observation_sha256) else {
                invalid.get_or_insert(InvalidEvidenceCode::MissingOracleObservation);
                continue;
            };
            if let Err(code) = validate_obligation_specific_observations(
                cell, obligation, case_id, candidate, oracle,
            ) {
                invalid.get_or_insert(code);
                continue;
            }
            let trusted_case = hell_testkit::committed_differential_cases()
                .into_iter()
                .find(|case| case.id.as_ref() == case_id);
            match compare_observations(
                candidate,
                oracle,
                &record.requested_normalizers,
                trusted_case.as_ref(),
            ) {
                Ok(Comparison::Exact) => {}
                Ok(Comparison::Normalized) => mode = VerificationMode::Normalized,
                Ok(Comparison::Mismatch { mismatch_sha256 }) => {
                    mismatch.get_or_insert(mismatch_sha256);
                }
                Err(code) => {
                    invalid.get_or_insert(code);
                }
            }
            evidence_ids.push(record.record_id.clone());
        }
        if let Some(code) = invalid {
            return ObligationVerdict::Invalid { code };
        }
        if let Some(mismatch_sha256) = mismatch {
            return ObligationVerdict::Mismatch { mismatch_sha256 };
        }
        if missing {
            return ObligationVerdict::Missing;
        }
        ObligationVerdict::Verified { mode, evidence_ids }
    }

    pub(super) fn require_empty(&self) -> Result<(), String> {
        if self.records.is_empty()
            && self.referenced_observations
                == self.observations.keys().cloned().collect::<BTreeSet<_>>()
        {
            Ok(())
        } else {
            Err("evidence repository contains extra or unassigned records".to_owned())
        }
    }
}

impl EvidenceRecord {
    fn json_without_id(&self) -> JsonValue {
        record_json(self)
    }

    pub(crate) fn json(&self) -> JsonValue {
        let mut fields = self
            .json_without_id()
            .object()
            .expect("record object")
            .clone();
        fields.insert("recordId".to_owned(), string(&self.record_id));
        JsonValue::Object(fields)
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        let mut expected_keys = vec![
            "candidateBuildInfoSchemaVersion",
            "candidateCompatTracing",
            "candidateExecutableSha256",
            "candidateObservationSha256",
            "candidateSha",
            "caseId",
            "caseSource",
            "cellKey",
            "conformancePlanSha256",
            "descriptorSha256",
            "obligationId",
            "oracle",
            "oracleObservationSha256",
            "platform",
            "profile",
            "recordId",
            "releasePlanSha256",
            "requestedNormalizers",
            "schemaVersion",
            "sourceInventorySha256",
        ];
        if super::mutant_active("producer-acceptance-trusted") {
            expected_keys.push("accepted");
        }
        require_exact_json_keys(fields, &expected_keys)?;
        if json_member(fields, "schemaVersion")?.number()? != 2 {
            return Err("unsupported evidence record schema".to_owned());
        }
        let cell = CellKey::parse(json_member(fields, "cellKey")?)?;
        let platform = ConformancePlatform::parse(json_member(fields, "platform")?.string()?)?;
        let profile = ProfileId::parse(json_member(fields, "profile")?.string()?)?;
        let mut record = Self {
            record_id: json_member(fields, "recordId")?.string()?.to_owned(),
            release_plan_sha256: json_member(fields, "releasePlanSha256")?
                .string()?
                .to_owned(),
            conformance_plan_sha256: json_member(fields, "conformancePlanSha256")?
                .string()?
                .to_owned(),
            candidate_sha: json_member(fields, "candidateSha")?.string()?.to_owned(),
            candidate_build_info_schema_version: json_member(
                fields,
                "candidateBuildInfoSchemaVersion",
            )?
            .number()?,
            candidate_compat_tracing: json_member(fields, "candidateCompatTracing")?.boolean()?,
            candidate_executable_sha256: json_member(fields, "candidateExecutableSha256")?
                .string()?
                .to_owned(),
            source_inventory_sha256: json_member(fields, "sourceInventorySha256")?
                .string()?
                .to_owned(),
            oracle: parse_oracle(json_member(fields, "oracle")?)?,
            platform,
            profile,
            target: EvidenceTarget {
                cell,
                obligation_id: json_member(fields, "obligationId")?.string()?.to_owned(),
                case_id: json_member(fields, "caseId")?.string()?.to_owned(),
            },
            descriptor_sha256: json_member(fields, "descriptorSha256")?
                .string()?
                .to_owned(),
            case_source: parse_case_source(json_member(fields, "caseSource")?)?,
            candidate_observation_sha256: json_member(fields, "candidateObservationSha256")?
                .string()?
                .to_owned(),
            oracle_observation_sha256: json_member(fields, "oracleObservationSha256")?
                .string()?
                .to_owned(),
            requested_normalizers: parse_strings(json_member(fields, "requestedNormalizers")?)?,
        };
        if record.candidate_build_info_schema_version != 2 || !record.candidate_compat_tracing {
            return Err(
                "evidence record candidate compatibility tracing attestation is invalid".to_owned(),
            );
        }
        if record.platform != record.target.cell.platform
            || record.profile != record.target.cell.profile
        {
            return Err("evidence record repeats contradictory platform/profile".to_owned());
        }
        let stated = std::mem::take(&mut record.record_id);
        let observed = record.canonical_id()?;
        record.record_id = stated;
        if record.record_id != observed {
            return Err("evidence record content-derived ID mismatch".to_owned());
        }
        Ok(record)
    }

    pub(crate) fn canonical_id(&self) -> Result<String, String> {
        let value = self.json_without_id();
        Ok(format!(
            "ev-{}",
            hell_testkit::sha256_bytes(&canonical_json_bytes(&value)?).hex()
        ))
    }
}

fn record_json(record: &EvidenceRecord) -> JsonValue {
    object([
        (
            "candidateBuildInfoSchemaVersion",
            number(record.candidate_build_info_schema_version),
        ),
        (
            "candidateCompatTracing",
            JsonValue::Bool(record.candidate_compat_tracing),
        ),
        (
            "candidateExecutableSha256",
            string(&record.candidate_executable_sha256),
        ),
        (
            "candidateObservationSha256",
            string(&record.candidate_observation_sha256),
        ),
        ("candidateSha", string(&record.candidate_sha)),
        ("caseId", string(&record.target.case_id)),
        ("caseSource", case_source_json(&record.case_source)),
        ("cellKey", record.target.cell.json()),
        (
            "conformancePlanSha256",
            string(&record.conformance_plan_sha256),
        ),
        ("descriptorSha256", string(&record.descriptor_sha256)),
        ("obligationId", string(&record.target.obligation_id)),
        ("oracle", oracle_json(&record.oracle)),
        (
            "oracleObservationSha256",
            string(&record.oracle_observation_sha256),
        ),
        ("platform", string(record.platform.as_str())),
        ("profile", string(record.profile.as_str())),
        ("releasePlanSha256", string(&record.release_plan_sha256)),
        (
            "requestedNormalizers",
            JsonValue::Array(
                record
                    .requested_normalizers
                    .iter()
                    .map(|value| string(value))
                    .collect(),
            ),
        ),
        ("schemaVersion", number(2)),
        (
            "sourceInventorySha256",
            string(&record.source_inventory_sha256),
        ),
    ])
}

fn oracle_json(oracle: &OracleBinding) -> JsonValue {
    object([
        ("commit", string(&oracle.commit)),
        ("executableSha256", string(&oracle.executable_sha256)),
        ("repository", string(&oracle.repository)),
        ("sourceSha256", string(&oracle.source_sha256)),
    ])
}

fn parse_oracle(value: &JsonValue) -> Result<OracleBinding, String> {
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &["commit", "executableSha256", "repository", "sourceSha256"],
    )?;
    Ok(OracleBinding {
        repository: json_member(fields, "repository")?.string()?.to_owned(),
        commit: json_member(fields, "commit")?.string()?.to_owned(),
        executable_sha256: json_member(fields, "executableSha256")?
            .string()?
            .to_owned(),
        source_sha256: json_member(fields, "sourceSha256")?.string()?.to_owned(),
    })
}

fn case_source_json(source: &CaseSource) -> JsonValue {
    match source {
        CaseSource::Committed => object([("kind", string("committed"))]),
        CaseSource::Generated {
            generator_version,
            seed,
        } => object([
            ("generatorVersion", string(generator_version)),
            ("kind", string("generated")),
            ("seed", number(*seed)),
        ]),
    }
}

fn parse_case_source(value: &JsonValue) -> Result<CaseSource, String> {
    let fields = value.object()?;
    match json_member(fields, "kind")?.string()? {
        "committed" => {
            require_exact_json_keys(fields, &["kind"])?;
            Ok(CaseSource::Committed)
        }
        "generated" => {
            require_exact_json_keys(fields, &["generatorVersion", "kind", "seed"])?;
            Ok(CaseSource::Generated {
                generator_version: json_member(fields, "generatorVersion")?
                    .string()?
                    .to_owned(),
                seed: json_member(fields, "seed")?.number()?,
            })
        }
        value => Err(format!("unknown evidence case source {value:?}")),
    }
}

fn parse_strings(value: &JsonValue) -> Result<Vec<String>, String> {
    value
        .array()?
        .iter()
        .map(|value| Ok(value.string()?.to_owned()))
        .collect()
}

fn validate_record_binding(
    record: &EvidenceRecord,
    cell: &PlannedCell,
    obligation: &PlannedObligation,
    trusted: &TrustedEvidenceBindings,
) -> Result<(), InvalidEvidenceCode> {
    require_digest(&record.descriptor_sha256, "case descriptor digest")
        .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    if record.release_plan_sha256 != trusted.release_plan_sha256
        || record.conformance_plan_sha256 != trusted.conformance_plan_sha256
        || (!super::mutant_active("candidate-evidence-sha-substitution")
            && record.candidate_sha != trusted.candidate_sha)
        || record.source_inventory_sha256 != trusted.source_inventory_sha256
        || record.oracle
            != *trusted
                .oracle
                .get(&record.platform)
                .ok_or(InvalidEvidenceCode::EvidenceBinding)?
        || (!super::mutant_active("native-platform-evidence-substitution")
            && record.platform != cell.key.platform)
        || record.profile != cell.key.profile
        || record.target.cell != cell.key
        || record.target.obligation_id != obligation.id
        || obligation
            .case_descriptor_sha256
            .get(&record.target.case_id)
            != Some(&record.descriptor_sha256)
        || record.candidate_executable_sha256
            != *trusted
                .candidate_executable_sha256
                .get(&cell.key.platform)
                .ok_or(InvalidEvidenceCode::EvidenceBinding)?
    {
        return Err(InvalidEvidenceCode::EvidenceBinding);
    }
    if !super::mutant_active("normalizer-scope-bypassed")
        && record.requested_normalizers != obligation.allowed_normalizers
    {
        return Err(InvalidEvidenceCode::NormalizerClosure);
    }
    match obligation.strategy {
        EvidenceStrategy::NativeOracle
            if !super::mutant_active("native-platform-evidence-substitution")
                && record.platform != cell.key.platform =>
        {
            Err(InvalidEvidenceCode::NativePlatformSubstitution)
        }
        _ => Ok(()),
    }
}

pub(crate) fn assurance_relabeled_native_evidence() -> Result<(), String> {
    let plan = super::build_release_conformance_plan(
        hell_builtins::UPSTREAM_COMMIT,
        hell_builtins::UPSTREAM_COMMIT,
        "2026-08-13T00:00:00Z",
        &hell_testkit::sha256_bytes(b"assurance trusted inputs").hex(),
        &hell_testkit::sha256_bytes(b"assurance source inventory").hex(),
        Vec::new(),
    )?;
    let executable_digests = ConformancePlatform::ALL
        .into_iter()
        .map(|platform| {
            (
                platform,
                hell_testkit::sha256_bytes(platform.as_str().as_bytes()).hex(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let oracle_bindings = ConformancePlatform::ALL
        .into_iter()
        .map(|platform| {
            (
                platform,
                OracleBinding {
                    repository: "chrisdone/hell".to_owned(),
                    commit: hell_builtins::UPSTREAM_COMMIT.to_owned(),
                    executable_sha256: hell_testkit::sha256_bytes(
                        format!("{} oracle executable", platform.as_str()).as_bytes(),
                    )
                    .hex(),
                    source_sha256: hell_testkit::sha256_bytes(
                        format!("{} oracle source", platform.as_str()).as_bytes(),
                    )
                    .hex(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let trusted = TrustedEvidenceBindings::from_platform_identities(
        hell_testkit::sha256_bytes(b"assurance release plan").hex(),
        &plan,
        executable_digests,
        oracle_bindings,
    )?;
    let cell = plan
        .cells
        .iter()
        .find(|cell| {
            cell.key.platform == ConformancePlatform::LinuxX86_64
                && matches!(cell.scope, super::ScopeDisposition::Required { .. })
                && !cell.obligations.is_empty()
        })
        .ok_or_else(|| "release plan has no required Linux assurance cell".to_owned())?;
    let mut obligation = cell.obligations[0].clone();
    let case_id = "assurance-platform-binding".to_owned();
    let descriptor_sha256 = hell_testkit::sha256_bytes(case_id.as_bytes()).hex();
    obligation.case_ids = vec![case_id.clone()];
    obligation.case_descriptor_sha256 =
        BTreeMap::from([(case_id.clone(), descriptor_sha256.clone())]);
    let relabeled_platform = ConformancePlatform::MacosAarch64;
    let record = EvidenceRecord {
        record_id: "assurance-platform-binding".to_owned(),
        release_plan_sha256: trusted.release_plan_sha256.clone(),
        conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
        candidate_sha: trusted.candidate_sha.clone(),
        candidate_executable_sha256: trusted.candidate_executable_sha256[&cell.key.platform]
            .clone(),
        candidate_build_info_schema_version: 2,
        candidate_compat_tracing: true,
        source_inventory_sha256: trusted.source_inventory_sha256.clone(),
        oracle: trusted.oracle[&relabeled_platform].clone(),
        platform: relabeled_platform,
        profile: cell.key.profile,
        target: EvidenceTarget {
            cell: cell.key.clone(),
            obligation_id: obligation.id.clone(),
            case_id,
        },
        descriptor_sha256,
        case_source: CaseSource::Committed,
        candidate_observation_sha256: hell_testkit::sha256_bytes(b"candidate observation").hex(),
        oracle_observation_sha256: hell_testkit::sha256_bytes(b"oracle observation").hex(),
        requested_normalizers: obligation.allowed_normalizers.clone(),
    };
    validate_record_binding(&record, cell, &obligation, &trusted)
        .map_err(|code| format!("{code:?}"))
}

#[derive(Debug)]
enum Comparison {
    Exact,
    Normalized,
    Mismatch { mismatch_sha256: String },
}

fn compare_observations(
    candidate: &Observation,
    oracle: &Observation,
    normalizer_ids: &[String],
    case: Option<&hell_testkit::DifferentialCase>,
) -> Result<Comparison, InvalidEvidenceCode> {
    if candidate.bytes == oracle.bytes {
        return Ok(Comparison::Exact);
    }
    let mut candidate_bytes = candidate.bytes.clone();
    let mut oracle_bytes = oracle.bytes.clone();
    if !normalizer_ids.is_empty() && !super::mutant_active("normalizer-output-not-replayed") {
        if normalizer_ids.iter().any(|id| {
            !hell_builtins::NormalizerId::ALL
                .iter()
                .any(|normalizer| normalizer.as_str() == id)
        }) {
            return Err(InvalidEvidenceCode::UnauthorizedNormalizer);
        }
        let case = case.ok_or(InvalidEvidenceCode::TrustedCaseUnavailable)?;
        candidate_bytes = replay_normalizers(normalizer_ids, &candidate_bytes, case)?;
        oracle_bytes = replay_normalizers(normalizer_ids, &oracle_bytes, case)?;
    }
    if !normalizer_ids.is_empty() && candidate_bytes == oracle_bytes {
        return Ok(Comparison::Normalized);
    }
    let mut framed = Vec::new();
    for bytes in [&candidate.bytes, &oracle.bytes] {
        framed.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?
                .to_be_bytes(),
        );
        framed.extend_from_slice(bytes);
    }
    Ok(Comparison::Mismatch {
        mismatch_sha256: hell_testkit::sha256_bytes(&framed).hex(),
    })
}

fn replay_normalizers(
    ids: &[String],
    bytes: &[u8],
    case: &hell_testkit::DifferentialCase,
) -> Result<Vec<u8>, InvalidEvidenceCode> {
    let value = parse_canonical_json(bytes).map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    let fields = value
        .object()
        .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    let context = json_member(fields, "normalizerContext")
        .and_then(JsonValue::object)
        .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    let executable = json_member(context, "executable")
        .and_then(JsonValue::string)
        .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    let sandbox = json_member(context, "sandbox")
        .and_then(JsonValue::string)
        .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    let script = json_member(context, "script")
        .and_then(JsonValue::string)
        .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    let raw = validate_base64_field(
        json_member(fields, "rawStderr").map_err(|_| InvalidEvidenceCode::EvidenceBinding)?,
        "raw stderr",
    )
    .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    let retained = validate_base64_field(
        json_member(fields, "stderr").map_err(|_| InvalidEvidenceCode::EvidenceBinding)?,
        "stderr",
    )
    .map_err(|_| InvalidEvidenceCode::EvidenceBinding)?;
    let normalizers = ids
        .iter()
        .map(|id| {
            hell_builtins::NormalizerId::ALL
                .iter()
                .copied()
                .find(|normalizer| normalizer.as_str() == id)
                .ok_or(InvalidEvidenceCode::UnauthorizedNormalizer)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let replayed = hell_testkit::replay_conformance_stderr(
        &raw,
        std::path::Path::new(executable),
        std::path::Path::new(sandbox),
        std::path::Path::new(script),
        case,
        &normalizers,
    )
    .map_err(|_| InvalidEvidenceCode::NormalizerReplayUnavailable)?;
    if replayed != retained {
        return Err(InvalidEvidenceCode::NormalizerReplayUnavailable);
    }
    let mut normalized = fields.clone();
    normalized.remove("normalizerContext");
    normalized.remove("rawStderr");
    normalized.insert(
        "stderr".to_owned(),
        object([
            ("encoding", string("base64")),
            ("value", string(&encode_base64_bytes(&replayed))),
        ]),
    );
    canonical_json_bytes(&JsonValue::Object(normalized))
        .map_err(|_| InvalidEvidenceCode::EvidenceBinding)
}

fn encode_base64_bytes(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from(((first & 3) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[usize::from(((second & 15) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[usize::from(third & 63)])
        } else {
            '='
        });
    }
    output
}

fn validate_obligation_specific_observations(
    cell: &PlannedCell,
    obligation: &PlannedObligation,
    case_id: &str,
    candidate: &Observation,
    oracle: &Observation,
) -> Result<(), InvalidEvidenceCode> {
    let case = hell_testkit::committed_differential_cases()
        .into_iter()
        .find(|case| case.id.as_ref() == case_id)
        .ok_or(InvalidEvidenceCode::TrustedCaseUnavailable)?;
    let candidate_semantic = semantic_document(candidate)
        .map_err(|_| InvalidEvidenceCode::CandidateSemanticObligationInvalid)?;
    hell_testkit::validate_conformance_semantic_obligation(
        &candidate_semantic,
        &case,
        &cell.key.builtin,
        cell.key.dimension,
        &obligation.id,
    )
    .map_err(|_| InvalidEvidenceCode::CandidateSemanticObligationInvalid)?;
    let oracle_semantic = semantic_document(oracle)
        .map_err(|_| InvalidEvidenceCode::OracleSemanticObligationInvalid)?;
    hell_testkit::validate_conformance_semantic_obligation(
        &oracle_semantic,
        &case,
        &cell.key.builtin,
        cell.key.dimension,
        &obligation.id,
    )
    .map_err(|_| InvalidEvidenceCode::OracleSemanticObligationInvalid)?;
    Ok(())
}

fn semantic_document(observation: &Observation) -> Result<String, String> {
    let value = parse_canonical_json(&observation.bytes)?;
    let trace = json_member(value.object()?, "semanticTrace")?.array()?;
    let [trace] = trace else {
        return Err("observation must retain one exact semantic document".to_owned());
    };
    trace.string().map(str::to_owned)
}

#[cfg(test)]
fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from(((first & 3) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[usize::from(((second & 15) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[usize::from(third & 63)])
        } else {
            '='
        });
    }
    output
}

pub(super) fn exploratory_mismatches(
    repository: &EvidenceRepository,
    trusted: &TrustedEvidenceBindings,
) -> Result<Vec<super::Blocker>, String> {
    let mut ids = BTreeSet::new();
    let mut blockers = Vec::new();
    for record in &repository.exploratory_records {
        let index = record
            .generated_case_id
            .rsplit_once('-')
            .and_then(|(_, index)| index.parse::<usize>().ok())
            .filter(|index| *index < 4_096)
            .ok_or_else(|| "exploratory generated case ID is not reproducible".to_owned())?;
        let regenerated = hell_testkit::generated_typed_cases(record.seed, index.saturating_add(1))
            .into_iter()
            .nth(index)
            .ok_or_else(|| "exploratory generated case cannot be regenerated".to_owned())?;
        if record.generator_version != "typed-generator-v1"
            || regenerated.id.as_ref() != record.generated_case_id
            || regenerated.ast_sha256.hex() != record.ast_sha256
            || hell_testkit::sha256_bytes(regenerated.source.as_bytes()).hex()
                != record.source_sha256
            || !ids.insert((record.platform, record.generated_case_id.as_str()))
        {
            return Err(
                "exploratory record generator identity differs or is duplicated".to_owned(),
            );
        }
        require_digest(&record.ast_sha256, "exploratory AST digest")?;
        require_digest(&record.source_sha256, "exploratory source digest")?;
        if record.release_plan_sha256 != trusted.release_plan_sha256
            || record.conformance_plan_sha256 != trusted.conformance_plan_sha256
            || record.source_inventory_sha256 != trusted.source_inventory_sha256
            || record.candidate_sha != trusted.candidate_sha
            || record.candidate_executable_sha256
                != trusted.candidate_executable_sha256[&record.platform]
            || record.oracle != trusted.oracle[&record.platform]
        {
            return Err("exploratory evidence binding differs".to_owned());
        }
        let candidate = repository
            .observations
            .get(&record.candidate_observation_sha256)
            .ok_or_else(|| "exploratory candidate observation is missing".to_owned())?;
        let oracle = repository
            .observations
            .get(&record.oracle_observation_sha256)
            .ok_or_else(|| "exploratory oracle observation is missing".to_owned())?;
        if candidate.bytes != oracle.bytes && !super::mutant_active("generated-mismatch-ignored") {
            let Comparison::Mismatch { mismatch_sha256 } =
                compare_observations(candidate, oracle, &[], None)
                    .map_err(|_| "exploratory comparison evidence is invalid".to_owned())?
            else {
                return Err("exploratory comparison was not a mismatch".to_owned());
            };
            blockers.push(super::Blocker::UnclassifiedMismatch {
                platform: record.platform,
                generated_case_id: record.generated_case_id.clone(),
                candidate_observation_sha256: candidate.sha256.clone(),
                oracle_observation_sha256: oracle.sha256.clone(),
                mismatch_sha256,
            });
        }
    }
    Ok(blockers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalizer_context() -> JsonValue {
        object([
            ("executable", string("/bin/hell")),
            ("sandbox", string("/sandbox")),
            ("script", string("/sandbox/main.hell")),
        ])
    }

    fn plan_and_trusted() -> (super::super::ConformancePlan, TrustedEvidenceBindings) {
        let plan = super::super::build_release_conformance_plan(
            &"a".repeat(40),
            &"b".repeat(40),
            "2026-08-13T00:00:00Z",
            &"c".repeat(64),
            &"d".repeat(64),
            Vec::new(),
        )
        .unwrap();
        let executables = ConformancePlatform::ALL
            .into_iter()
            .enumerate()
            .map(|(index, platform)| {
                (
                    platform,
                    char::from(b'6' + u8::try_from(index).unwrap())
                        .to_string()
                        .repeat(64),
                )
            })
            .collect();
        let oracles = ConformancePlatform::ALL
            .into_iter()
            .enumerate()
            .map(|(index, platform)| {
                (
                    platform,
                    OracleBinding {
                        repository: "chrisdone/hell".to_owned(),
                        commit: "f".repeat(40),
                        executable_sha256: char::from(b'1' + u8::try_from(index).unwrap())
                            .to_string()
                            .repeat(64),
                        source_sha256: "4".repeat(64),
                    },
                )
            })
            .collect();
        let trusted = TrustedEvidenceBindings::from_platform_identities(
            "5".repeat(64),
            &plan,
            executables,
            oracles,
        )
        .unwrap();
        (plan, trusted)
    }

    fn manifest(
        plan: &super::super::ConformancePlan,
        trusted: &TrustedEvidenceBindings,
        platform: ConformancePlatform,
        records: Vec<EvidenceMember>,
        observations: Vec<EvidenceMember>,
        assigned_adjustment: u64,
    ) -> EvidenceManifest {
        EvidenceManifest::new(EvidenceManifestInput {
            platform,
            candidate_sha: trusted.candidate_sha.clone(),
            candidate_executable_sha256: trusted.candidate_executable_sha256[&platform].clone(),
            release_plan_sha256: trusted.release_plan_sha256.clone(),
            conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
            oracle: trusted.oracle[&platform].clone(),
            records,
            exploratory_records: Vec::new(),
            observations,
            assigned_obligations: assigned_obligation_count(plan, platform)
                .unwrap()
                .checked_add(assigned_adjustment)
                .unwrap(),
        })
        .unwrap()
    }

    fn manifest_members(manifests: &[EvidenceManifest]) -> BTreeMap<String, Vec<u8>> {
        manifests
            .iter()
            .map(|manifest| {
                (
                    format!("platform-manifests/{}.json", manifest.platform.as_str()),
                    canonical_json_bytes(&manifest.json()).unwrap(),
                )
            })
            .collect()
    }

    fn exact_exploratory_archive(
        plan: &super::super::ConformancePlan,
        trusted: &TrustedEvidenceBindings,
    ) -> (Vec<EvidenceManifest>, BTreeMap<String, Vec<u8>>) {
        let observation_bytes = canonical_json_bytes(&object([
            ("diagnostic", string("None")),
            (
                "exit",
                object([("kind", string("code")), ("value", number(0))]),
            ),
            ("filesystem", string("[]")),
            ("mode", string("Run")),
            ("normalizerContext", normalizer_context()),
            (
                "rawStderr",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("resourceAudit", string("None")),
            ("schemaVersion", number(4)),
            ("semanticTrace", JsonValue::Array(Vec::new())),
            (
                "stderr",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("statusSuccess", JsonValue::Bool(true)),
            (
                "stdout",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("termination", string("exited")),
        ]))
        .unwrap();
        let observation = Observation::parse_canonical(observation_bytes.clone()).unwrap();
        let observation_member = EvidenceMember {
            id: None,
            path: format!("conformance-observations/{}.json", observation.sha256),
            sha256: observation.sha256.clone(),
        };
        let mut members = BTreeMap::from([(
            format!("observations/{}.json", observation.sha256),
            observation_bytes,
        )]);
        let mut manifests = Vec::new();
        for platform in ConformancePlatform::ALL {
            let mut exploratory = Vec::new();
            for generated in hell_testkit::generated_typed_cases(
                EXPLORATORY_GENERATOR_SEED,
                EXPLORATORY_GENERATOR_COUNT,
            ) {
                let record = ExploratoryRecord {
                    generated_case_id: generated.id.to_string(),
                    platform,
                    generator_version: EXPLORATORY_GENERATOR_VERSION.to_owned(),
                    seed: generated.seed,
                    source_sha256: hell_testkit::sha256_bytes(generated.source.as_bytes()).hex(),
                    ast_sha256: generated.ast_sha256.hex(),
                    release_plan_sha256: trusted.release_plan_sha256.clone(),
                    conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
                    source_inventory_sha256: trusted.source_inventory_sha256.clone(),
                    candidate_sha: trusted.candidate_sha.clone(),
                    candidate_executable_sha256: trusted.candidate_executable_sha256[&platform]
                        .clone(),
                    candidate_build_info_schema_version: 2,
                    candidate_compat_tracing: true,
                    oracle: trusted.oracle[&platform].clone(),
                    candidate_observation_sha256: observation.sha256.clone(),
                    oracle_observation_sha256: observation.sha256.clone(),
                };
                let id = record.canonical_id().unwrap();
                let bytes = canonical_json_bytes(&record.json().unwrap()).unwrap();
                exploratory.push(EvidenceMember {
                    id: Some(id.clone()),
                    path: format!("conformance-evidence/{id}.json"),
                    sha256: hell_testkit::sha256_bytes(&bytes).hex(),
                });
                members.insert(format!("records/{id}.json"), bytes);
            }
            exploratory.sort_by(|left, right| left.path.cmp(&right.path));
            manifests.push(
                EvidenceManifest::new(EvidenceManifestInput {
                    platform,
                    candidate_sha: trusted.candidate_sha.clone(),
                    candidate_executable_sha256: trusted.candidate_executable_sha256[&platform]
                        .clone(),
                    release_plan_sha256: trusted.release_plan_sha256.clone(),
                    conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
                    oracle: trusted.oracle[&platform].clone(),
                    records: Vec::new(),
                    exploratory_records: exploratory,
                    observations: vec![observation_member.clone()],
                    assigned_obligations: assigned_obligation_count(plan, platform).unwrap(),
                })
                .unwrap(),
            );
        }
        members.extend(manifest_members(&manifests));
        (manifests, members)
    }

    #[test]
    fn observation_digest_and_overflow_are_fail_closed() {
        let mut observation = Observation::from_bytes(b"value\n".to_vec());
        observation.validate().unwrap();
        observation.bytes.push(b'x');
        assert!(observation.validate().is_err());
        observation = Observation::from_bytes(Vec::new());
        observation.overflow = true;
        assert!(observation.validate().is_err());
    }

    #[test]
    fn unimplemented_or_unauthorized_normalizers_fail_closed() {
        let observation = |stdout: &[u8]| {
            Observation::parse_canonical(
                canonical_json_bytes(&object([
                    ("diagnostic", string("None")),
                    (
                        "exit",
                        object([("kind", string("code")), ("value", number(0))]),
                    ),
                    ("filesystem", string("[]")),
                    ("mode", string("Run")),
                    ("normalizerContext", normalizer_context()),
                    (
                        "rawStderr",
                        object([("encoding", string("base64")), ("value", string(""))]),
                    ),
                    ("resourceAudit", string("None")),
                    ("schemaVersion", number(4)),
                    ("semanticTrace", JsonValue::Array(Vec::new())),
                    (
                        "stderr",
                        object([("encoding", string("base64")), ("value", string(""))]),
                    ),
                    ("statusSuccess", JsonValue::Bool(true)),
                    (
                        "stdout",
                        object([
                            ("encoding", string("base64")),
                            ("value", string(&encode_base64(stdout))),
                        ]),
                    ),
                    ("termination", string("exited")),
                ]))
                .unwrap(),
            )
            .unwrap()
        };
        let candidate = observation(b"one\r\ntwo\r\n");
        let oracle = observation(b"one\ntwo\n");
        assert_eq!(
            compare_observations(
                &candidate,
                &oracle,
                &["diagnostic-path-separator-v1".to_owned()],
                None,
            )
            .unwrap_err(),
            InvalidEvidenceCode::TrustedCaseUnavailable
        );
        assert_eq!(
            compare_observations(
                &candidate,
                &oracle,
                &["presentation-line-endings-v1".to_owned()],
                None,
            )
            .unwrap_err(),
            InvalidEvidenceCode::UnauthorizedNormalizer
        );
        assert!(matches!(
            compare_observations(&candidate, &oracle, &[], None).unwrap(),
            Comparison::Mismatch { .. }
        ));
    }

    fn diagnostic_observation(raw_stderr: &[u8], sandbox: &str, script: &str) -> Observation {
        Observation::parse_canonical(
            canonical_json_bytes(&object([
                ("diagnostic", string("None")),
                (
                    "exit",
                    object([("kind", string("code")), ("value", number(0))]),
                ),
                ("filesystem", string("[]")),
                ("mode", string("Run")),
                (
                    "normalizerContext",
                    object([
                        ("executable", string("/bin/hell")),
                        ("sandbox", string(sandbox)),
                        ("script", string(script)),
                    ]),
                ),
                (
                    "rawStderr",
                    object([
                        ("encoding", string("base64")),
                        ("value", string(&encode_base64(raw_stderr))),
                    ]),
                ),
                ("resourceAudit", string("None")),
                ("schemaVersion", number(4)),
                ("semanticTrace", JsonValue::Array(Vec::new())),
                (
                    "stderr",
                    object([
                        ("encoding", string("base64")),
                        (
                            "value",
                            string(&encode_base64(b"<SANDBOX>/main.hell:1:1: error[H0200]")),
                        ),
                    ]),
                ),
                ("statusSuccess", JsonValue::Bool(true)),
                (
                    "stdout",
                    object([("encoding", string("base64")), ("value", string(""))]),
                ),
                ("termination", string("exited")),
            ]))
            .unwrap(),
        )
        .unwrap()
    }

    fn assert_normalizer_closure_is_bound(
        plan: &super::super::ConformancePlan,
        trusted: &TrustedEvidenceBindings,
    ) {
        let cell = plan
            .cells
            .iter()
            .find(|cell| {
                cell.key.platform == ConformancePlatform::LinuxX86_64
                    && matches!(cell.scope, super::super::ScopeDisposition::Required { .. })
            })
            .unwrap();
        let mut obligation = cell.obligations[0].clone();
        obligation.allowed_normalizers = vec!["diagnostic-path-separator-v1".to_owned()];
        obligation.case_descriptor_sha256 = BTreeMap::from([("case".to_owned(), "d".repeat(64))]);
        let record = EvidenceRecord {
            record_id: "unused".to_owned(),
            release_plan_sha256: trusted.release_plan_sha256.clone(),
            conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
            candidate_sha: trusted.candidate_sha.clone(),
            candidate_executable_sha256: trusted.candidate_executable_sha256[&cell.key.platform]
                .clone(),
            candidate_build_info_schema_version: 2,
            candidate_compat_tracing: true,
            source_inventory_sha256: trusted.source_inventory_sha256.clone(),
            oracle: trusted.oracle[&cell.key.platform].clone(),
            platform: cell.key.platform,
            profile: cell.key.profile,
            target: EvidenceTarget {
                cell: cell.key.clone(),
                obligation_id: obligation.id.clone(),
                case_id: "case".to_owned(),
            },
            descriptor_sha256: "d".repeat(64),
            case_source: CaseSource::Committed,
            candidate_observation_sha256: "e".repeat(64),
            oracle_observation_sha256: "f".repeat(64),
            requested_normalizers: Vec::new(),
        };
        assert_eq!(
            validate_record_binding(&record, cell, &obligation, trusted),
            Err(InvalidEvidenceCode::NormalizerClosure)
        );
    }

    #[test]
    fn trusted_normalizer_is_replayed_on_both_raw_observations() {
        let candidate = diagnostic_observation(
            br"C:\work\one\main.hell:1:1: error[H0200]",
            r"C:\work\one",
            r"C:\work\one\main.hell",
        );
        let oracle = diagnostic_observation(
            b"/tmp/two/main.hell:1:1: error[H0200]",
            "/tmp/two",
            "/tmp/two/main.hell",
        );
        let case = hell_testkit::DifferentialCase {
            normalization: hell_testkit::OutputNormalization {
                stderr_replacements: Vec::new(),
                normalize_path_separators: true,
            },
            ..hell_testkit::DifferentialCase::default()
        };
        assert!(matches!(
            compare_observations(
                &candidate,
                &oracle,
                &["diagnostic-path-separator-v1".to_owned()],
                Some(&case),
            )
            .unwrap(),
            Comparison::Normalized
        ));

        let (plan, trusted) = plan_and_trusted();
        assert_normalizer_closure_is_bound(&plan, &trusted);
    }

    #[test]
    fn evidence_bindings_reject_candidate_and_native_platform_substitution() {
        let (plan, trusted) = plan_and_trusted();
        let cell = plan
            .cells
            .iter()
            .find(|cell| {
                cell.key.platform == ConformancePlatform::LinuxX86_64
                    && matches!(cell.scope, super::super::ScopeDisposition::Required { .. })
            })
            .unwrap();
        let mut obligation = cell.obligations[0].clone();
        obligation.case_descriptor_sha256 = BTreeMap::from([("case".to_owned(), "d".repeat(64))]);
        let mut record = EvidenceRecord {
            record_id: "unused".to_owned(),
            release_plan_sha256: trusted.release_plan_sha256.clone(),
            conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
            candidate_sha: "f".repeat(40),
            candidate_executable_sha256: trusted.candidate_executable_sha256[&cell.key.platform]
                .clone(),
            candidate_build_info_schema_version: 2,
            candidate_compat_tracing: true,
            source_inventory_sha256: trusted.source_inventory_sha256.clone(),
            oracle: trusted.oracle[&cell.key.platform].clone(),
            platform: cell.key.platform,
            profile: cell.key.profile,
            target: EvidenceTarget {
                cell: cell.key.clone(),
                obligation_id: obligation.id.clone(),
                case_id: "case".to_owned(),
            },
            descriptor_sha256: "d".repeat(64),
            case_source: CaseSource::Committed,
            candidate_observation_sha256: "e".repeat(64),
            oracle_observation_sha256: "f".repeat(64),
            requested_normalizers: obligation.allowed_normalizers.clone(),
        };
        assert_eq!(
            validate_record_binding(&record, cell, &obligation, &trusted),
            Err(InvalidEvidenceCode::EvidenceBinding)
        );
        record.candidate_sha = trusted.candidate_sha.clone();
        record.platform = ConformancePlatform::MacosAarch64;
        // Keep the candidate executable bound to the planned Linux cell while
        // substituting the native oracle/platform identity. This isolates the
        // platform-binding check from the independently tested executable
        // digest binding.
        record.oracle = trusted.oracle[&record.platform].clone();
        assert_eq!(
            validate_record_binding(&record, cell, &obligation, &trusted),
            Err(InvalidEvidenceCode::EvidenceBinding)
        );
    }

    #[test]
    fn observation_schema_rejects_unknown_fields_and_incomplete_capture() {
        let valid = object([
            ("diagnostic", string("None")),
            (
                "exit",
                object([("kind", string("code")), ("value", number(0))]),
            ),
            ("filesystem", string("[]")),
            ("mode", string("Run")),
            ("normalizerContext", normalizer_context()),
            (
                "rawStderr",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("resourceAudit", string("None")),
            ("schemaVersion", number(4)),
            ("semanticTrace", JsonValue::Array(Vec::new())),
            (
                "stderr",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("statusSuccess", JsonValue::Bool(true)),
            (
                "stdout",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("termination", string("exited")),
        ]);
        assert!(Observation::parse_canonical(canonical_json_bytes(&valid).unwrap()).is_ok());
        let mut fields = valid.object().unwrap().clone();
        fields.insert("accepted".to_owned(), JsonValue::Bool(true));
        assert!(
            Observation::parse_canonical(canonical_json_bytes(&JsonValue::Object(fields)).unwrap())
                .is_err()
        );
        let mut fields = valid.object().unwrap().clone();
        fields.insert("termination".to_owned(), string("truncated"));
        assert!(
            Observation::parse_canonical(canonical_json_bytes(&JsonValue::Object(fields)).unwrap())
                .is_err()
        );
        let mut fields = valid.object().unwrap().clone();
        fields.insert("termination".to_owned(), string("signaled"));
        assert!(
            Observation::parse_canonical(canonical_json_bytes(&JsonValue::Object(fields)).unwrap())
                .is_err()
        );
        let mut fields = valid.object().unwrap().clone();
        fields.insert("statusSuccess".to_owned(), JsonValue::Bool(false));
        assert!(
            Observation::parse_canonical(canonical_json_bytes(&JsonValue::Object(fields)).unwrap())
                .is_err()
        );
        let mut diagnostic = valid.object().unwrap().clone();
        diagnostic.insert(
            "diagnostic".to_owned(),
            string("Some(DiagnosticObservation { code: \"H9999\" })"),
        );
        let diagnostic = Observation::parse_canonical(
            canonical_json_bytes(&JsonValue::Object(diagnostic)).unwrap(),
        )
        .unwrap();
        let baseline = Observation::parse_canonical(canonical_json_bytes(&valid).unwrap()).unwrap();
        assert!(matches!(
            compare_observations(&baseline, &diagnostic, &[], None).unwrap(),
            Comparison::Mismatch { .. }
        ));
    }

    #[test]
    fn producer_acceptance_fields_are_rejected() {
        let (plan, trusted) = plan_and_trusted();
        let cell = plan
            .cells
            .iter()
            .find(|cell| matches!(cell.scope, super::super::ScopeDisposition::Required { .. }))
            .unwrap();
        let mut record = EvidenceRecord {
            record_id: String::new(),
            release_plan_sha256: trusted.release_plan_sha256.clone(),
            conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
            candidate_sha: trusted.candidate_sha.clone(),
            candidate_executable_sha256: trusted.candidate_executable_sha256[&cell.key.platform]
                .clone(),
            candidate_build_info_schema_version: 2,
            candidate_compat_tracing: true,
            source_inventory_sha256: trusted.source_inventory_sha256.clone(),
            oracle: trusted.oracle[&cell.key.platform].clone(),
            platform: cell.key.platform,
            profile: cell.key.profile,
            target: EvidenceTarget {
                cell: cell.key.clone(),
                obligation_id: cell.obligations[0].id.clone(),
                case_id: "producer-verdict-case".to_owned(),
            },
            descriptor_sha256: "d".repeat(64),
            case_source: CaseSource::Committed,
            candidate_observation_sha256: "e".repeat(64),
            oracle_observation_sha256: "f".repeat(64),
            requested_normalizers: Vec::new(),
        };
        record.record_id = record.canonical_id().unwrap();
        let baseline = record.json();
        assert!(EvidenceRecord::parse(&baseline).is_ok());

        let mut fields = baseline.object().unwrap().clone();
        fields.insert("accepted".to_owned(), JsonValue::Bool(true));
        assert!(EvidenceRecord::parse(&JsonValue::Object(fields)).is_err());

        let mut fields = baseline.object().unwrap().clone();
        fields.remove("candidateCompatTracing");
        assert!(EvidenceRecord::parse(&JsonValue::Object(fields)).is_err());

        let mut fields = baseline.object().unwrap().clone();
        fields.insert("candidateCompatTracing".to_owned(), JsonValue::Bool(false));
        assert!(
            EvidenceRecord::parse(&JsonValue::Object(fields))
                .unwrap_err()
                .contains("compatibility tracing attestation")
        );

        let mut fields = baseline.object().unwrap().clone();
        fields.insert(
            "candidateBuildInfoSchemaVersion".to_owned(),
            JsonValue::Number(3),
        );
        assert!(
            EvidenceRecord::parse(&JsonValue::Object(fields))
                .unwrap_err()
                .contains("compatibility tracing attestation")
        );
    }

    #[test]
    fn archive_manifest_inventory_and_assigned_counts_are_recomputed() {
        let (plan, trusted) = plan_and_trusted();
        let manifests = ConformancePlatform::ALL
            .into_iter()
            .map(|platform| manifest(&plan, &trusted, platform, Vec::new(), Vec::new(), 0))
            .collect::<Vec<_>>();
        assert_eq!(
            TrustedEvidenceBindings::from_manifests(&plan, &manifests).unwrap(),
            trusted
        );
        let members = manifest_members(&manifests);
        assert!(
            EvidenceRepository::from_archive_members(&manifests, &members, &trusted, &plan)
                .unwrap_err()
                .contains("exact trusted schedule")
        );

        let duplicates = vec![
            manifests[0].clone(),
            manifests[0].clone(),
            manifests[2].clone(),
        ];
        assert!(
            EvidenceRepository::from_archive_members(&duplicates, &members, &trusted, &plan)
                .is_err()
        );

        let mut forged = manifests.clone();
        forged[0] = manifest(
            &plan,
            &trusted,
            forged[0].platform,
            Vec::new(),
            Vec::new(),
            1,
        );
        let forged_members = manifest_members(&forged);
        assert!(
            EvidenceRepository::from_archive_members(&forged, &forged_members, &trusted, &plan)
                .is_err()
        );

        let mut extra = members;
        extra.insert(
            format!("observations/{}.json", "6".repeat(64)),
            b"{}\n".to_vec(),
        );
        assert!(
            EvidenceRepository::from_archive_members(&manifests, &extra, &trusted, &plan).is_err()
        );
    }

    #[test]
    fn exact_exploratory_schedule_is_required_per_platform() {
        let (plan, trusted) = plan_and_trusted();
        let (manifests, members) = exact_exploratory_archive(&plan, &trusted);
        let repository =
            EvidenceRepository::from_archive_members(&manifests, &members, &trusted, &plan)
                .unwrap();
        assert_eq!(
            repository.exploratory_records.len(),
            ConformancePlatform::ALL.len() * EXPLORATORY_GENERATOR_COUNT
        );

        let mut omitted = manifests.clone();
        let platform = omitted[0].platform;
        let mut records = omitted[0].exploratory_records.clone();
        records.pop();
        omitted[0] = EvidenceManifest::new(EvidenceManifestInput {
            platform,
            candidate_sha: trusted.candidate_sha.clone(),
            candidate_executable_sha256: trusted.candidate_executable_sha256[&platform].clone(),
            release_plan_sha256: trusted.release_plan_sha256.clone(),
            conformance_plan_sha256: trusted.conformance_plan_sha256.clone(),
            oracle: trusted.oracle[&platform].clone(),
            records: Vec::new(),
            exploratory_records: records,
            observations: omitted[0].observations.clone(),
            assigned_obligations: assigned_obligation_count(&plan, platform).unwrap(),
        })
        .unwrap();
        let mut omitted_members = members;
        omitted_members.insert(
            format!("platform-manifests/{}.json", platform.as_str()),
            canonical_json_bytes(&omitted[0].json()).unwrap(),
        );
        assert!(
            EvidenceRepository::from_archive_members(&omitted, &omitted_members, &trusted, &plan,)
                .unwrap_err()
                .contains("exact trusted schedule")
        );
    }

    fn empty_observation_fixture() -> (Vec<u8>, Observation) {
        let observation_bytes = canonical_json_bytes(&object([
            ("diagnostic", string("None")),
            (
                "exit",
                object([("kind", string("code")), ("value", number(0))]),
            ),
            ("filesystem", string("[]")),
            ("mode", string("Run")),
            ("normalizerContext", normalizer_context()),
            (
                "rawStderr",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("resourceAudit", string("None")),
            ("schemaVersion", number(4)),
            ("semanticTrace", JsonValue::Array(Vec::new())),
            (
                "stderr",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("statusSuccess", JsonValue::Bool(true)),
            (
                "stdout",
                object([("encoding", string("base64")), ("value", string(""))]),
            ),
            ("termination", string("exited")),
        ]))
        .unwrap();
        let observation = Observation::parse_canonical(observation_bytes.clone()).unwrap();
        (observation_bytes, observation)
    }

    #[test]
    fn record_cannot_borrow_an_observation_from_another_platform_manifest() {
        let (plan, trusted) = plan_and_trusted();
        let cell = plan
            .cells
            .iter()
            .find(|cell| {
                cell.key.platform == ConformancePlatform::LinuxX86_64
                    && matches!(cell.scope, super::super::ScopeDisposition::Required { .. })
            })
            .unwrap();
        let obligation = &cell.obligations[0];
        let (observation_bytes, observation) = empty_observation_fixture();
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
            profile: cell.key.profile,
            target: EvidenceTarget {
                cell: cell.key.clone(),
                obligation_id: obligation.id.clone(),
                case_id: "foreign-observation".to_owned(),
            },
            descriptor_sha256: "7".repeat(64),
            case_source: CaseSource::Committed,
            candidate_observation_sha256: observation.sha256.clone(),
            oracle_observation_sha256: observation.sha256.clone(),
            requested_normalizers: Vec::new(),
        };
        record.record_id = record.canonical_id().unwrap();
        assert_eq!(EvidenceRecord::parse(&record.json()).unwrap(), record);
        let mut forged = record.json().object().unwrap().clone();
        forged.insert("candidateSha".to_owned(), string(&"9".repeat(40)));
        assert!(EvidenceRecord::parse(&JsonValue::Object(forged)).is_err());
        let record_bytes = canonical_json_bytes(&record.json()).unwrap();
        let record_member = EvidenceMember {
            id: Some(record.record_id.clone()),
            path: format!("conformance-evidence/{}.json", record.record_id),
            sha256: hell_testkit::sha256_bytes(&record_bytes).hex(),
        };
        let observation_member = EvidenceMember {
            id: None,
            path: format!("conformance-observations/{}.json", observation.sha256),
            sha256: observation.sha256.clone(),
        };
        let manifests = vec![
            manifest(
                &plan,
                &trusted,
                ConformancePlatform::LinuxX86_64,
                vec![record_member],
                Vec::new(),
                0,
            ),
            manifest(
                &plan,
                &trusted,
                ConformancePlatform::MacosAarch64,
                Vec::new(),
                vec![observation_member],
                0,
            ),
            manifest(
                &plan,
                &trusted,
                ConformancePlatform::WindowsX86_64,
                Vec::new(),
                Vec::new(),
                0,
            ),
        ];
        let mut members = manifest_members(&manifests);
        members.insert(format!("records/{}.json", record.record_id), record_bytes);
        members.insert(
            format!("observations/{}.json", observation.sha256),
            observation_bytes,
        );
        assert!(
            EvidenceRepository::from_archive_members(&manifests, &members, &trusted, &plan)
                .unwrap_err()
                .contains("outside its platform manifest")
        );
    }
}
