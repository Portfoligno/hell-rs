use std::collections::BTreeSet;
use std::path::Path;

use crate::json::{
    JsonValue, canonical_json_bytes, json_member, parse_json, require_exact_json_keys,
};
use crate::release::manifest::read_regular;
use crate::release::schema::{number, object, string};

const CONTROL_PATHS: [&str; 9] = [
    ".github/release/conformance-exemptions.toml",
    "compat/builtin-registry.json",
    "compat/claim-rules.toml",
    "compat/corpus-obligations.toml",
    "compat/divergences.toml",
    "compat/expected-mismatches.toml",
    "compat/normalizers.toml",
    "compat/requirements/2026-05-29.toml",
    "release-policy.toml",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrustedConformanceInputs {
    pub(crate) aggregate_sha256: String,
    pub(crate) manifest: JsonValue,
}

pub(crate) fn build_trusted_inputs(
    trusted_root: &Path,
    candidate_root: &Path,
    workflow_sha: &str,
) -> Result<TrustedConformanceInputs, String> {
    crate::release::schema::require_sha(workflow_sha, "trusted input workflow SHA")?;
    let mut files = Vec::new();
    for relative in CONTROL_PATHS {
        validate_control_path(relative)?;
        let trusted = read_regular(&trusted_root.join(relative))?;
        let candidate = read_regular(&candidate_root.join(relative))?;
        if trusted != candidate {
            return Err(format!(
                "candidate control input {relative} differs from trusted automation"
            ));
        }
        if text_control(relative) && !trusted.ends_with(b"\n") {
            return Err(format!(
                "trusted text input {relative} lacks trailing newline"
            ));
        }
        if relative == "compat/builtin-registry.json" {
            verify_registry_manifest(&trusted)?;
        }
        files.push(object([
            ("path", string(relative)),
            (
                "sha256",
                string(&hell_testkit::sha256_bytes(&trusted).hex()),
            ),
        ]));
    }
    files.sort_by(|left, right| {
        json_member(left.object().expect("file object"), "path")
            .expect("path")
            .string()
            .expect("path string")
            .cmp(
                json_member(right.object().expect("file object"), "path")
                    .expect("path")
                    .string()
                    .expect("path string"),
            )
    });
    let without_digest = object([
        (
            "exploratoryPolicy",
            object([
                (
                    "generatedAgreementMayVerify",
                    JsonValue::Bool(super::GENERATED_AGREEMENT_MAY_VERIFY),
                ),
                (
                    "generatedMismatchBlocks",
                    JsonValue::Bool(super::GENERATED_MISMATCH_BLOCKS),
                ),
            ]),
        ),
        ("files", JsonValue::Array(files.clone())),
        ("schemaVersion", number(1)),
        ("workflowSha", string(workflow_sha)),
    ]);
    let aggregate_sha256 =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&without_digest)?).hex();
    let manifest = object([
        ("aggregateSha256", string(&aggregate_sha256)),
        (
            "exploratoryPolicy",
            object([
                (
                    "generatedAgreementMayVerify",
                    JsonValue::Bool(super::GENERATED_AGREEMENT_MAY_VERIFY),
                ),
                (
                    "generatedMismatchBlocks",
                    JsonValue::Bool(super::GENERATED_MISMATCH_BLOCKS),
                ),
            ]),
        ),
        ("files", JsonValue::Array(files)),
        ("schemaVersion", number(1)),
        ("workflowSha", string(workflow_sha)),
    ]);
    Ok(TrustedConformanceInputs {
        aggregate_sha256,
        manifest,
    })
}

pub(crate) fn verify_registry_manifest(bytes: &[u8]) -> Result<(), String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "builtin registry is not UTF-8".to_owned())?;
    let value = parse_json(text)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err("builtin registry is not canonical JSON with one LF".to_owned());
    }
    let fields = value.object()?;
    require_exact_json_keys(fields, &["builtins", "schemaVersion"])?;
    if json_member(fields, "schemaVersion")?.number()? != 1 {
        return Err("unsupported builtin registry schema".to_owned());
    }
    let entries = json_member(fields, "builtins")?.array()?;
    if entries.len() != hell_builtins::registry().len() {
        return Err("builtin registry manifest count differs from runtime registry".to_owned());
    }
    let mut ids = BTreeSet::new();
    for (entry, builtin) in entries.iter().zip(hell_builtins::registry()) {
        let entry = entry.object()?;
        require_exact_json_keys(entry, &["arity", "id", "visibility", "wiring"])?;
        let visibility = match builtin.visibility {
            hell_builtins::Visibility::Public => "public",
            hell_builtins::Visibility::Internal => "internal",
        };
        let wiring = match builtin.wiring {
            hell_builtins::WiringStatus::Executable => "implemented",
            hell_builtins::WiringStatus::DeclaredOnly => "declared-only",
        };
        let id = json_member(entry, "id")?.string()?;
        if !ids.insert(id)
            || id != builtin.name
            || json_member(entry, "arity")?.number()? != u64::from(builtin.arity)
            || json_member(entry, "visibility")?.string()? != visibility
            || json_member(entry, "wiring")?.string()? != wiring
        {
            return Err(format!(
                "builtin registry entry differs at runtime ID {}",
                builtin.id.0
            ));
        }
    }
    Ok(())
}

fn validate_control_path(relative: &str) -> Result<(), String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || relative.contains('\\')
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!("control input path {relative:?} is not canonical"));
    }
    Ok(())
}

fn text_control(relative: &str) -> bool {
    Path::new(relative)
        .extension()
        .is_some_and(|extension| extension == "toml" || extension == "json")
}

pub(crate) fn parse_trusted_inputs(value: &JsonValue) -> Result<TrustedConformanceInputs, String> {
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &[
            "aggregateSha256",
            "exploratoryPolicy",
            "files",
            "schemaVersion",
            "workflowSha",
        ],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 1 {
        return Err("unsupported trusted input manifest schema".to_owned());
    }
    crate::release::schema::require_sha(
        json_member(fields, "workflowSha")?.string()?,
        "trusted input workflow SHA",
    )?;
    let exploratory_policy = json_member(fields, "exploratoryPolicy")?.object()?;
    require_exact_json_keys(
        exploratory_policy,
        &["generatedAgreementMayVerify", "generatedMismatchBlocks"],
    )?;
    if json_member(exploratory_policy, "generatedAgreementMayVerify")?.boolean()?
        != super::GENERATED_AGREEMENT_MAY_VERIFY
        || json_member(exploratory_policy, "generatedMismatchBlocks")?.boolean()?
            != super::GENERATED_MISMATCH_BLOCKS
    {
        return Err("trusted input exploratory policy differs from trusted code".to_owned());
    }
    let files = json_member(fields, "files")?.array()?;
    let observed = files
        .iter()
        .map(|entry| {
            let fields = entry.object()?;
            require_exact_json_keys(fields, &["path", "sha256"])?;
            crate::release::schema::require_digest(
                json_member(fields, "sha256")?.string()?,
                "trusted input digest",
            )?;
            Ok(json_member(fields, "path")?.string()?.to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    if observed
        != CONTROL_PATHS
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
    {
        return Err("trusted input manifest exact path inventory differs".to_owned());
    }
    let aggregate_sha256 = json_member(fields, "aggregateSha256")?.string()?.to_owned();
    crate::release::schema::require_digest(&aggregate_sha256, "trusted input aggregate digest")?;
    let without = object([
        (
            "exploratoryPolicy",
            object([
                (
                    "generatedAgreementMayVerify",
                    JsonValue::Bool(super::GENERATED_AGREEMENT_MAY_VERIFY),
                ),
                (
                    "generatedMismatchBlocks",
                    JsonValue::Bool(super::GENERATED_MISMATCH_BLOCKS),
                ),
            ]),
        ),
        ("files", JsonValue::Array(files.to_vec())),
        ("schemaVersion", number(1)),
        (
            "workflowSha",
            string(json_member(fields, "workflowSha")?.string()?),
        ),
    ]);
    if hell_testkit::sha256_bytes(&canonical_json_bytes(&without)?).hex() != aggregate_sha256 {
        return Err("trusted input aggregate self-digest mismatch".to_owned());
    }
    Ok(TrustedConformanceInputs {
        aggregate_sha256,
        manifest: value.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_registry_is_canonical_and_matches_runtime_order() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        verify_registry_manifest(
            &std::fs::read(root.join("compat/builtin-registry.json")).unwrap(),
        )
        .unwrap();
    }
}
