use std::collections::{BTreeMap, BTreeSet};

use hell_builtins::CompatibilityDimension;

use super::{
    CellKey, ConformancePlatform, ExemptionKind, PlannedExemption, ProfileId, RELEASE_STANDARD,
};

pub(crate) fn parse_release_exemptions(bytes: &[u8]) -> Result<Vec<PlannedExemption>, String> {
    let blocks = parse_exemption_blocks(bytes)?;
    let mut ids = BTreeSet::new();
    blocks
        .into_iter()
        .map(|fields| parse_exemption(fields, &mut ids))
        .collect()
}

fn parse_exemption_blocks(bytes: &[u8]) -> Result<Vec<BTreeMap<String, String>>, String> {
    if !bytes.ends_with(b"\n") {
        return Err("release exemption catalog lacks one trailing newline".to_owned());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "release exemption catalog is not UTF-8".to_owned())?;
    let mut lines = text.lines();
    if lines.next() != Some("schema_version = 1") || lines.next() != Some("allow_wildcards = false")
    {
        return Err("release exemption catalog header is not canonical".to_owned());
    }
    let remaining = lines.collect::<Vec<_>>();
    let mut blocks = Vec::new();
    let mut current = None::<BTreeMap<String, String>>;
    for line in remaining {
        if line.is_empty() {
            continue;
        }
        if line == "[[exemptions]]" {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(BTreeMap::new());
            continue;
        }
        let block = current
            .as_mut()
            .ok_or_else(|| "release exemption field precedes its table".to_owned())?;
        let (key, raw) = line
            .split_once(" = ")
            .ok_or_else(|| "release exemption assignment is not canonical".to_owned())?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        {
            return Err("release exemption key is not canonical".to_owned());
        }
        let value = crate::strict_toml::string(raw)?;
        if block.insert(key.to_owned(), value).is_some() {
            return Err(format!("duplicate release exemption field {key}"));
        }
    }
    if let Some(block) = current {
        blocks.push(block);
    }

    Ok(blocks)
}

fn parse_exemption(
    mut fields: BTreeMap<String, String>,
    ids: &mut BTreeSet<String>,
) -> Result<PlannedExemption, String> {
    let kind = take(&mut fields, "kind")?;
    let kind = match kind.as_str() {
        "known-divergence" => ExemptionKind::KnownDivergence,
        "evidence-gap" => ExemptionKind::EvidenceGap,
        _ => return Err(format!("unknown release exemption kind {kind:?}")),
    };
    let expected_mismatch_sha256 = fields.remove("expected_mismatch_sha256");
    if matches!(kind, ExemptionKind::KnownDivergence) != expected_mismatch_sha256.is_some() {
        return Err("release exemption mismatch digest contradicts its kind".to_owned());
    }
    let id = take(&mut fields, "id")?;
    if !ids.insert(id.clone()) {
        return Err(format!("duplicate release exemption ID {id}"));
    }
    let dimension = take(&mut fields, "dimension")?;
    let dimension = CompatibilityDimension::ALL
        .into_iter()
        .find(|value| value.as_str() == dimension)
        .ok_or_else(|| "release exemption dimension is unknown".to_owned())?;
    let standard = take(&mut fields, "standard")?;
    if standard != RELEASE_STANDARD {
        return Err("release exemption standard differs".to_owned());
    }
    let exemption = PlannedExemption {
        id,
        kind,
        candidate_sha: take(&mut fields, "candidate_sha")?,
        standard,
        baseline: take(&mut fields, "baseline")?,
        cell: CellKey::new(
            take(&mut fields, "builtin")?,
            dimension,
            ProfileId::parse(&take(&mut fields, "profile")?)?,
            ConformancePlatform::parse(&take(&mut fields, "platform")?)?,
        )?,
        obligation_id: take(&mut fields, "obligation_id")?,
        expected_mismatch_sha256,
        issue: take(&mut fields, "issue")?,
        rationale: take(&mut fields, "rationale")?,
        review_group: take(&mut fields, "review_group")?,
        expires_on: take(&mut fields, "expires_on")?,
    };
    if !fields.is_empty() {
        return Err(format!(
            "unknown release exemption fields: {:?}",
            fields.keys().collect::<Vec<_>>()
        ));
    }
    Ok(exemption)
}

fn take(fields: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    fields
        .remove(key)
        .ok_or_else(|| format!("release exemption lacks {key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_exemption_parses_and_wildcard_or_unknown_field_fails_later_or_now() {
        let text = concat!(
            "schema_version = 1\nallow_wildcards = false\n\n[[exemptions]]\n",
            "id = \"EX-1\"\nkind = \"evidence-gap\"\n",
            "candidate_sha = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n",
            "standard = \"upstream-release-v1\"\nbaseline = \"2026-05-29\"\n",
            "builtin = \"Bool.bool\"\ndimension = \"pure-runtime\"\n",
            "profile = \"upstream\"\nplatform = \"linux-x86_64\"\n",
            "obligation_id = \"adapter-success\"\nissue = \"COMPAT-1\"\n",
            "rationale = \"Temporary exact evidence gap.\"\n",
            "review_group = \"release-conformance\"\nexpires_on = \"2026-12-31\"\n"
        );
        let parsed = parse_release_exemptions(text.as_bytes()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].cell.builtin, "Bool.bool");
        assert!(parse_release_exemptions(text.replace("issue =", "unknown =").as_bytes()).is_err());
    }
}
