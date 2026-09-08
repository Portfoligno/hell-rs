use std::path::PathBuf;

use hell_memcordon::{AcquisitionReceiptV1, NativeArgument, ProviderLifecycleReceiptV1};

use super::{provider, task::Task};
use crate::release::manifest::read_regular;

pub(super) fn validate(
    task: &Task,
    acquisition: &AcquisitionReceiptV1,
    provider: &ProviderLifecycleReceiptV1,
) -> Result<PathBuf, String> {
    if acquisition.schema_version != hell_memcordon::ACQUISITION_RECEIPT_SCHEMA_V1
        || provider.schema_version != hell_memcordon::PROVIDER_RECEIPT_SCHEMA_V1
        || provider.provider_lease_id != super::provider::lease_id(task, acquisition)
        || provider.failure.is_some()
        || provider.cleanup_succeeded
        || acquisition.runtime_lock_digest
            != hell_memcordon::runtime_lock_digest(&read_regular(&task.lock)?).hex()
    {
        return Err(
            "qualified prerequisite lease is not bound to the current task and runtime lock"
                .to_owned(),
        );
    }
    for (name, expected) in [
        ("package-inspect.json", &provider.package_inspection_digest),
        ("package-verify.json", &provider.package_verification_digest),
        ("doctor.json", &provider.qualification_digest),
    ] {
        let bytes = read_regular(&task.output.join(name))?;
        if expected.as_deref() != Some(hell_testkit::sha256_bytes(&bytes).hex().as_str()) {
            return Err(format!(
                "qualified prerequisite {name} differs from its provider lease"
            ));
        }
    }
    let target = provider::find_component(&task.runtime_root, provider::agent_name())?;
    if hell_testkit::sha256_file(&target)
        .map_err(|error| error.to_string())?
        .hex()
        != provider.agent_sha256
    {
        return Err("qualified provider agent differs from its installed lease".to_owned());
    }
    let canaries: serde_json::Value =
        serde_json::from_slice(&read_regular(&task.output.join("canaries.json"))?)
            .map_err(|error| format!("invalid prerequisite canary receipt: {error}"))?;
    if canaries["schemaVersion"] != 1
        || canaries["operation"] != task.operation
        || canaries["platform"] != Task::platform_id()?
    {
        return Err(
            "prerequisite canary is not bound to the current operation/platform".to_owned(),
        );
    }
    let canary = canaries["canaries"]
        .as_array()
        .filter(|entries| entries.len() == 1)
        .and_then(|entries| entries.first())
        .ok_or("prerequisite canary inventory is not exact")?;
    if canary["id"] != "provider-adoption" {
        return Err("required provider adoption canary is missing".to_owned());
    }
    let raw = read_regular(&task.output.join("raw/provider-adoption-canary.json"))?;
    let normalized = read_regular(&task.output.join("normalized/provider-adoption-canary.json"))?;
    if canary["reportSha256"] != hell_testkit::sha256_bytes(&raw).hex()
        || canary["projectionSha256"] != hell_testkit::sha256_bytes(&normalized).hex()
    {
        return Err("prerequisite canary report digest differs".to_owned());
    }
    let target_argv = [
        NativeArgument::from_os_str(target.as_os_str()),
        NativeArgument::from_os_str(std::ffi::OsStr::new("--version")),
    ];
    let projection =
        hell_memcordon::project_schema8_report(&raw, &acquisition.mechanism, &target_argv)
            .map_err(|error| error.to_string())?;
    let retained: hell_memcordon::Schema8ProjectionV1 = serde_json::from_slice(&normalized)
        .map_err(|error| format!("invalid prerequisite projection: {error}"))?;
    if projection != retained
        || projection.wrapper_status != 0
        || projection.target_status != Some(0)
    {
        return Err("prerequisite canary does not prove successful sealed execution".to_owned());
    }
    std::fs::canonicalize(&task.output)
        .map_err(|error| format!("cannot bind prerequisite evidence root: {error}"))
}
