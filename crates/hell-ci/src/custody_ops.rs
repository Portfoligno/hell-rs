use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use crate::strict_toml;
use hell_testkit::{Digest, sha256_bytes, sha256_file};

fn component_path<const N: usize>(components: [&str; N]) -> PathBuf {
    components.iter().collect()
}

#[derive(Default)]
struct Options {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    provider: Option<String>,
    trust_domain: Option<String>,
    bucket: Option<String>,
    candidate: Option<String>,
    epoch: Option<String>,
    epoch_file: Option<PathBuf>,
    retention_until: Option<String>,
    policy: Option<PathBuf>,
    role: Option<String>,
    reviewer: Option<String>,
    issued_at: Option<String>,
    first: Option<PathBuf>,
    second: Option<PathBuf>,
    first_receipt: Option<PathBuf>,
    second_receipt: Option<PathBuf>,
    review: Option<PathBuf>,
    expected: Option<String>,
    run_id: Option<String>,
    run_attempt: Option<String>,
    artifact_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManifestEntry {
    path: String,
    digest: Digest,
    size: u64,
}

struct CustodyPolicy {
    minimum_years: i64,
    scrub_interval_days: u64,
}

fn load_custody_policy(path: &Path) -> Result<CustodyPolicy, String> {
    let document = fs::read_to_string(path)
        .map_err(|error| format!("cannot read custody policy {}: {error}", path.display()))?;
    let mut values = strict_toml::assignments(&document)?;
    if strict_toml::unsigned(&strict_toml::take(&mut values, "schema_version")?)? != 1 {
        return Err("custody policy schema_version must be 1".to_owned());
    }
    let state = strict_toml::string(&strict_toml::take(&mut values, "state")?)?;
    if !matches!(state.as_str(), "review-required" | "reviewed") {
        return Err("custody policy state is unsupported".to_owned());
    }
    if strict_toml::string(&strict_toml::take(&mut values, "package_format")?)?
        != "merkle-directory-v1"
    {
        return Err("custody package format is unsupported".to_owned());
    }
    let minimum_years = strict_toml::unsigned(&strict_toml::take(&mut values, "minimum_years")?)?;
    let minimum_copies = strict_toml::unsigned(&strict_toml::take(&mut values, "minimum_copies")?)?;
    let scrub_interval =
        strict_toml::unsigned(&strict_toml::take(&mut values, "scrub_interval_days")?)?;
    if minimum_years == 0 || minimum_copies < 2 || scrub_interval == 0 {
        return Err("custody policy retention, copy, and scrub requirements are unsafe".to_owned());
    }
    for key in [
        "require_object_lock",
        "require_version_id",
        "require_encryption_at_rest",
        "require_independent_retrieval",
    ] {
        if !strict_toml::boolean(&strict_toml::take(&mut values, key)?)? {
            return Err(format!("custody policy must enable {key}"));
        }
    }
    strict_toml::finish(&values)?;
    Ok(CustodyPolicy {
        minimum_years: i64::try_from(minimum_years)
            .map_err(|_| "custody minimum_years is out of range".to_owned())?,
        scrub_interval_days: scrub_interval,
    })
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .is_some_and(|value| value == "custody-ops")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    if let Some(action) = arguments.get(1).and_then(|value| value.to_str())
        && action.starts_with("workflow-")
    {
        return run_workflow_action(action);
    }
    let (action, options) = parse(arguments)?;
    match action.as_str() {
        "package" => package(&options),
        "upload" => upload(&options),
        "retrieve" => retrieve(&options, "retrieval"),
        "scrub" => retrieve(&options, "scrub"),
        "recover" => retrieve(&options, "recovery"),
        "verify-package" => verify_package(required_path(options.input.as_ref(), "--input")?),
        "materialize" => materialize_package(
            required_path(options.input.as_ref(), "--input")?,
            required_path(options.output.as_ref(), "--output")?,
        ),
        "packet" => packet(&options),
        "copy-record" => copy_record(&options),
        "review-core" => review_core(&options),
        "gate-record" => gate_record(&options),
        "verify-source" => verify_source(&options),
        action => Err(format!("unknown custody-ops action {action:?}")),
    }
}

const CUSTODY_DISPATCH_KEYS: &[&str] = &[
    "acquisition_time",
    "artifact_class",
    "candidate_sha",
    "expected_artifact_set_sha256",
    "provider_artifact_id",
    "retention_until",
    "review_issued_at",
    "source_run_attempt",
    "source_run_id",
];

struct WorkflowProvider {
    provider: String,
    trust_domain: String,
    bucket: String,
    active_candidate: String,
    active_epoch: String,
    active_manifest: String,
    active_receipt_key: String,
    active_receipt_version: String,
    active_receipt_sha256: String,
    active_activation_record_key: String,
    active_activation_record_version: String,
    active_activation_record_sha256: String,
    active_activation_packet_key: String,
    active_activation_packet_version: String,
    active_activation_packet_sha256: String,
    active_activation_dsse_key: String,
    active_activation_dsse_version: String,
    active_activation_dsse_sha256: String,
    activation_public_state: String,
    activation_public_completion_sha256: String,
    current_transition: Option<WorkflowTransitionContext>,
}

struct WorkflowTransitionContext {
    record_key: String,
    record_version: String,
    record_sha256: String,
    packet_key: String,
    packet_version: String,
    packet_sha256: String,
    dsse_key: String,
    dsse_version: String,
    dsse_sha256: String,
}

fn workflow_provider(require_active_receipt: bool) -> Result<WorkflowProvider, String> {
    let context = aws(&[
        "ssm",
        "get-parameter",
        "--name",
        "/hell-rs/custody/provider-context",
        "--with-decryption",
        "--query",
        "Parameter.Value",
        "--output",
        "text",
    ])?;
    let document = String::from_utf8(context.stdout)
        .map_err(|_| "protected custody provider context is not UTF-8".to_owned())?;
    let mut values = strict_toml::assignments(&document)?;
    if strict_toml::unsigned(&strict_toml::take(&mut values, "schema_version")?)? != 1 {
        return Err("custody provider context schema_version must be 1".to_owned());
    }
    let mut provider = take_workflow_provider(&mut values)?;
    provider.current_transition = take_transition_context(&mut values)?;
    strict_toml::finish(&values)?;
    validate_workflow_provider(&provider, require_active_receipt)?;
    Ok(provider)
}

fn take_workflow_provider(
    values: &mut std::collections::BTreeMap<String, String>,
) -> Result<WorkflowProvider, String> {
    let required = |values: &mut std::collections::BTreeMap<String, String>, key: &str| {
        strict_toml::string(&strict_toml::take(values, key)?)
    };
    Ok(WorkflowProvider {
        provider: required(values, "provider")?,
        trust_domain: required(values, "trust_domain")?,
        bucket: required(values, "bucket")?,
        active_candidate: optional_context_string(values, "active_candidate")?,
        active_epoch: optional_context_string(values, "active_epoch")?,
        active_manifest: optional_context_string(values, "active_manifest")?,
        active_receipt_key: required(values, "active_receipt_key")?,
        active_receipt_version: required(values, "active_receipt_version")?,
        active_receipt_sha256: required(values, "active_receipt_sha256")?,
        active_activation_record_key: optional_context_string(
            values,
            "active_activation_record_key",
        )?,
        active_activation_record_version: optional_context_string(
            values,
            "active_activation_record_version",
        )?,
        active_activation_record_sha256: optional_context_string(
            values,
            "active_activation_record_sha256",
        )?,
        active_activation_packet_key: optional_context_string(
            values,
            "active_activation_packet_key",
        )?,
        active_activation_packet_version: optional_context_string(
            values,
            "active_activation_packet_version",
        )?,
        active_activation_packet_sha256: optional_context_string(
            values,
            "active_activation_packet_sha256",
        )?,
        active_activation_dsse_key: optional_context_string(values, "active_activation_dsse_key")?,
        active_activation_dsse_version: optional_context_string(
            values,
            "active_activation_dsse_version",
        )?,
        active_activation_dsse_sha256: optional_context_string(
            values,
            "active_activation_dsse_sha256",
        )?,
        activation_public_state: optional_context_string(values, "activation_public_state")?,
        activation_public_completion_sha256: optional_context_string(
            values,
            "activation_public_completion_sha256",
        )?,
        current_transition: None,
    })
}

fn take_transition_context(
    values: &mut std::collections::BTreeMap<String, String>,
) -> Result<Option<WorkflowTransitionContext>, String> {
    let transition_values = [
        optional_context_string(values, "current_transition_record_key")?,
        optional_context_string(values, "current_transition_record_version")?,
        optional_context_string(values, "current_transition_record_sha256")?,
        optional_context_string(values, "current_transition_packet_key")?,
        optional_context_string(values, "current_transition_packet_version")?,
        optional_context_string(values, "current_transition_packet_sha256")?,
        optional_context_string(values, "current_transition_dsse_key")?,
        optional_context_string(values, "current_transition_dsse_version")?,
        optional_context_string(values, "current_transition_dsse_sha256")?,
    ];
    validate_transition_context(&transition_values)?;
    if transition_values.iter().all(String::is_empty) {
        return Ok(None);
    }
    let [
        record_key,
        record_version,
        record_sha256,
        packet_key,
        packet_version,
        packet_sha256,
        dsse_key,
        dsse_version,
        dsse_sha256,
    ] = transition_values;
    Ok(Some(WorkflowTransitionContext {
        record_key,
        record_version,
        record_sha256,
        packet_key,
        packet_version,
        packet_sha256,
        dsse_key,
        dsse_version,
        dsse_sha256,
    }))
}

fn validate_workflow_provider(
    provider: &WorkflowProvider,
    require_active_receipt: bool,
) -> Result<(), String> {
    for (label, value) in [
        ("provider", provider.provider.as_str()),
        ("trust domain", provider.trust_domain.as_str()),
        ("bucket", provider.bucket.as_str()),
    ] {
        require_atom(value, label)?;
    }
    if require_active_receipt {
        crate::promotion_policy::require_git_sha(
            &provider.active_candidate,
            "active custody candidate",
        )?;
        require_digest(&provider.active_epoch, "active custody epoch")?;
        require_digest(&provider.active_manifest, "active custody manifest")?;
        require_atom(&provider.active_receipt_key, "active receipt key")?;
        require_atom(&provider.active_receipt_version, "active receipt version")?;
        require_digest(&provider.active_receipt_sha256, "active receipt digest")?;
        for (label, value) in [
            (
                "activation record key",
                provider.active_activation_record_key.as_str(),
            ),
            (
                "activation record version",
                provider.active_activation_record_version.as_str(),
            ),
            (
                "activation packet key",
                provider.active_activation_packet_key.as_str(),
            ),
            (
                "activation packet version",
                provider.active_activation_packet_version.as_str(),
            ),
            (
                "activation DSSE key",
                provider.active_activation_dsse_key.as_str(),
            ),
            (
                "activation DSSE version",
                provider.active_activation_dsse_version.as_str(),
            ),
        ] {
            require_atom(value, label)?;
        }
        for (label, value) in [
            (
                "activation record digest",
                provider.active_activation_record_sha256.as_str(),
            ),
            (
                "activation packet digest",
                provider.active_activation_packet_sha256.as_str(),
            ),
            (
                "activation DSSE digest",
                provider.active_activation_dsse_sha256.as_str(),
            ),
        ] {
            require_digest(value, label)?;
        }
        match provider.activation_public_state.as_str() {
            "pending-publication" if provider.activation_public_completion_sha256.is_empty() => {}
            "completed-publication" => require_digest(
                &provider.activation_public_completion_sha256,
                "activation public completion digest",
            )?,
            _ => {
                return Err(
                    "active custody context has an invalid public activation state".to_owned(),
                );
            }
        }
    }
    Ok(())
}

fn validate_transition_context(transition_values: &[String; 9]) -> Result<(), String> {
    if transition_values.iter().any(|value| !value.is_empty()) {
        for (index, value) in transition_values.iter().enumerate() {
            if index % 3 == 2 {
                require_digest(value, "current transition digest")?;
            } else {
                require_atom(value, "current transition locator")?;
            }
        }
    }
    Ok(())
}

fn optional_context_string(
    values: &mut std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<String, String> {
    values
        .remove(key)
        .map_or_else(|| Ok(String::new()), |value| strict_toml::string(&value))
}

fn run_workflow_action(action: &str) -> Result<String, String> {
    let dispatch = || crate::assurance::github_dispatch_object(CUSTODY_DISPATCH_KEYS);
    let mut options = Options::default();
    match action {
        "workflow-verify-source" => {
            let inputs = dispatch()?;
            options.input = Some(component_path(["ci-out", "source", "evidence"]));
            options.output = Some(component_path([
                "ci-out",
                "source",
                "source-selection.json",
            ]));
            options.candidate = inputs.get("candidate_sha").cloned();
            options.run_id = inputs.get("source_run_id").cloned();
            options.run_attempt = inputs.get("source_run_attempt").cloned();
            options.artifact_id = inputs.get("provider_artifact_id").cloned();
            options.expected = inputs.get("expected_artifact_set_sha256").cloned();
            verify_source(&options)
        }
        "workflow-package" => {
            let inputs = dispatch()?;
            options.input = Some(component_path(["ci-out", "source"]));
            options.output = Some(component_path(["ci-out", "custody-package"]));
            options.candidate = inputs.get("candidate_sha").cloned();
            options.epoch_file = Some(component_path(["ci-out", "assurance-epoch.json"]));
            package(&options)
        }
        "workflow-upload" => {
            let inputs = dispatch()?;
            apply_workflow_provider(&mut options, workflow_provider(false)?);
            options.input = Some(component_path(["ci-out", "custody-package"]));
            options.output = Some(component_path(["ci-out", "upload-receipt.json"]));
            options.retention_until = inputs.get("retention_until").cloned();
            options.policy = Some(component_path(["compat", "custody-policy.toml"]));
            upload(&options)
        }
        "workflow-upload-packet" | "workflow-provider-packet" => workflow_packet(action),
        "workflow-activate" => workflow_activate(),
        "workflow-activation-packet" => workflow_activation_packet(),
        "workflow-commit-activation" => workflow_commit_activation(),
        "workflow-publish-transition" => workflow_publish_transition(),
        "workflow-verify-public-source-artifact" => workflow_verify_public_source_artifact(),
        "workflow-publish-public-transition" => workflow_publish_public_transition(),
        "workflow-observe-public-transition" => workflow_observe_public_transition(),
        "workflow-retain-prior-public-transition" => workflow_retain_prior_public_transition(),
        "workflow-dispatch-initial-surveillance" => workflow_dispatch_initial_surveillance(),
        "workflow-finalize-initial-surveillance" => workflow_finalize_initial_surveillance(),
        "workflow-complete-initial-activation" => workflow_complete_initial_activation(),
        "workflow-record-initial-surveillance-failure" => {
            workflow_record_initial_surveillance_failure()
        }
        "workflow-require-initial-surveillance-success" => Err(
            "initial public surveillance did not complete successfully; activation remains pending"
                .to_owned(),
        ),
        "workflow-retrieve" => workflow_retrieve(),
        "workflow-copy-record" => workflow_copy_record(),
        "workflow-review-packet" => workflow_review_packet(),
        "workflow-transition-packet" => workflow_transition_packet(),
        "workflow-surveillance-retrieve" => workflow_surveillance_retrieve(),
        "workflow-surveillance-retrieval-packet-primary"
        | "workflow-surveillance-retrieval-packet-secondary" => {
            workflow_surveillance_retrieval_packet(action)
        }
        "workflow-materialize-active" => materialize_package(
            &component_path(["ci-out", "custody-maintenance", "package"]),
            &component_path(["ci-out", "active-promotion-record"]),
        ),
        "workflow-materialize-review-package" => workflow_materialize_review_package(),
        "workflow-retain-review-subject" => workflow_retain_review_subject(),
        "workflow-initial-scrub" => workflow_initial_scrub(),
        "workflow-initial-scrub-packet" => workflow_initial_scrub_packet(),
        "workflow-stage-current-scrub" => workflow_stage_current_scrub(),
        "workflow-scrub" | "workflow-recover" | "workflow-maintenance-packet" => {
            workflow_maintenance(action)
        }
        _ => Err("unknown custody workflow action".to_owned()),
    }
}

fn workflow_retain_review_subject() -> Result<String, String> {
    copy_retained_tree(
        &component_path(["ci-out", "custody-subject"]),
        &component_path(["ci-out", "custody", "retained"]),
    )?;
    Ok("retained exact custody review subject beside the final gate record".to_owned())
}

fn workflow_initial_scrub() -> Result<String, String> {
    let upload_path = component_path([
        "ci-out",
        "custody",
        "current",
        "upload",
        "upload-receipt.json",
    ]);
    let upload_document = fs::read_to_string(&upload_path)
        .map_err(|error| format!("cannot read initial scrub upload receipt: {error}"))?;
    let upload = parse_upload_receipt(&upload_document)?;
    let retrieved = component_path(["ci-out", "custody", "current", "retrieved", "package"]);
    verify_package(&retrieved)?;
    let retrieval = validated_retrieval(&retrieved, &upload_document, &upload)?;
    let retrieval_document = fs::read_to_string(
        component_path(["ci-out", "custody", "current", "retrieved"])
            .join("retrieval-receipt.json"),
    )
    .map_err(|error| format!("cannot read initial retrieval receipt: {error}"))?;
    let receipt = initial_maintenance_receipt(
        &upload,
        retrieval,
        &quoted_field(&retrieval_document, "retrievedAt")?,
        sha256_bytes(upload_document.as_bytes()),
    )?;
    let output = component_path(["ci-out", "custody-maintenance"]);
    fs::create_dir(&output)
        .map_err(|error| format!("cannot create initial scrub receipt directory: {error}"))?;
    write_atomic(
        &output.join("scrub-receipt.json"),
        canonical_maintenance_receipt(&receipt).as_bytes(),
    )?;
    Ok("derived candidate-scoped current scrub from initial independent retrieval".to_owned())
}

fn initial_maintenance_receipt(
    upload: &UploadReceipt,
    retrieval: ValidatedRetrieval,
    retrieved_at: &str,
    upload_receipt_sha256: Digest,
) -> Result<MaintenanceReceipt, String> {
    parse_utc_timestamp(retrieved_at)?;
    Ok(MaintenanceReceipt {
        provider: upload.provider.clone(),
        trust_domain: upload.trust_domain.clone(),
        account: upload.account_or_tenant.clone(),
        uploaded_by: upload.uploaded_by.clone(),
        retrieved_by: retrieval.retrieved_by,
        retriever_stable_id: retrieval.retriever_stable_id,
        candidate: upload.candidate.clone(),
        epoch: upload.epoch.clone(),
        root_sha256: upload.root_sha256.clone(),
        manifest_sha256: upload.manifest_sha256.clone(),
        upload_receipt_sha256: upload_receipt_sha256.hex(),
        retention_until: upload.retention_until.clone(),
        retrieved_path: provider_retrieval_path(&upload.provider)?,
        retrieved_at: retrieved_at.to_owned(),
    })
}

fn workflow_initial_scrub_packet() -> Result<String, String> {
    let receipt = component_path(["ci-out", "custody-maintenance", "scrub-receipt.json"]);
    let document = fs::read_to_string(&receipt)
        .map_err(|error| format!("cannot read initial scrub receipt: {error}"))?;
    let retrieved_by = quoted_field(&document, "retrievedBy")?;
    packet(&Options {
        input: Some(receipt),
        output: Some(component_path([
            "ci-out",
            "custody-maintenance-packet.json",
        ])),
        role: Some("custody-provider".to_owned()),
        reviewer: Some(format!("custody-provider:{retrieved_by}")),
        ..Options::default()
    })
}

fn workflow_stage_current_scrub() -> Result<String, String> {
    let source = component_path(["ci-out", "custody-maintenance"]);
    let receipt = source.join("scrub-receipt.json");
    let signature = component_path(["ci-out", "custody-maintenance-receipt.dsse.json"]);
    if !receipt.is_file() || !signature.is_file() {
        return Err("current scrub staging requires the raw and signed scrub receipts".to_owned());
    }
    let destination = component_path(["ci-out", "current-scrub-package"]);
    fs::create_dir(&destination)
        .map_err(|error| format!("cannot create current scrub package: {error}"))?;
    for (input, name) in [
        (&receipt, "scrub-receipt.json"),
        (&signature, "custody-maintenance-receipt.dsse.json"),
    ] {
        fs::copy(input, destination.join(name))
            .map_err(|error| format!("cannot stage current scrub receipt: {error}"))?;
    }
    Ok("staged canonical current scrub package".to_owned())
}

fn workflow_retrieve() -> Result<String, String> {
    let mut options = Options::default();
    apply_workflow_provider(&mut options, workflow_provider(false)?);
    options.input = Some(component_path([
        "ci-out",
        "custody",
        "current",
        "upload",
        "upload-receipt.json",
    ]));
    options.output = Some(component_path([
        "ci-out",
        "custody",
        "current",
        "retrieved",
    ]));
    options.policy = Some(component_path(["compat", "custody-policy.toml"]));
    retrieve(&options, "retrieval")
}

fn workflow_copy_record() -> Result<String, String> {
    let options = Options {
        input: Some(component_path([
            "ci-out",
            "custody",
            "current",
            "retrieved",
            "package",
        ])),
        first: Some(component_path([
            "ci-out",
            "custody",
            "current",
            "upload",
            "upload-receipt.json",
        ])),
        output: Some(component_path([
            "ci-out",
            "custody",
            "current",
            "copy-record.json",
        ])),
        policy: Some(component_path(["compat", "custody-policy.toml"])),
        ..Options::default()
    };
    copy_record(&options)
}

fn workflow_transition_packet() -> Result<String, String> {
    packet(&Options {
        input: Some(component_path([
            "ci-out",
            "surveillance",
            "promotion-transition.json",
        ])),
        output: Some(component_path([
            "ci-out",
            "surveillance",
            "promotion-transition-packet.json",
        ])),
        role: Some("custody-reviewer".to_owned()),
        reviewer: Some("custody-reviewer:promotion-surveillance".to_owned()),
        ..Options::default()
    })
}

fn workflow_surveillance_retrieval_packet(action: &str) -> Result<String, String> {
    packet(&Options {
        input: Some(component_path([
            "ci-out",
            "custody-maintenance",
            "provider-observation.json",
        ])),
        output: Some(component_path([
            "ci-out",
            "custody-maintenance",
            "provider-observation-packet.json",
        ])),
        role: Some("custody-provider".to_owned()),
        reviewer: Some(if action.ends_with("-primary") {
            "custody-provider:promotion-surveillance-primary".to_owned()
        } else {
            "custody-provider:promotion-surveillance-secondary".to_owned()
        }),
        ..Options::default()
    })
}

fn workflow_materialize_review_package() -> Result<String, String> {
    let inputs = crate::assurance::github_dispatch_object(CUSTODY_DISPATCH_KEYS)?;
    if inputs.get("artifact_class").map(String::as_str) != Some("pre-review-evidence") {
        return Err("only pre-review evidence may enter final role-graph review".to_owned());
    }
    let output = Path::new("ci-out");
    materialize_package_into_existing(
        &component_path(["ci-out", "custody", "transport", "custody-package"]),
        output,
    )?;
    copy_retained_tree(
        &component_path(["ci-out", "custody"]),
        &output.join("evidence").join("custody"),
    )?;
    Ok("materialized post-custody evidence for final role-graph review".to_owned())
}

fn copy_retained_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink() {
        return Err("retained custody evidence cannot contain symlinks".to_owned());
    }
    if metadata.is_file() {
        if destination.exists() {
            return Err(format!(
                "retained custody destination already exists: {}",
                destination.display()
            ));
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        fs::copy(source, destination).map_err(|error| {
            format!(
                "cannot copy retained custody file {}: {error}",
                source.display()
            )
        })?;
        if sha256_file(source).map_err(|error| error.to_string())?
            != sha256_file(destination).map_err(|error| error.to_string())?
        {
            return Err("copied custody evidence digest changed".to_owned());
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err("retained custody evidence is not a regular file or directory".to_owned());
    }
    if destination.exists() {
        return Err(format!(
            "retained custody destination already exists: {}",
            destination.display()
        ));
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("cannot create {}: {error}", destination.display()))?;
    let mut entries = fs::read_dir(source)
        .map_err(|error| format!("cannot read {}: {error}", source.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate {}: {error}", source.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        copy_retained_tree(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

fn workflow_activate() -> Result<String, String> {
    let inputs = crate::assurance::github_dispatch_object(CUSTODY_DISPATCH_KEYS)?;
    if inputs.get("artifact_class").map(String::as_str) != Some("final-promotion-record") {
        return Err("only a final promotion record may become active custody evidence".to_owned());
    }
    let provider = workflow_provider(false)?;
    let provider_root = component_path(["ci-out", "custody"])
        .join(&provider.provider)
        .join("upload");
    let raw_path = provider_root.join("upload-receipt.json");
    let pointer_path = provider_root.join("upload-receipt-provider-pointer.json");
    let gate_path = component_path(["ci-out", "custody", "custody-receipt.json"]);
    let raw = fs::read_to_string(&raw_path)
        .map_err(|error| format!("cannot read {}: {error}", raw_path.display()))?;
    let receipt = parse_upload_receipt(&raw)?;
    if receipt.provider != provider.provider
        || receipt.trust_domain != provider.trust_domain
        || receipt.bucket != provider.bucket
    {
        return Err("final custody receipt does not match activation provider".to_owned());
    }
    let (key, version, digest, retention) = parse_provider_pointer(&pointer_path)?;
    let raw_digest = sha256_bytes(raw.as_bytes()).hex();
    if key != raw_digest || digest != raw_digest || retention != receipt.retention_until {
        return Err("provider pointer does not select the final upload receipt".to_owned());
    }
    let gate = fs::read_to_string(&gate_path)
        .map_err(|error| format!("cannot read {}: {error}", gate_path.display()))?;
    for value in [
        receipt.candidate.as_str(),
        receipt.epoch.as_str(),
        receipt.provider.as_str(),
        digest.as_str(),
    ] {
        if !gate.contains(&format!("\"{value}\"")) {
            return Err("verified custody gate does not bind activation receipt".to_owned());
        }
    }
    let activated_at = current_utc_timestamp()?;
    let gate_sha256 = sha256_file(&gate_path)
        .map_err(|error| error.to_string())?
        .hex();
    let activation_run_id = required_positive_environment("GITHUB_RUN_ID")?;
    let activation_run_attempt = required_positive_environment("GITHUB_RUN_ATTEMPT")?;
    let activation_repository_id = required_positive_environment("GITHUB_REPOSITORY_ID")?;
    let activation_workflow_ref = std::env::var("GITHUB_WORKFLOW_REF")
        .map_err(|_| "activation lacks GITHUB_WORKFLOW_REF".to_owned())?;
    let mut activation = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"activationRunId\": {activation_run_id},\n  \"activationRunAttempt\": {activation_run_attempt},\n  \"activationRepositoryId\": {activation_repository_id}"
    );
    for (field, value) in [
        ("activationWorkflowRef", activation_workflow_ref.as_str()),
        ("candidateCommit", receipt.candidate.as_str()),
        ("assuranceEpochSha256", receipt.epoch.as_str()),
        ("manifestSha256", receipt.manifest_sha256.as_str()),
        ("provider", receipt.provider.as_str()),
        ("trustDomain", receipt.trust_domain.as_str()),
        ("receiptKey", key.as_str()),
        ("receiptVersion", version.as_str()),
        ("receiptSha256", digest.as_str()),
        ("custodyGateSha256", gate_sha256.as_str()),
        ("activatedAt", activated_at.as_str()),
    ] {
        activation.push_str(",\n  \"");
        activation.push_str(field);
        activation.push_str("\": ");
        push_json(&mut activation, value);
    }
    activation.push_str("\n}\n");
    let output = component_path(["ci-out", "custody-activation"])
        .join(&provider.provider)
        .join("activation-receipt.json");
    write_atomic(&output, activation.as_bytes())?;
    Ok(format!(
        "activated exact final custody receipt for provider {}",
        provider.provider
    ))
}

fn workflow_activation_packet() -> Result<String, String> {
    let provider = workflow_provider(false)?;
    let directory = component_path(["ci-out", "custody-activation"]).join(&provider.provider);
    packet(&Options {
        input: Some(directory.join("activation-receipt.json")),
        output: Some(directory.join("activation-packet.json")),
        role: Some("custody-provider".to_owned()),
        reviewer: Some(format!("custody-provider:{}-activation", provider.provider)),
        ..Options::default()
    })
}

fn workflow_commit_activation() -> Result<String, String> {
    let provider = workflow_provider(false)?;
    let directory = component_path(["ci-out", "custody-activation"]).join(&provider.provider);
    let record = directory.join("activation-receipt.json");
    let packet_path = directory.join("activation-packet.json");
    let dsse = directory.join("activation-receipt.dsse.json");
    for path in [&record, &packet_path, &dsse] {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "activation evidence {} is not regular",
                path.display()
            ));
        }
    }
    let status = Command::new(
        std::env::current_exe().map_err(|error| format!("cannot locate hell-ci: {error}"))?,
    )
    .args([
        OsStr::new("review-verify"),
        OsStr::new("--input"),
        dsse.as_os_str(),
        OsStr::new("--policy"),
        OsStr::new("compat/reviews.allowed_signers"),
        OsStr::new("--role"),
        OsStr::new("custody-provider"),
    ])
    .status()
    .map_err(|error| format!("cannot verify activation DSSE: {error}"))?;
    if !status.success() {
        return Err("activation DSSE verification failed".to_owned());
    }
    let record_text = fs::read_to_string(&record)
        .map_err(|error| format!("cannot read activation record: {error}"))?;
    let active_candidate = quoted_field(&record_text, "candidateCommit")?;
    let active_epoch = quoted_field(&record_text, "assuranceEpochSha256")?;
    let record_digest = sha256_file(&record)
        .map_err(|error| error.to_string())?
        .hex();
    if quoted_field(&record_text, "provider")? != provider.provider {
        return Err("signed activation packet does not bind provider activation record".to_owned());
    }
    crate::assurance::verify_review_packet_first_artifact(
        &packet_path,
        "custody-provider",
        &active_candidate,
        &active_epoch,
        &record_digest,
    )?;
    let upload_root = component_path(["ci-out", "custody"])
        .join(&provider.provider)
        .join("upload");
    let upload_document = fs::read_to_string(upload_root.join("upload-receipt.json"))
        .map_err(|error| format!("cannot read final upload receipt: {error}"))?;
    let upload = parse_upload_receipt(&upload_document)?;
    let (record_key, record_version, record_sha) =
        retain_activation_object(&provider.bucket, &record, &upload.retention_until)?;
    let (packet_key, packet_version, packet_sha) =
        retain_activation_object(&provider.bucket, &packet_path, &upload.retention_until)?;
    let (dsse_key, dsse_version, dsse_sha) =
        retain_activation_object(&provider.bucket, &dsse, &upload.retention_until)?;
    let (receipt_key, receipt_version, receipt_sha, _) =
        parse_provider_pointer(&upload_root.join("upload-receipt-provider-pointer.json"))?;
    let context = format!(
        "schema_version = 1\nprovider = {:?}\ntrust_domain = {:?}\nbucket = {:?}\nactive_candidate = {:?}\nactive_epoch = {:?}\nactive_manifest = {:?}\nactive_receipt_key = {:?}\nactive_receipt_version = {:?}\nactive_receipt_sha256 = {:?}\nactive_activation_record_key = {:?}\nactive_activation_record_version = {:?}\nactive_activation_record_sha256 = {:?}\nactive_activation_packet_key = {:?}\nactive_activation_packet_version = {:?}\nactive_activation_packet_sha256 = {:?}\nactive_activation_dsse_key = {:?}\nactive_activation_dsse_version = {:?}\nactive_activation_dsse_sha256 = {:?}\nactivation_public_state = \"pending-publication\"\nactivation_public_completion_sha256 = \"\"\n",
        provider.provider,
        provider.trust_domain,
        provider.bucket,
        active_candidate,
        active_epoch,
        upload.manifest_sha256,
        receipt_key,
        receipt_version,
        receipt_sha,
        record_key,
        record_version,
        record_sha,
        packet_key,
        packet_version,
        packet_sha,
        dsse_key,
        dsse_version,
        dsse_sha,
    );
    aws(&[
        "ssm",
        "put-parameter",
        "--name",
        "/hell-rs/custody/provider-context",
        "--type",
        "SecureString",
        "--value",
        &context,
        "--overwrite",
    ])?;
    Ok(format!(
        "committed signed final activation for provider {}",
        provider.provider
    ))
}

fn retain_activation_object(
    bucket: &str,
    path: &Path,
    retention_until: &str,
) -> Result<(String, String, String), String> {
    let digest = sha256_file(path).map_err(|error| error.to_string())?;
    let key = digest.hex();
    let metadata = put_immutable_object(bucket, &key, path, digest, retention_until)?;
    Ok((key, metadata.version, digest.hex()))
}

fn workflow_dispatch_initial_surveillance() -> Result<String, String> {
    let run_id = required_positive_environment("GITHUB_RUN_ID")?;
    let run_attempt = required_positive_environment("GITHUB_RUN_ATTEMPT")?;
    let primary = component_path([
        "ci-out",
        "custody-activation",
        "primary-worm",
        "activation-receipt.json",
    ]);
    let secondary = component_path([
        "ci-out",
        "custody-activation",
        "secondary-worm",
        "activation-receipt.json",
    ]);
    let primary_text = verify_dispatch_activation(&primary, "primary-worm")?;
    let secondary_text = verify_dispatch_activation(&secondary, "secondary-worm")?;
    let candidate = quoted_field(&primary_text, "candidateCommit")?;
    let epoch = quoted_field(&primary_text, "assuranceEpochSha256")?;
    if quoted_field(&secondary_text, "candidateCommit")? != candidate
        || quoted_field(&secondary_text, "assuranceEpochSha256")? != epoch
        || quoted_field(&primary_text, "custodyGateSha256")?
            != quoted_field(&secondary_text, "custodyGateSha256")?
    {
        return Err("dual activation receipts disagree on initial surveillance subject".to_owned());
    }
    verify_activation_run_binding(&primary_text, &secondary_text, run_id, run_attempt)?;
    let inputs = crate::assurance::github_dispatch_object(CUSTODY_DISPATCH_KEYS)?;
    if inputs.get("artifact_class").map(String::as_str) != Some("final-promotion-record")
        || inputs.get("candidate_sha").map(String::as_str) != Some(candidate.as_str())
    {
        return Err("initial surveillance dispatch differs from custody dispatch".to_owned());
    }
    let correlation = initial_activation_correlation(
        &candidate,
        &epoch,
        run_id,
        run_attempt,
        &public_report_file_digest(&primary)?,
        &public_report_file_digest(&secondary)?,
    );
    let body =
        initial_surveillance_dispatch_body(&candidate, &epoch, run_id, run_attempt, &correlation);
    let endpoint = component_path([
        "repos",
        "Portfoligno",
        "hell-rs",
        "actions",
        "workflows",
        "promotion-surveillance.yml",
        "dispatches",
    ]);
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| "initial surveillance dispatch lacks GITHUB_TOKEN".to_owned())?;
    let mut child = Command::new("gh")
        .args([
            OsStr::new("api"),
            OsStr::new("--method"),
            OsStr::new("POST"),
            endpoint.as_os_str(),
            OsStr::new("--input"),
            OsStr::new("-"),
        ])
        .env("GH_TOKEN", &token)
        .env_remove("GITHUB_TOKEN")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start initial surveillance dispatch: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "initial surveillance dispatch lacks stdin".to_owned())?
        .write_all(body.as_bytes())
        .map_err(|error| format!("cannot write initial surveillance dispatch: {error}"))?;
    let response = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for initial surveillance dispatch: {error}"))?;
    if !response.status.success() || !response.stdout.is_empty() {
        return Err("initial surveillance dispatch failed or returned a body".to_owned());
    }
    let receipt = format!(
        "{{\n  \"schemaVersion\": 2,\n  \"candidateCommit\": \"{candidate}\",\n  \"assuranceEpochSha256\": \"{epoch}\",\n  \"activationRunId\": {run_id},\n  \"activationRunAttempt\": {run_attempt},\n  \"activationCorrelationSha256\": \"{correlation}\",\n  \"primaryActivationSha256\": \"{}\",\n  \"secondaryActivationSha256\": \"{}\",\n  \"requestSha256\": \"{}\",\n  \"workflowPath\": \".github/workflows/promotion-surveillance.yml\",\n  \"ref\": \"main\",\n  \"state\": \"dispatch-accepted-pending-publication\"\n}}\n",
        public_report_file_digest(&primary)?,
        public_report_file_digest(&secondary)?,
        sha256_bytes(body.as_bytes()).hex(),
    );
    write_atomic(
        &component_path(["ci-out", "initial-surveillance-dispatch.json"]),
        receipt.as_bytes(),
    )?;
    Ok("dispatched pending initial public surveillance for exact dual activation".to_owned())
}

fn verify_dispatch_activation(path: &Path, provider: &str) -> Result<String, String> {
    let directory = path
        .parent()
        .ok_or_else(|| "activation receipt has no directory".to_owned())?;
    let packet = directory.join("activation-packet.json");
    let dsse = directory.join("activation-receipt.dsse.json");
    verify_public_transition_signature_for_role(&dsse, "custody-provider")?;
    let document = fs::read_to_string(path)
        .map_err(|error| format!("cannot read dispatch activation receipt: {error}"))?;
    if quoted_field(&document, "provider")? != provider {
        return Err("activation receipt provider differs from dispatch channel".to_owned());
    }
    crate::assurance::verify_review_packet_first_artifact(
        &packet,
        "custody-provider",
        &quoted_field(&document, "candidateCommit")?,
        &quoted_field(&document, "assuranceEpochSha256")?,
        &public_report_file_digest(path)?,
    )?;
    Ok(document)
}

pub(crate) fn verify_activation_run_binding(
    primary: &str,
    secondary: &str,
    run_id: u64,
    run_attempt: u64,
) -> Result<(), String> {
    if run_id == 0
        || run_attempt == 0
        || unsigned_field(primary, "activationRunId")? != run_id
        || unsigned_field(secondary, "activationRunId")? != run_id
        || unsigned_field(primary, "activationRunAttempt")? != run_attempt
        || unsigned_field(secondary, "activationRunAttempt")? != run_attempt
    {
        return Err("signed dual activation receipts differ from activation run".to_owned());
    }
    Ok(())
}

fn initial_surveillance_dispatch_body(
    candidate: &str,
    epoch: &str,
    run_id: u64,
    run_attempt: u64,
    correlation: &str,
) -> String {
    let mut body = String::from("{\"ref\":\"main\",\"inputs\":{");
    for (index, (field, value)) in [
        ("candidate_sha", candidate.to_owned()),
        ("assurance_epoch_sha256", epoch.to_owned()),
        ("activation_run_id", run_id.to_string()),
        ("activation_run_attempt", run_attempt.to_string()),
        ("activation_correlation_sha256", correlation.to_owned()),
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            body.push(',');
        }
        push_json(&mut body, field);
        body.push(':');
        push_json(&mut body, &value);
    }
    body.push_str("}}\n");
    body
}

pub(crate) fn initial_activation_correlation(
    candidate: &str,
    epoch: &str,
    run_id: u64,
    run_attempt: u64,
    primary_sha256: &str,
    secondary_sha256: &str,
) -> String {
    sha256_bytes(
        format!(
            "{{\"activationRunAttempt\":{run_attempt},\"activationRunId\":{run_id},\"assuranceEpochSha256\":\"{epoch}\",\"candidateCommit\":\"{candidate}\",\"primaryActivationSha256\":\"{primary_sha256}\",\"secondaryActivationSha256\":\"{secondary_sha256}\"}}\n"
        )
        .as_bytes(),
    )
    .hex()
}

struct InitialSurveillanceCompletion {
    activation_run_id: u64,
    activation_run_attempt: u64,
    primary_activation_sha256: String,
    secondary_activation_sha256: String,
    run_id: u64,
    run_attempt: u64,
    transition_artifact_id: u64,
    transition_archive_sha256: String,
    public_artifact_id: u64,
    public_archive_sha256: String,
    publication_receipt_sha256: String,
}

struct InitialActivationBinding {
    run_id: u64,
    run_attempt: u64,
    primary_sha256: String,
    secondary_sha256: String,
}

struct CompletedSurveillanceRun {
    run_id: u64,
    run_attempt: u64,
}

fn workflow_finalize_initial_surveillance() -> Result<String, String> {
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| "initial surveillance finalizer lacks GITHUB_TOKEN".to_owned())?;
    let run_id = require_nonzero_u64(
        &std::env::var("INITIAL_SURVEILLANCE_RUN_ID")
            .map_err(|_| "initial finalizer lacks surveillance run ID".to_owned())?,
        "initial surveillance run ID",
    )?;
    let run_attempt = require_nonzero_u64(
        &std::env::var("INITIAL_SURVEILLANCE_RUN_ATTEMPT")
            .map_err(|_| "initial finalizer lacks surveillance run attempt".to_owned())?,
        "initial surveillance run attempt",
    )?;
    let run = completed_initial_surveillance_runs(&token)?
        .into_iter()
        .find(|run| run.run_id == run_id && run.run_attempt == run_attempt)
        .ok_or_else(|| "workflow_run finalizer does not select exact successful run".to_owned())?;
    let (candidate, epoch, correlation, transition_artifact_id) =
        initial_correlation_from_run(&token, &run)?;
    verify_retained_activation_correlation(&token, &candidate, &epoch, &correlation, &run)?;
    let artifacts = initial_surveillance_artifacts(&token, &run)?;
    let public_name = format!(
        "promotion-public-current-state-{}-{}",
        run.run_id, run.run_attempt
    );
    let public_artifact_id = exact_initial_artifact(&artifacts, &public_name)?
        .ok_or_else(|| "completed surveillance lacks public publication artifact".to_owned())?;
    let completion = verify_initial_surveillance_artifacts(
        &run,
        transition_artifact_id,
        public_artifact_id,
        &correlation,
        &candidate,
        &epoch,
    )?;
    let document = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"candidateCommit\": \"{candidate}\",\n  \"assuranceEpochSha256\": \"{epoch}\",\n  \"activationRunId\": {},\n  \"activationRunAttempt\": {},\n  \"activationCorrelationSha256\": \"{correlation}\",\n  \"primaryActivationSha256\": \"{}\",\n  \"secondaryActivationSha256\": \"{}\",\n  \"surveillanceRunId\": {},\n  \"surveillanceRunAttempt\": {},\n  \"transitionArtifactId\": {},\n  \"transitionArchiveSha256\": \"{}\",\n  \"publicArtifactId\": {},\n  \"publicArchiveSha256\": \"{}\",\n  \"publicPublicationReceiptSha256\": \"{}\",\n  \"state\": \"completed-success-and-publicly-observed\"\n}}\n",
        completion.activation_run_id,
        completion.activation_run_attempt,
        completion.primary_activation_sha256,
        completion.secondary_activation_sha256,
        completion.run_id,
        completion.run_attempt,
        completion.transition_artifact_id,
        completion.transition_archive_sha256,
        completion.public_artifact_id,
        completion.public_archive_sha256,
        completion.publication_receipt_sha256,
    );
    write_atomic(
        &component_path(["ci-out", "initial-surveillance-completion.json"]),
        document.as_bytes(),
    )?;
    Ok("finalized exact completed initial public surveillance".to_owned())
}

fn workflow_record_initial_surveillance_failure() -> Result<String, String> {
    let run_id = require_nonzero_u64(
        &std::env::var("INITIAL_SURVEILLANCE_RUN_ID")
            .map_err(|_| "initial failure record lacks run ID".to_owned())?,
        "failed initial surveillance run ID",
    )?;
    let run_attempt = require_nonzero_u64(
        &std::env::var("INITIAL_SURVEILLANCE_RUN_ATTEMPT")
            .map_err(|_| "initial failure record lacks run attempt".to_owned())?,
        "failed initial surveillance run attempt",
    )?;
    let conclusion = std::env::var("INITIAL_SURVEILLANCE_CONCLUSION")
        .map_err(|_| "initial failure record lacks conclusion".to_owned())?;
    if !matches!(
        conclusion.as_str(),
        "action_required" | "cancelled" | "failure" | "stale" | "timed_out"
    ) {
        return Err("initial surveillance failure conclusion is unsupported".to_owned());
    }
    let document = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"surveillanceRunId\": {run_id},\n  \"surveillanceRunAttempt\": {run_attempt},\n  \"conclusion\": \"{conclusion}\",\n  \"state\": \"activation-pending-publication-failed\"\n}}\n"
    );
    write_atomic(
        &component_path(["ci-out", "initial-surveillance-failure.json"]),
        document.as_bytes(),
    )?;
    Ok("retained failed initial-public completion evidence".to_owned())
}

fn workflow_complete_initial_activation() -> Result<String, String> {
    let completion_path = component_path(["ci-out", "initial-surveillance-completion.json"]);
    let completion = fs::read_to_string(&completion_path)
        .map_err(|error| format!("cannot read initial public completion: {error}"))?;
    if quoted_field(&completion, "state")? != "completed-success-and-publicly-observed" {
        return Err("initial public completion has not reached its terminal state".to_owned());
    }
    let mut provider = workflow_provider(true)?;
    let completion_sha256 = public_report_file_digest(&completion_path)?;
    if quoted_field(&completion, "candidateCommit")? != provider.active_candidate
        || quoted_field(&completion, "assuranceEpochSha256")? != provider.active_epoch
    {
        return Err(
            "initial public completion differs from pending provider activation".to_owned(),
        );
    }
    verify_completion_activation_binding(&completion, &provider)?;
    if provider.activation_public_state == "completed-publication"
        && provider.activation_public_completion_sha256 == completion_sha256
    {
        return Ok(format!(
            "initial public activation was already completed for provider {}",
            provider.provider
        ));
    }
    if provider.activation_public_state != "pending-publication" {
        return Err("provider activation completion is a replay or fork".to_owned());
    }
    "completed-publication".clone_into(&mut provider.activation_public_state);
    provider.activation_public_completion_sha256 = completion_sha256;
    let empty = ("", "", "");
    let (record, packet, dsse) =
        provider
            .current_transition
            .as_ref()
            .map_or((empty, empty, empty), |transition| {
                (
                    (
                        transition.record_key.as_str(),
                        transition.record_version.as_str(),
                        transition.record_sha256.as_str(),
                    ),
                    (
                        transition.packet_key.as_str(),
                        transition.packet_version.as_str(),
                        transition.packet_sha256.as_str(),
                    ),
                    (
                        transition.dsse_key.as_str(),
                        transition.dsse_version.as_str(),
                        transition.dsse_sha256.as_str(),
                    ),
                )
            });
    let context = provider_context_with_transition(&provider, record, packet, dsse);
    aws(&[
        "ssm",
        "put-parameter",
        "--name",
        "/hell-rs/custody/provider-context",
        "--type",
        "SecureString",
        "--value",
        &context,
        "--overwrite",
    ])?;
    Ok(format!(
        "completed initial public activation for provider {}",
        provider.provider
    ))
}

fn verify_completion_activation_binding(
    completion: &str,
    provider: &WorkflowProvider,
) -> Result<(), String> {
    let activation_run_id = unsigned_field(completion, "activationRunId")?;
    let activation_run_attempt = unsigned_field(completion, "activationRunAttempt")?;
    if activation_run_id == 0 || activation_run_attempt == 0 {
        return Err("initial public completion has an invalid activation run identity".to_owned());
    }
    let primary = quoted_field(completion, "primaryActivationSha256")?;
    let secondary = quoted_field(completion, "secondaryActivationSha256")?;
    require_digest(&primary, "initial completion primary activation digest")?;
    require_digest(&secondary, "initial completion secondary activation digest")?;
    let correlation = initial_activation_correlation(
        &provider.active_candidate,
        &provider.active_epoch,
        activation_run_id,
        activation_run_attempt,
        &primary,
        &secondary,
    );
    if quoted_field(completion, "activationCorrelationSha256")? != correlation {
        return Err("initial public completion activation correlation is not exact".to_owned());
    }
    let expected_record = match provider.provider.as_str() {
        "primary-worm" => primary,
        "secondary-worm" => secondary,
        _ => return Err("initial completion provider is unsupported".to_owned()),
    };
    if expected_record != provider.active_activation_record_sha256 {
        return Err(
            "initial public completion does not bind the pending provider activation".to_owned(),
        );
    }
    Ok(())
}

fn initial_correlation_from_run(
    token: &str,
    run: &CompletedSurveillanceRun,
) -> Result<(String, String, String, u64), String> {
    let artifacts = initial_surveillance_artifacts(token, run)?;
    let name = format!("promotion-surveillance-{}-{}", run.run_id, run.run_attempt);
    let artifact_id = exact_initial_artifact(&artifacts, &name)?
        .ok_or_else(|| "completed surveillance lacks transition artifact".to_owned())?;
    let run_id = run.run_id.to_string();
    let run_attempt = run.run_attempt.to_string();
    let root = component_path([
        "ci-out",
        "initial-surveillance-bootstrap",
        &run_id,
        &run_attempt,
    ]);
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create initial finalizer bootstrap: {error}"))?;
    let archive = root.join("transition.zip");
    download_public_source_archive(artifact_id, &archive)?;
    let extracted = root.join("transition");
    crate::assurance::extract_external_zip(&archive, &extracted)?;
    let marker = exact_public_source_file(&extracted, "initial-activation-correlation.json")?;
    let document = fs::read_to_string(marker)
        .map_err(|error| format!("cannot read initial activation marker: {error}"))?;
    let candidate = quoted_field(&document, "candidateCommit")?;
    require_git_sha(&candidate, "initial activation marker candidate")?;
    let epoch = quoted_field(&document, "assuranceEpochSha256")?;
    Digest::from_hex(&epoch).map_err(|error| format!("invalid activation epoch: {error}"))?;
    let correlation = quoted_field(&document, "activationCorrelationSha256")?;
    Digest::from_hex(&correlation)
        .map_err(|error| format!("invalid activation correlation: {error}"))?;
    Ok((candidate, epoch, correlation, artifact_id))
}

fn verify_retained_activation_correlation(
    token: &str,
    candidate: &str,
    epoch: &str,
    correlation: &str,
    surveillance_run: &CompletedSurveillanceRun,
) -> Result<(), String> {
    let bootstrap = component_path([
        "ci-out",
        "initial-surveillance-bootstrap",
        &surveillance_run.run_id.to_string(),
        &surveillance_run.run_attempt.to_string(),
        "transition",
    ]);
    let marker = exact_public_source_file(&bootstrap, "initial-activation-correlation.json")?;
    let marker_text = fs::read_to_string(marker)
        .map_err(|error| format!("cannot read retained activation marker: {error}"))?;
    let activation_run = CompletedSurveillanceRun {
        run_id: unsigned_field(&marker_text, "activationRunId")?,
        run_attempt: unsigned_field(&marker_text, "activationRunAttempt")?,
    };
    let artifacts = initial_surveillance_artifacts(token, &activation_run)?;
    let primary = retained_activation_from_artifact(
        exact_initial_artifact(&artifacts, "custody-final-activation-primary-worm")?
            .ok_or_else(|| "initial finalizer lacks primary activation artifact".to_owned())?,
        "primary-worm",
        &activation_run,
    )?;
    let secondary = retained_activation_from_artifact(
        exact_initial_artifact(&artifacts, "custody-final-activation-secondary-worm")?
            .ok_or_else(|| "initial finalizer lacks secondary activation artifact".to_owned())?,
        "secondary-worm",
        &activation_run,
    )?;
    verify_activation_run_binding(
        &primary,
        &secondary,
        activation_run.run_id,
        activation_run.run_attempt,
    )?;
    let derived = initial_activation_correlation(
        candidate,
        epoch,
        activation_run.run_id,
        activation_run.run_attempt,
        &sha256_bytes(primary.as_bytes()).hex(),
        &sha256_bytes(secondary.as_bytes()).hex(),
    );
    if derived != correlation
        || quoted_field(&marker_text, "primaryActivationSha256")?
            != sha256_bytes(primary.as_bytes()).hex()
        || quoted_field(&marker_text, "secondaryActivationSha256")?
            != sha256_bytes(secondary.as_bytes()).hex()
    {
        return Err("initial public completion differs from signed activation receipts".to_owned());
    }
    Ok(())
}

fn retained_activation_from_artifact(
    artifact_id: u64,
    provider: &str,
    activation_run: &CompletedSurveillanceRun,
) -> Result<String, String> {
    let root = component_path([
        "ci-out",
        "initial-activation-source",
        &activation_run.run_id.to_string(),
        &activation_run.run_attempt.to_string(),
        provider,
    ]);
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create retained activation source: {error}"))?;
    let archive = root.join("artifact.zip");
    download_public_source_archive(artifact_id, &archive)?;
    let extracted = root.join("extracted");
    crate::assurance::extract_external_zip(&archive, &extracted)?;
    let record = exact_public_source_file(&extracted, "activation-receipt.json")?;
    let packet = exact_public_source_file(&extracted, "activation-packet.json")?;
    let dsse = exact_public_source_file(&extracted, "activation-receipt.dsse.json")?;
    verify_public_transition_signature_for_role(&dsse, "custody-provider")?;
    let document = fs::read_to_string(&record)
        .map_err(|error| format!("cannot read retained activation receipt: {error}"))?;
    if quoted_field(&document, "provider")? != provider {
        return Err("retained activation artifact provider changed".to_owned());
    }
    crate::assurance::verify_review_packet_first_artifact(
        &packet,
        "custody-provider",
        &quoted_field(&document, "candidateCommit")?,
        &quoted_field(&document, "assuranceEpochSha256")?,
        &public_report_file_digest(&record)?,
    )?;
    Ok(document)
}

fn completed_initial_surveillance_runs(
    token: &str,
) -> Result<Vec<CompletedSurveillanceRun>, String> {
    let endpoint = component_path([
        "repos",
        "Portfoligno",
        "hell-rs",
        "actions",
        "workflows",
        "promotion-surveillance.yml",
        "runs",
    ]);
    let output = github_api_output(
        token,
        &[
            OsString::from("api"),
            OsString::from("--method"),
            OsString::from("GET"),
            endpoint.as_os_str().to_owned(),
            OsString::from("-f"),
            OsString::from("event=workflow_dispatch"),
            OsString::from("-f"),
            OsString::from("status=completed"),
            OsString::from("-f"),
            OsString::from("per_page=100"),
            OsString::from("--jq"),
            OsString::from(
                ".workflow_runs[] | [.id,.run_attempt,.created_at,.event,.status,.conclusion,.path] | @tsv",
            ),
        ],
    )?;
    String::from_utf8(output.stdout)
        .map_err(|_| "initial surveillance run response is not UTF-8".to_owned())?
        .lines()
        .map(parse_completed_surveillance_run)
        .collect()
}

fn parse_completed_surveillance_run(line: &str) -> Result<CompletedSurveillanceRun, String> {
    let fields = line.split('\t').collect::<Vec<_>>();
    if fields.len() != 7
        || fields[3] != "workflow_dispatch"
        || fields[4] != "completed"
        || fields[5] != "success"
        || !matches!(
            fields[6],
            ".github/workflows/promotion-surveillance.yml"
                | ".github/workflows/promotion-surveillance.yml@main"
        )
    {
        return Err("initial surveillance run response is not exact success evidence".to_owned());
    }
    validate_utc_timestamp(fields[2])?;
    Ok(CompletedSurveillanceRun {
        run_id: require_nonzero_u64(fields[0], "initial surveillance run ID")?,
        run_attempt: require_nonzero_u64(fields[1], "initial surveillance run attempt")?,
    })
}

fn initial_surveillance_artifacts(
    token: &str,
    run: &CompletedSurveillanceRun,
) -> Result<Vec<(u64, String)>, String> {
    let run_id = run.run_id.to_string();
    let endpoint = component_path([
        "repos",
        "Portfoligno",
        "hell-rs",
        "actions",
        "runs",
        &run_id,
        "artifacts",
    ]);
    let output = github_api_output(
        token,
        &[
            OsString::from("api"),
            OsString::from("--method"),
            OsString::from("GET"),
            endpoint.as_os_str().to_owned(),
            OsString::from("-f"),
            OsString::from("per_page=100"),
            OsString::from("--jq"),
            OsString::from(".artifacts[] | [.id,.name,.expired] | @tsv"),
        ],
    )?;
    String::from_utf8(output.stdout)
        .map_err(|_| "initial surveillance artifact response is not UTF-8".to_owned())?
        .lines()
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() != 3 || fields[2] != "false" {
                return Err("initial surveillance artifact response is invalid".to_owned());
            }
            Ok((
                require_nonzero_u64(fields[0], "initial surveillance artifact ID")?,
                fields[1].to_owned(),
            ))
        })
        .collect()
}

fn exact_initial_artifact(artifacts: &[(u64, String)], name: &str) -> Result<Option<u64>, String> {
    let matches = artifacts
        .iter()
        .filter(|(_, observed)| observed == name)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(*id)),
        _ => Err("initial surveillance artifact name is ambiguous".to_owned()),
    }
}

struct InitialPublicFiles {
    record: PathBuf,
    packet: PathBuf,
    dsse: PathBuf,
    report: PathBuf,
    divergences: PathBuf,
    statement: PathBuf,
    receipt: PathBuf,
}

fn verify_initial_surveillance_artifacts(
    run: &CompletedSurveillanceRun,
    transition_artifact_id: u64,
    public_artifact_id: u64,
    correlation: &str,
    candidate: &str,
    epoch: &str,
) -> Result<InitialSurveillanceCompletion, String> {
    let run_id = run.run_id.to_string();
    let run_attempt = run.run_attempt.to_string();
    let root = component_path([
        "ci-out",
        "initial-surveillance-completion",
        &run_id,
        &run_attempt,
    ]);
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create initial surveillance evidence root: {error}"))?;
    let transition_archive = root.join("transition.zip");
    download_public_source_archive(transition_artifact_id, &transition_archive)?;
    let transition = root.join("transition");
    crate::assurance::extract_external_zip(&transition_archive, &transition)?;
    let activation = verify_initial_correlation_file(&transition, correlation, candidate, epoch)?;
    let public_archive = root.join("public.zip");
    download_public_source_archive(public_artifact_id, &public_archive)?;
    let public = root.join("public");
    crate::assurance::extract_external_zip(&public_archive, &public)?;
    let files = initial_public_files(&public)?;
    verify_observed_public_transition_files(
        &transition,
        &files.record,
        &files.packet,
        &files.dsse,
        &files.report,
        &files.divergences,
        &files.statement,
    )?;
    verify_initial_public_completion(run, &public, &files, candidate, epoch)?;
    Ok(InitialSurveillanceCompletion {
        activation_run_id: activation.run_id,
        activation_run_attempt: activation.run_attempt,
        primary_activation_sha256: activation.primary_sha256,
        secondary_activation_sha256: activation.secondary_sha256,
        run_id: run.run_id,
        run_attempt: run.run_attempt,
        transition_artifact_id,
        transition_archive_sha256: public_report_file_digest(&transition_archive)?,
        public_artifact_id,
        public_archive_sha256: public_report_file_digest(&public_archive)?,
        publication_receipt_sha256: public_report_file_digest(&files.receipt)?,
    })
}

fn verify_initial_correlation_file(
    transition: &Path,
    correlation: &str,
    candidate: &str,
    epoch: &str,
) -> Result<InitialActivationBinding, String> {
    let marker = exact_public_source_file(transition, "initial-activation-correlation.json")?;
    let document = fs::read_to_string(marker)
        .map_err(|error| format!("cannot read initial activation correlation: {error}"))?;
    let run_id = unsigned_field(&document, "activationRunId")?;
    let run_attempt = unsigned_field(&document, "activationRunAttempt")?;
    let primary_sha256 = quoted_field(&document, "primaryActivationSha256")?;
    let secondary_sha256 = quoted_field(&document, "secondaryActivationSha256")?;
    require_digest(&primary_sha256, "initial marker primary activation digest")?;
    require_digest(
        &secondary_sha256,
        "initial marker secondary activation digest",
    )?;
    if run_id == 0
        || run_attempt == 0
        || quoted_field(&document, "candidateCommit")? != candidate
        || quoted_field(&document, "assuranceEpochSha256")? != epoch
        || quoted_field(&document, "activationCorrelationSha256")? != correlation
        || initial_activation_correlation(
            candidate,
            epoch,
            run_id,
            run_attempt,
            &primary_sha256,
            &secondary_sha256,
        ) != correlation
        || quoted_field(&document, "state")? != "signed-dual-activation-bound"
    {
        return Err("completed surveillance run has the wrong activation correlation".to_owned());
    }
    Ok(InitialActivationBinding {
        run_id,
        run_attempt,
        primary_sha256,
        secondary_sha256,
    })
}

fn initial_public_files(root: &Path) -> Result<InitialPublicFiles, String> {
    Ok(InitialPublicFiles {
        record: exact_public_source_file(root, "public-current-state.json")?,
        packet: exact_public_source_file(root, "public-current-state-packet.json")?,
        dsse: exact_public_source_file(root, "public-current-state.dsse.json")?,
        report: exact_public_source_file(root, "public-compatibility-report.md")?,
        divergences: exact_public_source_file(root, "public-accepted-divergences.json")?,
        statement: exact_public_source_file(root, "public-public-release-statement.json")?,
        receipt: exact_public_source_file(root, "public-report-publication.json")?,
    })
}

fn verify_initial_public_completion(
    run: &CompletedSurveillanceRun,
    public_root: &Path,
    files: &InitialPublicFiles,
    candidate: &str,
    epoch: &str,
) -> Result<(), String> {
    verify_public_transition_signature(&files.dsse)?;
    crate::surveillance_ops::verify_transition(&files.record)?;
    let record_text = fs::read_to_string(&files.record)
        .map_err(|error| format!("cannot read initial public transition: {error}"))?;
    if quoted_field(&record_text, "candidateCommit")? != candidate
        || quoted_field(&record_text, "assuranceEpochSha256")? != epoch
        || quoted_field(&record_text, "derivedState")? != "promoted"
    {
        return Err("initial public transition is not the exact promoted activation".to_owned());
    }
    verify_public_release_packet_paths(
        &files.packet,
        &files.record,
        &files.report,
        &files.divergences,
        &files.statement,
    )?;
    let base_url = std::env::var("PUBLIC_COMPATIBILITY_REPORT_BASE_URL")
        .map_err(|_| "initial public completion lacks public base URL".to_owned())?;
    verify_initial_publication_receipt(run, files, &base_url, candidate, epoch)?;
    for (key, expected) in [
        ("current-state.json", files.record.as_path()),
        ("current-state-packet.json", files.packet.as_path()),
        ("current-state.dsse.json", files.dsse.as_path()),
        ("current-state-publication.json", files.receipt.as_path()),
        ("compatibility-report.md", files.report.as_path()),
        ("accepted-divergences.json", files.divergences.as_path()),
        ("public-release-statement.json", files.statement.as_path()),
    ] {
        verify_public_report_object(&base_url, key, expected, public_root)?;
    }
    Ok(())
}

fn verify_initial_publication_receipt(
    run: &CompletedSurveillanceRun,
    files: &InitialPublicFiles,
    base_url: &str,
    candidate: &str,
    epoch: &str,
) -> Result<(), String> {
    crate::assurance::verify_publication_receipt(
        &files.receipt,
        &crate::assurance::PublicationReceiptExpectation {
            public_base_url: base_url,
            candidate,
            epoch,
            state: "promoted",
            record_sha256: &public_report_file_digest(&files.record)?,
            packet_sha256: &public_report_file_digest(&files.packet)?,
            dsse_sha256: &public_report_file_digest(&files.dsse)?,
            report_sha256: &public_report_file_digest(&files.report)?,
            divergences_sha256: &public_report_file_digest(&files.divergences)?,
            release_statement_sha256: &public_report_file_digest(&files.statement)?,
        },
    )?;
    let receipt = fs::read_to_string(&files.receipt)
        .map_err(|error| format!("cannot read initial public receipt: {error}"))?;
    if unsigned_field(&receipt, "publisherRunId")? != run.run_id
        || unsigned_field(&receipt, "publisherRunAttempt")? != run.run_attempt
    {
        return Err("initial public receipt differs from completed surveillance run".to_owned());
    }
    Ok(())
}

fn github_api_output(token: &str, arguments: &[OsString]) -> Result<Output, String> {
    let output = Command::new("gh")
        .args(arguments)
        .env("GH_TOKEN", token)
        .env_remove("GITHUB_TOKEN")
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env_remove("AWS_SESSION_TOKEN")
        .output()
        .map_err(|error| format!("cannot query initial surveillance provider API: {error}"))?;
    if !output.status.success() {
        return Err("initial surveillance provider API query failed".to_owned());
    }
    Ok(output)
}

fn workflow_publish_transition() -> Result<String, String> {
    let provider = workflow_provider(true)?;
    require_provider_activation_visibility(&provider)?;
    let current_transition = workflow_current_transition(&provider)?;
    let record = component_path(["ci-out", "surveillance", "promotion-transition.json"]);
    let packet_path =
        component_path(["ci-out", "surveillance", "promotion-transition-packet.json"]);
    let dsse = component_path(["ci-out", "surveillance", "promotion-transition.dsse.json"]);
    for path in [&record, &packet_path, &dsse] {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "transition evidence {} is not regular",
                path.display()
            ));
        }
    }
    let status = Command::new(
        std::env::current_exe().map_err(|error| format!("cannot locate hell-ci: {error}"))?,
    )
    .args([
        OsStr::new("review-verify"),
        OsStr::new("--input"),
        dsse.as_os_str(),
        OsStr::new("--policy"),
        OsStr::new("compat/reviews.allowed_signers"),
        OsStr::new("--role"),
        OsStr::new("custody-reviewer"),
    ])
    .status()
    .map_err(|error| format!("cannot verify transition DSSE: {error}"))?;
    if !status.success() {
        return Err("transition DSSE verification failed".to_owned());
    }
    let record_text = fs::read_to_string(&record)
        .map_err(|error| format!("cannot read promotion transition: {error}"))?;
    verify_transition_supersedes(current_transition.as_ref(), &record_text)?;
    let record_sha = sha256_bytes(record_text.as_bytes()).hex();
    crate::assurance::verify_review_packet_first_artifact(
        &packet_path,
        "custody-reviewer",
        &quoted_field(&record_text, "candidateCommit")?,
        &quoted_field(&record_text, "assuranceEpochSha256")?,
        &record_sha,
    )?;
    let active_record = component_path(["ci-out", "active-provider-activation.json"]);
    get_object(
        &provider.bucket,
        &provider.active_activation_record_key,
        &provider.active_activation_record_version,
        &active_record,
    )?;
    if sha256_file(&active_record)
        .map_err(|error| error.to_string())?
        .hex()
        != provider.active_activation_record_sha256
    {
        return Err("provider activation record digest changed".to_owned());
    }
    let activation = fs::read_to_string(&active_record)
        .map_err(|error| format!("cannot read provider activation record: {error}"))?;
    for field in ["candidateCommit", "assuranceEpochSha256"] {
        if quoted_field(&activation, field)? != quoted_field(&record_text, field)? {
            return Err(format!("transition differs from active provider {field}"));
        }
    }
    let upload_receipt = workflow_active_receipt()?;
    let upload = parse_upload_receipt(
        &fs::read_to_string(&upload_receipt)
            .map_err(|error| format!("cannot read active upload receipt: {error}"))?,
    )?;
    let (record_key, record_version, record_sha) =
        retain_activation_object(&provider.bucket, &record, &upload.retention_until)?;
    let (packet_key, packet_version, packet_sha) =
        retain_activation_object(&provider.bucket, &packet_path, &upload.retention_until)?;
    let (dsse_key, dsse_version, dsse_sha) =
        retain_activation_object(&provider.bucket, &dsse, &upload.retention_until)?;
    let context = provider_context_with_transition(
        &provider,
        (&record_key, &record_version, &record_sha),
        (&packet_key, &packet_version, &packet_sha),
        (&dsse_key, &dsse_version, &dsse_sha),
    );
    aws(&[
        "ssm",
        "put-parameter",
        "--name",
        "/hell-rs/custody/provider-context",
        "--type",
        "SecureString",
        "--value",
        &context,
        "--overwrite",
    ])?;
    Ok(format!(
        "published signed current promotion state to provider {}",
        provider.provider
    ))
}

struct PublicSourceContext {
    artifact_id: u64,
    run_id: u64,
    run_attempt: u64,
    repository_id: u64,
    source_commit: String,
    workflow_ref: String,
    workflow_path: String,
    artifact_name: String,
    event: String,
}

struct PublicSourceFacts {
    selection_sha256: String,
    archive_sha256: String,
    archive_size: u64,
    extracted_sha256: String,
    artifact_api_sha256: String,
    run_api_sha256: String,
    workflow_sha256: String,
}

fn workflow_verify_public_source_artifact() -> Result<String, String> {
    let context = public_source_context()?;
    let directory = component_path(["ci-out", "surveillance"]);
    let record = directory.join("promotion-transition.json");
    let packet = directory.join("promotion-transition-packet.json");
    let dsse = directory.join("promotion-transition.dsse.json");
    verify_public_transition_signature(&dsse)?;
    crate::surveillance_ops::verify_transition(&record)?;
    let record_text = fs::read_to_string(&record)
        .map_err(|error| format!("cannot read public source transition: {error}"))?;
    let record_sha256 = sha256_bytes(record_text.as_bytes()).hex();
    crate::assurance::verify_review_packet_first_artifact(
        &packet,
        "custody-reviewer",
        &quoted_field(&record_text, "candidateCommit")?,
        &quoted_field(&record_text, "assuranceEpochSha256")?,
        &record_sha256,
    )?;
    verify_public_release_packet(&packet, &record, &directory)?;
    let facts = produce_public_source_selection(&context, &directory, &record_text)?;
    Ok(format!(
        "verified immutable public source artifact {} with selection {}",
        context.artifact_id, facts.selection_sha256
    ))
}

fn produce_public_source_selection(
    context: &PublicSourceContext,
    source_directory: &Path,
    transition: &str,
) -> Result<PublicSourceFacts, String> {
    let root = component_path(["ci-out", "public-source-selection"]);
    if root.exists() {
        return Err("public source selection output already exists".to_owned());
    }
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create public source selection root: {error}"))?;
    let archive = root.join("artifact.zip");
    download_public_source_archive(context.artifact_id, &archive)?;
    let extracted = root.join("extracted");
    crate::assurance::extract_external_zip(&archive, &extracted)?;
    let extracted_sha256 = directory_digest(&extracted)?;
    if extracted_sha256 != directory_digest(source_directory)? {
        return Err("provider archive tree differs from downloaded transition artifact".to_owned());
    }
    let selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root: Path::new("."),
            input_directory: &extracted,
            output_directory: &root,
            artifact_name: &context.artifact_name,
            workflow_path: &context.workflow_path,
            event_name: &context.event,
            run_id: context.run_id,
            run_attempt: context.run_attempt,
            artifact_id: context.artifact_id,
            provider_head: &context.source_commit,
            candidate: &quoted_field(transition, "candidateCommit")?,
            expected_directory_sha256: &extracted_sha256,
        },
    )?;
    let selection_path = root.join("public-source-selection.json");
    write_atomic(&selection_path, selection.as_bytes())?;
    public_source_facts(&root, &selection)
}

fn download_public_source_archive(artifact_id: u64, output: &Path) -> Result<(), String> {
    let endpoint = component_path(["repos", "Portfoligno", "hell-rs", "actions", "artifacts"])
        .join(artifact_id.to_string())
        .join("zip");
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| "public source selection requires GITHUB_TOKEN".to_owned())?;
    let response = Command::new("gh")
        .args([
            OsStr::new("api"),
            OsStr::new("--method"),
            OsStr::new("GET"),
            endpoint.as_os_str(),
        ])
        .env("GH_TOKEN", token)
        .env_remove("GITHUB_TOKEN")
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env_remove("AWS_SESSION_TOKEN")
        .output()
        .map_err(|error| format!("cannot download public source archive: {error}"))?;
    if !response.status.success() {
        return Err(format!(
            "public source archive download failed: {}",
            String::from_utf8_lossy(&response.stderr)
        ));
    }
    write_atomic(output, &response.stdout)
}

fn public_source_facts(root: &Path, selection: &str) -> Result<PublicSourceFacts, String> {
    let archive = root.join("artifact.zip");
    let archive_size = fs::metadata(&archive)
        .map_err(|error| format!("cannot inspect public source archive: {error}"))?
        .len();
    let archive_sha256 = public_report_file_digest(&archive)?;
    if archive_sha256 != quoted_field(selection, "providerArchiveSha256")?
        || archive_size != unsigned_field(selection, "providerArchiveSize")?
    {
        return Err("public source archive differs from exact provider metadata".to_owned());
    }
    let artifact_api = root.join("provider-selected-artifact.json");
    let run_api = root.join("provider-selected-run.json");
    let selection_path = root.join("public-source-selection.json");
    let selection_sha256 = public_report_file_digest(&selection_path)?;
    let artifact_api_sha256 = public_report_file_digest(&artifact_api)?;
    let run_api_sha256 = public_report_file_digest(&run_api)?;
    if artifact_api_sha256 != quoted_field(selection, "providerArtifactApiSha256")?
        || run_api_sha256 != quoted_field(selection, "providerRunApiSha256")?
    {
        return Err("public source retained provider API bytes changed".to_owned());
    }
    Ok(PublicSourceFacts {
        selection_sha256,
        archive_sha256,
        archive_size,
        extracted_sha256: directory_digest(&root.join("extracted"))?,
        artifact_api_sha256,
        run_api_sha256,
        workflow_sha256: quoted_field(selection, "workflowBlobSha256")?,
    })
}

fn workflow_publish_public_transition() -> Result<String, String> {
    let context = public_publication_context()?;
    let bucket = context.bucket;
    let base_url = context.base_url;
    let source = public_source_context()?;
    let directory = component_path(["ci-out", "surveillance"]);
    let record = directory.join("promotion-transition.json");
    let packet = directory.join("promotion-transition-packet.json");
    let dsse = directory.join("promotion-transition.dsse.json");
    verify_public_transition_signature(&dsse)?;
    let record_text = fs::read_to_string(&record)
        .map_err(|error| format!("cannot read published transition: {error}"))?;
    crate::surveillance_ops::verify_transition(&record)?;
    let record_sha256 = sha256_bytes(record_text.as_bytes()).hex();
    crate::assurance::verify_review_packet_first_artifact(
        &packet,
        "custody-reviewer",
        &quoted_field(&record_text, "candidateCommit")?,
        &quoted_field(&record_text, "assuranceEpochSha256")?,
        &record_sha256,
    )?;
    verify_public_release_packet(&packet, &record, &directory)?;
    let source_facts = reverify_public_source_selection(&source, &directory, &record_text)?;
    let prior_transition = retrieve_prior_public_transition(&directory, &base_url)?;
    verify_transition_supersedes(prior_transition.as_ref(), &record_text)?;
    publish_public_transition_objects(&bucket, &base_url, &directory, &record, &packet, &dsse)?;
    let subject = provider_subject()?;
    let receipt = PublishedStateAuthorityBuilder {
        directory: &directory,
        base_url: &base_url,
        source: &source,
        source_facts: &source_facts,
        subject: &subject,
    }
    .receipt(&record_text)?;
    let receipt_path = directory.join("public-report-publication.json");
    write_atomic(&receipt_path, receipt.as_bytes())?;
    verify_published_state_authority_receipt(&receipt, &source, &source_facts, &subject)?;
    crate::assurance::verify_publication_receipt(
        &receipt_path,
        &crate::assurance::PublicationReceiptExpectation {
            public_base_url: &base_url,
            candidate: &quoted_field(&record_text, "candidateCommit")?,
            epoch: &quoted_field(&record_text, "assuranceEpochSha256")?,
            state: &quoted_field(&record_text, "derivedState")?,
            record_sha256: &public_report_file_digest(&record)?,
            packet_sha256: &public_report_file_digest(&packet)?,
            dsse_sha256: &public_report_file_digest(&dsse)?,
            report_sha256: &public_report_file_digest(&directory.join("compatibility-report.md"))?,
            divergences_sha256: &public_report_file_digest(
                &directory.join("accepted-divergences.json"),
            )?,
            release_statement_sha256: &public_report_file_digest(
                &directory.join("public-release-statement.json"),
            )?,
        },
    )?;
    aws(&[
        "s3api",
        "put-object",
        "--bucket",
        &bucket,
        "--key",
        "current-state-publication.json",
        "--body",
        path_text(&receipt_path)?.as_str(),
        "--content-type",
        "application/json",
        "--cache-control",
        "no-cache, no-store, must-revalidate",
    ])?;
    verify_public_report_object(
        &base_url,
        "current-state-publication.json",
        &receipt_path,
        &directory,
    )?;
    Ok("published and anonymously reverified stable public current state".to_owned())
}

struct PublishedStateAuthorityBuilder<'a> {
    directory: &'a Path,
    base_url: &'a str,
    source: &'a PublicSourceContext,
    source_facts: &'a PublicSourceFacts,
    subject: &'a ProviderSubject,
}

impl PublishedStateAuthorityBuilder<'_> {
    fn receipt(&self, record_text: &str) -> Result<String, String> {
        Ok(format!(
            "{{\n  \"schemaVersion\": 2,\n  \"candidateCommit\": \"{}\",\n  \"assuranceEpochSha256\": \"{}\",\n  \"derivedState\": \"{}\",\n  \"observedAt\": \"{}\",\n  \"publicBaseUrl\": \"{}\",\n  \"recordSha256\": \"{}\",\n  \"packetSha256\": \"{}\",\n  \"dsseSha256\": \"{}\",\n  \"compatibilityReportSha256\": \"{}\",\n  \"acceptedDivergencesSha256\": \"{}\",\n  \"releaseStatementSha256\": \"{}\",\n  \"sourceArtifactId\": {source_artifact_id},\n  \"sourceArtifactName\": \"{}\",\n  \"sourceSelectionSha256\": \"{}\",\n  \"sourceProviderArchiveSha256\": \"{}\",\n  \"sourceProviderArchiveSize\": {},\n  \"sourceExtractedSha256\": \"{}\",\n  \"sourceArtifactApiSha256\": \"{}\",\n  \"sourceRunApiSha256\": \"{}\",\n  \"sourceWorkflowSha256\": \"{}\",\n  \"publisherRunId\": {run_id},\n  \"publisherRunAttempt\": {run_attempt},\n  \"publisherRepositoryId\": {repository_id},\n  \"publisherSourceCommit\": \"{source_commit}\",\n  \"publisherWorkflowRef\": \"{workflow_ref}\",\n  \"publisherEvent\": \"{}\",\n  \"publisherAccount\": \"{}\",\n  \"publisherArn\": \"{}\",\n  \"publisherStableId\": \"{}\",\n  \"state\": \"published-and-anonymously-reverified\"\n}}\n",
            quoted_field(record_text, "candidateCommit")?,
            quoted_field(record_text, "assuranceEpochSha256")?,
            quoted_field(record_text, "derivedState")?,
            quoted_field(record_text, "observedAt")?,
            self.base_url,
            public_report_file_digest(&self.directory.join("promotion-transition.json"))?,
            public_report_file_digest(&self.directory.join("promotion-transition-packet.json"))?,
            public_report_file_digest(&self.directory.join("promotion-transition.dsse.json"))?,
            public_report_file_digest(&self.directory.join("compatibility-report.md"))?,
            public_report_file_digest(&self.directory.join("accepted-divergences.json"))?,
            public_report_file_digest(&self.directory.join("public-release-statement.json"))?,
            self.source.artifact_name,
            self.source_facts.selection_sha256,
            self.source_facts.archive_sha256,
            self.source_facts.archive_size,
            self.source_facts.extracted_sha256,
            self.source_facts.artifact_api_sha256,
            self.source_facts.run_api_sha256,
            self.source_facts.workflow_sha256,
            self.source.event,
            self.subject.account,
            self.subject.arn,
            self.subject.stable_id,
            source_artifact_id = self.source.artifact_id,
            run_id = self.source.run_id,
            run_attempt = self.source.run_attempt,
            repository_id = self.source.repository_id,
            source_commit = self.source.source_commit,
            workflow_ref = self.source.workflow_ref,
        ))
    }
}

#[cfg(test)]
pub(crate) fn build_synthetic_published_state_authority(
    root: &Path,
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    candidate: &str,
    epoch: &str,
    finalized_claim_sha256: &str,
) -> Result<PathBuf, String> {
    validate_synthetic_public_identity(candidate, epoch, finalized_claim_sha256)?;
    let publication = root.join("synthetic-published-state");
    fs::create_dir(&publication)
        .map_err(|error| format!("cannot create synthetic published state: {error}"))?;
    let record_text = write_synthetic_publication_files(
        &publication,
        authority,
        candidate,
        epoch,
        finalized_claim_sha256,
    )?;
    let provider_subject = retain_synthetic_public_provider_subject(root, &publication)?;
    let (source, source_facts, subject) =
        synthetic_public_source(root, &provider_subject, candidate)?;
    let receipt = PublishedStateAuthorityBuilder {
        directory: &publication,
        base_url: "https://synthetic.invalid",
        source: &source,
        source_facts: &source_facts,
        subject: &subject,
    }
    .receipt(&record_text)?;
    let receipt_path = publication.join("public-report-publication.json");
    write_atomic(&receipt_path, receipt.as_bytes())?;
    verify_published_state_authority_receipt(&receipt, &source, &source_facts, &subject)?;
    let wrapper_path = write_synthetic_publication_wrapper(
        &publication,
        authority,
        &receipt_path,
        finalized_claim_sha256,
        &source_facts,
        &subject,
    )?;
    verify_synthetic_published_state_authority(
        &wrapper_path,
        authority,
        candidate,
        epoch,
        finalized_claim_sha256,
    )?;
    Ok(wrapper_path)
}

#[cfg(test)]
fn retain_synthetic_public_provider_subject(
    root: &Path,
    publication: &Path,
) -> Result<PathBuf, String> {
    let subject = root.join("synthetic-public-provider-subject");
    fs::create_dir(&subject)
        .map_err(|error| format!("cannot create synthetic public provider subject: {error}"))?;
    for name in [
        "promotion-transition.json",
        "promotion-transition-packet.json",
        "promotion-transition.dsse.json",
        "compatibility-report.md",
        "accepted-divergences.json",
        "public-release-statement.json",
    ] {
        write_atomic(
            &subject.join(name),
            &fs::read(publication.join(name))
                .map_err(|error| format!("cannot read synthetic public source file: {error}"))?,
        )?;
    }
    Ok(subject)
}

#[cfg(test)]
const SYNTHETIC_OBSERVED_AT: &str = "2026-08-11T00:00:00Z";

#[cfg(test)]
fn write_synthetic_publication_files(
    publication: &Path,
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    candidate: &str,
    epoch: &str,
    finalized_claim_sha256: &str,
) -> Result<String, String> {
    let record = synthetic_transition_record(
        authority,
        candidate,
        epoch,
        finalized_claim_sha256,
        SYNTHETIC_OBSERVED_AT,
    );
    let report = format!(
        "# Synthetic compatibility report\n\ndomain: {}\nfixture: {}\nroot-sha256: {}\nfinalized-claim-sha256: {finalized_claim_sha256}\n",
        crate::synthetic_promotion::SyntheticAuthority::domain(),
        authority.fixture_id(),
        authority.root_digest(),
    );
    let divergences = format!(
        "{{\"domain\":\"{}\",\"fixtureId\":\"{}\",\"rootDigest\":\"{}\",\"records\":[],\"state\":\"synthetic\"}}\n",
        crate::synthetic_promotion::SyntheticAuthority::domain(),
        authority.fixture_id(),
        authority.root_digest(),
    );
    let release = format!(
        "{{\"domain\":\"{}\",\"fixtureId\":\"{}\",\"rootDigest\":\"{}\",\"finalizedClaimSha256\":\"{finalized_claim_sha256}\",\"state\":\"synthetic-promoted\"}}\n",
        crate::synthetic_promotion::SyntheticAuthority::domain(),
        authority.fixture_id(),
        authority.root_digest(),
    );
    for (name, bytes) in [
        ("promotion-transition.json", record.as_bytes()),
        ("compatibility-report.md", report.as_bytes()),
        ("accepted-divergences.json", divergences.as_bytes()),
        ("public-release-statement.json", release.as_bytes()),
    ] {
        write_atomic(&publication.join(name), bytes)?;
    }
    let packet = synthetic_publication_packet(publication, authority, finalized_claim_sha256)?;
    let packet_path = publication.join("promotion-transition-packet.json");
    write_atomic(&packet_path, packet.as_bytes())?;
    let packet_sha256 = public_report_file_digest(&packet_path)?;
    let authentication = crate::synthetic_promotion::synthetic_authentication_document(
        authority,
        "public-transition",
        &packet_sha256,
    )?;
    write_atomic(
        &publication.join("promotion-transition.dsse.json"),
        authentication.as_bytes(),
    )?;
    Ok(record)
}

#[cfg(test)]
fn synthetic_transition_record(
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    candidate: &str,
    epoch: &str,
    finalized_claim_sha256: &str,
    observed_at: &str,
) -> String {
    format!(
        "{{\n  \"candidateCommit\": \"{candidate}\",\n  \"assuranceEpochSha256\": \"{epoch}\",\n  \"derivedState\": \"promoted\",\n  \"observedAt\": \"{observed_at}\",\n  \"syntheticAuthorityDomain\": \"{}\",\n  \"syntheticFixtureId\": \"{}\",\n  \"syntheticRootDigest\": \"{}\",\n  \"finalizedClaimSha256\": \"{finalized_claim_sha256}\"\n}}\n",
        crate::synthetic_promotion::SyntheticAuthority::domain(),
        authority.fixture_id(),
        authority.root_digest(),
    )
}

#[cfg(test)]
fn synthetic_publication_packet(
    publication: &Path,
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    finalized_claim_sha256: &str,
) -> Result<String, String> {
    Ok(format!(
        "schema_version = 1\ndomain = \"{}\"\nfixture_id = \"{}\"\nroot_digest = \"{}\"\nfinalized_claim_sha256 = \"{finalized_claim_sha256}\"\nrecord_sha256 = \"{}\"\nreport_sha256 = \"{}\"\ndivergences_sha256 = \"{}\"\nrelease_sha256 = \"{}\"\n",
        crate::synthetic_promotion::SyntheticAuthority::domain(),
        authority.fixture_id(),
        authority.root_digest(),
        public_report_file_digest(&publication.join("promotion-transition.json"))?,
        public_report_file_digest(&publication.join("compatibility-report.md"))?,
        public_report_file_digest(&publication.join("accepted-divergences.json"))?,
        public_report_file_digest(&publication.join("public-release-statement.json"))?,
    ))
}

#[cfg(test)]
fn synthetic_public_source(
    root: &Path,
    publication: &Path,
    active_candidate: &str,
) -> Result<(PublicSourceContext, PublicSourceFacts, ProviderSubject), String> {
    let workflow = ".github/workflows/promotion-surveillance.yml";
    let artifact_name = "promotion-public-current-state-19-2";
    let (selection_root, provider_head) =
        crate::assurance::tests::exact_synthetic_provider_selection(
            root,
            publication,
            workflow,
            artifact_name,
            active_candidate,
        )?;
    let selection_path = selection_root.join("selection.json");
    let selection = fs::read_to_string(&selection_path)
        .map_err(|error| format!("cannot read synthetic provider selection: {error}"))?;
    synthetic_public_source_from_selection(
        &selection_root,
        &selection,
        provider_head,
        active_candidate,
    )
}

#[cfg(test)]
fn reverify_synthetic_public_source(
    root: &Path,
    publication: &Path,
    active_candidate: &str,
) -> Result<(PublicSourceContext, PublicSourceFacts, ProviderSubject), String> {
    let workflow = ".github/workflows/promotion-surveillance.yml";
    let provider_head = crate::assurance::tests::reverify_retained_synthetic_provider_selection(
        root,
        publication,
        workflow,
        active_candidate,
    )?;
    let selection_root = root.join("synthetic-provider-selection");
    let selection = fs::read_to_string(selection_root.join("selection.json"))
        .map_err(|error| format!("cannot read retained synthetic provider selection: {error}"))?;
    synthetic_public_source_from_selection(
        &selection_root,
        &selection,
        provider_head,
        active_candidate,
    )
}

#[cfg(test)]
fn synthetic_public_source_from_selection(
    selection_root: &Path,
    selection: &str,
    provider_head: String,
    active_candidate: &str,
) -> Result<(PublicSourceContext, PublicSourceFacts, ProviderSubject), String> {
    let workflow = ".github/workflows/promotion-surveillance.yml";
    let artifact_name = "promotion-public-current-state-19-2";
    let selection_path = selection_root.join("selection.json");
    if synthetic_json_string(selection, "candidateCommit")? != active_candidate
        || provider_head == active_candidate
    {
        return Err("synthetic public provider head/active candidate split changed".to_owned());
    }
    let source = PublicSourceContext {
        artifact_id: synthetic_json_u64(selection, "providerArtifactId")?,
        run_id: synthetic_json_u64(selection, "providerRunId")?,
        run_attempt: synthetic_json_u64(selection, "providerRunAttempt")?,
        repository_id: synthetic_json_string(selection, "repositoryId")?
            .parse()
            .map_err(|_| "synthetic provider repository ID is invalid".to_owned())?,
        source_commit: provider_head,
        workflow_ref: format!("Portfoligno/hell-rs/{workflow}@refs/heads/main"),
        workflow_path: workflow.to_owned(),
        artifact_name: artifact_name.to_owned(),
        event: "workflow_dispatch".to_owned(),
    };
    let facts = PublicSourceFacts {
        selection_sha256: public_report_file_digest(&selection_path)?,
        archive_sha256: synthetic_json_string(selection, "providerArchiveSha256")?,
        archive_size: synthetic_json_u64(selection, "providerArchiveSize")?,
        extracted_sha256: synthetic_json_string(selection, "directorySha256")?,
        artifact_api_sha256: synthetic_json_string(selection, "providerArtifactApiSha256")?,
        run_api_sha256: synthetic_json_string(selection, "providerRunApiSha256")?,
        workflow_sha256: synthetic_json_string(selection, "workflowBlobSha256")?,
    };
    let subject = parse_provider_subject(
        b"123456789012\tarn:aws:sts::123456789012:assumed-role/synthetic-publisher/run\tsynthetic-provider-stable-id\n",
    )?;
    Ok((source, facts, subject))
}

#[cfg(test)]
fn synthetic_json_string(document: &str, field: &str) -> Result<String, String> {
    let marker = format!("\"{field}\":\"");
    let remainder = document
        .split_once(&marker)
        .map(|(_, remainder)| remainder)
        .ok_or_else(|| format!("synthetic provider selection lacks {field}"))?;
    let value = remainder
        .split_once('"')
        .map(|(value, _)| value)
        .ok_or_else(|| format!("synthetic provider selection field {field} is malformed"))?;
    unescape_json(value)
}

#[cfg(test)]
fn synthetic_json_u64(document: &str, field: &str) -> Result<u64, String> {
    let marker = format!("\"{field}\":");
    let remainder = document
        .split_once(&marker)
        .map(|(_, remainder)| remainder)
        .ok_or_else(|| format!("synthetic provider selection lacks {field}"))?;
    let end = remainder
        .find([',', '}'])
        .ok_or_else(|| format!("synthetic provider selection field {field} is malformed"))?;
    remainder[..end]
        .parse()
        .map_err(|_| format!("synthetic provider selection field {field} is not an integer"))
}

#[cfg(test)]
fn write_synthetic_publication_wrapper(
    publication: &Path,
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    receipt: &Path,
    finalized_claim_sha256: &str,
    source_facts: &PublicSourceFacts,
    subject: &ProviderSubject,
) -> Result<PathBuf, String> {
    let provider_identity_sha256 = synthetic_provider_identity_sha256(subject);
    let wrapper = format!(
        "schema_version = 1\ndomain = \"{}\"\nfixture_id = \"{}\"\nroot_digest = \"{}\"\nfinalized_claim_sha256 = \"{finalized_claim_sha256}\"\nreceipt_path = \"public-report-publication.json\"\nreceipt_sha256 = \"{}\"\npacket_sha256 = \"{}\"\nauthentication_sha256 = \"{}\"\nsource_selection_path = \"../synthetic-provider-selection/selection.json\"\nsource_selection_sha256 = \"{}\"\nprovider_identity_sha256 = \"{provider_identity_sha256}\"\nstate = \"synthetic-published-never-production-admissible\"\n",
        crate::synthetic_promotion::SyntheticAuthority::domain(),
        authority.fixture_id(),
        authority.root_digest(),
        public_report_file_digest(receipt)?,
        public_report_file_digest(&publication.join("promotion-transition-packet.json"))?,
        public_report_file_digest(&publication.join("promotion-transition.dsse.json"))?,
        source_facts.selection_sha256,
    );
    let path = publication.join("synthetic-public-authority.toml");
    write_atomic(&path, wrapper.as_bytes())?;
    Ok(path)
}

#[cfg(test)]
fn synthetic_provider_identity_sha256(subject: &ProviderSubject) -> String {
    sha256_bytes(
        format!(
            "{}\0{}\0{}",
            subject.account, subject.arn, subject.stable_id
        )
        .as_bytes(),
    )
    .hex()
}

#[cfg(test)]
pub(crate) fn verify_synthetic_published_state_authority(
    wrapper_path: &Path,
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    candidate: &str,
    epoch: &str,
    finalized_claim_sha256: &str,
) -> Result<(), String> {
    validate_synthetic_public_identity(candidate, epoch, finalized_claim_sha256)?;
    let publication = wrapper_path
        .parent()
        .ok_or_else(|| "synthetic public authority lacks a directory".to_owned())?;
    let wrapper = verify_synthetic_public_wrapper(wrapper_path, authority, finalized_claim_sha256)?;
    let receipt_path = publication.join("public-report-publication.json");
    verify_synthetic_public_provider_binding(publication, &receipt_path, &wrapper, candidate)?;
    verify_synthetic_public_objects(
        publication,
        authority,
        candidate,
        epoch,
        finalized_claim_sha256,
    )?;
    verify_synthetic_public_packet_and_receipt(
        wrapper_path,
        &receipt_path,
        &wrapper,
        authority,
        candidate,
        epoch,
        finalized_claim_sha256,
    )
}

#[cfg(test)]
fn verify_synthetic_public_wrapper(
    wrapper_path: &Path,
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    finalized_claim_sha256: &str,
) -> Result<BTreeMap<String, String>, String> {
    let wrapper_text = fs::read_to_string(wrapper_path)
        .map_err(|error| format!("cannot read synthetic public authority: {error}"))?;
    let wrapper = strict_toml::assignments(&wrapper_text)?;
    let expected_keys = [
        "authentication_sha256",
        "domain",
        "finalized_claim_sha256",
        "fixture_id",
        "packet_sha256",
        "provider_identity_sha256",
        "receipt_path",
        "receipt_sha256",
        "root_digest",
        "schema_version",
        "source_selection_path",
        "source_selection_sha256",
        "state",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if wrapper.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_keys
        || synthetic_toml_string(&wrapper, "domain")?
            != crate::synthetic_promotion::SyntheticAuthority::domain()
        || synthetic_toml_string(&wrapper, "fixture_id")? != authority.fixture_id()
        || synthetic_toml_string(&wrapper, "root_digest")? != authority.root_digest()
        || synthetic_toml_string(&wrapper, "finalized_claim_sha256")? != finalized_claim_sha256
        || synthetic_toml_string(&wrapper, "receipt_path")? != "public-report-publication.json"
        || synthetic_toml_string(&wrapper, "source_selection_path")?
            != "../synthetic-provider-selection/selection.json"
        || synthetic_toml_string(&wrapper, "state")?
            != "synthetic-published-never-production-admissible"
    {
        return Err("synthetic public authority wrapper changed".to_owned());
    }
    Ok(wrapper)
}

#[cfg(test)]
fn verify_synthetic_public_provider_binding(
    publication: &Path,
    receipt_path: &Path,
    wrapper: &BTreeMap<String, String>,
    candidate: &str,
) -> Result<(), String> {
    if synthetic_toml_string(wrapper, "receipt_sha256")? != public_report_file_digest(receipt_path)?
    {
        return Err("synthetic public receipt digest changed".to_owned());
    }
    let fixture_root = publication
        .parent()
        .ok_or_else(|| "synthetic public authority lacks a fixture root".to_owned())?;
    let provider_subject = fixture_root.join("synthetic-public-provider-subject");
    verify_synthetic_public_provider_subject(publication, &provider_subject)?;
    let (source, source_facts, subject) =
        reverify_synthetic_public_source(fixture_root, &provider_subject, candidate)?;
    let receipt = fs::read_to_string(receipt_path)
        .map_err(|error| format!("cannot read synthetic public receipt: {error}"))?;
    verify_published_state_authority_receipt(&receipt, &source, &source_facts, &subject)?;
    if quoted_field(&receipt, "candidateCommit")? != candidate
        || quoted_field(&receipt, "publisherSourceCommit")? != source.source_commit
        || source.source_commit == candidate
        || quoted_field(&receipt, "sourceSelectionSha256")? != source_facts.selection_sha256
        || synthetic_toml_string(wrapper, "source_selection_sha256")?
            != source_facts.selection_sha256
        || synthetic_toml_string(wrapper, "provider_identity_sha256")?
            != synthetic_provider_identity_sha256(&subject)
    {
        return Err("synthetic public active candidate/provider source split changed".to_owned());
    }
    Ok(())
}

#[cfg(test)]
fn verify_synthetic_public_provider_subject(
    publication: &Path,
    provider_subject: &Path,
) -> Result<(), String> {
    let expected = [
        "accepted-divergences.json",
        "compatibility-report.md",
        "promotion-transition-packet.json",
        "promotion-transition.dsse.json",
        "promotion-transition.json",
        "public-release-statement.json",
    ];
    let mut actual = fs::read_dir(provider_subject)
        .map_err(|error| format!("cannot inventory synthetic public provider subject: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| {
                format!("cannot enumerate synthetic public provider subject: {error}")
            })?;
            if !entry
                .file_type()
                .map_err(|error| {
                    format!("cannot inspect synthetic public provider subject: {error}")
                })?
                .is_file()
            {
                return Err("synthetic public provider subject contains a non-file".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "synthetic public provider subject path is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    actual.sort();
    if actual != expected {
        return Err("synthetic public provider subject inventory changed".to_owned());
    }
    for name in expected {
        let selected = fs::read(provider_subject.join(name))
            .map_err(|error| format!("cannot read selected synthetic public object: {error}"))?;
        let published = fs::read(publication.join(name))
            .map_err(|error| format!("cannot read published synthetic public object: {error}"))?;
        if selected != published {
            return Err(format!(
                "synthetic selected public object {name} differs from publication input"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn verify_synthetic_public_objects(
    publication: &Path,
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    candidate: &str,
    epoch: &str,
    finalized_claim_sha256: &str,
) -> Result<(), String> {
    let report = fs::read_to_string(publication.join("compatibility-report.md"))
        .map_err(|error| format!("cannot read synthetic public report: {error}"))?;
    if report
        != format!(
            "# Synthetic compatibility report\n\ndomain: {}\nfixture: {}\nroot-sha256: {}\nfinalized-claim-sha256: {finalized_claim_sha256}\n",
            crate::synthetic_promotion::SyntheticAuthority::domain(),
            authority.fixture_id(),
            authority.root_digest(),
        )
    {
        return Err("synthetic public report changed".to_owned());
    }
    let record_path = publication.join("promotion-transition.json");
    let record = fs::read_to_string(&record_path)
        .map_err(|error| format!("cannot read synthetic public transition: {error}"))?;
    let observed_at = quoted_field(&record, "observedAt")?;
    if observed_at != SYNTHETIC_OBSERVED_AT {
        return Err("synthetic public transition timestamp changed".to_owned());
    }
    validate_utc_timestamp(&observed_at)?;
    if record
        != synthetic_transition_record(
            authority,
            candidate,
            epoch,
            finalized_claim_sha256,
            &observed_at,
        )
    {
        return Err("synthetic public transition semantics changed".to_owned());
    }
    let expected_divergences = format!(
        "{{\"domain\":\"{}\",\"fixtureId\":\"{}\",\"rootDigest\":\"{}\",\"records\":[],\"state\":\"synthetic\"}}\n",
        crate::synthetic_promotion::SyntheticAuthority::domain(),
        authority.fixture_id(),
        authority.root_digest(),
    );
    let expected_release = format!(
        "{{\"domain\":\"{}\",\"fixtureId\":\"{}\",\"rootDigest\":\"{}\",\"finalizedClaimSha256\":\"{finalized_claim_sha256}\",\"state\":\"synthetic-promoted\"}}\n",
        crate::synthetic_promotion::SyntheticAuthority::domain(),
        authority.fixture_id(),
        authority.root_digest(),
    );
    if fs::read_to_string(publication.join("accepted-divergences.json"))
        .map_err(|error| format!("cannot read synthetic divergences: {error}"))?
        != expected_divergences
        || fs::read_to_string(publication.join("public-release-statement.json"))
            .map_err(|error| format!("cannot read synthetic release statement: {error}"))?
            != expected_release
    {
        return Err("synthetic public release semantics changed".to_owned());
    }
    Ok(())
}

#[cfg(test)]
fn verify_synthetic_public_packet_and_receipt(
    wrapper_path: &Path,
    receipt_path: &Path,
    wrapper: &BTreeMap<String, String>,
    authority: &crate::synthetic_promotion::SyntheticAuthority,
    candidate: &str,
    epoch: &str,
    finalized_claim_sha256: &str,
) -> Result<(), String> {
    let publication = receipt_path
        .parent()
        .ok_or_else(|| "synthetic public receipt lacks a directory".to_owned())?;
    let packet_path = publication.join("promotion-transition-packet.json");
    let expected_packet =
        synthetic_publication_packet(publication, authority, finalized_claim_sha256)?;
    if fs::read_to_string(&packet_path)
        .map_err(|error| format!("cannot read synthetic public packet: {error}"))?
        != expected_packet
        || synthetic_toml_string(wrapper, "packet_sha256")?
            != public_report_file_digest(&packet_path)?
    {
        return Err("synthetic public packet changed".to_owned());
    }
    let authentication_path = publication.join("promotion-transition.dsse.json");
    let authentication = fs::read_to_string(&authentication_path)
        .map_err(|error| format!("cannot read synthetic public authentication: {error}"))?;
    crate::synthetic_promotion::verify_synthetic_authentication_text(
        authority,
        "public-transition",
        &authentication,
        &public_report_file_digest(&packet_path)?,
    )?;
    if synthetic_toml_string(wrapper, "authentication_sha256")?
        != public_report_file_digest(&authentication_path)?
    {
        return Err("synthetic public authentication digest changed".to_owned());
    }
    let production_policy = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("compat/reviews.allowed_signers");
    if crate::assurance::verify_review_binding(
        &authentication_path,
        &production_policy,
        "custody-reviewer",
        candidate,
        epoch,
        &BTreeSet::from([public_report_file_digest(&packet_path)?]),
    )
    .is_ok()
    {
        return Err("synthetic authentication entered the production trust verifier".to_owned());
    }
    let expectation = crate::assurance::PublicationReceiptExpectation {
        public_base_url: "https://synthetic.invalid",
        candidate,
        epoch,
        state: "promoted",
        record_sha256: &public_report_file_digest(&publication.join("promotion-transition.json"))?,
        packet_sha256: &public_report_file_digest(
            &publication.join("promotion-transition-packet.json"),
        )?,
        dsse_sha256: &public_report_file_digest(
            &publication.join("promotion-transition.dsse.json"),
        )?,
        report_sha256: &public_report_file_digest(&publication.join("compatibility-report.md"))?,
        divergences_sha256: &public_report_file_digest(
            &publication.join("accepted-divergences.json"),
        )?,
        release_statement_sha256: &public_report_file_digest(
            &publication.join("public-release-statement.json"),
        )?,
    };
    crate::assurance::verify_publication_receipt(receipt_path, &expectation)?;
    if crate::assurance::verify_publication_receipt(wrapper_path, &expectation).is_ok() {
        return Err("synthetic public wrapper entered the production receipt parser".to_owned());
    }
    Ok(())
}

#[cfg(test)]
fn synthetic_toml_string<'a>(
    document: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    document
        .get(key)
        .and_then(|value| value.strip_prefix('"')?.strip_suffix('"'))
        .ok_or_else(|| format!("synthetic public authority field {key} is invalid"))
}

#[cfg(test)]
fn validate_synthetic_public_identity(
    candidate: &str,
    epoch: &str,
    finalized_claim_sha256: &str,
) -> Result<(), String> {
    if candidate.len() != 40
        || !candidate
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || [epoch, finalized_claim_sha256].into_iter().any(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    {
        return Err("synthetic public authority identity is not canonical".to_owned());
    }
    Ok(())
}

fn verify_published_state_authority_receipt(
    receipt: &str,
    source: &PublicSourceContext,
    source_facts: &PublicSourceFacts,
    subject: &ProviderSubject,
) -> Result<(), String> {
    let exact_numbers = [
        ("sourceArtifactId", source.artifact_id),
        ("sourceProviderArchiveSize", source_facts.archive_size),
        ("publisherRunId", source.run_id),
        ("publisherRunAttempt", source.run_attempt),
        ("publisherRepositoryId", source.repository_id),
    ];
    let exact_strings = [
        ("sourceArtifactName", source.artifact_name.as_str()),
        (
            "sourceSelectionSha256",
            source_facts.selection_sha256.as_str(),
        ),
        (
            "sourceProviderArchiveSha256",
            source_facts.archive_sha256.as_str(),
        ),
        (
            "sourceExtractedSha256",
            source_facts.extracted_sha256.as_str(),
        ),
        (
            "sourceArtifactApiSha256",
            source_facts.artifact_api_sha256.as_str(),
        ),
        ("sourceRunApiSha256", source_facts.run_api_sha256.as_str()),
        (
            "sourceWorkflowSha256",
            source_facts.workflow_sha256.as_str(),
        ),
        ("publisherSourceCommit", source.source_commit.as_str()),
        ("publisherWorkflowRef", source.workflow_ref.as_str()),
        ("publisherEvent", source.event.as_str()),
        ("publisherAccount", subject.account.as_str()),
        ("publisherArn", subject.arn.as_str()),
        ("publisherStableId", subject.stable_id.as_str()),
    ];
    if exact_numbers
        .into_iter()
        .any(|(field, expected)| unsigned_field(receipt, field) != Ok(expected))
        || exact_strings
            .into_iter()
            .any(|(field, expected)| quoted_field(receipt, field).as_deref() != Ok(expected))
    {
        return Err("public publication receipt authority inputs changed".to_owned());
    }
    Ok(())
}

fn publish_public_transition_objects(
    bucket: &str,
    base_url: &str,
    output: &Path,
    record: &Path,
    packet: &Path,
    dsse: &Path,
) -> Result<(), String> {
    let report = output.join("compatibility-report.md");
    let divergences = output.join("accepted-divergences.json");
    let statement = output.join("public-release-statement.json");
    for (key, path) in [
        ("current-state.json", record),
        ("current-state-packet.json", packet),
        ("current-state.dsse.json", dsse),
        ("compatibility-report.md", &report),
        ("accepted-divergences.json", &divergences),
        ("public-release-statement.json", &statement),
    ] {
        public_report_file_digest(path)?;
        aws(&[
            "s3api",
            "put-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--body",
            path_text(path)?.as_str(),
            "--content-type",
            "application/json",
            "--cache-control",
            "no-cache, no-store, must-revalidate",
        ])?;
        verify_public_report_object(base_url, key, path, output)?;
    }
    Ok(())
}

fn retrieve_prior_public_transition(
    directory: &Path,
    base_url: &str,
) -> Result<Option<RetrievedTransition>, String> {
    let record_path = directory.join("prior-public-current-state.json");
    if !fetch_public_report_object(base_url, "current-state.json", &record_path)? {
        return Ok(None);
    }
    let packet_path = directory.join("prior-public-current-state-packet.json");
    let dsse_path = directory.join("prior-public-current-state.dsse.json");
    if !fetch_public_report_object(base_url, "current-state-packet.json", &packet_path)?
        || !fetch_public_report_object(base_url, "current-state.dsse.json", &dsse_path)?
    {
        return Err("public current-state trio is incomplete".to_owned());
    }
    verify_public_transition_signature(&dsse_path)?;
    crate::surveillance_ops::verify_transition(&record_path)?;
    let document = fs::read_to_string(&record_path)
        .map_err(|error| format!("cannot read prior public transition: {error}"))?;
    let record_sha256 = sha256_bytes(document.as_bytes()).hex();
    crate::assurance::verify_review_packet_first_artifact(
        &packet_path,
        "custody-reviewer",
        &quoted_field(&document, "candidateCommit")?,
        &quoted_field(&document, "assuranceEpochSha256")?,
        &record_sha256,
    )?;
    Ok(Some(RetrievedTransition {
        record_sha256,
        packet_sha256: public_report_file_digest(&packet_path)?,
        dsse_sha256: public_report_file_digest(&dsse_path)?,
        derived_state: quoted_field(&document, "derivedState")?,
        observed_at: quoted_field(&document, "observedAt")?,
        supersedes_sha256: quoted_field(&document, "supersedesSha256")?,
    }))
}

fn workflow_observe_public_transition() -> Result<String, String> {
    let base_url = std::env::var("PUBLIC_COMPATIBILITY_REPORT_BASE_URL")
        .map_err(|_| "public report observation lacks its base URL".to_owned())?;
    let output = component_path(["ci-out", "surveillance", "public-observation"]);
    fs::create_dir(&output)
        .map_err(|error| format!("cannot create public observation directory: {error}"))?;
    let record_text = fetch_verified_public_transition(&base_url, &output)?
        .ok_or_else(|| "public current state is missing current-state.json".to_owned())?;
    let record = output.join("current-state.json");
    let packet = output.join("current-state-packet.json");
    let dsse = output.join("current-state.dsse.json");
    let receipt = output.join("current-state-publication.json");
    let report = output.join("compatibility-report.md");
    let divergences = output.join("accepted-divergences.json");
    let statement = output.join("public-release-statement.json");
    verify_public_provider_agreement(&record, &packet, &dsse)?;
    reverify_observed_public_source(
        &receipt,
        &record,
        &packet,
        &dsse,
        &report,
        &divergences,
        &statement,
    )?;
    retain_public_observation(&base_url, &record_text, &output)?;
    Ok("reverified public current state against both durable provider heads".to_owned())
}

fn fetch_verified_public_transition(
    base_url: &str,
    output: &Path,
) -> Result<Option<String>, String> {
    let record = output.join("current-state.json");
    if !fetch_public_report_object(base_url, "current-state.json", &record)? {
        return Ok(None);
    }
    let files = [
        (
            "current-state-packet.json",
            output.join("current-state-packet.json"),
        ),
        (
            "current-state.dsse.json",
            output.join("current-state.dsse.json"),
        ),
        (
            "current-state-publication.json",
            output.join("current-state-publication.json"),
        ),
        (
            "compatibility-report.md",
            output.join("compatibility-report.md"),
        ),
        (
            "accepted-divergences.json",
            output.join("accepted-divergences.json"),
        ),
        (
            "public-release-statement.json",
            output.join("public-release-statement.json"),
        ),
    ];
    for (key, path) in &files {
        if !fetch_public_report_object(base_url, key, path)? {
            return Err(format!("public current state is missing {key}"));
        }
    }
    verify_fetched_public_transition(base_url, output, &record)?;
    fs::read_to_string(&record)
        .map(Some)
        .map_err(|error| format!("cannot read observed public transition: {error}"))
}

fn verify_fetched_public_transition(
    base_url: &str,
    output: &Path,
    record: &Path,
) -> Result<(), String> {
    let packet = output.join("current-state-packet.json");
    let dsse = output.join("current-state.dsse.json");
    let receipt = output.join("current-state-publication.json");
    let report = output.join("compatibility-report.md");
    let divergences = output.join("accepted-divergences.json");
    let statement = output.join("public-release-statement.json");
    verify_public_transition_signature(&dsse)?;
    crate::surveillance_ops::verify_transition(record)?;
    let record_text = fs::read_to_string(record)
        .map_err(|error| format!("cannot read observed public transition: {error}"))?;
    let record_sha256 = public_report_file_digest(record)?;
    let packet_sha256 = public_report_file_digest(&packet)?;
    let dsse_sha256 = public_report_file_digest(&dsse)?;
    crate::assurance::verify_review_packet_first_artifact(
        &packet,
        "custody-reviewer",
        &quoted_field(&record_text, "candidateCommit")?,
        &quoted_field(&record_text, "assuranceEpochSha256")?,
        &record_sha256,
    )?;
    verify_public_release_packet(&packet, record, output)?;
    if public_report_file_digest(&report)?
        != quoted_field(&record_text, "compatibilityReportSha256")?
    {
        return Err("public compatibility report differs from transition digest".to_owned());
    }
    crate::assurance::verify_public_release_statement(
        &statement,
        &crate::assurance::PublicReleaseExpectation {
            candidate: &quoted_field(&record_text, "candidateCommit")?,
            epoch: &quoted_field(&record_text, "assuranceEpochSha256")?,
            state: &quoted_field(&record_text, "derivedState")?,
            report_sha256: &public_report_file_digest(&report)?,
            divergences_sha256: &public_report_file_digest(&divergences)?,
            transition_sha256: &record_sha256,
            issued_at: &quoted_field(&record_text, "observedAt")?,
        },
    )?;
    crate::assurance::verify_publication_receipt(
        &receipt,
        &crate::assurance::PublicationReceiptExpectation {
            public_base_url: base_url,
            candidate: &quoted_field(&record_text, "candidateCommit")?,
            epoch: &quoted_field(&record_text, "assuranceEpochSha256")?,
            state: &quoted_field(&record_text, "derivedState")?,
            record_sha256: &record_sha256,
            packet_sha256: &packet_sha256,
            dsse_sha256: &dsse_sha256,
            report_sha256: &public_report_file_digest(&report)?,
            divergences_sha256: &public_report_file_digest(&divergences)?,
            release_statement_sha256: &public_report_file_digest(&statement)?,
        },
    )
}

pub(crate) fn verify_retained_prior_public_transition(
    directory: &Path,
    base_url: &str,
) -> Result<String, String> {
    let record = directory.join("current-state.json");
    verify_fetched_public_transition(base_url, directory, &record)?;
    fs::read_to_string(record)
        .map_err(|error| format!("cannot read retained prior public transition: {error}"))
}

pub(crate) fn verify_retained_published_current_transition(
    directory: &Path,
) -> Result<String, String> {
    let record = directory.join("public-current-state.json");
    let packet = directory.join("public-current-state-packet.json");
    let dsse = directory.join("public-current-state.dsse.json");
    let receipt = directory.join("public-current-state-publication.json");
    let report = directory.join("public-compatibility-report.md");
    let divergences = directory.join("public-accepted-divergences.json");
    let statement = directory.join("public-public-release-statement.json");
    verify_public_transition_signature(&dsse)?;
    crate::surveillance_ops::verify_transition(&record)?;
    let record_text = fs::read_to_string(&record)
        .map_err(|error| format!("cannot read published current transition: {error}"))?;
    let record_sha256 = public_report_file_digest(&record)?;
    let packet_sha256 = public_report_file_digest(&packet)?;
    let dsse_sha256 = public_report_file_digest(&dsse)?;
    crate::assurance::verify_review_packet_first_artifact(
        &packet,
        "custody-reviewer",
        &quoted_field(&record_text, "candidateCommit")?,
        &quoted_field(&record_text, "assuranceEpochSha256")?,
        &record_sha256,
    )?;
    verify_public_release_packet_paths(&packet, &record, &report, &divergences, &statement)?;
    let report_sha256 = public_report_file_digest(&report)?;
    if report_sha256 != quoted_field(&record_text, "compatibilityReportSha256")? {
        return Err("published current report differs from the signed transition".to_owned());
    }
    crate::assurance::verify_public_release_statement(
        &statement,
        &crate::assurance::PublicReleaseExpectation {
            candidate: &quoted_field(&record_text, "candidateCommit")?,
            epoch: &quoted_field(&record_text, "assuranceEpochSha256")?,
            state: &quoted_field(&record_text, "derivedState")?,
            report_sha256: &report_sha256,
            divergences_sha256: &public_report_file_digest(&divergences)?,
            transition_sha256: &record_sha256,
            issued_at: &quoted_field(&record_text, "observedAt")?,
        },
    )?;
    let receipt_text = fs::read_to_string(&receipt)
        .map_err(|error| format!("cannot read published current receipt: {error}"))?;
    crate::assurance::verify_publication_receipt(
        &receipt,
        &crate::assurance::PublicationReceiptExpectation {
            public_base_url: &quoted_field(&receipt_text, "publicBaseUrl")?,
            candidate: &quoted_field(&record_text, "candidateCommit")?,
            epoch: &quoted_field(&record_text, "assuranceEpochSha256")?,
            state: &quoted_field(&record_text, "derivedState")?,
            record_sha256: &record_sha256,
            packet_sha256: &packet_sha256,
            dsse_sha256: &dsse_sha256,
            report_sha256: &report_sha256,
            divergences_sha256: &public_report_file_digest(&divergences)?,
            release_statement_sha256: &public_report_file_digest(&statement)?,
        },
    )?;
    Ok(record_text)
}

fn workflow_retain_prior_public_transition() -> Result<String, String> {
    let base_url = std::env::var("PUBLIC_COMPATIBILITY_REPORT_BASE_URL")
        .map_err(|_| "prior public transition collection lacks its base URL".to_owned())?;
    let output = component_path(["ci-out", "evidence", "prior-public"]);
    fs::create_dir(&output)
        .map_err(|error| format!("cannot create prior public evidence directory: {error}"))?;
    let record = fetch_verified_public_transition(&base_url, &output)?;
    let availability = if let Some(record) = record {
        format!(
            "{{\n  \"schemaVersion\": 1,\n  \"publicBaseUrl\": {},\n  \"state\": \"available-signed-public-promotion\",\n  \"candidateCommit\": {},\n  \"assuranceEpochSha256\": {},\n  \"recordSha256\": \"{}\",\n  \"acceptedDivergencesSha256\": \"{}\"\n}}\n",
            crate::assurance::json_string(&base_url),
            crate::assurance::json_string(&quoted_field(&record, "candidateCommit")?),
            crate::assurance::json_string(&quoted_field(&record, "assuranceEpochSha256")?),
            public_report_file_digest(&output.join("current-state.json"))?,
            public_report_file_digest(&output.join("accepted-divergences.json"))?,
        )
    } else {
        format!(
            "{{\n  \"schemaVersion\": 1,\n  \"publicBaseUrl\": {},\n  \"state\": \"no-public-promotion-observed\"\n}}\n",
            crate::assurance::json_string(&base_url),
        )
    };
    write_atomic(&output.join("availability.json"), availability.as_bytes())?;
    Ok("retained authenticated prior public promotion state".to_owned())
}

fn retain_public_observation(
    base_url: &str,
    record_text: &str,
    output: &Path,
) -> Result<(), String> {
    let record_sha256 = public_report_file_digest(&output.join("current-state.json"))?;
    let packet_sha256 = public_report_file_digest(&output.join("current-state-packet.json"))?;
    let dsse_sha256 = public_report_file_digest(&output.join("current-state.dsse.json"))?;
    let report_sha256 = public_report_file_digest(&output.join("compatibility-report.md"))?;
    let divergences_sha256 = public_report_file_digest(&output.join("accepted-divergences.json"))?;
    let release_statement_sha256 =
        public_report_file_digest(&output.join("public-release-statement.json"))?;
    let observation = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"candidateCommit\": \"{}\",\n  \"assuranceEpochSha256\": \"{}\",\n  \"derivedState\": \"{}\",\n  \"observedAt\": \"{}\",\n  \"publicBaseUrl\": \"{}\",\n  \"recordSha256\": \"{record_sha256}\",\n  \"packetSha256\": \"{packet_sha256}\",\n  \"dsseSha256\": \"{dsse_sha256}\",\n  \"compatibilityReportSha256\": \"{report_sha256}\",\n  \"acceptedDivergencesSha256\": \"{divergences_sha256}\",\n  \"releaseStatementSha256\": \"{release_statement_sha256}\",\n  \"publicationReceiptSha256\": \"{}\",\n  \"state\": \"exact-public-and-dual-provider-agreement\"\n}}\n",
        quoted_field(record_text, "candidateCommit")?,
        quoted_field(record_text, "assuranceEpochSha256")?,
        quoted_field(record_text, "derivedState")?,
        quoted_field(record_text, "observedAt")?,
        base_url,
        public_report_file_digest(&output.join("current-state-publication.json"))?,
    );
    write_atomic(
        &component_path([
            "ci-out",
            "surveillance",
            "public-current-state-observation.json",
        ]),
        observation.as_bytes(),
    )?;
    Ok(())
}

fn verify_public_provider_agreement(
    record: &Path,
    packet: &Path,
    dsse: &Path,
) -> Result<(), String> {
    for provider in ["active-primary", "active-secondary"] {
        let provider_root = component_path(["ci-out", provider, "transition"]);
        for (name, public_path) in [
            ("promotion-transition.json", record),
            ("promotion-transition-packet.json", packet),
            ("promotion-transition.dsse.json", dsse),
        ] {
            if public_report_file_digest(&provider_root.join(name))?
                != public_report_file_digest(public_path)?
            {
                return Err(format!(
                    "public current state differs from {provider} provider head"
                ));
            }
        }
    }
    Ok(())
}

fn verify_public_release_packet(
    packet: &Path,
    record: &Path,
    directory: &Path,
) -> Result<(), String> {
    verify_public_release_packet_paths(
        packet,
        record,
        &directory.join("compatibility-report.md"),
        &directory.join("accepted-divergences.json"),
        &directory.join("public-release-statement.json"),
    )
}

fn verify_public_release_packet_paths(
    packet: &Path,
    record: &Path,
    report: &Path,
    divergences: &Path,
    statement: &Path,
) -> Result<(), String> {
    let document = fs::read_to_string(record)
        .map_err(|error| format!("cannot read public release transition: {error}"))?;
    let mut expected = vec![public_report_file_digest(record)?];
    if document.starts_with("{\n  \"schemaVersion\": 2,") {
        for field in [
            "primaryObservationSha256",
            "secondaryObservationSha256",
            "surveillancePolicySha256",
            "failureSha256",
            "supersedesSha256",
        ] {
            expected.push(quoted_field(&document, field)?);
        }
    } else {
        expected.push(quoted_field(&document, "objectiveInputSha256")?);
        expected.push(quoted_field(&document, "supersedesSha256")?);
    }
    for path in [report, divergences, statement] {
        expected.push(public_report_file_digest(path)?);
    }
    crate::assurance::verify_review_packet_artifacts(packet, "custody-reviewer", &expected)
}

fn reverify_observed_public_source(
    receipt_path: &Path,
    record: &Path,
    packet: &Path,
    dsse: &Path,
    report: &Path,
    divergences: &Path,
    statement: &Path,
) -> Result<(), String> {
    let receipt = fs::read_to_string(receipt_path)
        .map_err(|error| format!("cannot read observed publication receipt: {error}"))?;
    let repository_id = required_positive_environment("GITHUB_REPOSITORY_ID")?;
    if unsigned_field(&receipt, "publisherRepositoryId")? != repository_id {
        return Err("public publisher repository ID differs from observer".to_owned());
    }
    let workflow_ref = quoted_field(&receipt, "publisherWorkflowRef")?;
    let (workflow_path, _) = public_workflow_identity(&workflow_ref)?;
    let source_commit = quoted_field(&receipt, "publisherSourceCommit")?;
    let root = component_path(["ci-out", "surveillance", "public-observed-source"]);
    if root.exists() {
        return Err("public observed source output already exists".to_owned());
    }
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create public observed source root: {error}"))?;
    let archive = root.join("artifact.zip");
    let artifact_id = unsigned_field(&receipt, "sourceArtifactId")?;
    download_public_source_archive(artifact_id, &archive)?;
    let extracted = root.join("extracted");
    crate::assurance::extract_external_zip(&archive, &extracted)?;
    verify_observed_public_transition_files(
        &extracted,
        record,
        packet,
        dsse,
        report,
        divergences,
        statement,
    )?;
    let source_root = root.join("provider-source");
    let workflow_file = workflow_path
        .split('/')
        .fold(source_root.clone(), |path, component| path.join(component));
    fs::create_dir_all(
        workflow_file
            .parent()
            .ok_or_else(|| "public workflow source has no parent".to_owned())?,
    )
    .map_err(|error| format!("cannot create public workflow source root: {error}"))?;
    write_atomic(
        &workflow_file,
        &crate::assurance::github_raw_source_at(
            "Portfoligno/hell-rs",
            &workflow_path,
            &source_commit,
        )?,
    )?;
    let directory_sha256 = directory_digest(&extracted)?;
    let selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root: &source_root,
            input_directory: &extracted,
            output_directory: &root,
            artifact_name: &quoted_field(&receipt, "sourceArtifactName")?,
            workflow_path: &workflow_path,
            event_name: &quoted_field(&receipt, "publisherEvent")?,
            run_id: unsigned_field(&receipt, "publisherRunId")?,
            run_attempt: unsigned_field(&receipt, "publisherRunAttempt")?,
            artifact_id,
            provider_head: &source_commit,
            candidate: &quoted_field(
                &fs::read_to_string(record)
                    .map_err(|error| format!("cannot read public transition: {error}"))?,
                "candidateCommit",
            )?,
            expected_directory_sha256: &directory_sha256,
        },
    )?;
    write_atomic(
        &root.join("public-source-selection.json"),
        selection.as_bytes(),
    )?;
    let facts = public_source_facts(&root, &selection)?;
    if facts.selection_sha256 != quoted_field(&receipt, "sourceSelectionSha256")?
        || facts.archive_sha256 != quoted_field(&receipt, "sourceProviderArchiveSha256")?
        || facts.archive_size != unsigned_field(&receipt, "sourceProviderArchiveSize")?
        || facts.extracted_sha256 != quoted_field(&receipt, "sourceExtractedSha256")?
        || facts.artifact_api_sha256 != quoted_field(&receipt, "sourceArtifactApiSha256")?
        || facts.run_api_sha256 != quoted_field(&receipt, "sourceRunApiSha256")?
        || facts.workflow_sha256 != quoted_field(&receipt, "sourceWorkflowSha256")?
    {
        return Err("public publication source provenance failed exact replay".to_owned());
    }
    Ok(())
}

fn verify_observed_public_transition_files(
    root: &Path,
    record: &Path,
    packet: &Path,
    dsse: &Path,
    report: &Path,
    divergences: &Path,
    statement: &Path,
) -> Result<(), String> {
    for (name, public) in [
        ("promotion-transition.json", record),
        ("promotion-transition-packet.json", packet),
        ("promotion-transition.dsse.json", dsse),
        ("compatibility-report.md", report),
        ("accepted-divergences.json", divergences),
        ("public-release-statement.json", statement),
    ] {
        let retained = exact_public_source_file(root, name)?;
        if public_report_file_digest(&retained)? != public_report_file_digest(public)? {
            return Err(
                "public release file differs from its exact provider source artifact".to_owned(),
            );
        }
    }
    Ok(())
}

fn exact_public_source_file(root: &Path, name: &str) -> Result<PathBuf, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut matches = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate public source artifact: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot read public source artifact entry: {error}"))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect public source artifact: {error}"))?;
            if kind.is_symlink() {
                return Err("public source artifact contains a symlink".to_owned());
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.file_name() == OsStr::new(name) {
                matches.push(entry.path());
            }
        }
    }
    if matches.len() != 1 {
        return Err(format!(
            "public source artifact does not contain exactly one {name}"
        ));
    }
    Ok(matches.remove(0))
}

struct PublicPublicationContext {
    bucket: String,
    base_url: String,
}

fn public_publication_context() -> Result<PublicPublicationContext, String> {
    let bucket = std::env::var("PUBLIC_COMPATIBILITY_REPORT_BUCKET")
        .map_err(|_| "public report publication lacks its bucket".to_owned())?;
    let base_url = std::env::var("PUBLIC_COMPATIBILITY_REPORT_BASE_URL")
        .map_err(|_| "public report publication lacks its base URL".to_owned())?;
    require_atom(&bucket, "public report bucket")?;
    Ok(PublicPublicationContext { bucket, base_url })
}

fn public_source_context() -> Result<PublicSourceContext, String> {
    let source_commit = std::env::var("GITHUB_SHA")
        .map_err(|_| "public report source selection lacks GITHUB_SHA".to_owned())?;
    crate::promotion_policy::require_git_sha(&source_commit, "public report source commit")?;
    let workflow_ref = std::env::var("GITHUB_WORKFLOW_REF")
        .map_err(|_| "public report source selection lacks GITHUB_WORKFLOW_REF".to_owned())?;
    let (workflow_path, artifact_prefix) = public_workflow_identity(&workflow_ref)?;
    let event = std::env::var("GITHUB_EVENT_NAME")
        .map_err(|_| "public report source selection lacks GITHUB_EVENT_NAME".to_owned())?;
    if !matches!(event.as_str(), "push" | "schedule" | "workflow_dispatch") {
        return Err("public report source artifact has an unsupported provider event".to_owned());
    }
    let run_id = required_positive_environment("GITHUB_RUN_ID")?;
    let run_attempt = required_positive_environment("GITHUB_RUN_ATTEMPT")?;
    Ok(PublicSourceContext {
        artifact_id: required_positive_environment("PUBLIC_REPORT_SOURCE_ARTIFACT_ID")?,
        run_id,
        run_attempt,
        repository_id: required_positive_environment("GITHUB_REPOSITORY_ID")?,
        source_commit,
        workflow_ref,
        workflow_path,
        artifact_name: format!("{artifact_prefix}-{run_id}-{run_attempt}"),
        event,
    })
}

fn public_workflow_identity(workflow_ref: &str) -> Result<(String, &'static str), String> {
    let (workflow_path, artifact_prefix) =
        if workflow_ref.contains("promotion-surveillance-watchdog.yml@") {
            (
                component_path([
                    ".github",
                    "workflows",
                    "promotion-surveillance-watchdog.yml",
                ]),
                "promotion-surveillance-watchdog",
            )
        } else {
            (
                component_path([".github", "workflows", "promotion-surveillance.yml"]),
                "promotion-surveillance",
            )
        };
    let workflow_path = path_text(&workflow_path)?;
    let expected_prefix = format!("Portfoligno/hell-rs/{workflow_path}@refs/heads/");
    if !workflow_ref.starts_with(&expected_prefix)
        || workflow_ref.len() == expected_prefix.len()
        || !workflow_ref.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'@' | b'.' | b'_' | b'-')
        })
    {
        return Err("public report workflow ref is not a stable provider identity".to_owned());
    }
    Ok((workflow_path, artifact_prefix))
}

fn reverify_public_source_selection(
    context: &PublicSourceContext,
    source_directory: &Path,
    transition: &str,
) -> Result<PublicSourceFacts, String> {
    let root = component_path(["ci-out", "public-source-selection"]);
    let extracted = root.join("extracted");
    let selection_path = root.join("public-source-selection.json");
    let selection = fs::read_to_string(&selection_path)
        .map_err(|error| format!("cannot read retained public source selection: {error}"))?;
    let reverified = root.join("reverified");
    if reverified.exists() {
        return Err("public source re-verification output already exists".to_owned());
    }
    let expected_directory_sha256 = directory_digest(&extracted)?;
    let live = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root: Path::new("."),
            input_directory: &extracted,
            output_directory: &reverified,
            artifact_name: &context.artifact_name,
            workflow_path: &context.workflow_path,
            event_name: &context.event,
            run_id: context.run_id,
            run_attempt: context.run_attempt,
            artifact_id: context.artifact_id,
            provider_head: &context.source_commit,
            candidate: &quoted_field(transition, "candidateCommit")?,
            expected_directory_sha256: &expected_directory_sha256,
        },
    )?;
    verify_retained_public_source_reselection(
        &root,
        &reverified,
        source_directory,
        &selection,
        &live,
    )
}

fn verify_retained_public_source_reselection(
    root: &Path,
    reverified: &Path,
    source_directory: &Path,
    selection: &str,
    live: &str,
) -> Result<PublicSourceFacts, String> {
    if directory_digest(&root.join("extracted"))? != directory_digest(source_directory)? {
        return Err("retained provider archive differs from publication input".to_owned());
    }
    if live != selection
        || public_report_file_digest(&root.join("provider-selected-artifact.json"))?
            != public_report_file_digest(&reverified.join("provider-selected-artifact.json"))?
        || public_report_file_digest(&root.join("provider-selected-run.json"))?
            != public_report_file_digest(&reverified.join("provider-selected-run.json"))?
    {
        return Err("public source provider selection changed before publication".to_owned());
    }
    public_source_facts(root, selection)
}

fn required_positive_environment(name: &str) -> Result<u64, String> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("public report publication lacks positive {name}"))
}

fn verify_public_transition_signature(dsse: &Path) -> Result<(), String> {
    verify_public_transition_signature_for_role(dsse, "custody-reviewer")
}

fn verify_public_transition_signature_for_role(dsse: &Path, role: &str) -> Result<(), String> {
    let status = Command::new(
        std::env::current_exe().map_err(|error| format!("cannot locate hell-ci: {error}"))?,
    )
    .args([
        OsStr::new("review-verify"),
        OsStr::new("--input"),
        dsse.as_os_str(),
        OsStr::new("--policy"),
        OsStr::new("compat/reviews.allowed_signers"),
        OsStr::new("--role"),
        OsStr::new(role),
    ])
    .status()
    .map_err(|error| format!("cannot verify public transition DSSE: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "public transition DSSE verification failed".to_owned())
}

fn fetch_public_report_object(base_url: &str, key: &str, output: &Path) -> Result<bool, String> {
    let url = PublicReportUrl::new(base_url, key)?.into_string();
    let response = Command::new("curl")
        .args([
            OsStr::new("--silent"),
            OsStr::new("--show-error"),
            OsStr::new("--proto"),
            OsStr::new("=https"),
            OsStr::new("--tlsv1.2"),
            OsStr::new("--output"),
            output.as_os_str(),
            OsStr::new("--write-out"),
            OsStr::new("%{http_code}"),
            OsStr::new(&url),
        ])
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env_remove("AWS_SESSION_TOKEN")
        .output()
        .map_err(|error| format!("cannot fetch current public report: {error}"))?;
    let status = std::str::from_utf8(&response.stdout)
        .map_err(|_| "public report HTTP status is not UTF-8".to_owned())?;
    match (response.status.success(), status) {
        (true, "200") => Ok(true),
        (true, "404") => Ok(false),
        _ => Err("public report endpoint did not return exact HTTP 200 or 404".to_owned()),
    }
}

fn verify_public_report_object(
    base_url: &str,
    key: &str,
    expected: &Path,
    output: &Path,
) -> Result<(), String> {
    let url = PublicReportUrl::new(base_url, key)?.into_string();
    let downloaded = output.join(format!("public-{key}"));
    let response = Command::new("curl")
        .args([
            OsStr::new("--fail"),
            OsStr::new("--silent"),
            OsStr::new("--show-error"),
            OsStr::new("--proto"),
            OsStr::new("=https"),
            OsStr::new("--tlsv1.2"),
            OsStr::new("--output"),
            downloaded.as_os_str(),
            OsStr::new(&url),
        ])
        .env_remove("AWS_ACCESS_KEY_ID")
        .env_remove("AWS_SECRET_ACCESS_KEY")
        .env_remove("AWS_SESSION_TOKEN")
        .output()
        .map_err(|error| format!("cannot anonymously fetch public report: {error}"))?;
    if !response.status.success()
        || public_report_file_digest(&downloaded)? != public_report_file_digest(expected)?
    {
        return Err("public report is not anonymously readable with exact bytes".to_owned());
    }
    Ok(())
}

fn public_report_file_digest(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect public report object: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("public report object is not a regular file".to_owned());
    }
    sha256_file(path)
        .map(Digest::hex)
        .map_err(|error| format!("cannot hash public report object: {error}"))
}

struct PublicReportUrl(String);

impl PublicReportUrl {
    fn new(base: &str, key: &str) -> Result<Self, String> {
        if !base.starts_with("https://")
            || base.ends_with('/')
            || base.contains(['?', '#', '@', '\\'])
            || !base.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'/' | b'.' | b'-')
            })
            || !matches!(
                key,
                "current-state.json"
                    | "current-state-packet.json"
                    | "current-state.dsse.json"
                    | "current-state-publication.json"
                    | "compatibility-report.md"
                    | "accepted-divergences.json"
                    | "public-release-statement.json"
            )
        {
            return Err("public report URL components are not canonical HTTPS values".to_owned());
        }
        let mut value =
            String::with_capacity(base.len().saturating_add(key.len()).saturating_add(1));
        value.push_str(base);
        value.push('/');
        value.push_str(key);
        if value
            .strip_prefix(base)
            .and_then(|suffix| suffix.strip_prefix('/'))
            != Some(key)
        {
            return Err("public report URL failed to round trip".to_owned());
        }
        Ok(Self(value))
    }

    fn into_string(self) -> String {
        self.0
    }
}

fn verify_transition_supersedes(
    current: Option<&RetrievedTransition>,
    proposed: &str,
) -> Result<(), String> {
    let proposed_prior = quoted_field(proposed, "priorState")?;
    let proposed_observed_at = quoted_field(proposed, "observedAt")?;
    let proposed_supersedes = quoted_field(proposed, "supersedesSha256")?;
    let Some(current) = current else {
        if proposed_prior != "promoted" {
            return Err("initial current transition must supersede promoted activation".to_owned());
        }
        return Ok(());
    };
    if proposed_prior != current.derived_state
        || proposed_supersedes != current.record_sha256
        || crate::assurance::utc_timestamp_seconds(&proposed_observed_at)?
            <= crate::assurance::utc_timestamp_seconds(&current.observed_at)?
    {
        return Err(
            "proposed transition is a replay or fork of the provider current head".to_owned(),
        );
    }
    Ok(())
}

fn provider_context_with_transition(
    provider: &WorkflowProvider,
    record: (&str, &str, &str),
    packet: (&str, &str, &str),
    dsse: (&str, &str, &str),
) -> String {
    format!(
        "schema_version = 1\nprovider = {:?}\ntrust_domain = {:?}\nbucket = {:?}\nactive_candidate = {:?}\nactive_epoch = {:?}\nactive_manifest = {:?}\nactive_receipt_key = {:?}\nactive_receipt_version = {:?}\nactive_receipt_sha256 = {:?}\nactive_activation_record_key = {:?}\nactive_activation_record_version = {:?}\nactive_activation_record_sha256 = {:?}\nactive_activation_packet_key = {:?}\nactive_activation_packet_version = {:?}\nactive_activation_packet_sha256 = {:?}\nactive_activation_dsse_key = {:?}\nactive_activation_dsse_version = {:?}\nactive_activation_dsse_sha256 = {:?}\nactivation_public_state = {:?}\nactivation_public_completion_sha256 = {:?}\ncurrent_transition_record_key = {:?}\ncurrent_transition_record_version = {:?}\ncurrent_transition_record_sha256 = {:?}\ncurrent_transition_packet_key = {:?}\ncurrent_transition_packet_version = {:?}\ncurrent_transition_packet_sha256 = {:?}\ncurrent_transition_dsse_key = {:?}\ncurrent_transition_dsse_version = {:?}\ncurrent_transition_dsse_sha256 = {:?}\n",
        provider.provider,
        provider.trust_domain,
        provider.bucket,
        provider.active_candidate,
        provider.active_epoch,
        provider.active_manifest,
        provider.active_receipt_key,
        provider.active_receipt_version,
        provider.active_receipt_sha256,
        provider.active_activation_record_key,
        provider.active_activation_record_version,
        provider.active_activation_record_sha256,
        provider.active_activation_packet_key,
        provider.active_activation_packet_version,
        provider.active_activation_packet_sha256,
        provider.active_activation_dsse_key,
        provider.active_activation_dsse_version,
        provider.active_activation_dsse_sha256,
        provider.activation_public_state,
        provider.activation_public_completion_sha256,
        record.0,
        record.1,
        record.2,
        packet.0,
        packet.1,
        packet.2,
        dsse.0,
        dsse.1,
        dsse.2,
    )
}

fn parse_provider_pointer(path: &Path) -> Result<(String, String, String, String), String> {
    let document = fs::read_to_string(path)
        .map_err(|error| format!("cannot read provider pointer {}: {error}", path.display()))?;
    let key = quoted_field(&document, "receiptKey")?;
    let version = quoted_field(&document, "receiptVersion")?;
    let digest = quoted_field(&document, "receiptSha256")?;
    let retention = quoted_field(&document, "retentionUntil")?;
    require_digest(&key, "provider pointer key")?;
    require_atom(&version, "provider pointer version")?;
    require_digest(&digest, "provider pointer digest")?;
    parse_utc_timestamp(&retention)?;
    let mut canonical = String::from("{\n  \"schemaVersion\": 1,\n  \"receiptKey\": ");
    push_json(&mut canonical, &key);
    for (field, value) in [
        ("receiptVersion", version.as_str()),
        ("receiptSha256", digest.as_str()),
        ("retentionUntil", retention.as_str()),
    ] {
        canonical.push_str(",\n  \"");
        canonical.push_str(field);
        canonical.push_str("\": ");
        push_json(&mut canonical, value);
    }
    canonical.push_str("\n}\n");
    if canonical != document {
        return Err("provider pointer is not exact canonical JSON".to_owned());
    }
    Ok((key, version, digest, retention))
}

fn workflow_packet(action: &str) -> Result<String, String> {
    let inputs = crate::assurance::github_dispatch_object(CUSTODY_DISPATCH_KEYS)?;
    let upload = action == "workflow-upload-packet";
    let input = if upload {
        component_path(["ci-out", "upload-receipt.json"])
    } else {
        component_path(["ci-out", "custody", "current", "copy-record.json"])
    };
    let receipt = fs::read_to_string(&input)
        .map_err(|error| format!("cannot read {}: {error}", input.display()))?;
    let provider_subject =
        quoted_field(&receipt, if upload { "uploadedBy" } else { "retrievedBy" })?;
    require_atom(&provider_subject, "custody provider packet subject")?;
    packet(&Options {
        input: Some(input),
        output: Some(if upload {
            component_path(["ci-out", "upload-receipt-packet.json"])
        } else {
            component_path(["ci-out", "custody", "current", "provider-packet.json"])
        }),
        role: Some("custody-provider".to_owned()),
        reviewer: Some(format!("custody-provider:{provider_subject}")),
        issued_at: inputs.get("review_issued_at").cloned(),
        ..Options::default()
    })
}

fn workflow_review_packet() -> Result<String, String> {
    let inputs = crate::assurance::github_dispatch_object(CUSTODY_DISPATCH_KEYS)?;
    packet(&Options {
        input: Some(component_path(["ci-out", "custody", "review-core.json"])),
        output: Some(component_path(["ci-out", "custody", "review-packet.json"])),
        role: Some("custody-reviewer".to_owned()),
        reviewer: Some("custody-reviewer:two-provider-review".to_owned()),
        issued_at: inputs.get("review_issued_at").cloned(),
        ..Options::default()
    })
}

fn workflow_maintenance(action: &str) -> Result<String, String> {
    if action == "workflow-maintenance-packet" {
        let provider = workflow_provider(false)?;
        let receipt = [
            component_path(["ci-out", "custody-maintenance", "scrub-receipt.json"]),
            component_path(["ci-out", "custody-maintenance", "recovery-receipt.json"]),
        ]
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| "custody maintenance receipt is unavailable".to_owned())?;
        return packet(&Options {
            input: Some(receipt),
            output: Some(component_path([
                "ci-out",
                "custody-maintenance-packet.json",
            ])),
            role: Some("custody-provider".to_owned()),
            reviewer: Some(format!(
                "custody-provider:{}-maintenance",
                provider.provider
            )),
            ..Options::default()
        });
    }
    let mut options = Options {
        input: Some(workflow_active_receipt()?),
        output: Some(component_path(["ci-out", "custody-maintenance"])),
        policy: Some(component_path(["compat", "custody-policy.toml"])),
        ..Options::default()
    };
    apply_workflow_provider(&mut options, workflow_provider(false)?);
    let result = retrieve(
        &options,
        if action == "workflow-scrub" {
            "scrub"
        } else {
            "recovery"
        },
    )?;
    workflow_active_activation()?;
    Ok(result)
}

fn workflow_surveillance_retrieve() -> Result<String, String> {
    let observed_at = current_utc_timestamp()?;
    let (observer_candidate, observer_epoch) = crate::assurance::epoch(Path::new("."))?;
    let retrieval = surveillance_retrieval(&observer_candidate, &observer_epoch.hex());
    let scrub_path = component_path(["ci-out", "custody-maintenance", "scrub-receipt.json"]);
    let scrub_sha256 = if retrieval.result == "pass" {
        sha256_file(&scrub_path)
            .map_err(|error| error.to_string())?
            .hex()
    } else {
        empty_digest()
    };
    let output = surveillance_observation_json(&retrieval, &observed_at, &scrub_sha256);
    write_atomic(
        &component_path(["ci-out", "custody-maintenance", "provider-observation.json"]),
        output.as_bytes(),
    )?;
    Ok(format!(
        "recorded signed-custody surveillance input with result {}",
        retrieval.result
    ))
}

struct SurveillanceRetrieval {
    provider: String,
    trust_domain: String,
    candidate: String,
    epoch: String,
    manifest: String,
    subject_known: bool,
    transition: Option<RetrievedTransition>,
    result: &'static str,
    failure: Option<String>,
}

fn surveillance_retrieval(observer_candidate: &str, observer_epoch: &str) -> SurveillanceRetrieval {
    match workflow_provider(true) {
        Ok(provider) => {
            let outcome = require_provider_activation_visibility(&provider)
                .and_then(|()| workflow_current_transition(&provider))
                .and_then(|transition| {
                    workflow_maintenance("workflow-scrub")?;
                    Ok(transition)
                });
            match outcome {
                Ok(transition) => SurveillanceRetrieval {
                    provider: provider.provider,
                    trust_domain: provider.trust_domain,
                    candidate: provider.active_candidate,
                    epoch: provider.active_epoch,
                    manifest: provider.active_manifest,
                    subject_known: true,
                    transition,
                    result: "pass",
                    failure: None,
                },
                Err(error) => SurveillanceRetrieval {
                    provider: provider.provider,
                    trust_domain: provider.trust_domain,
                    candidate: provider.active_candidate,
                    epoch: provider.active_epoch,
                    manifest: provider.active_manifest,
                    subject_known: true,
                    transition: None,
                    result: "fail",
                    failure: Some(error),
                },
            }
        }
        Err(error) => SurveillanceRetrieval {
            provider: "unknown-provider".to_owned(),
            trust_domain: "unknown-trust-domain".to_owned(),
            candidate: observer_candidate.to_owned(),
            epoch: observer_epoch.to_owned(),
            manifest: sha256_bytes(b"unavailable-active-manifest").hex(),
            subject_known: false,
            transition: None,
            result: "fail",
            failure: Some(error),
        },
    }
}

fn require_provider_activation_visibility(provider: &WorkflowProvider) -> Result<(), String> {
    match (
        std::env::var("GITHUB_EVENT_NAME").as_deref(),
        provider.activation_public_state.as_str(),
    ) {
        (Ok("workflow_dispatch"), "pending-publication" | "completed-publication")
        | (Ok("schedule"), "completed-publication") => Ok(()),
        _ => Err("provider activation is not finalized for this surveillance event".to_owned()),
    }
}

fn surveillance_observation_json(
    retrieval: &SurveillanceRetrieval,
    observed_at: &str,
    scrub_sha256: &str,
) -> String {
    let failure_code = if retrieval.failure.is_some() {
        if retrieval.subject_known {
            "custody-scrub-failed"
        } else {
            "provider-context-invalid"
        }
    } else {
        "none"
    };
    let failure_sha256 = retrieval
        .failure
        .as_deref()
        .map_or_else(empty_digest, |value| sha256_bytes(value.as_bytes()).hex());
    let transition_record_sha256 = retrieval
        .transition
        .as_ref()
        .map_or_else(empty_digest, |value| value.record_sha256.clone());
    let transition_packet_sha256 = retrieval
        .transition
        .as_ref()
        .map_or_else(empty_digest, |value| value.packet_sha256.clone());
    let transition_dsse_sha256 = retrieval
        .transition
        .as_ref()
        .map_or_else(empty_digest, |value| value.dsse_sha256.clone());
    let transition_supersedes_sha256 = retrieval
        .transition
        .as_ref()
        .map_or_else(empty_digest, |value| value.supersedes_sha256.clone());
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("provider", retrieval.provider.as_str()),
        ("trustDomain", retrieval.trust_domain.as_str()),
        ("candidateCommit", retrieval.candidate.as_str()),
        ("assuranceEpochSha256", retrieval.epoch.as_str()),
        ("manifestSha256", retrieval.manifest.as_str()),
        ("observedAt", observed_at),
        ("result", retrieval.result),
        ("failureCode", failure_code),
        ("failureSha256", failure_sha256.as_str()),
        (
            "scrubReceiptPath",
            "ci-out/custody-maintenance/scrub-receipt.json",
        ),
        ("scrubReceiptSha256", scrub_sha256),
        (
            "transitionRecordPath",
            "ci-out/custody-maintenance/transition/promotion-transition.json",
        ),
        ("transitionRecordSha256", transition_record_sha256.as_str()),
        (
            "transitionPacketPath",
            "ci-out/custody-maintenance/transition/promotion-transition-packet.json",
        ),
        ("transitionPacketSha256", transition_packet_sha256.as_str()),
        (
            "transitionDssePath",
            "ci-out/custody-maintenance/transition/promotion-transition.dsse.json",
        ),
        ("transitionDsseSha256", transition_dsse_sha256.as_str()),
        (
            "transitionDerivedState",
            retrieval
                .transition
                .as_ref()
                .map_or("initial-activation", |value| value.derived_state.as_str()),
        ),
        (
            "transitionObservedAt",
            retrieval
                .transition
                .as_ref()
                .map_or(observed_at, |value| value.observed_at.as_str()),
        ),
        (
            "transitionSupersedesSha256",
            transition_supersedes_sha256.as_str(),
        ),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    write!(
        output,
        ",\n  \"subjectKnown\": {},\n  \"transitionAvailable\": {}",
        retrieval.subject_known,
        retrieval.transition.is_some()
    )
    .expect("writing to String cannot fail");
    output.push_str("\n}\n");
    output
}

fn empty_digest() -> String {
    sha256_bytes(b"").hex()
}

struct RetrievedTransition {
    record_sha256: String,
    packet_sha256: String,
    dsse_sha256: String,
    derived_state: String,
    observed_at: String,
    supersedes_sha256: String,
}

fn workflow_current_transition(
    provider: &WorkflowProvider,
) -> Result<Option<RetrievedTransition>, String> {
    let Some(context) = provider.current_transition.as_ref() else {
        return Ok(None);
    };
    let directory = component_path(["ci-out", "custody-maintenance", "transition"]);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create current transition directory: {error}"))?;
    let objects = [
        (
            context.record_key.as_str(),
            context.record_version.as_str(),
            context.record_sha256.as_str(),
            directory.join("promotion-transition.json"),
        ),
        (
            context.packet_key.as_str(),
            context.packet_version.as_str(),
            context.packet_sha256.as_str(),
            directory.join("promotion-transition-packet.json"),
        ),
        (
            context.dsse_key.as_str(),
            context.dsse_version.as_str(),
            context.dsse_sha256.as_str(),
            directory.join("promotion-transition.dsse.json"),
        ),
    ];
    for (key, version, digest, output) in &objects {
        get_object(&provider.bucket, key, version, output)?;
        if sha256_file(output)
            .map_err(|error| error.to_string())?
            .hex()
            != *digest
        {
            return Err("current signed transition object digest mismatch".to_owned());
        }
    }
    crate::surveillance_ops::verify_transition(&objects[0].3)?;
    let record = fs::read_to_string(&objects[0].3)
        .map_err(|error| format!("cannot read current transition record: {error}"))?;
    let packet = fs::read_to_string(&objects[1].3)
        .map_err(|error| format!("cannot read current transition packet: {error}"))?;
    if quoted_field(&record, "candidateCommit")? != provider.active_candidate
        || quoted_field(&record, "assuranceEpochSha256")? != provider.active_epoch
        || !packet.contains(&format!("\"{}\"", context.record_sha256))
    {
        return Err("current transition does not bind the active provider subject".to_owned());
    }
    let status = Command::new(
        std::env::current_exe().map_err(|error| format!("cannot locate hell-ci: {error}"))?,
    )
    .args([
        OsStr::new("review-verify"),
        OsStr::new("--input"),
        objects[2].3.as_os_str(),
        OsStr::new("--policy"),
        OsStr::new("compat/reviews.allowed_signers"),
        OsStr::new("--role"),
        OsStr::new("custody-reviewer"),
    ])
    .status()
    .map_err(|error| format!("cannot verify current transition DSSE: {error}"))?;
    if !status.success() {
        return Err("current transition DSSE verification failed".to_owned());
    }
    Ok(Some(RetrievedTransition {
        record_sha256: context.record_sha256.clone(),
        packet_sha256: context.packet_sha256.clone(),
        dsse_sha256: context.dsse_sha256.clone(),
        derived_state: quoted_field(&record, "derivedState")?,
        observed_at: quoted_field(&record, "observedAt")?,
        supersedes_sha256: quoted_field(&record, "supersedesSha256")?,
    }))
}

fn workflow_active_activation() -> Result<(), String> {
    let provider = workflow_provider(true)?;
    let directory = component_path(["ci-out", "custody-maintenance", "activation"]);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create activation retrieval directory: {error}"))?;
    let objects = [
        (
            provider.active_activation_record_key.as_str(),
            provider.active_activation_record_version.as_str(),
            provider.active_activation_record_sha256.as_str(),
            directory.join("activation-receipt.json"),
        ),
        (
            provider.active_activation_packet_key.as_str(),
            provider.active_activation_packet_version.as_str(),
            provider.active_activation_packet_sha256.as_str(),
            directory.join("activation-packet.json"),
        ),
        (
            provider.active_activation_dsse_key.as_str(),
            provider.active_activation_dsse_version.as_str(),
            provider.active_activation_dsse_sha256.as_str(),
            directory.join("activation-receipt.dsse.json"),
        ),
    ];
    for (key, version, digest, output) in &objects {
        get_object(&provider.bucket, key, version, output)?;
        if sha256_file(output)
            .map_err(|error| error.to_string())?
            .hex()
            != *digest
        {
            return Err("active signed activation object digest mismatch".to_owned());
        }
    }
    let record = fs::read_to_string(&objects[0].3)
        .map_err(|error| format!("cannot read active activation record: {error}"))?;
    let packet = fs::read_to_string(&objects[1].3)
        .map_err(|error| format!("cannot read active activation packet: {error}"))?;
    let record_digest = sha256_bytes(record.as_bytes()).hex();
    if quoted_field(&record, "provider")? != provider.provider
        || !packet.contains(&format!("\"{record_digest}\""))
    {
        return Err("active activation packet does not bind provider record".to_owned());
    }
    let status = Command::new(
        std::env::current_exe().map_err(|error| format!("cannot locate hell-ci: {error}"))?,
    )
    .args([
        OsStr::new("review-verify"),
        OsStr::new("--input"),
        objects[2].3.as_os_str(),
        OsStr::new("--policy"),
        OsStr::new("compat/reviews.allowed_signers"),
        OsStr::new("--role"),
        OsStr::new("custody-provider"),
    ])
    .status()
    .map_err(|error| format!("cannot verify active activation DSSE: {error}"))?;
    if !status.success() {
        return Err("active activation DSSE verification failed".to_owned());
    }
    Ok(())
}

fn workflow_active_receipt() -> Result<PathBuf, String> {
    let provider = workflow_provider(true)?;
    let path = component_path(["ci-out", "active-upload-receipt.json"]);
    get_object(
        &provider.bucket,
        &provider.active_receipt_key,
        &provider.active_receipt_version,
        &path,
    )?;
    if sha256_file(&path).map_err(|error| error.to_string())?.hex()
        != provider.active_receipt_sha256
    {
        return Err("active custody upload receipt digest mismatch".to_owned());
    }
    let document = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read active custody upload receipt: {error}"))?;
    parse_upload_receipt(&document)?;
    Ok(path)
}

fn apply_workflow_provider(options: &mut Options, provider: WorkflowProvider) {
    options.provider = Some(provider.provider);
    options.trust_domain = Some(provider.trust_domain);
    options.bucket = Some(provider.bucket);
}

fn parse(arguments: &[OsString]) -> Result<(String, Options), String> {
    let action = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(|| "custody-ops requires an action".to_owned())?
        .to_owned();
    let mut options = Options::default();
    let mut index = 2;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "custody-ops option must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag {
            "--input" => set_path(&mut options.input, value, flag)?,
            "--output" => set_path(&mut options.output, value, flag)?,
            "--provider" => set_text(&mut options.provider, value, flag)?,
            "--trust-domain" => set_text(&mut options.trust_domain, value, flag)?,
            "--bucket" => set_text(&mut options.bucket, value, flag)?,
            "--candidate" => set_text(&mut options.candidate, value, flag)?,
            "--epoch" => set_text(&mut options.epoch, value, flag)?,
            "--epoch-file" => set_path(&mut options.epoch_file, value, flag)?,
            "--retention-until" => set_text(&mut options.retention_until, value, flag)?,
            "--policy" => set_path(&mut options.policy, value, flag)?,
            "--role" => set_text(&mut options.role, value, flag)?,
            "--reviewer" => set_text(&mut options.reviewer, value, flag)?,
            "--issued-at" => set_text(&mut options.issued_at, value, flag)?,
            "--first" => set_path(&mut options.first, value, flag)?,
            "--second" => set_path(&mut options.second, value, flag)?,
            "--first-receipt" => set_path(&mut options.first_receipt, value, flag)?,
            "--second-receipt" => set_path(&mut options.second_receipt, value, flag)?,
            "--review" => set_path(&mut options.review, value, flag)?,
            "--expected" => set_text(&mut options.expected, value, flag)?,
            "--run-id" => set_text(&mut options.run_id, value, flag)?,
            "--run-attempt" => set_text(&mut options.run_attempt, value, flag)?,
            "--artifact-id" => set_text(&mut options.artifact_id, value, flag)?,
            _ => return Err(format!("unknown custody-ops option {flag:?}")),
        }
        index += 2;
    }
    Ok((action, options))
}

fn verify_source(options: &Options) -> Result<String, String> {
    let input = required_path(options.input.as_ref(), "--input")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    let expected = required_text(options.expected.as_ref(), "--expected")?;
    require_digest(expected, "source artifact directory digest")?;
    let candidate = required_text(options.candidate.as_ref(), "--candidate")?;
    require_git_sha(candidate, "source artifact candidate")?;
    let run_id = require_nonzero_u64(
        required_text(options.run_id.as_ref(), "--run-id")?,
        "run ID",
    )?;
    let run_attempt = require_nonzero_u64(
        required_text(options.run_attempt.as_ref(), "--run-attempt")?,
        "run attempt",
    )?;
    let artifact_id = require_nonzero_u64(
        required_text(options.artifact_id.as_ref(), "--artifact-id")?,
        "artifact ID",
    )?;
    let observed = sha256_bytes(assurance_directory_manifest(input)?.as_bytes()).hex();
    if observed != expected {
        return Err("downloaded custody source artifact directory digest mismatch".to_owned());
    }
    let record = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"candidateCommit\": \"{candidate}\",\n  \"runId\": {run_id},\n  \"runAttempt\": {run_attempt},\n  \"providerArtifactId\": {artifact_id},\n  \"directorySha256\": \"{observed}\",\n  \"selectionState\": \"exact-provider-object\"\n}}\n"
    );
    write_atomic(output, record.as_bytes())?;
    Ok(format!(
        "verified exact custody source artifact selection {}",
        output.display()
    ))
}

fn require_nonzero_u64(value: &str, label: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("{label} must be a nonzero integer"))
}

fn packet(options: &Options) -> Result<String, String> {
    let input = required_path(options.input.as_ref(), "--input")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    let role = required_text(options.role.as_ref(), "--role")?;
    let reviewer = required_text(options.reviewer.as_ref(), "--reviewer")?;
    let generated_issued_at;
    let issued_at = if let Some(issued_at) = options.issued_at.as_deref() {
        issued_at
    } else {
        generated_issued_at = current_utc_timestamp()?;
        &generated_issued_at
    };
    if !matches!(role, "custody-provider" | "custody-reviewer")
        || !reviewer.starts_with(&format!("{role}:"))
    {
        return Err("custody packet reviewer does not match an authorized role".to_owned());
    }
    parse_utc_timestamp(issued_at)?;
    let document = fs::read_to_string(input).map_err(|error| {
        format!(
            "cannot read custody packet input {}: {error}",
            input.display()
        )
    })?;
    let candidate = quoted_field(&document, "candidateCommit")?;
    let epoch = quoted_field(&document, "assuranceEpochSha256")?;
    let emergency_transition = document.starts_with("{\n  \"schemaVersion\": 2,")
        && document.contains("\"derivedState\": \"at-risk\"");
    let manifest = if emergency_transition {
        None
    } else {
        Some(quoted_field(&document, "manifestSha256")?)
    };
    let input_digest = sha256_bytes(document.as_bytes()).hex();
    for (label, digest) in [
        ("packet epoch", epoch.as_str()),
        ("packet input", input_digest.as_str()),
    ] {
        require_digest(digest, label)?;
    }
    if let Some(manifest) = manifest.as_deref() {
        require_digest(manifest, "packet manifest")?;
    }
    let artifacts = packet_artifacts(
        input,
        &document,
        role,
        emergency_transition,
        manifest,
        input_digest,
    )?;
    let artifact_identity = artifacts.join("\n");
    let review_id = sha256_bytes(
        [
            candidate.as_bytes(),
            epoch.as_bytes(),
            role.as_bytes(),
            artifact_identity.as_bytes(),
        ]
        .concat()
        .as_slice(),
    )
    .hex();
    let result = packet_json(
        &review_id, role, reviewer, &candidate, &epoch, &artifacts, issued_at,
    );
    write_atomic(output, result.as_bytes())?;
    Ok(format!(
        "wrote content-bound {role} custody packet at {}",
        output.display()
    ))
}

fn packet_artifacts(
    input: &Path,
    document: &str,
    role: &str,
    emergency_transition: bool,
    manifest: Option<String>,
    input_digest: String,
) -> Result<Vec<String>, String> {
    let mut artifacts = manifest
        .into_iter()
        .chain([input_digest])
        .collect::<Vec<_>>();
    if input.file_name() == Some(OsStr::new("upload-receipt.json")) {
        let pointer = input.with_file_name("upload-receipt-provider-pointer.json");
        artifacts.push(
            sha256_file(&pointer)
                .map_err(|error| format!("cannot hash {}: {error}", pointer.display()))?
                .hex(),
        );
    }
    if role == "custody-provider" && document.contains("\"contentSha256\":") {
        validate_copy_record(document)?;
        artifacts.push(copy_core_digest(document)?);
    } else if role == "custody-reviewer" && emergency_transition {
        for field in [
            "primaryObservationSha256",
            "secondaryObservationSha256",
            "surveillancePolicySha256",
            "failureSha256",
            "supersedesSha256",
        ] {
            artifacts.push(quoted_field(document, field)?);
        }
    } else if role == "custody-reviewer" && document.contains("\"derivedState\":") {
        artifacts.push(quoted_field(document, "objectiveInputSha256")?);
        artifacts.push(quoted_field(document, "supersedesSha256")?);
    } else if role == "custody-reviewer" {
        for field in [
            "firstUploadReceiptSha256",
            "secondUploadReceiptSha256",
            "firstProviderReceiptSha256",
            "secondProviderReceiptSha256",
        ] {
            artifacts.push(quoted_field(document, field)?);
        }
    }
    if role == "custody-reviewer" && document.contains("\"derivedState\":") {
        let directory = input
            .parent()
            .ok_or_else(|| "transition packet input has no directory".to_owned())?;
        for name in [
            "compatibility-report.md",
            "accepted-divergences.json",
            "public-release-statement.json",
        ] {
            artifacts.push(public_report_file_digest(&directory.join(name))?);
        }
    }
    Ok(artifacts)
}

fn packet_json(
    review_id: &str,
    role: &str,
    reviewer: &str,
    candidate: &str,
    epoch: &str,
    artifacts: &[String],
    issued_at: &str,
) -> String {
    let mut result = String::from("{\"schemaVersion\":1,\"reviewId\":");
    push_json(&mut result, review_id);
    for (field, value) in [
        ("role", role),
        ("reviewer", reviewer),
        ("decision", "accept"),
        ("candidateCommit", candidate),
        ("assuranceEpochSha256", epoch),
    ] {
        result.push_str(",\"");
        result.push_str(field);
        result.push_str("\":");
        push_json(&mut result, value);
    }
    result.push_str(",\"reviewedArtifacts\":[");
    for (index, artifact) in artifacts.iter().enumerate() {
        if index != 0 {
            result.push(',');
        }
        push_json(&mut result, artifact);
    }
    result.push_str(
        "],\"distinctSubjects\":1,\"independenceViolations\":[],\"findings\":[],\"issuedAt\":",
    );
    push_json(&mut result, issued_at);
    result.push_str("}\n");
    result
}

fn copy_record(options: &Options) -> Result<String, String> {
    let retrieved = required_path(options.input.as_ref(), "--input")?;
    let upload_path = required_path(options.first.as_ref(), "--first")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    retrieved
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "custody"))
        .ok_or_else(|| "retrieved copy is not under a custody retained root".to_owned())?;
    let policy = load_custody_policy(required_path(options.policy.as_ref(), "--policy")?)?;
    verify_package(retrieved)?;
    let upload_document = fs::read_to_string(upload_path).map_err(|error| {
        format!(
            "cannot read upload receipt {}: {error}",
            upload_path.display()
        )
    })?;
    let upload = parse_upload_receipt(&upload_document)?;
    require_minimum_retention(&upload.retention_until, policy.minimum_years)?;
    let retrieval = validated_retrieval(retrieved, &upload_document, &upload)?;
    let scrub_age_days = retrieval.scrub_age_days;
    if scrub_age_days > policy.scrub_interval_days {
        return Err("retrieved custody copy is older than the committed scrub cadence".to_owned());
    }
    let manifest = assurance_directory_manifest(retrieved)?;
    let manifest_sha256 = sha256_bytes(manifest.as_bytes()).hex();
    let upload_receipt_sha256 = sha256_bytes(upload_document.as_bytes()).hex();
    let mut versions = String::new();
    for (digest, object) in &upload.objects {
        writeln!(versions, "{digest} {}", object.version).expect("writing to String cannot fail");
    }
    let object_version = sha256_bytes(versions.as_bytes()).hex();
    let mut record = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", upload.candidate.as_str()),
        ("assuranceEpochSha256", upload.epoch.as_str()),
        ("manifestSha256", manifest_sha256.as_str()),
        ("uploadReceiptSha256", upload_receipt_sha256.as_str()),
        ("accountOrTenant", upload.account_or_tenant.as_str()),
        ("contentSha256", manifest_sha256.as_str()),
        ("objectVersion", object_version.as_str()),
        ("provider", upload.provider.as_str()),
        ("retrievedBy", retrieval.retrieved_by.as_str()),
        (
            "retrievedPath",
            provider_retrieval_path(&upload.provider)?.as_str(),
        ),
        ("retrievedSha256", manifest_sha256.as_str()),
        ("trustDomain", upload.trust_domain.as_str()),
        ("uploadedBy", upload.uploaded_by.as_str()),
        ("uploaderStableId", upload.uploader_stable_id.as_str()),
        ("retrieverStableId", retrieval.retriever_stable_id.as_str()),
    ] {
        record.push_str(",\n  \"");
        record.push_str(field);
        record.push_str("\": ");
        push_json(&mut record, value);
    }
    write!(
        record,
        ",\n  \"retentionYears\": {},\n  \"scrubAgeDays\": {},\n  \"objectLock\": true,\n  \"encryptionAtRest\": true,\n  \"innerManifestValid\": true,\n  \"candidateEpochMatch\": true\n}}\n",
        policy.minimum_years,
        scrub_age_days,
    )
    .expect("writing to String cannot fail");
    write_atomic(output, record.as_bytes())?;
    Ok(format!(
        "wrote provider-derived custody copy record {}",
        output.display()
    ))
}

fn provider_retrieval_path(provider: &str) -> Result<String, String> {
    if provider.is_empty()
        || !provider
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("custody provider is not a portable path component".to_owned());
    }
    path_text(&PathBuf::from(provider).join("retrieved").join("package"))
}

struct ValidatedRetrieval {
    retrieved_by: String,
    retriever_stable_id: String,
    scrub_age_days: u64,
}

#[derive(Clone)]
struct MaintenanceReceipt {
    provider: String,
    trust_domain: String,
    account: String,
    uploaded_by: String,
    retrieved_by: String,
    retriever_stable_id: String,
    candidate: String,
    epoch: String,
    root_sha256: String,
    manifest_sha256: String,
    upload_receipt_sha256: String,
    retention_until: String,
    retrieved_path: String,
    retrieved_at: String,
}

/// Verifies two current provider-signed scrub receipts against one already
/// retained custody gate record.
///
/// # Errors
///
/// Returns an error when a receipt is noncanonical, stale, signed by the wrong
/// role, disagrees with the candidate/epoch/manifest, or fails provider,
/// account, trust-domain, actor, or signer independence.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_current_scrub_set(
    first: &Path,
    first_dsse: &Path,
    second: &Path,
    second_dsse: &Path,
    signer_policy: &Path,
    custody_receipt: &Path,
    candidate: &str,
    epoch: &str,
    max_age_days: u64,
) -> Result<String, String> {
    let custody = fs::read_to_string(custody_receipt)
        .map_err(|error| format!("cannot read current custody receipt: {error}"))?;
    if quoted_field(&custody, "candidateCommit")? != candidate
        || quoted_field(&custody, "assuranceEpochSha256")? != epoch
    {
        return Err("current scrub set disagrees with custody candidate or epoch".to_owned());
    }
    let manifest = quoted_field(&custody, "manifestSha256")?;
    let first = verify_maintenance_receipt(
        first,
        first_dsse,
        signer_policy,
        candidate,
        epoch,
        &manifest,
        max_age_days,
    )?;
    let second = verify_maintenance_receipt(
        second,
        second_dsse,
        signer_policy,
        candidate,
        epoch,
        &manifest,
        max_age_days,
    )?;
    require_scrub_independence(&first, &second)?;
    verify_scrubs_match_custody_copies(custody_receipt, &custody, [&first.0, &second.0])?;
    let identity = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n",
        sha256_file(first_dsse)
            .map_err(|error| error.to_string())?
            .hex(),
        sha256_file(second_dsse)
            .map_err(|error| error.to_string())?
            .hex(),
        first.0.provider,
        first.1,
        second.0.provider,
        second.1,
    );
    Ok(sha256_bytes(identity.as_bytes()).hex())
}

fn verify_scrubs_match_custody_copies(
    custody_path: &Path,
    custody: &str,
    receipts: [&MaintenanceReceipt; 2],
) -> Result<(), String> {
    let copies = custody_copy_documents(custody)?;
    if copies.len() != receipts.len() {
        return Err("current custody receipt does not contain exactly two copies".to_owned());
    }
    let retained_root = custody_path
        .parent()
        .ok_or_else(|| "current custody receipt has no retained root".to_owned())?;
    let package = safe_retained_path(retained_root, &quoted_field(custody, "packageRoot")?)?;
    let root = fs::read_to_string(package.join("root.sha256"))
        .map_err(|error| format!("cannot read retained custody package root: {error}"))?;
    for receipt in receipts {
        let matching = copies
            .iter()
            .filter(|copy| quoted_field(copy, "provider") == Ok(receipt.provider.clone()))
            .collect::<Vec<_>>();
        let [copy] = matching.as_slice() else {
            return Err("current scrub does not select exactly one custody copy".to_owned());
        };
        for (field, expected) in [
            ("trustDomain", receipt.trust_domain.as_str()),
            ("accountOrTenant", receipt.account.as_str()),
            ("uploadedBy", receipt.uploaded_by.as_str()),
            ("retrievedBy", receipt.retrieved_by.as_str()),
            ("retrieverStableId", receipt.retriever_stable_id.as_str()),
            ("retrievedPath", receipt.retrieved_path.as_str()),
            (
                "uploadReceiptSha256",
                receipt.upload_receipt_sha256.as_str(),
            ),
        ] {
            if quoted_field(copy, field)? != expected {
                return Err(format!("current scrub disagrees with custody copy {field}"));
            }
        }
        if root.trim() != receipt.root_sha256 {
            return Err("current scrub package root differs from custody package".to_owned());
        }
        let upload_path =
            safe_retained_path(retained_root, &quoted_field(copy, "uploadReceiptPath")?)?;
        let upload = fs::read_to_string(upload_path)
            .map_err(|error| format!("cannot read retained custody upload receipt: {error}"))?;
        if quoted_field(&upload, "retentionUntil")? != receipt.retention_until {
            return Err("current scrub retention differs from custody upload".to_owned());
        }
    }
    Ok(())
}

fn safe_retained_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("custody retained path is not canonical and relative".to_owned());
    }
    Ok(root.join(relative))
}

fn custody_copy_documents(document: &str) -> Result<Vec<String>, String> {
    let marker = "\"copies\": [";
    let mut remaining = document
        .split_once(marker)
        .map(|(_, remaining)| remaining)
        .ok_or_else(|| "current custody receipt lacks copies".to_owned())?;
    let mut copies = Vec::new();
    loop {
        remaining =
            remaining.trim_start_matches(|value: char| value.is_whitespace() || value == ',');
        if remaining.starts_with(']') {
            break;
        }
        if !remaining.starts_with('{') {
            return Err("current custody copy is not an object".to_owned());
        }
        let mut depth = 0_u64;
        let mut in_string = false;
        let mut escaped = false;
        let mut end = None;
        for (index, character) in remaining.char_indices() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    in_string = false;
                }
                continue;
            }
            match character {
                '"' => in_string = true,
                '{' => depth = depth.saturating_add(1),
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = Some(index + character.len_utf8());
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.ok_or_else(|| "current custody copy object is unterminated".to_owned())?;
        copies.push(remaining[..end].to_owned());
        remaining = &remaining[end..];
    }
    Ok(copies)
}

fn verify_maintenance_receipt(
    path: &Path,
    dsse: &Path,
    signer_policy: &Path,
    candidate: &str,
    epoch: &str,
    manifest: &str,
    max_age_days: u64,
) -> Result<(MaintenanceReceipt, String, String), String> {
    let document = fs::read_to_string(path)
        .map_err(|error| format!("cannot read maintenance receipt: {error}"))?;
    let receipt = parse_maintenance_receipt(&document)?;
    if receipt.candidate != candidate
        || receipt.epoch != epoch
        || receipt.manifest_sha256 != manifest
        || observation_age_days(&receipt.retrieved_at)? > max_age_days
    {
        return Err("maintenance receipt is stale or has the wrong subject".to_owned());
    }
    let artifacts = BTreeSet::from([
        receipt.manifest_sha256.clone(),
        sha256_bytes(document.as_bytes()).hex(),
    ]);
    let (subject, fingerprint) = crate::assurance::verify_review_binding(
        dsse,
        signer_policy,
        "custody-provider",
        candidate,
        epoch,
        &artifacts,
    )?;
    Ok((receipt, subject, fingerprint))
}

fn require_scrub_independence(
    first: &(MaintenanceReceipt, String, String),
    second: &(MaintenanceReceipt, String, String),
) -> Result<(), String> {
    for (label, first, second) in [
        (
            "provider",
            first.0.provider.as_str(),
            second.0.provider.as_str(),
        ),
        (
            "trust domain",
            first.0.trust_domain.as_str(),
            second.0.trust_domain.as_str(),
        ),
        (
            "account",
            first.0.account.as_str(),
            second.0.account.as_str(),
        ),
        (
            "retriever stable ID",
            first.0.retriever_stable_id.as_str(),
            second.0.retriever_stable_id.as_str(),
        ),
        ("subject", first.1.as_str(), second.1.as_str()),
        ("signer fingerprint", first.2.as_str(), second.2.as_str()),
    ] {
        if first == second {
            return Err(format!("current scrub providers share one {label}"));
        }
    }
    for receipt in [&first.0, &second.0] {
        if receipt.uploaded_by == receipt.retrieved_by {
            return Err("current scrub uploader and retriever are identical".to_owned());
        }
    }
    Ok(())
}

fn parse_maintenance_receipt(document: &str) -> Result<MaintenanceReceipt, String> {
    let receipt = MaintenanceReceipt {
        provider: quoted_field(document, "provider")?,
        trust_domain: quoted_field(document, "trustDomain")?,
        account: quoted_field(document, "accountOrTenant")?,
        uploaded_by: quoted_field(document, "uploadedBy")?,
        retrieved_by: quoted_field(document, "retrievedBy")?,
        retriever_stable_id: quoted_field(document, "retrieverStableId")?,
        candidate: quoted_field(document, "candidateCommit")?,
        epoch: quoted_field(document, "assuranceEpochSha256")?,
        root_sha256: quoted_field(document, "packageRootSha256")?,
        manifest_sha256: quoted_field(document, "manifestSha256")?,
        upload_receipt_sha256: quoted_field(document, "uploadReceiptSha256")?,
        retention_until: quoted_field(document, "retentionUntil")?,
        retrieved_path: quoted_field(document, "retrievedPath")?,
        retrieved_at: quoted_field(document, "retrievedAt")?,
    };
    if quoted_field(document, "kind")? != "scrub"
        || quoted_field(document, "state")? != "retrieved-and-verified"
        || unsigned_field(document, "schemaVersion")? != 1
    {
        return Err("maintenance receipt kind, state, or schema is invalid".to_owned());
    }
    for field in [
        "outerDigestValid",
        "innerManifestValid",
        "candidateEpochMatch",
        "objectLockValid",
    ] {
        if boolean_field(document, field)? != "true" {
            return Err(format!("maintenance receipt {field} is not true"));
        }
    }
    require_git_sha(&receipt.candidate, "maintenance candidate")?;
    for (label, value) in [
        ("maintenance epoch", receipt.epoch.as_str()),
        ("maintenance root", receipt.root_sha256.as_str()),
        ("maintenance manifest", receipt.manifest_sha256.as_str()),
        (
            "maintenance upload receipt",
            receipt.upload_receipt_sha256.as_str(),
        ),
    ] {
        require_digest(value, label)?;
    }
    for (label, value) in [
        ("maintenance provider", receipt.provider.as_str()),
        ("maintenance trust domain", receipt.trust_domain.as_str()),
        ("maintenance account", receipt.account.as_str()),
        (
            "maintenance retriever stable ID",
            receipt.retriever_stable_id.as_str(),
        ),
    ] {
        require_atom(value, label)?;
    }
    parse_utc_timestamp(&receipt.retention_until)?;
    parse_utc_timestamp(&receipt.retrieved_at)?;
    let canonical = canonical_maintenance_receipt(&receipt);
    if canonical != document {
        return Err(
            "maintenance receipt is not exact canonical JSON or has unknown/duplicate fields"
                .to_owned(),
        );
    }
    Ok(receipt)
}

fn canonical_maintenance_receipt(receipt: &MaintenanceReceipt) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"kind\": \"scrub\"");
    for (field, value) in [
        ("provider", receipt.provider.as_str()),
        ("trustDomain", receipt.trust_domain.as_str()),
        ("accountOrTenant", receipt.account.as_str()),
        ("uploadedBy", receipt.uploaded_by.as_str()),
        ("retrievedBy", receipt.retrieved_by.as_str()),
        ("retrieverStableId", receipt.retriever_stable_id.as_str()),
        ("candidateCommit", receipt.candidate.as_str()),
        ("assuranceEpochSha256", receipt.epoch.as_str()),
        ("packageRootSha256", receipt.root_sha256.as_str()),
        ("manifestSha256", receipt.manifest_sha256.as_str()),
        (
            "uploadReceiptSha256",
            receipt.upload_receipt_sha256.as_str(),
        ),
        ("retentionUntil", receipt.retention_until.as_str()),
        ("retrievedPath", receipt.retrieved_path.as_str()),
        ("retrievedAt", receipt.retrieved_at.as_str()),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str(",\n  \"outerDigestValid\": true,\n  \"innerManifestValid\": true,\n  \"candidateEpochMatch\": true,\n  \"objectLockValid\": true,\n  \"state\": \"retrieved-and-verified\"\n}\n");
    output
}

fn validated_retrieval(
    retrieved: &Path,
    upload_document: &str,
    upload: &UploadReceipt,
) -> Result<ValidatedRetrieval, String> {
    let retrieval_path = retrieved
        .parent()
        .ok_or_else(|| "retrieved package has no receipt directory".to_owned())?
        .join("retrieval-receipt.json");
    let retrieval = fs::read_to_string(&retrieval_path).map_err(|error| {
        format!(
            "cannot read retrieval receipt {}: {error}",
            retrieval_path.display()
        )
    })?;
    let retrieved_at = quoted_field(&retrieval, "retrievedAt")?;
    parse_utc_timestamp(&retrieved_at)?;
    for (field, expected) in [
        ("candidateCommit", upload.candidate.as_str()),
        ("assuranceEpochSha256", upload.epoch.as_str()),
        ("provider", upload.provider.as_str()),
        ("trustDomain", upload.trust_domain.as_str()),
        ("accountOrTenant", upload.account_or_tenant.as_str()),
        ("uploadedBy", upload.uploaded_by.as_str()),
        ("manifestSha256", upload.manifest_sha256.as_str()),
        ("retentionUntil", upload.retention_until.as_str()),
    ] {
        if quoted_field(&retrieval, field)? != expected {
            return Err(format!("retrieval receipt does not preserve {field}"));
        }
    }
    let retrieved_by = quoted_field(&retrieval, "retrievedBy")?;
    let retriever_stable_id = quoted_field(&retrieval, "retrieverStableId")?;
    if upload.uploaded_by == retrieved_by {
        return Err("custody upload and retrieval principals are identical".to_owned());
    }
    let canonical = retrieval_receipt_json(
        "retrieval",
        &ProviderIdentity {
            provider: &upload.provider,
            trust_domain: &upload.trust_domain,
            bucket: &upload.bucket,
        },
        upload,
        &ProviderSubject {
            account: upload.account_or_tenant.clone(),
            arn: retrieved_by.clone(),
            stable_id: retriever_stable_id.clone(),
        },
        sha256_bytes(upload_document.as_bytes()),
        &upload.candidate,
        &upload.epoch,
        Digest::from_hex(&upload.root_sha256).map_err(str::to_owned)?,
        retrieved,
        &retrieved_at,
    )?;
    if canonical != retrieval {
        return Err(
            "retrieval receipt is not exact canonical JSON or contains unknown/duplicate fields"
                .to_owned(),
        );
    }
    Ok(ValidatedRetrieval {
        retrieved_by,
        retriever_stable_id,
        scrub_age_days: observation_age_days(&retrieved_at)?,
    })
}

fn review_core(options: &Options) -> Result<String, String> {
    let package = required_path(options.input.as_ref(), "--input")?;
    let first = required_path(options.first_receipt.as_ref(), "--first-receipt")?;
    let second = required_path(options.second_receipt.as_ref(), "--second-receipt")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    let manifest = assurance_directory_manifest(package)?;
    let manifest_sha256 = sha256_bytes(manifest.as_bytes()).hex();
    let package_manifest = fs::read_to_string(package.join("manifest.json"))
        .map_err(|error| format!("cannot read package identity: {error}"))?;
    let candidate = quoted_field(&package_manifest, "candidateCommit")?;
    let epoch = quoted_field(&package_manifest, "assuranceEpochSha256")?;
    let first_digest = sha256_file(first).map_err(|error| error.to_string())?.hex();
    let second_digest = sha256_file(second)
        .map_err(|error| error.to_string())?
        .hex();
    let first_upload = signed_upload_receipt(first)?;
    let second_upload = signed_upload_receipt(second)?;
    let first_upload_digest = sha256_file(&first_upload)
        .map_err(|error| error.to_string())?
        .hex();
    let second_upload_digest = sha256_file(&second_upload)
        .map_err(|error| error.to_string())?
        .hex();
    let mut record = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", candidate.as_str()),
        ("assuranceEpochSha256", epoch.as_str()),
        ("manifestSha256", manifest_sha256.as_str()),
        ("firstUploadReceiptSha256", first_upload_digest.as_str()),
        ("secondUploadReceiptSha256", second_upload_digest.as_str()),
        ("firstProviderReceiptSha256", first_digest.as_str()),
        ("secondProviderReceiptSha256", second_digest.as_str()),
    ] {
        record.push_str(",\n  \"");
        record.push_str(field);
        record.push_str("\": ");
        push_json(&mut record, value);
    }
    record.push_str("\n}\n");
    write_atomic(output, record.as_bytes())?;
    Ok(format!(
        "wrote two-provider custody review core {}",
        output.display()
    ))
}

fn signed_upload_receipt(provider_receipt: &Path) -> Result<PathBuf, String> {
    let parent = provider_receipt
        .parent()
        .ok_or_else(|| "provider receipt has no retained directory".to_owned())?;
    let path = parent.join("upload").join("upload-receipt.dsse.json");
    if !path.is_file() {
        return Err(format!(
            "provider evidence lacks signed upload receipt {}",
            path.display()
        ));
    }
    Ok(path)
}

fn gate_record(options: &Options) -> Result<String, String> {
    let package = required_path(options.input.as_ref(), "--input")?;
    let first_path = required_path(options.first.as_ref(), "--first")?;
    let second_path = required_path(options.second.as_ref(), "--second")?;
    let first_receipt = required_path(options.first_receipt.as_ref(), "--first-receipt")?;
    let second_receipt = required_path(options.second_receipt.as_ref(), "--second-receipt")?;
    let review = required_path(options.review.as_ref(), "--review")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    let record_root = output
        .parent()
        .ok_or_else(|| "custody gate output has no retained root".to_owned())?;
    let first = fs::read_to_string(first_path)
        .map_err(|error| format!("cannot read first custody copy: {error}"))?;
    let second = fs::read_to_string(second_path)
        .map_err(|error| format!("cannot read second custody copy: {error}"))?;
    validate_copy_record(&first)?;
    validate_copy_record(&second)?;
    for field in ["candidateCommit", "assuranceEpochSha256", "manifestSha256"] {
        if quoted_field(&first, field)? != quoted_field(&second, field)? {
            return Err(format!("custody copies disagree on {field}"));
        }
    }
    for field in [
        "provider",
        "trustDomain",
        "accountOrTenant",
        "retrievedBy",
        "retrievedPath",
        "retrieverStableId",
    ] {
        if quoted_field(&first, field)? == quoted_field(&second, field)? {
            return Err(format!("custody copies are not independent by {field}"));
        }
    }
    if first_receipt == second_receipt {
        return Err("custody providers reuse one signed receipt".to_owned());
    }
    let manifest = assurance_directory_manifest(package)?;
    let manifest_sha256 = sha256_bytes(manifest.as_bytes()).hex();
    if quoted_field(&first, "manifestSha256")? != manifest_sha256 {
        return Err("custody copies do not bind the packaged directory manifest".to_owned());
    }
    let manifest_path = output.with_file_name("custody-manifest.json");
    write_atomic(&manifest_path, manifest.as_bytes())?;
    let candidate = quoted_field(&first, "candidateCommit")?;
    let epoch = quoted_field(&first, "assuranceEpochSha256")?;
    let first_receipt_digest = sha256_file(first_receipt)
        .map_err(|error| error.to_string())?
        .hex();
    let second_receipt_digest = sha256_file(second_receipt)
        .map_err(|error| error.to_string())?
        .hex();
    let review_digest = sha256_file(review)
        .map_err(|error| error.to_string())?
        .hex();
    let mut record = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", candidate.as_str()),
        ("assuranceEpochSha256", epoch.as_str()),
        (
            "manifestPath",
            retained_relative(record_root, &manifest_path)?.as_str(),
        ),
        ("manifestSha256", manifest_sha256.as_str()),
        (
            "packageRoot",
            retained_relative(record_root, package)?.as_str(),
        ),
        (
            "reviewPath",
            retained_relative(record_root, review)?.as_str(),
        ),
        ("reviewSha256", review_digest.as_str()),
    ] {
        record.push_str(",\n  \"");
        record.push_str(field);
        record.push_str("\": ");
        push_json(&mut record, value);
    }
    record.push_str(",\n  \"copies\": [\n");
    record.push_str(&gate_copy_json(
        &first,
        first_receipt,
        &first_receipt_digest,
        record_root,
    )?);
    record.push_str(",\n");
    record.push_str(&gate_copy_json(
        &second,
        second_receipt,
        &second_receipt_digest,
        record_root,
    )?);
    record.push_str("\n  ]\n}\n");
    write_atomic(output, record.as_bytes())?;
    Ok(format!(
        "wrote exact two-provider custody gate record {}",
        output.display()
    ))
}

fn gate_copy_json(
    document: &str,
    receipt: &Path,
    receipt_digest: &str,
    record_root: &Path,
) -> Result<String, String> {
    let (upload_receipt, upload_review, upload_review_digest) =
        validated_upload_evidence(document, receipt)?;
    let mut output = String::from("    {");
    let mut first = true;
    for field in [
        "accountOrTenant",
        "candidateEpochMatch",
        "contentSha256",
        "encryptionAtRest",
        "innerManifestValid",
        "objectLock",
        "objectVersion",
        "provider",
        "retentionYears",
        "retrievedBy",
        "retrievedPath",
        "retrieverStableId",
        "retrievedSha256",
        "scrubAgeDays",
        "trustDomain",
        "uploadReceiptSha256",
        "uploadedBy",
        "uploaderStableId",
    ] {
        if !first {
            output.push(',');
        }
        first = false;
        output.push_str("\n      \"");
        output.push_str(field);
        output.push_str("\": ");
        if matches!(
            field,
            "candidateEpochMatch" | "encryptionAtRest" | "innerManifestValid" | "objectLock"
        ) {
            output.push_str(boolean_field(document, field)?);
        } else if matches!(field, "retentionYears" | "scrubAgeDays") {
            write!(output, "{}", unsigned_field(document, field)?)
                .expect("writing to String cannot fail");
        } else {
            push_json(&mut output, &quoted_field(document, field)?);
        }
    }
    for (field, value) in [
        (
            "uploadReceiptPath",
            retained_relative(record_root, &upload_receipt)?,
        ),
        (
            "uploadProviderReceiptPath",
            retained_relative(record_root, &upload_review)?,
        ),
        ("uploadProviderReceiptSha256", upload_review_digest),
        (
            "providerReceiptPath",
            retained_relative(record_root, receipt)?,
        ),
        ("providerReceiptSha256", receipt_digest.to_owned()),
    ] {
        output.push_str(",\n      \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, &value);
    }
    output.push_str("\n    }");
    Ok(output)
}

fn validated_upload_evidence(
    copy_document: &str,
    retrieval_receipt: &Path,
) -> Result<(PathBuf, PathBuf, String), String> {
    let signed = signed_upload_receipt(retrieval_receipt)?;
    let raw = signed.with_file_name("upload-receipt.json");
    let document = fs::read_to_string(&raw).map_err(|error| {
        format!(
            "cannot read retained upload receipt {}: {error}",
            raw.display()
        )
    })?;
    let receipt = parse_upload_receipt(&document)?;
    let raw_digest = sha256_bytes(document.as_bytes()).hex();
    if quoted_field(copy_document, "uploadReceiptSha256")? != raw_digest {
        return Err("custody copy does not bind its retained upload receipt".to_owned());
    }
    for (copy_field, upload_value) in [
        ("candidateCommit", receipt.candidate.as_str()),
        ("assuranceEpochSha256", receipt.epoch.as_str()),
        ("provider", receipt.provider.as_str()),
        ("trustDomain", receipt.trust_domain.as_str()),
        ("accountOrTenant", receipt.account_or_tenant.as_str()),
        ("uploadedBy", receipt.uploaded_by.as_str()),
        ("uploaderStableId", receipt.uploader_stable_id.as_str()),
    ] {
        if quoted_field(copy_document, copy_field)? != upload_value {
            return Err(format!(
                "custody copy changes upload receipt field {copy_field}"
            ));
        }
    }
    let signed_digest = sha256_file(&signed)
        .map_err(|error| error.to_string())?
        .hex();
    Ok((raw, signed, signed_digest))
}

fn copy_core_digest(document: &str) -> Result<String, String> {
    let mut canonical = String::from("{\"schemaVersion\":1");
    for field in [
        "accountOrTenant",
        "candidateEpochMatch",
        "contentSha256",
        "encryptionAtRest",
        "innerManifestValid",
        "objectLock",
        "objectVersion",
        "provider",
        "retentionYears",
        "retrievedBy",
        "retrievedPath",
        "retrieverStableId",
        "retrievedSha256",
        "scrubAgeDays",
        "trustDomain",
        "uploadReceiptSha256",
        "uploadedBy",
        "uploaderStableId",
    ] {
        canonical.push(',');
        push_json(&mut canonical, field);
        canonical.push(':');
        if matches!(
            field,
            "candidateEpochMatch" | "encryptionAtRest" | "innerManifestValid" | "objectLock"
        ) {
            canonical.push_str(boolean_field(document, field)?);
        } else if matches!(field, "retentionYears" | "scrubAgeDays") {
            write!(canonical, "{}", unsigned_field(document, field)?)
                .expect("writing to String cannot fail");
        } else {
            push_json(&mut canonical, &quoted_field(document, field)?);
        }
    }
    canonical.push_str("}\n");
    Ok(sha256_bytes(canonical.as_bytes()).hex())
}

fn validate_copy_record(document: &str) -> Result<(), String> {
    let mut canonical = String::from("{\n  \"schemaVersion\": 1");
    for field in [
        "candidateCommit",
        "assuranceEpochSha256",
        "manifestSha256",
        "uploadReceiptSha256",
        "accountOrTenant",
        "contentSha256",
        "objectVersion",
        "provider",
        "retrievedBy",
        "retrievedPath",
        "retrievedSha256",
        "trustDomain",
        "uploadedBy",
        "uploaderStableId",
        "retrieverStableId",
    ] {
        canonical.push_str(",\n  \"");
        canonical.push_str(field);
        canonical.push_str("\": ");
        push_json(&mut canonical, &quoted_field(document, field)?);
    }
    write!(
        canonical,
        ",\n  \"retentionYears\": {},\n  \"scrubAgeDays\": {},\n  \"objectLock\": {},\n  \"encryptionAtRest\": {},\n  \"innerManifestValid\": {},\n  \"candidateEpochMatch\": {}\n}}\n",
        unsigned_field(document, "retentionYears")?,
        unsigned_field(document, "scrubAgeDays")?,
        boolean_field(document, "objectLock")?,
        boolean_field(document, "encryptionAtRest")?,
        boolean_field(document, "innerManifestValid")?,
        boolean_field(document, "candidateEpochMatch")?,
    )
    .expect("writing to String cannot fail");
    if canonical == document {
        Ok(())
    } else {
        Err(
            "custody copy record is not exact canonical JSON or has unknown/duplicate fields"
                .to_owned(),
        )
    }
}

fn boolean_field<'a>(document: &'a str, field: &str) -> Result<&'a str, String> {
    let value = raw_field(document, field)?;
    match value {
        "true" | "false" => Ok(value),
        _ => Err(format!("custody field {field} is not boolean")),
    }
}

fn unsigned_field(document: &str, field: &str) -> Result<u64, String> {
    raw_field(document, field)?
        .parse()
        .map_err(|_| format!("custody field {field} is not unsigned"))
}

fn raw_field<'a>(document: &'a str, field: &str) -> Result<&'a str, String> {
    let prefix = format!("\"{field}\": ");
    document
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&prefix))
        .map(|value| value.strip_suffix(',').unwrap_or(value))
        .ok_or_else(|| format!("missing custody field {field}"))
}

fn assurance_directory_manifest(root: &Path) -> Result<String, String> {
    let entries = collect_entries(root)?;
    let mut output = String::from(
        "{\n  \"schemaVersion\": 1,\n  \"format\": \"merkle-directory-v1\",\n  \"files\": [",
    );
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"path\": ");
        push_json(&mut output, &entry.path);
        write!(
            output,
            ", \"sha256\": \"{}\", \"size\": {}}}",
            entry.digest.hex(),
            entry.size
        )
        .expect("writing to String cannot fail");
    }
    output.push_str("\n  ]\n}\n");
    Ok(output)
}

pub(crate) fn directory_digest(root: &Path) -> Result<String, String> {
    assurance_directory_manifest(root).map(|manifest| sha256_bytes(manifest.as_bytes()).hex())
}

fn package(options: &Options) -> Result<String, String> {
    let input = required_path(options.input.as_ref(), "--input")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    if output.starts_with(input) {
        return Err("custody package output must be outside its input".to_owned());
    }
    let candidate = required_text(options.candidate.as_ref(), "--candidate")?;
    let epoch_from_file = options
        .epoch_file
        .as_deref()
        .map(crate::assurance::retained_epoch_digest)
        .transpose()?;
    let epoch = match (options.epoch.as_deref(), epoch_from_file.as_ref()) {
        (Some(epoch), None) => epoch,
        (None, Some((epoch_candidate, epoch))) => {
            if epoch_candidate != candidate {
                return Err(
                    "retained assurance epoch candidate does not match custody candidate"
                        .to_owned(),
                );
            }
            epoch
        }
        (Some(_), Some(_)) => return Err("use exactly one of --epoch and --epoch-file".to_owned()),
        (None, None) => return Err("custody-ops requires --epoch or --epoch-file".to_owned()),
    };
    require_git_sha(candidate, "candidate")?;
    require_digest(epoch, "assurance epoch")?;
    if output.exists() {
        return Err(format!(
            "custody output {} already exists",
            output.display()
        ));
    }
    fs::create_dir_all(output.join("blobs"))
        .map_err(|error| format!("cannot create custody package: {error}"))?;
    let entries = collect_entries(input)?;
    if entries.is_empty() {
        return Err("custody package input is empty".to_owned());
    }
    let mut copied = BTreeSet::new();
    for entry in &entries {
        if copied.insert(entry.digest.hex()) {
            let source = input.join(&entry.path);
            let destination = output.join("blobs").join(entry.digest.hex());
            fs::copy(&source, &destination).map_err(|error| {
                format!(
                    "cannot copy {} to {}: {error}",
                    source.display(),
                    destination.display()
                )
            })?;
        }
    }
    let manifest = manifest_json(candidate, epoch, &entries);
    write_atomic(&output.join("manifest.json"), manifest.as_bytes())?;
    let root = package_root_digest(candidate, epoch, &entries);
    write_atomic(
        &output.join("root.sha256"),
        format!("{}\n", root.hex()).as_bytes(),
    )?;
    verify_package(output)?;
    Ok(format!(
        "created deterministic content-addressed custody package {}",
        output.display()
    ))
}

fn verify_package(package: &Path) -> Result<String, String> {
    let manifest = fs::read_to_string(package.join("manifest.json"))
        .map_err(|error| format!("cannot read custody manifest: {error}"))?;
    let (candidate, epoch, entries) = parse_manifest(&manifest)?;
    if entries.is_empty() {
        return Err("custody manifest has no files".to_owned());
    }
    for entry in &entries {
        let blob = package.join("blobs").join(entry.digest.hex());
        let metadata = fs::symlink_metadata(&blob)
            .map_err(|error| format!("cannot inspect {}: {error}", blob.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != entry.size
        {
            return Err(format!("custody blob {} is not exact", blob.display()));
        }
        if sha256_file(&blob).map_err(|error| error.to_string())? != entry.digest {
            return Err(format!("custody blob {} digest mismatch", blob.display()));
        }
    }
    let expected = package_root_digest(&candidate, &epoch, &entries).hex();
    let observed = fs::read_to_string(package.join("root.sha256"))
        .map_err(|error| format!("cannot read custody root digest: {error}"))?;
    if observed.trim() != expected {
        return Err("custody root digest does not match manifest".to_owned());
    }
    Ok("verified deterministic custody package".to_owned())
}

fn materialize_package(package: &Path, output: &Path) -> Result<String, String> {
    verify_package(package)?;
    if output.exists() {
        return Err(format!(
            "custody materialization output {} already exists",
            output.display()
        ));
    }
    let manifest = fs::read_to_string(package.join("manifest.json"))
        .map_err(|error| format!("cannot read custody manifest: {error}"))?;
    let (_, _, entries) = parse_manifest(&manifest)?;
    for entry in entries {
        let destination = output.join(&entry.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        let source = package.join("blobs").join(entry.digest.hex());
        fs::copy(&source, &destination).map_err(|error| {
            format!(
                "cannot materialize {} as {}: {error}",
                source.display(),
                destination.display()
            )
        })?;
        if sha256_file(&destination).map_err(|error| error.to_string())? != entry.digest {
            return Err(format!(
                "materialized custody file {} digest mismatch",
                destination.display()
            ));
        }
    }
    Ok(format!(
        "materialized verified active promotion record {}",
        output.display()
    ))
}

fn materialize_package_into_existing(package: &Path, output: &Path) -> Result<String, String> {
    verify_package(package)?;
    let manifest = fs::read_to_string(package.join("manifest.json"))
        .map_err(|error| format!("cannot read custody manifest: {error}"))?;
    let (_, _, entries) = parse_manifest(&manifest)?;
    for entry in entries {
        let destination = output.join(&entry.path);
        if destination.exists() {
            return Err(format!(
                "custody materialization would overwrite {}",
                destination.display()
            ));
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        let source = package.join("blobs").join(entry.digest.hex());
        fs::copy(&source, &destination).map_err(|error| {
            format!(
                "cannot materialize {} as {}: {error}",
                source.display(),
                destination.display()
            )
        })?;
        if sha256_file(&destination).map_err(|error| error.to_string())? != entry.digest {
            return Err(format!(
                "materialized custody file {} digest mismatch",
                destination.display()
            ));
        }
    }
    Ok(format!(
        "materialized verified custody package into {}",
        output.display()
    ))
}

pub(crate) fn materialize_verified_package(
    package: &Path,
    output: &Path,
) -> Result<String, String> {
    materialize_package(package, output)
}

fn upload(options: &Options) -> Result<String, String> {
    let package = required_path(options.input.as_ref(), "--input")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    verify_package(package)?;
    let identity = provider_identity(options)?;
    let policy = load_custody_policy(required_path(options.policy.as_ref(), "--policy")?)?;
    let retention = required_text(options.retention_until.as_ref(), "--retention-until")?;
    require_minimum_retention(retention, policy.minimum_years)?;
    let manifest = fs::read_to_string(package.join("manifest.json"))
        .map_err(|error| format!("cannot read custody manifest: {error}"))?;
    let (candidate, epoch, entries) = parse_manifest(&manifest)?;
    let root_digest = package_root_digest(&candidate, &epoch, &entries);
    let provider_subject = provider_subject()?;
    let mut objects = BTreeMap::new();
    let manifest_digest = sha256_bytes(manifest.as_bytes());
    let mut digests = BTreeMap::new();
    for digest in entries
        .iter()
        .map(|entry| entry.digest)
        .chain([manifest_digest])
    {
        digests.insert(digest.hex(), digest);
    }
    for digest in digests.into_values() {
        let body = if digest == manifest_digest {
            package.join("manifest.json")
        } else {
            package.join("blobs").join(digest.hex())
        };
        // The object key is the already-computed content digest. It is passed as
        // one structured argv value and is never assembled into a command string.
        let key = digest.hex();
        let metadata = put_immutable_object(identity.bucket, &key, &body, digest, retention)?;
        objects.insert(digest.hex(), (key, metadata));
    }
    let receipt = upload_receipt_json(
        &identity,
        &provider_subject,
        &candidate,
        &epoch,
        retention,
        root_digest,
        manifest_digest,
        &objects,
    );
    write_atomic(output, receipt.as_bytes())?;
    let receipt_digest = sha256_bytes(receipt.as_bytes());
    let receipt_key = receipt_digest.hex();
    let receipt_metadata = put_immutable_object(
        identity.bucket,
        &receipt_key,
        output,
        receipt_digest,
        retention,
    )?;
    let mut pointer = String::from("{\n  \"schemaVersion\": 1,\n  \"receiptKey\": ");
    push_json(&mut pointer, &receipt_key);
    for (field, value) in [
        ("receiptVersion", receipt_metadata.version.as_str()),
        ("receiptSha256", receipt_key.as_str()),
        ("retentionUntil", retention),
    ] {
        pointer.push_str(",\n  \"");
        pointer.push_str(field);
        pointer.push_str("\": ");
        push_json(&mut pointer, value);
    }
    pointer.push_str("\n}\n");
    write_atomic(
        &output.with_file_name("upload-receipt-provider-pointer.json"),
        pointer.as_bytes(),
    )?;
    Ok(format!(
        "uploaded immutable custody copy to provider {}",
        identity.provider
    ))
}

fn put_immutable_object(
    bucket: &str,
    key: &str,
    body: &Path,
    digest: Digest,
    retention: &str,
) -> Result<ObjectMetadata, String> {
    let put = aws(&[
        "s3api",
        "put-object",
        "--bucket",
        bucket,
        "--key",
        key,
        "--body",
        path_text(body)?.as_str(),
        "--checksum-algorithm",
        "SHA256",
        "--checksum-sha256",
        &base64(&digest.0),
        "--server-side-encryption",
        "aws:kms",
        "--object-lock-mode",
        "COMPLIANCE",
        "--object-lock-retain-until-date",
        retention,
    ])?;
    if put.stdout.is_empty() {
        return Err("object provider returned an empty put response".to_owned());
    }
    let metadata = head_object(bucket, key, None)?;
    verify_uploaded_metadata(&metadata, digest, retention)?;
    Ok(metadata)
}

fn verify_uploaded_metadata(
    metadata: &ObjectMetadata,
    digest: Digest,
    retention: &str,
) -> Result<(), String> {
    if metadata.checksum != base64(&digest.0)
        || metadata.object_lock_mode != "COMPLIANCE"
        || metadata.retention_until != retention
        || metadata.encryption != "aws:kms"
        || metadata.version.is_empty()
    {
        return Err("provider metadata does not prove immutable encrypted custody".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn retrieve(options: &Options, kind: &str) -> Result<String, String> {
    let policy = load_custody_policy(required_path(options.policy.as_ref(), "--policy")?)?;
    let upload_receipt = required_path(options.input.as_ref(), "--input")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    let identity = provider_identity(options)?;
    if output.exists() {
        return Err(format!(
            "retrieval output {} already exists",
            output.display()
        ));
    }
    let receipt_document = fs::read_to_string(upload_receipt)
        .map_err(|error| format!("cannot read {}: {error}", upload_receipt.display()))?;
    let upload_receipt_sha256 = sha256_bytes(receipt_document.as_bytes());
    let receipt = parse_upload_receipt(&receipt_document)?;
    require_minimum_retention(&receipt.retention_until, policy.minimum_years)?;
    if receipt.provider != identity.provider
        || receipt.trust_domain != identity.trust_domain
        || receipt.bucket != identity.bucket
    {
        return Err("upload receipt does not match configured custody provider".to_owned());
    }
    let provider_subject = provider_subject()?;
    if receipt.account_or_tenant != provider_subject.account {
        return Err("upload receipt account differs from retrieval account".to_owned());
    }
    if receipt.uploaded_by == provider_subject.arn {
        return Err("custody retrieval actor must differ from uploader".to_owned());
    }
    let manifest_object = receipt
        .objects
        .get(&receipt.manifest_sha256)
        .ok_or_else(|| "upload receipt omits its provider manifest object".to_owned())?;
    let retrieved_package = output.join("package");
    fs::create_dir_all(retrieved_package.join("blobs"))
        .map_err(|error| format!("cannot create retrieval output: {error}"))?;
    let manifest_path = retrieved_package.join("manifest.json");
    get_object(
        identity.bucket,
        &manifest_object.key,
        &manifest_object.version,
        &manifest_path,
    )?;
    let manifest_metadata = head_object(
        identity.bucket,
        &manifest_object.key,
        Some(&manifest_object.version),
    )?;
    verify_retrieved_metadata(
        &manifest_metadata,
        manifest_object,
        &receipt.retention_until,
    )?;
    if sha256_file(&manifest_path)
        .map_err(|error| error.to_string())?
        .hex()
        != receipt.manifest_sha256
    {
        return Err("retrieved provider manifest digest mismatch".to_owned());
    }
    let manifest = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("cannot read {}: {error}", manifest_path.display()))?;
    let (candidate, epoch, entries) = parse_manifest(&manifest)?;
    let root_digest = package_root_digest(&candidate, &epoch, &entries);
    if candidate != receipt.candidate
        || epoch != receipt.epoch
        || root_digest.hex() != receipt.root_sha256
    {
        return Err("retrieved provider manifest is not bound to upload receipt".to_owned());
    }
    let mut digests = BTreeMap::new();
    for digest in entries.iter().map(|entry| entry.digest) {
        digests.insert(digest.hex(), digest);
    }
    for digest in digests.into_values() {
        let digest_text = digest.hex();
        let object = receipt
            .objects
            .get(&digest_text)
            .ok_or_else(|| format!("upload receipt omits content object {digest_text}"))?;
        let key = object.key.as_str();
        let destination = retrieved_package.join("blobs").join(digest.hex());
        get_object(identity.bucket, key, &object.version, &destination)?;
        if sha256_file(&destination).map_err(|error| error.to_string())? != digest {
            return Err(format!("retrieved object {key} digest mismatch"));
        }
        let metadata = head_object(identity.bucket, key, Some(&object.version))?;
        verify_retrieved_metadata(&metadata, object, &receipt.retention_until)
            .map_err(|error| format!("retrieved object {key}: {error}"))?;
    }
    write_atomic(
        &retrieved_package.join("root.sha256"),
        format!("{}\n", root_digest.hex()).as_bytes(),
    )?;
    verify_package(&retrieved_package)?;
    let observed_at = current_utc_timestamp()?;
    let receipt = retrieval_receipt_json(
        kind,
        &identity,
        &receipt,
        &provider_subject,
        upload_receipt_sha256,
        &candidate,
        &epoch,
        root_digest,
        &retrieved_package,
        &observed_at,
    )?;
    write_atomic(
        &output.join(format!("{kind}-receipt.json")),
        receipt.as_bytes(),
    )?;
    Ok(format!(
        "completed independent {kind} from provider {}",
        identity.provider
    ))
}

struct ProviderIdentity<'a> {
    provider: &'a str,
    trust_domain: &'a str,
    bucket: &'a str,
}

fn provider_identity(options: &Options) -> Result<ProviderIdentity<'_>, String> {
    let identity = ProviderIdentity {
        provider: required_text(options.provider.as_ref(), "--provider")?,
        trust_domain: required_text(options.trust_domain.as_ref(), "--trust-domain")?,
        bucket: required_text(options.bucket.as_ref(), "--bucket")?,
    };
    for (label, value) in [
        ("provider", identity.provider),
        ("trust domain", identity.trust_domain),
        ("bucket", identity.bucket),
    ] {
        require_atom(value, label)?;
    }
    Ok(identity)
}

#[derive(Clone)]
struct ObjectMetadata {
    version: String,
    object_lock_mode: String,
    retention_until: String,
    encryption: String,
    checksum: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiptObject {
    key: String,
    version: String,
    checksum: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UploadReceipt {
    provider: String,
    trust_domain: String,
    account_or_tenant: String,
    uploaded_by: String,
    uploader_stable_id: String,
    bucket: String,
    candidate: String,
    epoch: String,
    root_sha256: String,
    manifest_sha256: String,
    retention_until: String,
    objects: BTreeMap<String, ReceiptObject>,
}

fn verify_retrieved_metadata(
    metadata: &ObjectMetadata,
    receipt: &ReceiptObject,
    retention_until: &str,
) -> Result<(), String> {
    if metadata.object_lock_mode != "COMPLIANCE"
        || metadata.encryption != "aws:kms"
        || metadata.version != receipt.version
        || metadata.checksum != receipt.checksum
        || metadata.retention_until != retention_until
    {
        Err("provider metadata no longer matches the immutable upload receipt".to_owned())
    } else {
        Ok(())
    }
}

fn parse_upload_receipt(document: &str) -> Result<UploadReceipt, String> {
    if !document.ends_with('\n') {
        return Err("upload receipt lacks trailing newline".to_owned());
    }
    let receipt = UploadReceipt {
        provider: quoted_field(document, "provider")?,
        trust_domain: quoted_field(document, "trustDomain")?,
        account_or_tenant: quoted_field(document, "accountOrTenant")?,
        uploaded_by: quoted_field(document, "uploadedBy")?,
        uploader_stable_id: quoted_field(document, "uploaderStableId")?,
        bucket: quoted_field(document, "bucket")?,
        candidate: quoted_field(document, "candidateCommit")?,
        epoch: quoted_field(document, "assuranceEpochSha256")?,
        root_sha256: quoted_field(document, "packageRootSha256")?,
        manifest_sha256: quoted_field(document, "manifestSha256")?,
        retention_until: quoted_field(document, "retentionUntil")?,
        objects: parse_receipt_objects(document)?,
    };
    require_git_sha(&receipt.candidate, "receipt candidate")?;
    for (label, digest) in [
        ("receipt epoch", receipt.epoch.as_str()),
        ("receipt root", receipt.root_sha256.as_str()),
        ("receipt manifest", receipt.manifest_sha256.as_str()),
    ] {
        require_digest(digest, label)?;
    }
    for (digest, object) in &receipt.objects {
        if object.key != *digest {
            return Err("custody object key is not its content digest".to_owned());
        }
        if object.checksum != base64(&Digest::from_hex(digest).map_err(str::to_owned)?.0) {
            return Err("custody receipt checksum encoding is inconsistent".to_owned());
        }
    }
    if canonical_upload_receipt(&receipt)? != document {
        return Err(
            "upload receipt is not exact canonical JSON or contains unknown/duplicate fields"
                .to_owned(),
        );
    }
    Ok(receipt)
}

pub fn fuzz_admit_custody_receipt(bytes: &[u8]) -> Result<(), String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "custody receipt is not canonical UTF-8".to_owned())?;
    parse_upload_receipt(document).map(|_| ())
}

fn canonical_upload_receipt(receipt: &UploadReceipt) -> Result<String, String> {
    let identity = ProviderIdentity {
        provider: &receipt.provider,
        trust_domain: &receipt.trust_domain,
        bucket: &receipt.bucket,
    };
    let subject = ProviderSubject {
        account: receipt.account_or_tenant.clone(),
        arn: receipt.uploaded_by.clone(),
        stable_id: receipt.uploader_stable_id.clone(),
    };
    let mut objects = BTreeMap::new();
    for (digest, object) in &receipt.objects {
        objects.insert(
            digest.clone(),
            (
                object.key.clone(),
                ObjectMetadata {
                    version: object.version.clone(),
                    object_lock_mode: "COMPLIANCE".to_owned(),
                    retention_until: receipt.retention_until.clone(),
                    encryption: "aws:kms".to_owned(),
                    checksum: object.checksum.clone(),
                },
            ),
        );
    }
    Ok(upload_receipt_json(
        &identity,
        &subject,
        &receipt.candidate,
        &receipt.epoch,
        &receipt.retention_until,
        Digest::from_hex(&receipt.root_sha256).map_err(str::to_owned)?,
        Digest::from_hex(&receipt.manifest_sha256).map_err(str::to_owned)?,
        &objects,
    ))
}

fn parse_receipt_objects(document: &str) -> Result<BTreeMap<String, ReceiptObject>, String> {
    let mut objects = BTreeMap::new();
    for line in document.lines().map(str::trim) {
        if !line.starts_with("{\"sha256\": ") {
            continue;
        }
        let digest = object_string_field(line, "sha256")?;
        require_digest(&digest, "receipt object digest")?;
        let object = ReceiptObject {
            key: object_string_field(line, "key")?,
            version: object_string_field(line, "version")?,
            checksum: object_string_field(line, "checksumSha256Base64")?,
        };
        if objects.insert(digest, object).is_some() {
            return Err("custody receipt repeats an object digest".to_owned());
        }
    }
    if objects.is_empty() {
        return Err("custody receipt has no provider objects".to_owned());
    }
    Ok(objects)
}

fn head_object(bucket: &str, key: &str, version: Option<&str>) -> Result<ObjectMetadata, String> {
    let mut arguments = vec!["s3api", "head-object", "--bucket", bucket, "--key", key];
    if let Some(version) = version {
        arguments.extend(["--version-id", version]);
    }
    arguments.extend([
        "--query",
        "[VersionId,ObjectLockMode,ObjectLockRetainUntilDate,ServerSideEncryption,ChecksumSHA256]",
        "--output",
        "text",
    ]);
    let output = aws(&arguments)?;
    parse_head_metadata(&output.stdout)
}

fn parse_head_metadata(bytes: &[u8]) -> Result<ObjectMetadata, String> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| "provider metadata is not UTF-8".to_owned())?;
    let fields = text.trim().split('\t').collect::<Vec<_>>();
    if fields.len() != 5
        || fields
            .iter()
            .any(|field| field.is_empty() || *field == "None")
    {
        return Err("provider metadata response is incomplete".to_owned());
    }
    let metadata = ObjectMetadata {
        version: fields[0].to_owned(),
        object_lock_mode: fields[1].to_owned(),
        retention_until: fields[2].to_owned(),
        encryption: fields[3].to_owned(),
        checksum: fields[4].to_owned(),
    };
    Ok(metadata)
}

fn get_object(bucket: &str, key: &str, version: &str, destination: &Path) -> Result<(), String> {
    let destination = path_text(destination)?;
    aws(&[
        "s3api",
        "get-object",
        "--bucket",
        bucket,
        "--key",
        key,
        "--version-id",
        version,
        destination.as_str(),
    ])?;
    Ok(())
}

struct ProviderSubject {
    account: String,
    arn: String,
    stable_id: String,
}

fn provider_subject() -> Result<ProviderSubject, String> {
    let output = aws(&[
        "sts",
        "get-caller-identity",
        "--query",
        "[Account,Arn,UserId]",
        "--output",
        "text",
    ])?;
    parse_provider_subject(&output.stdout)
}

fn parse_provider_subject(bytes: &[u8]) -> Result<ProviderSubject, String> {
    let text = String::from_utf8(bytes.to_vec())
        .map_err(|_| "provider subject identity is not UTF-8".to_owned())?;
    let fields = text.trim().split('\t').collect::<Vec<_>>();
    if fields.len() != 3 {
        return Err("provider subject identity is incomplete".to_owned());
    }
    for (label, value) in [
        ("provider account", fields[0]),
        ("provider ARN", fields[1]),
        ("provider stable ID", fields[2]),
    ] {
        require_atom(value, label)?;
    }
    Ok(ProviderSubject {
        account: fields[0].to_owned(),
        arn: fields[1].to_owned(),
        stable_id: fields[2]
            .split_once(':')
            .map_or(fields[2], |(stable, _)| stable)
            .to_owned(),
    })
}

fn aws(arguments: &[&str]) -> Result<Output, String> {
    let output = Command::new("aws")
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot run AWS provider adapter: {error}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "AWS provider adapter failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn collect_entries(root: &Path) -> Result<Vec<ManifestEntry>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut children = fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            let path = child.path();
            let kind = child
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if kind.is_symlink() {
                return Err(format!("custody input contains symlink {}", path.display()));
            }
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| format!("{} is outside custody root", path.display()))?;
                let relative = portable_relative(relative)?;
                let metadata = child
                    .metadata()
                    .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
                entries.push(ManifestEntry {
                    path: relative,
                    digest: sha256_file(&path).map_err(|error| error.to_string())?,
                    size: metadata.len(),
                });
            }
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn manifest_json(candidate: &str, epoch: &str, entries: &[ManifestEntry]) -> String {
    let root = package_root_digest(candidate, epoch, entries);
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"candidateCommit\": ");
    push_json(&mut output, candidate);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json(&mut output, epoch);
    output.push_str(",\n  \"format\": \"merkle-directory-v1\",\n  \"files\": [");
    for (index, entry) in entries.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"path\": ");
        push_json(&mut output, &entry.path);
        write!(
            output,
            ", \"sha256\": \"{}\", \"size\": {}}}",
            entry.digest.hex(),
            entry.size
        )
        .expect("writing to String cannot fail");
    }
    output.push_str("\n  ],\n  \"rootSha256\": \"");
    output.push_str(&root.hex());
    output.push_str("\"\n}\n");
    output
}

fn parse_manifest(document: &str) -> Result<(String, String, Vec<ManifestEntry>), String> {
    if !document.ends_with('\n') {
        return Err("custody manifest lacks trailing newline".to_owned());
    }
    let candidate = quoted_field(document, "candidateCommit")?;
    let epoch = quoted_field(document, "assuranceEpochSha256")?;
    require_git_sha(&candidate, "manifest candidate")?;
    require_digest(&epoch, "manifest epoch")?;
    if quoted_field(document, "format")? != "merkle-directory-v1" {
        return Err("custody manifest format is unsupported".to_owned());
    }
    let mut entries = Vec::new();
    for line in document.lines().map(str::trim) {
        if !line.starts_with("{\"path\": ") {
            continue;
        }
        let line = line.strip_suffix(',').unwrap_or(line);
        let path = object_string_field(line, "path")?;
        let digest = object_string_field(line, "sha256")?;
        let size = object_u64_field(line, "size")?;
        require_digest(&digest, "manifest file digest")?;
        let digest = hell_testkit::Digest::from_hex(&digest)
            .map_err(|error| format!("invalid manifest digest: {error}"))?;
        portable_relative(Path::new(&path))?;
        entries.push(ManifestEntry { path, digest, size });
    }
    if entries.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err("custody manifest paths are not strictly sorted and unique".to_owned());
    }
    let expected = package_root_digest(&candidate, &epoch, &entries).hex();
    if quoted_field(document, "rootSha256")? != expected {
        return Err("custody manifest root digest is invalid".to_owned());
    }
    Ok((candidate, epoch, entries))
}

fn package_root_digest(candidate: &str, epoch: &str, entries: &[ManifestEntry]) -> Digest {
    let mut canonical = format!("candidate {candidate}\nepoch {epoch}\n");
    for entry in entries {
        writeln!(
            canonical,
            "{} {} {}",
            entry.path,
            entry.digest.hex(),
            entry.size
        )
        .expect("writing to String cannot fail");
    }
    sha256_bytes(canonical.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn upload_receipt_json(
    identity: &ProviderIdentity<'_>,
    provider_subject: &ProviderSubject,
    candidate: &str,
    epoch: &str,
    retention: &str,
    root: Digest,
    manifest_digest: Digest,
    objects: &BTreeMap<String, (String, ObjectMetadata)>,
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"provider\": ");
    push_json(&mut output, identity.provider);
    for (name, value) in [
        ("trustDomain", identity.trust_domain),
        ("accountOrTenant", &provider_subject.account),
        ("bucket", identity.bucket),
        ("uploadedBy", &provider_subject.arn),
        ("uploaderStableId", &provider_subject.stable_id),
        ("candidateCommit", candidate),
        ("assuranceEpochSha256", epoch),
        ("packageRootSha256", &root.hex()),
        ("manifestSha256", &manifest_digest.hex()),
        ("retentionUntil", retention),
    ] {
        output.push_str(",\n  \"");
        output.push_str(name);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str(",\n  \"objectLockMode\": \"COMPLIANCE\",\n  \"encryption\": \"aws:kms\",\n  \"objects\": [");
    for (index, (digest, (key, metadata))) in objects.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"sha256\": ");
        push_json(&mut output, digest);
        output.push_str(", \"key\": ");
        push_json(&mut output, key);
        output.push_str(", \"version\": ");
        push_json(&mut output, &metadata.version);
        output.push_str(", \"checksumSha256Base64\": ");
        push_json(&mut output, &metadata.checksum);
        output.push('}');
    }
    output.push_str("\n  ]\n}\n");
    output
}

#[allow(clippy::too_many_arguments)]
fn retrieval_receipt_json(
    kind: &str,
    identity: &ProviderIdentity<'_>,
    upload_receipt: &UploadReceipt,
    provider_subject: &ProviderSubject,
    upload_receipt_sha256: Digest,
    candidate: &str,
    epoch: &str,
    root: Digest,
    retrieved: &Path,
    observed_at: &str,
) -> Result<String, String> {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"kind\": ");
    push_json(&mut output, kind);
    for (name, value) in [
        ("provider", identity.provider),
        ("trustDomain", identity.trust_domain),
        ("accountOrTenant", &provider_subject.account),
        ("uploadedBy", &upload_receipt.uploaded_by),
        ("retrievedBy", &provider_subject.arn),
        ("retrieverStableId", &provider_subject.stable_id),
        ("candidateCommit", candidate),
        ("assuranceEpochSha256", epoch),
        ("packageRootSha256", &root.hex()),
        ("manifestSha256", &upload_receipt.manifest_sha256),
        ("uploadReceiptSha256", &upload_receipt_sha256.hex()),
        ("retentionUntil", &upload_receipt.retention_until),
        ("retrievedPath", path_text(retrieved)?.as_str()),
        ("retrievedAt", observed_at),
    ] {
        output.push_str(",\n  \"");
        output.push_str(name);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str(",\n  \"outerDigestValid\": true,\n  \"innerManifestValid\": true,\n  \"candidateEpochMatch\": true,\n  \"objectLockValid\": true,\n  \"state\": \"retrieved-and-verified\"\n}\n");
    Ok(output)
}

fn quoted_field(document: &str, field: &str) -> Result<String, String> {
    let prefix = format!("\"{field}\": \"");
    let line = document
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("missing manifest field {field}"))?;
    let value = line
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(',').or(Some(value)))
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("manifest field {field} is malformed"))?;
    unescape_json(value)
}

fn object_string_field(document: &str, field: &str) -> Result<String, String> {
    let prefix = format!("\"{field}\": \"");
    let start = document
        .find(&prefix)
        .ok_or_else(|| format!("missing object field {field}"))?
        + prefix.len();
    let remainder = &document[start..];
    let end = remainder
        .find('"')
        .ok_or_else(|| format!("object field {field} is unterminated"))?;
    unescape_json(&remainder[..end])
}

fn object_u64_field(document: &str, field: &str) -> Result<u64, String> {
    let prefix = format!("\"{field}\": ");
    let start = document
        .find(&prefix)
        .ok_or_else(|| format!("missing object field {field}"))?
        + prefix.len();
    let digits = document[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    digits
        .parse()
        .map_err(|_| format!("object field {field} is not an integer"))
}

fn unescape_json(value: &str) -> Result<String, String> {
    if value.contains('\\') {
        return Err("custody identifiers may not require JSON escapes".to_owned());
    }
    require_atom(value, "JSON value")?;
    Ok(value.to_owned())
}

fn portable_relative(path: &Path) -> Result<String, String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("custody path {} is not confined", path.display()));
    }
    let mut text = String::new();
    for (index, component) in path.components().enumerate() {
        if index != 0 {
            text.push('/');
        }
        let component = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| format!("custody path {} is not UTF-8", path.display()))?;
        require_atom(component, "path component")?;
        text.push_str(component);
    }
    if text.is_empty() {
        Err("custody path is empty".to_owned())
    } else {
        Ok(text)
    }
}

fn retained_relative(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "retained record {} is outside {}",
            path.display(),
            root.display()
        )
    })?;
    portable_relative(relative)
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from((first & 0x03) << 4 | second >> 4)],
        ));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from((second & 0x0f) << 2 | third >> 6)])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }
    output
}

fn parse_utc_timestamp(value: &str) -> Result<(i64, u32, u32, u32, u32, u32), String> {
    require_atom(value, "retention timestamp")?;
    let without_zone = value
        .strip_suffix('Z')
        .ok_or_else(|| "retention timestamp must be UTC".to_owned())?;
    let (date, time) = without_zone
        .split_once('T')
        .ok_or_else(|| "retention timestamp must contain a date and time".to_owned())?;
    let date = date
        .split('-')
        .map(str::parse)
        .collect::<Result<Vec<i64>, _>>()
        .map_err(|_| "retention timestamp date is invalid".to_owned())?;
    let time = time
        .split(':')
        .map(str::parse)
        .collect::<Result<Vec<u32>, _>>()
        .map_err(|_| "retention timestamp time is invalid".to_owned())?;
    if date.len() != 3 || time.len() != 3 {
        return Err("retention timestamp must use YYYY-MM-DDTHH:MM:SSZ".to_owned());
    }
    let year = date[0];
    let month = u32::try_from(date[1]).map_err(|_| "retention month is invalid".to_owned())?;
    let day = u32::try_from(date[2]).map_err(|_| "retention day is invalid".to_owned())?;
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || time[0] > 23
        || time[1] > 59
        || time[2] > 59
    {
        return Err("retention timestamp is outside the UTC calendar".to_owned());
    }
    Ok((year, month, day, time[0], time[1], time[2]))
}

pub(crate) fn validate_utc_timestamp(value: &str) -> Result<(), String> {
    parse_utc_timestamp(value).map(|_| ())
}

pub(crate) fn utc_age_days(value: &str) -> Result<u64, String> {
    observation_age_days(value)
}

pub(crate) fn utc_age_seconds(value: &str) -> Result<u64, String> {
    let (year, month, day, hour, minute, second) = parse_utc_timestamp(value)?;
    let observed_days = unix_days_from_civil(year, month, day);
    let observed_day_seconds = u64::from(hour)
        .saturating_mul(3_600)
        .saturating_add(u64::from(minute).saturating_mul(60))
        .saturating_add(u64::from(second));
    let observed_days = u64::try_from(observed_days)
        .map_err(|_| "observation predates the Unix epoch".to_owned())?;
    let observed = observed_days
        .checked_mul(86_400)
        .and_then(|days| days.checked_add(observed_day_seconds))
        .ok_or_else(|| "observation timestamp exceeds supported range".to_owned())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?
        .as_secs();
    now.checked_sub(observed)
        .ok_or_else(|| "observation timestamp is in the future".to_owned())
}

fn require_minimum_retention(value: &str, minimum_years: i64) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    let days = i64::try_from(now.as_secs() / 86_400)
        .map_err(|_| "system clock is outside the supported range".to_owned())?;
    let seconds = now.as_secs() % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    let current = (
        year,
        month,
        day,
        u32::try_from(seconds / 3_600).expect("UTC hour is bounded"),
        u32::try_from(seconds % 3_600 / 60).expect("UTC minute is bounded"),
        u32::try_from(seconds % 60).expect("UTC second is bounded"),
    );
    require_minimum_retention_at(value, minimum_years, current)
}

fn require_minimum_retention_at(
    value: &str,
    minimum_years: i64,
    current: (i64, u32, u32, u32, u32, u32),
) -> Result<(), String> {
    let observed = parse_utc_timestamp(value)?;
    let required_year = current
        .0
        .checked_add(minimum_years)
        .ok_or_else(|| "minimum retention year overflows".to_owned())?;
    let required = (
        required_year,
        current.1,
        current.2.min(days_in_month(required_year, current.1)),
        current.3,
        current.4,
        current.5,
    );
    if observed < required {
        Err(format!(
            "provider retention is shorter than the committed {minimum_years}-year minimum"
        ))
    } else {
        Ok(())
    }
}

const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

fn civil_from_unix_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (
        year,
        u32::try_from(month).expect("civil month is bounded"),
        u32::try_from(day).expect("civil day is bounded"),
    )
}

pub(crate) fn current_utc_timestamp() -> Result<String, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    let days = i64::try_from(now.as_secs() / 86_400)
        .map_err(|_| "system clock is outside the supported range".to_owned())?;
    let seconds = now.as_secs() % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}

fn observation_age_days(observed_at: &str) -> Result<u64, String> {
    let (year, month, day, hour, minute, second) = parse_utc_timestamp(observed_at)?;
    let observed_days = unix_days_from_civil(year, month, day);
    let observed_seconds = observed_days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(i64::from(hour) * 3_600))
        .and_then(|value| value.checked_add(i64::from(minute) * 60))
        .and_then(|value| value.checked_add(i64::from(second)))
        .ok_or_else(|| "custody observation timestamp is out of range".to_owned())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    let now = i64::try_from(now.as_secs())
        .map_err(|_| "system clock is outside the supported range".to_owned())?;
    if observed_seconds > now {
        return Err("custody observation timestamp is in the future".to_owned());
    }
    u64::try_from((now - observed_seconds) / 86_400)
        .map_err(|_| "custody observation age is out of range".to_owned())
}

fn unix_days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month = i64::from(month);
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn required_path<'a>(value: Option<&'a PathBuf>, flag: &str) -> Result<&'a Path, String> {
    value
        .map(PathBuf::as_path)
        .ok_or_else(|| format!("custody-ops requires {flag}"))
}

fn required_text<'a>(value: Option<&'a String>, flag: &str) -> Result<&'a str, String> {
    value
        .map(String::as_str)
        .ok_or_else(|| format!("custody-ops requires {flag}"))
}

fn set_path(target: &mut Option<PathBuf>, value: &OsStr, flag: &str) -> Result<(), String> {
    if target.replace(PathBuf::from(value)).is_some() {
        Err(format!("{flag} was provided more than once"))
    } else {
        Ok(())
    }
}

fn set_text(target: &mut Option<String>, value: &OsStr, flag: &str) -> Result<(), String> {
    let value = value
        .to_str()
        .ok_or_else(|| format!("{flag} value must be UTF-8"))?;
    if target.replace(value.to_owned()).is_some() {
        Err(format!("{flag} was provided more than once"))
    } else {
        Ok(())
    }
}

fn require_git_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() == "0000000000000000000000000000000000000000".len()
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Ok(())
    } else {
        Err(format!("{label} is not a full Git SHA"))
    }
}

fn require_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() == "0000000000000000000000000000000000000000000000000000000000000000".len()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a lowercase SHA-256"))
    }
}

fn require_atom(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+' | b'=')
        })
    {
        Err(format!("{label} is not a safe canonical atom"))
    } else {
        Ok(())
    }
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("path {} is not UTF-8", path.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("cannot replace {}: {error}", path.display()))
}

fn push_json(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => write!(output, "\\u{:04x}", u32::from(value))
                .expect("writing to String cannot fail"),
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_candidate() -> String {
        hell_builtins::UPSTREAM_COMMIT.to_owned()
    }

    fn different_candidate() -> String {
        let mut candidate = fixture_candidate();
        candidate.replace_range(..1, if candidate.starts_with('0') { "1" } else { "0" });
        candidate
    }

    fn fixture_digest() -> String {
        hell_builtins::PROMOTION_POLICY_SHA256.to_owned()
    }

    fn pending_provider(provider: &str, activation_sha256: &str) -> WorkflowProvider {
        WorkflowProvider {
            provider: provider.to_owned(),
            trust_domain: "trust-domain".to_owned(),
            bucket: "bucket".to_owned(),
            active_candidate: fixture_candidate(),
            active_epoch: fixture_digest(),
            active_manifest: fixture_digest(),
            active_receipt_key: "receipt-key".to_owned(),
            active_receipt_version: "receipt-version".to_owned(),
            active_receipt_sha256: fixture_digest(),
            active_activation_record_key: "activation-record-key".to_owned(),
            active_activation_record_version: "activation-record-version".to_owned(),
            active_activation_record_sha256: activation_sha256.to_owned(),
            active_activation_packet_key: "activation-packet-key".to_owned(),
            active_activation_packet_version: "activation-packet-version".to_owned(),
            active_activation_packet_sha256: fixture_digest(),
            active_activation_dsse_key: "activation-dsse-key".to_owned(),
            active_activation_dsse_version: "activation-dsse-version".to_owned(),
            active_activation_dsse_sha256: fixture_digest(),
            activation_public_state: "pending-publication".to_owned(),
            activation_public_completion_sha256: String::new(),
            current_transition: None,
        }
    }

    fn activation_completion(primary: &str, secondary: &str, run_id: u64) -> String {
        let candidate = fixture_candidate();
        let epoch = fixture_digest();
        let run_attempt = 3;
        let correlation = initial_activation_correlation(
            &candidate,
            &epoch,
            run_id,
            run_attempt,
            primary,
            secondary,
        );
        format!(
            "{{\n  \"activationRunId\": {run_id},\n  \"activationRunAttempt\": {run_attempt},\n  \"activationCorrelationSha256\": \"{correlation}\",\n  \"primaryActivationSha256\": \"{primary}\",\n  \"secondaryActivationSha256\": \"{secondary}\"\n}}\n"
        )
    }

    #[test]
    fn initial_completion_is_bound_to_the_exact_pending_provider_activation() {
        let primary = sha256_bytes(b"primary activation").hex();
        let secondary = sha256_bytes(b"secondary activation").hex();
        let completion = activation_completion(&primary, &secondary, 41);
        assert!(
            verify_completion_activation_binding(
                &completion,
                &pending_provider("primary-worm", &primary),
            )
            .is_ok()
        );
        assert!(
            verify_completion_activation_binding(
                &completion,
                &pending_provider("secondary-worm", &secondary),
            )
            .is_ok()
        );
        assert!(
            verify_completion_activation_binding(
                &completion,
                &pending_provider("primary-worm", &sha256_bytes(b"new activation").hex()),
            )
            .is_err()
        );
        assert!(
            verify_completion_activation_binding(
                &completion.replace("\"activationRunId\": 41", "\"activationRunId\": 42"),
                &pending_provider("primary-worm", &primary),
            )
            .is_err()
        );
        assert!(
            verify_completion_activation_binding(
                &completion.replace(&primary, &sha256_bytes(b"fork").hex()),
                &pending_provider("primary-worm", &primary),
            )
            .is_err()
        );
    }

    #[test]
    fn manifest_round_trip_is_sorted_content_addressed_and_candidate_bound() {
        let entries = vec![
            ManifestEntry {
                path: "a/file".to_owned(),
                digest: sha256_bytes(b"a"),
                size: 1,
            },
            ManifestEntry {
                path: "b/file".to_owned(),
                digest: sha256_bytes(b"b"),
                size: 1,
            },
        ];
        let candidate = fixture_candidate();
        let epoch = fixture_digest();
        let manifest = manifest_json(&candidate, &epoch, &entries);
        let parsed = parse_manifest(&manifest).unwrap();
        assert_eq!(parsed, (candidate.clone(), epoch.clone(), entries.clone()));
        assert_ne!(
            package_root_digest(&candidate, &epoch, &entries),
            package_root_digest(&different_candidate(), &epoch, &entries)
        );
    }

    #[test]
    fn manifest_rejects_traversal_and_duplicate_paths() {
        assert!(portable_relative(&Path::new("..").join("escape")).is_err());
        let candidate = fixture_candidate();
        let epoch = fixture_digest();
        let duplicate = vec![
            ManifestEntry {
                path: "same".to_owned(),
                digest: sha256_bytes(b"a"),
                size: 1,
            },
            ManifestEntry {
                path: "same".to_owned(),
                digest: sha256_bytes(b"b"),
                size: 1,
            },
        ];
        assert!(parse_manifest(&manifest_json(&candidate, &epoch, &duplicate)).is_err());
    }

    #[test]
    fn retained_tree_copy_is_digest_preserving_and_refuses_overwrite() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hell-custody-retained-copy-{}-{nonce}",
            std::process::id()
        ));
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(source.join("provider")).unwrap();
        fs::write(source.join("provider").join("receipt.json"), b"{}\n").unwrap();
        copy_retained_tree(&source, &destination).unwrap();
        assert_eq!(
            sha256_file(&source.join("provider").join("receipt.json")).unwrap(),
            sha256_file(&destination.join("provider").join("receipt.json")).unwrap()
        );
        assert!(copy_retained_tree(&source, &destination).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provider_metadata_is_strict_and_sha256_base64_is_stable() {
        assert_eq!(
            base64(&sha256_bytes(b"evidence").0),
            "7oJQ+3bglLNLRx8Tpz275R0a4ULp31nXwNMewg8KCo4="
        );
        assert!(require_atom("provider\nforged", "provider").is_err());
        assert!(require_atom("provider; forged", "provider").is_err());
        assert!(require_atom("provider$(forged)", "provider").is_err());
        assert!(parse_utc_timestamp("2033-01-01T00:00:00Z").is_ok());
        assert!(
            require_minimum_retention_at("2033-01-01T00:00:00Z", 7, (2026, 1, 1, 0, 0, 0)).is_ok()
        );
        assert!(
            require_minimum_retention_at("2032-12-31T23:59:59Z", 7, (2026, 1, 1, 0, 0, 0)).is_err()
        );
    }

    fn proposed_transition(prior: &str, observed_at: &str, supersedes: &str) -> String {
        format!(
            "{{\n  \"priorState\": \"{prior}\",\n  \"observedAt\": \"{observed_at}\",\n  \"supersedesSha256\": \"{supersedes}\"\n}}\n"
        )
    }

    #[test]
    fn provider_transition_context_is_all_or_none() {
        let mut empty = std::collections::BTreeMap::new();
        assert!(take_transition_context(&mut empty).unwrap().is_none());
        let mut partial = std::collections::BTreeMap::from([(
            "current_transition_record_key".to_owned(),
            "\"record-key\"".to_owned(),
        )]);
        assert!(take_transition_context(&mut partial).is_err());

        let digest = fixture_digest();
        let mut complete = std::collections::BTreeMap::new();
        for key in [
            "current_transition_record_key",
            "current_transition_record_version",
            "current_transition_packet_key",
            "current_transition_packet_version",
            "current_transition_dsse_key",
            "current_transition_dsse_version",
        ] {
            complete.insert(key.to_owned(), "\"immutable-locator\"".to_owned());
        }
        for key in [
            "current_transition_record_sha256",
            "current_transition_packet_sha256",
            "current_transition_dsse_sha256",
        ] {
            complete.insert(key.to_owned(), format!("\"{digest}\""));
        }
        assert!(take_transition_context(&mut complete).unwrap().is_some());
    }

    #[test]
    fn provider_transition_head_rejects_replay_and_fork() {
        let digest = fixture_digest();
        let current = RetrievedTransition {
            record_sha256: digest.clone(),
            packet_sha256: digest.clone(),
            dsse_sha256: digest.clone(),
            derived_state: "at-risk".to_owned(),
            observed_at: "2026-08-09T12:00:00Z".to_owned(),
            supersedes_sha256: digest.clone(),
        };
        assert!(
            verify_transition_supersedes(
                Some(&current),
                &proposed_transition("at-risk", "2026-08-09T12:00:01Z", &digest),
            )
            .is_ok()
        );
        assert!(
            verify_transition_supersedes(
                Some(&current),
                &proposed_transition("promoted", "2026-08-09T12:00:01Z", &digest),
            )
            .is_err()
        );
        assert!(
            verify_transition_supersedes(
                Some(&current),
                &proposed_transition("at-risk", "2026-08-09T12:00:00Z", &digest),
            )
            .is_err()
        );
        assert!(
            verify_transition_supersedes(
                Some(&current),
                &proposed_transition("at-risk", "2026-08-09T12:00:01Z", &different_candidate(),),
            )
            .is_err()
        );
        assert!(
            verify_transition_supersedes(
                None,
                &proposed_transition("promoted", "2026-08-09T12:00:01Z", &digest),
            )
            .is_ok()
        );
        assert!(
            verify_transition_supersedes(
                None,
                &proposed_transition("revoked", "2026-08-09T12:00:01Z", &digest),
            )
            .is_err()
        );
    }

    #[test]
    fn upload_receipt_rejects_unknown_and_duplicate_json_fields() {
        let digest = sha256_bytes(b"object");
        let mut objects = BTreeMap::new();
        objects.insert(
            digest.hex(),
            (
                digest.hex(),
                ObjectMetadata {
                    version: "version-one".to_owned(),
                    object_lock_mode: "COMPLIANCE".to_owned(),
                    retention_until: "2034-01-01T00:00:00Z".to_owned(),
                    encryption: "aws:kms".to_owned(),
                    checksum: base64(&digest.0),
                },
            ),
        );
        let receipt = upload_receipt_json(
            &ProviderIdentity {
                provider: "primary-worm",
                trust_domain: "primary",
                bucket: "custody-primary",
            },
            &ProviderSubject {
                account: "100000000001".to_owned(),
                arn: "arn:aws:sts::100000000001:assumed-role/upload/run".to_owned(),
                stable_id: "UPLOADROLE".to_owned(),
            },
            &fixture_candidate(),
            &fixture_digest(),
            "2034-01-01T00:00:00Z",
            digest,
            digest,
            &objects,
        );
        assert!(parse_upload_receipt(&receipt).is_ok());
        let forged = receipt.replacen("\n}", ",\n  \"provider\": \"secondary-worm\"\n}", 1);
        assert!(parse_upload_receipt(&forged).is_err());
    }

    #[test]
    fn semantic_fuzz_target_custody_manifest_calls_the_exact_production_decoder() {
        let digest = sha256_bytes(b"custody fuzz object");
        let objects = BTreeMap::from([(
            digest.hex(),
            (
                digest.hex(),
                ObjectMetadata {
                    version: "version-one".to_owned(),
                    object_lock_mode: "COMPLIANCE".to_owned(),
                    retention_until: "2034-01-01T00:00:00Z".to_owned(),
                    encryption: "aws:kms".to_owned(),
                    checksum: base64(&digest.0),
                },
            ),
        )]);
        let canonical = upload_receipt_json(
            &ProviderIdentity {
                provider: "primary-worm",
                trust_domain: "primary",
                bucket: "custody-primary",
            },
            &ProviderSubject {
                account: "100000000001".to_owned(),
                arn: "arn:aws:sts::100000000001:assumed-role/upload/run".to_owned(),
                stable_id: "UPLOADROLE".to_owned(),
            },
            &fixture_candidate(),
            &fixture_digest(),
            "2034-01-01T00:00:00Z",
            digest,
            digest,
            &objects,
        );
        assert!(parse_upload_receipt(&canonical).is_ok());
        for index in (0..canonical.len()).step_by(canonical.len().div_ceil(256)) {
            let mut bytes = canonical.as_bytes().to_vec();
            bytes[index] = 0;
            let mutated = String::from_utf8(bytes).unwrap();
            let outcome = std::panic::catch_unwind(|| parse_upload_receipt(&mutated));
            assert!(outcome.is_ok(), "custody decoder panicked at byte {index}");
            assert!(
                outcome.unwrap().is_err(),
                "custody decoder accepted a NUL at byte {index}"
            );
        }
    }

    #[test]
    fn fake_provider_metadata_requires_complete_immutable_evidence() {
        let checksum = base64(&sha256_bytes(b"object").0);
        let response =
            format!("version-1\tCOMPLIANCE\t2034-01-01T00:00:00Z\taws:kms\t{checksum}\n");
        let metadata = parse_head_metadata(response.as_bytes()).unwrap();
        assert_eq!(metadata.version, "version-1");
        assert_eq!(metadata.checksum, checksum);
        assert!(parse_head_metadata(b"version-1\tCOMPLIANCE\tNone\taws:kms\tvalue\n").is_err());
        assert!(parse_head_metadata(b"version-1\tCOMPLIANCE\t2034-01-01T00:00:00Z\n").is_err());
    }

    #[test]
    fn upload_success_without_exact_metadata_cannot_form_an_immutable_receipt() {
        let digest = sha256_bytes(b"uploaded object");
        let checksum = base64(&digest.0);
        let receipt = ReceiptObject {
            key: "content-addressed-key".to_owned(),
            version: "version-1".to_owned(),
            checksum: checksum.clone(),
        };
        let metadata = ObjectMetadata {
            version: receipt.version.clone(),
            object_lock_mode: "COMPLIANCE".to_owned(),
            retention_until: "2034-01-01T00:00:00Z".to_owned(),
            encryption: "aws:kms".to_owned(),
            checksum: checksum.clone(),
        };
        assert!(verify_retrieved_metadata(&metadata, &receipt, "2034-01-01T00:00:00Z").is_ok());
        assert!(verify_uploaded_metadata(&metadata, digest, "2034-01-01T00:00:00Z").is_ok());
        for changed in [
            ObjectMetadata {
                version: String::new(),
                ..metadata.clone()
            },
            ObjectMetadata {
                object_lock_mode: "GOVERNANCE".to_owned(),
                ..metadata.clone()
            },
            ObjectMetadata {
                retention_until: "2033-01-01T00:00:00Z".to_owned(),
                ..metadata.clone()
            },
            ObjectMetadata {
                encryption: "AES256".to_owned(),
                ..metadata.clone()
            },
            ObjectMetadata {
                checksum: base64(&sha256_bytes(b"different object").0),
                ..metadata.clone()
            },
        ] {
            assert!(verify_uploaded_metadata(&changed, digest, "2034-01-01T00:00:00Z").is_err());
            assert!(verify_retrieved_metadata(&changed, &receipt, "2034-01-01T00:00:00Z").is_err());
        }
    }

    #[test]
    fn interrupted_custody_retrieval_never_verifies_a_partial_package() {
        let root = std::env::temp_dir().join(format!(
            "hell-interrupted-custody-retrieval-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("blobs")).unwrap();
        let bytes = b"complete retained object";
        let digest = sha256_bytes(bytes);
        let entries = vec![ManifestEntry {
            path: "evidence/object".to_owned(),
            digest,
            size: bytes.len() as u64,
        }];
        let candidate = fixture_candidate();
        let epoch = fixture_digest();
        fs::write(root.join("blobs").join(digest.hex()), bytes).unwrap();
        fs::write(
            root.join("manifest.json"),
            manifest_json(&candidate, &epoch, &entries),
        )
        .unwrap();
        fs::write(
            root.join("root.sha256"),
            format!(
                "{}\n",
                package_root_digest(&candidate, &epoch, &entries).hex()
            ),
        )
        .unwrap();
        assert!(verify_package(&root).is_ok());
        fs::write(root.join("blobs").join(digest.hex()), &bytes[..7]).unwrap();
        assert!(verify_package(&root).is_err());
        fs::remove_file(root.join("blobs").join(digest.hex())).unwrap();
        assert!(verify_package(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn provider_packet_core_digest_matches_gate_verifier_canonical_form() {
        let digest = fixture_digest();
        let document = format!(
            "{{\n  \"accountOrTenant\": \"account-one\",\n  \"candidateEpochMatch\": true,\n  \"contentSha256\": \"{digest}\",\n  \"encryptionAtRest\": true,\n  \"innerManifestValid\": true,\n  \"objectLock\": true,\n  \"objectVersion\": \"version\",\n  \"provider\": \"account-one\",\n  \"retentionYears\": 7,\n  \"retrievedBy\": \"retriever\",\n  \"retrievedPath\": \"ci-out/retrieved\",\n  \"retrieverStableId\": \"retriever-role\",\n  \"retrievedSha256\": \"{digest}\",\n  \"scrubAgeDays\": 0,\n  \"trustDomain\": \"secondary\",\n  \"uploadReceiptSha256\": \"{digest}\",\n  \"uploadedBy\": \"uploader\",\n  \"uploaderStableId\": \"uploader-role\"\n}}\n"
        );
        let canonical = format!(
            "{{\"schemaVersion\":1,\"accountOrTenant\":\"account-one\",\"candidateEpochMatch\":true,\"contentSha256\":\"{digest}\",\"encryptionAtRest\":true,\"innerManifestValid\":true,\"objectLock\":true,\"objectVersion\":\"version\",\"provider\":\"account-one\",\"retentionYears\":7,\"retrievedBy\":\"retriever\",\"retrievedPath\":\"ci-out/retrieved\",\"retrieverStableId\":\"retriever-role\",\"retrievedSha256\":\"{digest}\",\"scrubAgeDays\":0,\"trustDomain\":\"secondary\",\"uploadReceiptSha256\":\"{digest}\",\"uploadedBy\":\"uploader\",\"uploaderStableId\":\"uploader-role\"}}\n"
        );
        assert_eq!(
            copy_core_digest(&document).unwrap(),
            sha256_bytes(canonical.as_bytes()).hex()
        );
    }

    #[test]
    fn initial_retrieval_becomes_an_exact_candidate_scoped_scrub() {
        let digest = fixture_digest();
        let upload = UploadReceipt {
            provider: "primary-worm".to_owned(),
            trust_domain: "organization-primary".to_owned(),
            account_or_tenant: "100000000001".to_owned(),
            uploaded_by: "primary-uploader".to_owned(),
            uploader_stable_id: "PRIMARYUPLOAD".to_owned(),
            bucket: "custody-primary".to_owned(),
            candidate: fixture_candidate(),
            epoch: digest.clone(),
            root_sha256: digest.clone(),
            manifest_sha256: digest.clone(),
            retention_until: "2034-01-01T00:00:00Z".to_owned(),
            objects: BTreeMap::new(),
        };
        let receipt = initial_maintenance_receipt(
            &upload,
            ValidatedRetrieval {
                retrieved_by: "primary-retriever".to_owned(),
                retriever_stable_id: "PRIMARYRETRIEVER".to_owned(),
                scrub_age_days: 0,
            },
            "2026-08-10T00:00:00Z",
            sha256_bytes(b"upload-receipt"),
        )
        .unwrap();
        let document = canonical_maintenance_receipt(&receipt);
        assert_eq!(
            parse_maintenance_receipt(&document).unwrap().candidate,
            upload.candidate
        );
        assert_eq!(
            quoted_field(&document, "retrievedPath").unwrap(),
            "primary-worm/retrieved/package"
        );
        assert!(
            parse_maintenance_receipt(
                &document.replace("\"kind\": \"scrub\"", "\"kind\": \"retrieval\"")
            )
            .is_err()
        );
        assert!(
            parse_maintenance_receipt(
                &document.replace("\"candidateCommit\":", "\"candidateCommitForged\":")
            )
            .is_err()
        );
    }

    #[test]
    fn current_scrub_retained_paths_are_confined() {
        let root = Path::new("retained");
        assert_eq!(
            safe_retained_path(root, "primary/upload-receipt.json").unwrap(),
            root.join("primary").join("upload-receipt.json")
        );
        assert!(safe_retained_path(root, "../upload-receipt.json").is_err());
        assert!(safe_retained_path(root, "/upload-receipt.json").is_err());
    }

    #[test]
    fn public_report_url_is_exact_https_and_fixed_object_only() {
        assert_eq!(
            PublicReportUrl::new("https://compat.example.test", "current-state.json")
                .unwrap()
                .into_string(),
            "https://compat.example.test/current-state.json"
        );
        assert_eq!(
            PublicReportUrl::new(
                "https://compat.example.test",
                "current-state-publication.json"
            )
            .unwrap()
            .into_string(),
            "https://compat.example.test/current-state-publication.json"
        );
        for (base, key) in [
            ("http://compat.example.test", "current-state.json"),
            ("https://user@compat.example.test", "current-state.json"),
            ("https://compat.example.test/", "current-state.json"),
            ("https://compat.example.test", "other.json"),
        ] {
            assert!(PublicReportUrl::new(base, key).is_err());
        }
    }

    #[test]
    fn public_receipt_exactly_binds_published_transition() {
        let path =
            std::env::temp_dir().join(format!("hell-public-receipt-{}.json", std::process::id()));
        let candidate = fixture_candidate();
        let digest = fixture_digest();
        let receipt = format!(
            "{{\"schemaVersion\":2,\"candidateCommit\":\"{candidate}\",\"assuranceEpochSha256\":\"{digest}\",\"derivedState\":\"promoted\",\"observedAt\":\"2026-08-10T00:00:00Z\",\"publicBaseUrl\":\"https://compat.example.test\",\"recordSha256\":\"{digest}\",\"packetSha256\":\"{digest}\",\"dsseSha256\":\"{digest}\",\"compatibilityReportSha256\":\"{digest}\",\"acceptedDivergencesSha256\":\"{digest}\",\"releaseStatementSha256\":\"{digest}\",\"sourceArtifactId\":1,\"sourceArtifactName\":\"promotion-surveillance-1-1\",\"sourceSelectionSha256\":\"{digest}\",\"sourceProviderArchiveSha256\":\"{digest}\",\"sourceProviderArchiveSize\":1,\"sourceExtractedSha256\":\"{digest}\",\"sourceArtifactApiSha256\":\"{digest}\",\"sourceRunApiSha256\":\"{digest}\",\"sourceWorkflowSha256\":\"{digest}\",\"publisherRunId\":1,\"publisherRunAttempt\":1,\"publisherRepositoryId\":1,\"publisherSourceCommit\":\"{candidate}\",\"publisherWorkflowRef\":\"Portfoligno/hell-rs/.github/workflows/promotion-surveillance.yml@refs/heads/main\",\"publisherEvent\":\"schedule\",\"publisherAccount\":\"1\",\"publisherArn\":\"arn:aws:sts::1:assumed-role/publisher/run\",\"publisherStableId\":\"stable\",\"state\":\"published-and-anonymously-reverified\"}}\n"
        );
        fs::write(&path, &receipt).unwrap();
        let expected = crate::assurance::PublicationReceiptExpectation {
            public_base_url: "https://compat.example.test",
            candidate: &candidate,
            epoch: &digest,
            state: "promoted",
            record_sha256: &digest,
            packet_sha256: &digest,
            dsse_sha256: &digest,
            report_sha256: &digest,
            divergences_sha256: &digest,
            release_statement_sha256: &digest,
        };
        assert!(crate::assurance::verify_publication_receipt(&path, &expected).is_ok());
        fs::write(&path, receipt.replace("}\n", ",\"extra\":true}\n")).unwrap();
        assert!(crate::assurance::verify_publication_receipt(&path, &expected).is_err());
        fs::remove_file(path).unwrap();
    }

    struct PublishedStateFixture {
        root: PathBuf,
        publication: PathBuf,
        candidate: String,
        epoch: String,
        record_text: String,
        source: PublicSourceContext,
        source_facts: PublicSourceFacts,
        subject: ProviderSubject,
    }

    fn published_state_fixture() -> PublishedStateFixture {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hell-published-state-authority-{}-{nonce}",
            std::process::id()
        ));
        let publication = root.join("publication");
        fs::create_dir_all(&publication).unwrap();
        let candidate = fixture_candidate();
        let epoch = fixture_digest();
        let record_text = format!(
            "{{\n  \"candidateCommit\": \"{candidate}\",\n  \"assuranceEpochSha256\": \"{epoch}\",\n  \"derivedState\": \"promoted\",\n  \"observedAt\": \"2026-08-10T00:00:00Z\"\n}}\n"
        );
        for (name, bytes) in [
            ("promotion-transition.json", record_text.as_bytes()),
            ("promotion-transition-packet.json", b"packet".as_slice()),
            ("promotion-transition.dsse.json", b"dsse".as_slice()),
            ("compatibility-report.md", b"report".as_slice()),
            ("accepted-divergences.json", b"divergences".as_slice()),
            (
                "public-release-statement.json",
                b"release-statement".as_slice(),
            ),
        ] {
            fs::write(publication.join(name), bytes).unwrap();
        }
        let selection_root = root.join("source-selection");
        let extracted = selection_root.join("extracted");
        let reverified = selection_root.join("reverified");
        let source_directory = root.join("source-directory");
        for directory in [&extracted, &reverified, &source_directory] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(extracted.join("state.json"), b"retained public state\n").unwrap();
        fs::write(
            source_directory.join("state.json"),
            b"retained public state\n",
        )
        .unwrap();
        fs::write(selection_root.join("artifact.zip"), b"provider archive").unwrap();
        for name in [
            "provider-selected-artifact.json",
            "provider-selected-run.json",
        ] {
            fs::write(selection_root.join(name), format!("{name}\n")).unwrap();
            fs::write(reverified.join(name), format!("{name}\n")).unwrap();
        }
        let archive_sha256 =
            public_report_file_digest(&selection_root.join("artifact.zip")).unwrap();
        let artifact_api_sha256 =
            public_report_file_digest(&selection_root.join("provider-selected-artifact.json"))
                .unwrap();
        let run_api_sha256 =
            public_report_file_digest(&selection_root.join("provider-selected-run.json")).unwrap();
        let selection = format!(
            "{{\n  \"providerArchiveSha256\": \"{archive_sha256}\",\n  \"providerArchiveSize\": 16,\n  \"providerArtifactApiSha256\": \"{artifact_api_sha256}\",\n  \"providerRunApiSha256\": \"{run_api_sha256}\",\n  \"workflowBlobSha256\": \"{epoch}\"\n}}\n"
        );
        fs::write(
            selection_root.join("public-source-selection.json"),
            &selection,
        )
        .unwrap();
        let source = PublicSourceContext {
            artifact_id: 17,
            run_id: 19,
            run_attempt: 2,
            repository_id: 23,
            source_commit: candidate.clone(),
            workflow_ref:
                "Portfoligno/hell-rs/.github/workflows/promotion-surveillance.yml@refs/heads/main"
                    .to_owned(),
            workflow_path: ".github/workflows/promotion-surveillance.yml".to_owned(),
            artifact_name: "promotion-public-current-state-19-2".to_owned(),
            event: "schedule".to_owned(),
        };
        let source_facts = verify_retained_public_source_reselection(
            &selection_root,
            &reverified,
            &source_directory,
            &selection,
            &selection,
        )
        .unwrap();
        let subject = parse_provider_subject(
            b"123456789012\tarn:aws:sts::123456789012:assumed-role/publisher/run\tprovider-stable-id:session\n",
        )
        .unwrap();
        PublishedStateFixture {
            root,
            publication,
            candidate,
            epoch,
            record_text,
            source,
            source_facts,
            subject,
        }
    }

    #[test]
    fn published_state_authority_builder_round_trips_verified_inputs() {
        let PublishedStateFixture {
            root,
            publication,
            candidate,
            epoch,
            record_text,
            mut source,
            mut source_facts,
            mut subject,
        } = published_state_fixture();
        let receipt = PublishedStateAuthorityBuilder {
            directory: &publication,
            base_url: "https://compat.example.test",
            source: &source,
            source_facts: &source_facts,
            subject: &subject,
        }
        .receipt(&record_text)
        .unwrap();
        let receipt_path = publication.join("public-report-publication.json");
        fs::write(&receipt_path, &receipt).unwrap();
        let record_sha256 =
            public_report_file_digest(&publication.join("promotion-transition.json")).unwrap();
        let packet_sha256 =
            public_report_file_digest(&publication.join("promotion-transition-packet.json"))
                .unwrap();
        let dsse_sha256 =
            public_report_file_digest(&publication.join("promotion-transition.dsse.json")).unwrap();
        let report_sha256 =
            public_report_file_digest(&publication.join("compatibility-report.md")).unwrap();
        let divergences_sha256 =
            public_report_file_digest(&publication.join("accepted-divergences.json")).unwrap();
        let release_statement_sha256 =
            public_report_file_digest(&publication.join("public-release-statement.json")).unwrap();
        let expected = crate::assurance::PublicationReceiptExpectation {
            public_base_url: "https://compat.example.test",
            candidate: &candidate,
            epoch: &epoch,
            state: "promoted",
            record_sha256: &record_sha256,
            packet_sha256: &packet_sha256,
            dsse_sha256: &dsse_sha256,
            report_sha256: &report_sha256,
            divergences_sha256: &divergences_sha256,
            release_statement_sha256: &release_statement_sha256,
        };
        assert!(crate::assurance::verify_publication_receipt(&receipt_path, &expected).is_ok());
        assert!(
            verify_published_state_authority_receipt(&receipt, &source, &source_facts, &subject)
                .is_ok()
        );

        source.artifact_id += 1;
        assert!(
            verify_published_state_authority_receipt(&receipt, &source, &source_facts, &subject)
                .is_err()
        );
        source.artifact_id -= 1;
        let original_selection_sha256 = source_facts.selection_sha256.clone();
        source_facts.selection_sha256 = sha256_bytes(b"substituted selection").hex();
        assert!(
            verify_published_state_authority_receipt(&receipt, &source, &source_facts, &subject)
                .is_err()
        );
        source_facts
            .selection_sha256
            .clone_from(&original_selection_sha256);
        subject.stable_id = "substituted-provider".to_owned();
        assert!(
            verify_published_state_authority_receipt(&receipt, &source, &source_facts, &subject)
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn signed_activation_run_identity_rejects_substitution() {
        let activation = "{\n  \"activationRunId\": 41,\n  \"activationRunAttempt\": 3\n}\n";
        assert!(verify_activation_run_binding(activation, activation, 41, 3).is_ok());
        assert!(verify_activation_run_binding(activation, activation, 42, 3).is_err());
        assert!(verify_activation_run_binding(activation, activation, 41, 4).is_err());
        let substituted = "{\n  \"activationRunId\": 41,\n  \"activationRunAttempt\": 4\n}\n";
        assert!(verify_activation_run_binding(activation, substituted, 41, 3).is_err());
    }

    fn review_packet_fixture(candidate: &str, epoch: &str, artifacts: &[String]) -> String {
        let artifact_identity = artifacts.join("\n");
        let review_id = sha256_bytes(
            [
                candidate.as_bytes(),
                epoch.as_bytes(),
                b"custody-reviewer",
                artifact_identity.as_bytes(),
            ]
            .concat()
            .as_slice(),
        )
        .hex();
        packet_json(
            &review_id,
            "custody-reviewer",
            "custody-reviewer:fixture",
            candidate,
            epoch,
            artifacts,
            "2026-08-10T00:00:00Z",
        )
    }

    #[test]
    fn transition_packet_requires_exact_first_artifact_schema() {
        let root =
            std::env::temp_dir().join(format!("hell-transition-packet-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("packet.json");
        let candidate = fixture_candidate();
        let epoch = fixture_digest();
        let record = sha256_bytes(b"record").hex();
        let other = sha256_bytes(b"other").hex();

        fs::write(
            &path,
            review_packet_fixture(&candidate, &epoch, &[record.clone(), other.clone()]),
        )
        .unwrap();
        assert!(
            crate::assurance::verify_review_packet_first_artifact(
                &path,
                "custody-reviewer",
                &candidate,
                &epoch,
                &record,
            )
            .is_ok()
        );

        fs::write(
            &path,
            review_packet_fixture(&candidate, &epoch, &[other, record.clone()]),
        )
        .unwrap();
        assert!(
            crate::assurance::verify_review_packet_first_artifact(
                &path,
                "custody-reviewer",
                &candidate,
                &epoch,
                &record,
            )
            .is_err()
        );

        let extra = review_packet_fixture(&candidate, &epoch, std::slice::from_ref(&record))
            .replace("}\n", ",\"extra\":true}\n");
        fs::write(&path, extra).unwrap();
        assert!(
            crate::assurance::verify_review_packet_first_artifact(
                &path,
                "custody-reviewer",
                &candidate,
                &epoch,
                &record,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
