use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use flate2::{Compression, GzBuilder, read::GzDecoder};
use tar::{EntryType, Header};

use crate::command::CommandSpec;
use crate::json::JsonValue;

use super::manifest::{read_json, read_regular, write_atomic, write_json, write_json_new};
use super::schema::{ReleasePlan, number, object, string};

const MAX_COPY_DEPTH: usize = 16;
const MAX_COPY_ENTRIES: usize = 1_000_000;
const MAX_COPY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone)]
struct Vector {
    id: String,
    valid: bool,
    mutation: String,
    diagnostic: Option<String>,
}

struct Manifest {
    protocol_version: String,
    protocol_projection: PathBuf,
    vectors: Vec<Vector>,
}

#[derive(Clone, Copy)]
struct VectorRegistration {
    id: &'static str,
    mutation: &'static str,
    diagnostic: Option<&'static str>,
}

const VECTOR_REGISTRY: [VectorRegistration; 37] = [
    registration("known-good", "none", None),
    registration(
        "duplicate-json-key",
        "duplicate-json-key",
        Some("release.json.duplicate-key"),
    ),
    registration(
        "unknown-field",
        "unknown-field",
        Some("release.json.unknown-field"),
    ),
    registration(
        "trailing-json-bytes",
        "trailing-json-bytes",
        Some("release.json.trailing-bytes"),
    ),
    registration(
        "noncanonical-integer",
        "noncanonical-integer",
        Some("release.json.noncanonical-integer"),
    ),
    registration(
        "wrong-candidate-sha",
        "wrong-candidate-sha",
        Some("release.binding.candidate-sha"),
    ),
    registration(
        "wrong-workflow-sha",
        "wrong-workflow-sha",
        Some("release.binding.workflow-sha"),
    ),
    registration(
        "wrong-source-inventory-digest",
        "wrong-source-inventory-digest",
        Some("release.binding.source-inventory"),
    ),
    registration(
        "wrong-oracle-identity",
        "wrong-oracle-identity",
        Some("release.binding.oracle"),
    ),
    registration(
        "wrong-executable-digest",
        "wrong-executable-digest",
        Some("release.binding.executable"),
    ),
    registration(
        "linux-evidence-relabeled-as-windows",
        "linux-evidence-relabeled-as-windows",
        Some("release.evidence.platform"),
    ),
    registration(
        "evidence-replayed-into-another-case",
        "evidence-replayed-into-another-case",
        Some("release.evidence.case"),
    ),
    registration(
        "missing-cell",
        "missing-cell",
        Some("release.ledger.missing-cell"),
    ),
    registration(
        "duplicate-cell",
        "duplicate-cell",
        Some("release.ledger.duplicate-cell"),
    ),
    registration(
        "unused-authoritative-evidence",
        "unused-authoritative-evidence",
        Some("release.evidence.unused"),
    ),
    registration(
        "contradictory-evidence-for-one-cell",
        "contradictory-evidence-for-one-cell",
        Some("release.evidence.contradictory"),
    ),
    registration(
        "exemption-with-mismatched-selector",
        "exemption-with-mismatched-selector",
        Some("release.exemption.selector"),
    ),
    registration(
        "expired-exemption",
        "expired-exemption",
        Some("release.exemption.expired"),
    ),
    registration(
        "exemption-uses-wall-clock-time",
        "exemption-uses-wall-clock-time",
        Some("release.exemption.evaluation-instant"),
    ),
    registration(
        "extra-archive-member",
        "extra-archive-member",
        Some("release.archive.extra-member"),
    ),
    registration(
        "duplicate-archive-member",
        "duplicate-archive-member",
        Some("release.archive.duplicate-member"),
    ),
    registration(
        "archive-path-traversal",
        "archive-path-traversal",
        Some("release.archive.path-traversal"),
    ),
    registration(
        "absolute-archive-path",
        "absolute-archive-path",
        Some("release.archive.absolute-path"),
    ),
    registration(
        "archive-symbolic-link",
        "archive-symbolic-link",
        Some("release.archive.unsupported-type"),
    ),
    registration(
        "malformed-tar-checksum",
        "malformed-tar-checksum",
        Some("release.archive.tar-checksum"),
    ),
    registration(
        "trailing-gzip-member",
        "trailing-gzip-member",
        Some("release.archive.trailing-gzip-member"),
    ),
    registration(
        "decompression-limit-exceeded",
        "decompression-limit-exceeded",
        Some("release.limit.archive-expanded"),
    ),
    registration(
        "subject-omitted-from-manifest",
        "subject-omitted-from-manifest",
        Some("release.subject.missing"),
    ),
    registration(
        "unlisted-extra-subject",
        "unlisted-extra-subject",
        Some("release.subject.extra"),
    ),
    registration(
        "release-gate-bound-to-another-subject-manifest",
        "release-gate-bound-to-another-subject-manifest",
        Some("release.binding.subject-manifest"),
    ),
    registration(
        "blocked-count-hidden-by-forged-summary",
        "blocked-count-hidden-by-forged-summary",
        Some("release.ledger.forged-count"),
    ),
    registration(
        "malformed-platform-report-count",
        "malformed-platform-report-count",
        Some("release.platform.forged-count"),
    ),
    registration(
        "wrong-native-environment-receipt",
        "wrong-native-environment-receipt",
        Some("release.binding.native-environment"),
    ),
    registration(
        "wrong-governance-profile",
        "wrong-governance-profile",
        Some("release.binding.governance-profile"),
    ),
    registration(
        "protocol-downgrade",
        "protocol-downgrade",
        Some("release.protocol.downgrade"),
    ),
    registration(
        "primary-accepts-independent-rejects",
        "primary-accepts-independent-rejects",
        Some("release.verifier-disagreement"),
    ),
    registration(
        "independent-accepts-primary-rejects",
        "independent-accepts-primary-rejects",
        Some("release.verifier-disagreement"),
    ),
];

const fn registration(
    id: &'static str,
    mutation: &'static str,
    diagnostic: Option<&'static str>,
) -> VectorRegistration {
    VectorRegistration {
        id,
        mutation,
        diagnostic,
    }
}

pub(crate) struct MaterializeOptions {
    pub(crate) plan: PathBuf,
    pub(crate) conformance_plan: PathBuf,
    pub(crate) bundle: PathBuf,
    pub(crate) platform_input: PathBuf,
    pub(crate) manifest: PathBuf,
    pub(crate) protocol_projection: PathBuf,
    pub(crate) independent_verifier: PathBuf,
    pub(crate) governance_post_assembly: PathBuf,
    pub(crate) governance_pre_attestation: PathBuf,
    pub(crate) output: PathBuf,
}

pub(crate) struct VerifyOptions {
    pub(crate) manifest: PathBuf,
    pub(crate) vectors_root: PathBuf,
    pub(crate) protocol_projection: PathBuf,
    pub(crate) output: PathBuf,
}

pub(crate) struct RegistryOptions {
    pub(crate) manifest: PathBuf,
    pub(crate) output: PathBuf,
}

struct OwnedOptions<T>(T);

impl<T> OwnedOptions<T> {
    fn new(options: T) -> Self {
        Self(options)
    }

    fn get(&self) -> &T {
        &self.0
    }
}

pub(crate) fn verify_registry(options: RegistryOptions) -> Result<String, String> {
    let transaction = OwnedOptions::new(options);
    let options = transaction.get();
    if options.output.exists() {
        return Err("release vector registry output already exists".to_owned());
    }
    let manifest = parse_manifest(&options.manifest)?;
    let vectors = manifest
        .vectors
        .iter()
        .map(|vector| {
            object([
                (
                    "diagnosticCode",
                    vector.diagnostic.as_deref().map_or(JsonValue::Null, string),
                ),
                ("id", string(&vector.id)),
                ("mutation", string(&vector.mutation)),
                ("valid", JsonValue::Bool(vector.valid)),
            ])
        })
        .collect();
    write_json_new(
        &options.output,
        &object([
            ("schemaVersion", number(1)),
            ("state", string("verified")),
            ("vectorCount", number(37)),
            ("vectors", JsonValue::Array(vectors)),
        ]),
    )?;
    Ok("verified exact release protocol vector registry".to_owned())
}

pub(crate) fn materialize(options: MaterializeOptions) -> Result<String, String> {
    let transaction = OwnedOptions::new(options);
    let options = transaction.get();
    if options.output.exists() {
        return Err("release vector output already exists".to_owned());
    }
    let manifest = parse_manifest(&options.manifest)?;
    if manifest.protocol_version != super::decision::ADMISSION_PROTOCOL_VERSION {
        return Err("release vector manifest protocol version differs".to_owned());
    }
    require_safe_relative(&manifest.protocol_projection)?;
    let supplied_projection = fs::canonicalize(&options.protocol_projection)
        .map_err(|error| format!("cannot canonicalize supplied protocol projection: {error}"))?;
    if !supplied_projection.ends_with(&manifest.protocol_projection) {
        return Err("release vector projection differs from manifest authority".to_owned());
    }
    let governance_resolve = validate_real_inputs(options)?;
    let staging = staging_path(&options.output)?;
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create release vector staging: {error}"))?;
    let result = materialize_staged(options, &manifest, &governance_resolve, &staging);
    match result {
        Ok(()) => {
            fs::rename(&staging, &options.output)
                .map_err(|error| format!("cannot promote release vector corpus: {error}"))?;
            Ok("materialized exact real-input release protocol vector corpus".to_owned())
        }
        Err(primary) => match fs::remove_dir_all(&staging) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(format!(
                "{primary}; additionally, cannot clean release vector staging: {cleanup}"
            )),
        },
    }
}

pub(crate) fn verify(options: VerifyOptions) -> Result<String, String> {
    let transaction = OwnedOptions::new(options);
    let options = transaction.get();
    if options.output.exists() {
        return Err("primary vector verification output already exists".to_owned());
    }
    let manifest = parse_manifest(&options.manifest)?;
    require_corpus_inventory(&options.vectors_root, &manifest)?;
    let protocol_sha256 =
        super::decision::protocol_sha256_from_projection(&options.protocol_projection)?;
    let staging = staging_path(&options.output)?;
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create primary vector verification staging: {error}"))?;
    let result = verify_corpus(&manifest, &options.vectors_root, &staging, &protocol_sha256)
        .and_then(|checked| {
            write_json(
                &staging.join("primary-vector-report.json"),
                &object([
                    ("checkedVectorCount", number(checked)),
                    ("implementation", string("hell-ci")),
                    ("schemaVersion", number(1)),
                    ("state", string("verified")),
                ]),
            )
            .map(|_| ())
        });
    match result {
        Ok(()) => {
            let report = staging.join("primary-vector-report.json");
            copy_regular(&report, &options.output)?;
            fs::remove_dir_all(&staging).map_err(|error| {
                format!("cannot clean primary vector verification staging: {error}")
            })?;
            Ok("executed exact primary release protocol vector corpus".to_owned())
        }
        Err(primary) => match fs::remove_dir_all(&staging) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(format!(
                "{primary}; additionally, cannot clean primary vector verification staging: {cleanup}"
            )),
        },
    }
}

fn verify_corpus(
    manifest: &Manifest,
    vectors_root: &Path,
    staging: &Path,
    protocol_sha256: &str,
) -> Result<u64, String> {
    let mut checked = 0_u64;
    for vector in &manifest.vectors {
        let root = vector_root(vectors_root, vector);
        require_vector_inventory(&root)?;
        let observed = parse_single_vector(&root.join("vector.toml"))?;
        require_same_vector(vector, &observed)?;
        let report = staging.join(format!("{}-primary-report.json", vector.id));
        let decision = staging.join(format!("{}-primary-decision.json", vector.id));
        let (plan, challenge) = verifier_plan_input(&root, staging, vector, "primary")?;
        let mut result = super::verify::technical_bundle_with_decision(
            plan,
            root.join("conformance-plan.json"),
            root.join("bundle"),
            report.clone(),
            decision.clone(),
            protocol_sha256.to_owned(),
            governance_receipt_digests_from_root(&root)?,
        );
        remove_verifier_challenge(challenge, result.as_ref().err())?;
        if vector.mutation == "malformed-platform-report-count" && result.is_ok() {
            let platform_result = verify_platform_vector_input(&root);
            if platform_result.is_ok() {
                return Err(
                    "malformed platform report vector passed platform verification".to_owned(),
                );
            }
            if decision.exists() {
                fs::remove_file(&decision).map_err(|error| {
                    format!("cannot remove admitted platform vector decision: {error}")
                })?;
            }
            write_json(
                &report,
                &object([
                    ("admitted", JsonValue::Bool(false)),
                    ("diagnosticCode", string("release.platform.forged-count")),
                    ("implementation", string("hell-ci")),
                    ("schemaVersion", number(1)),
                    ("state", string("blocked")),
                ]),
            )?;
            result = match platform_result {
                Err(error) => Err(error),
                Ok(()) => return Err("platform vector preflight changed outcome".to_owned()),
            };
        }
        if is_disagreement_vector(vector) {
            verify_primary_disagreement_outcome(vector, &root, &report, &decision, result)?;
            checked = checked
                .checked_add(1)
                .ok_or_else(|| "primary vector count overflow".to_owned())?;
            continue;
        }
        verify_observed_outcome(
            vector,
            result.map(|_| ()),
            &report,
            &decision,
            &root.join("expected-primary.json"),
        )?;
        checked = checked
            .checked_add(1)
            .ok_or_else(|| "primary vector count overflow".to_owned())?;
    }
    Ok(checked)
}

fn verify_primary_disagreement_outcome(
    vector: &Vector,
    root: &Path,
    report: &Path,
    decision: &Path,
    result: Result<String, String>,
) -> Result<(), String> {
    match vector.mutation.as_str() {
        "primary-accepts-independent-rejects" => {
            result.map_err(|error| format!("primary disagreement side was rejected: {error}"))?;
            if read_regular(decision)? != read_regular(&root.join("expected-primary.json"))? {
                return Err(
                    "primary disagreement decision differs from its executed outcome".to_owned(),
                );
            }
            require_expected_rejection_document(&root.join("expected-independent.json"))
        }
        "independent-accepts-primary-rejects" => {
            if result.is_ok() {
                return Err("primary rejection challenge was admitted".to_owned());
            }
            let diagnostic = diagnostic_from_report(report)?;
            require_expected_rejection(&root.join("expected-primary.json"), &diagnostic)?;
            require_expected_decision(&root.join("expected-independent.json"))
        }
        _ => Err("non-disagreement vector reached primary disagreement replay".to_owned()),
    }
}

fn require_expected_rejection_document(path: &Path) -> Result<(), String> {
    let diagnostic = diagnostic_from_report(path)?;
    require_expected_rejection(path, &diagnostic)
}

fn require_expected_decision(path: &Path) -> Result<(), String> {
    let value = read_json(path)?;
    super::decision::VerifierDecision::parse(&value).map(|_| ())
}

fn verify_observed_outcome(
    vector: &Vector,
    result: Result<(), String>,
    report: &Path,
    decision: &Path,
    expected: &Path,
) -> Result<(), String> {
    match (vector.valid, result) {
        (true, Ok(())) => {
            if read_regular(decision)? != read_regular(expected)? {
                return Err(format!(
                    "primary decision differs from expected decision for vector {:?}",
                    vector.id
                ));
            }
            Ok(())
        }
        (false, Err(primary)) => {
            let diagnostic = diagnostic_from_report(report).map_err(|persistence| {
                format!(
                    "{primary}; additionally, primary verifier did not persist a typed vector diagnostic: {persistence}"
                )
            })?;
            if vector.diagnostic.as_deref() != Some(diagnostic.as_str()) {
                return Err(format!(
                    "primary diagnostic differs for vector {:?}: observed {diagnostic:?}",
                    vector.id
                ));
            }
            require_expected_rejection(expected, &diagnostic)
        }
        (true, Err(primary)) => Err(format!(
            "known-good vector {:?} was rejected by the primary verifier: {primary}",
            vector.id
        )),
        (false, Ok(())) => Err(format!(
            "invalid vector {:?} was admitted by the primary verifier",
            vector.id
        )),
    }
}

fn require_expected_rejection(path: &Path, diagnostic: &str) -> Result<(), String> {
    let value = read_json(path)?;
    let fields = value.object()?;
    crate::json::require_exact_json_keys(
        fields,
        &["admitted", "diagnosticCode", "schemaVersion", "state"],
    )?;
    if fields.get("admitted") != Some(&JsonValue::Bool(false))
        || fields.get("diagnosticCode") != Some(&JsonValue::String(diagnostic.to_owned()))
        || fields.get("schemaVersion") != Some(&JsonValue::Number(1))
        || fields.get("state") != Some(&JsonValue::String("blocked".to_owned()))
    {
        return Err("expected vector rejection does not match its manifest diagnostic".to_owned());
    }
    Ok(())
}

fn validate_real_inputs(options: &MaterializeOptions) -> Result<PathBuf, String> {
    let plan = ReleasePlan::parse(&read_json(&options.plan)?)?;
    let governance_resolve = options
        .plan
        .parent()
        .ok_or_else(|| "release vector plan has no artifact root".to_owned())?
        .join("governance-resolve.json");
    let resolve_sha256 = super::governance::verify_snapshot(
        &governance_resolve,
        &plan,
        super::governance::Phase::Resolve,
        None,
        None,
    )?;
    let post_assembly_sha256 = super::governance::verify_snapshot(
        &options.governance_post_assembly,
        &plan,
        super::governance::Phase::PostAssembly,
        Some(&resolve_sha256),
        Some(&resolve_sha256),
    )?;
    let pre_attestation_sha256 = super::governance::verify_snapshot(
        &options.governance_pre_attestation,
        &plan,
        super::governance::Phase::PreAttestation,
        Some(&resolve_sha256),
        Some(&post_assembly_sha256),
    )?;
    let governance_receipts = super::verify::GovernanceReceiptDigests {
        resolve: resolve_sha256,
        post_assembly: post_assembly_sha256,
        pre_attestation: pre_attestation_sha256,
    };
    let conformance =
        crate::conformance::ConformancePlan::parse(&read_json(&options.conformance_plan)?)?;
    if conformance.plan_sha256 != plan.conformance_plan_sha256
        || conformance.candidate_sha != plan.resolution.candidate_sha
        || conformance.workflow_sha != plan.resolution.workflow_sha
        || conformance.source_inventory_sha256 != plan.source_inventory_sha256
        || conformance.trusted_inputs_sha256 != plan.trusted_conformance_inputs_sha256
    {
        return Err("release vector inputs are not plan-bound".to_owned());
    }
    for (platform_id, platform) in [
        ("linux-x86_64", super::schema::ReleasePlatform::LinuxX86_64),
        (
            "macos-aarch64",
            super::schema::ReleasePlatform::MacosAarch64,
        ),
        (
            "windows-x86_64",
            super::schema::ReleasePlatform::WindowsX86_64,
        ),
    ] {
        super::assemble::verify_platform_report(
            &options
                .platform_input
                .join(platform_id)
                .join("platform-report.json"),
            &plan,
            &conformance,
            platform,
        )?;
    }
    let verification_root = staging_path(&options.output)?.with_extension("input-verification");
    if verification_root.exists() {
        return Err("release vector input verification path already exists".to_owned());
    }
    fs::create_dir(&verification_root)
        .map_err(|error| format!("cannot create release vector input verification: {error}"))?;
    let protocol_sha256 =
        super::decision::protocol_sha256_from_projection(&options.protocol_projection)?;
    let result = super::verify::technical_bundle_with_decision(
        options.plan.clone(),
        options.conformance_plan.clone(),
        options.bundle.clone(),
        verification_root.join("primary-report.json"),
        verification_root.join("primary-decision.json"),
        protocol_sha256,
        governance_receipts,
    );
    match fs::remove_dir_all(&verification_root) {
        Ok(()) => result.map(|_| governance_resolve),
        Err(cleanup) => match result {
            Ok(_) => Err(format!(
                "cannot clean release vector input verification: {cleanup}"
            )),
            Err(primary) => Err(format!(
                "{primary}; additionally, cannot clean release vector input verification: {cleanup}"
            )),
        },
    }
}

fn materialize_staged(
    options: &MaterializeOptions,
    manifest: &Manifest,
    governance_resolve: &Path,
    staging: &Path,
) -> Result<(), String> {
    let mut outcomes = Vec::new();
    for vector in &manifest.vectors {
        let root = if vector.valid {
            staging.join("valid").join(&vector.id)
        } else {
            staging.join("invalid").join(&vector.id)
        };
        fs::create_dir_all(&root)
            .map_err(|error| format!("cannot create release vector {:?}: {error}", vector.id))?;
        copy_regular(&options.plan, &root.join("plan.json"))?;
        copy_regular(
            &options.conformance_plan,
            &root.join("conformance-plan.json"),
        )?;
        copy_tree(&options.bundle, &root.join("bundle"))?;
        copy_tree(&options.platform_input, &root.join("platform-input"))?;
        for (source, name) in [
            (governance_resolve, "governance-resolve.json"),
            (
                options.governance_post_assembly.as_path(),
                "governance-post-assembly.json",
            ),
            (
                options.governance_pre_attestation.as_path(),
                "governance-pre-attestation.json",
            ),
        ] {
            copy_regular(source, &root.join(name))?;
        }
        write_vector(&root.join("vector.toml"), vector)?;
        if !is_disagreement_vector(vector) {
            apply_mutation(&root, vector)?;
        }
        let primary = run_primary(options, &root, vector)?;
        let independent = run_independent(options, &root, vector)?;
        require_expected_outcome(vector, primary, independent)?;
        outcomes.push(object([
            (
                "diagnostic",
                vector.diagnostic.as_deref().map_or(JsonValue::Null, string),
            ),
            ("id", string(&vector.id)),
            ("valid", JsonValue::Bool(vector.valid)),
        ]));
    }
    write_json(
        &staging.join("materialization-report.json"),
        &object([
            ("protocolVersion", string(&manifest.protocol_version)),
            ("schemaVersion", number(1)),
            ("state", string("materialized")),
            ("vectors", JsonValue::Array(outcomes)),
        ]),
    )?;
    Ok(())
}

fn run_primary(
    options: &MaterializeOptions,
    root: &Path,
    vector: &Vector,
) -> Result<VerifierOutcome, String> {
    let protocol_sha256 =
        super::decision::protocol_sha256_from_projection(&options.protocol_projection)?;
    let report = root.join("primary-report.json");
    let decision = root.join(".primary-decision.json");
    let (plan, challenge) = verifier_plan_input(root, root, vector, "primary")?;
    let result = super::verify::technical_bundle_with_decision(
        plan,
        root.join("conformance-plan.json"),
        root.join("bundle"),
        report.clone(),
        decision.clone(),
        protocol_sha256,
        governance_receipt_digests_from_root(root)?,
    );
    remove_verifier_challenge(challenge, result.as_ref().err())?;
    match result {
        Ok(_) if vector.mutation == "malformed-platform-report-count" => {
            let Err(error) = verify_platform_vector_input(root) else {
                return Err(
                    "malformed platform report vector passed primary verification".to_owned(),
                );
            };
            fs::remove_file(&decision).map_err(|remove| {
                format!("{error}; additionally, cannot remove primary vector decision: {remove}")
            })?;
            fs::remove_file(&report).map_err(|remove| {
                format!("{error}; additionally, cannot remove primary vector report: {remove}")
            })?;
            let diagnostic = "release.platform.forged-count".to_owned();
            write_expected_rejection(&root.join("expected-primary.json"), &diagnostic)?;
            Ok(VerifierOutcome::Rejected {
                diagnostic,
                detail: error,
            })
        }
        Ok(_) => {
            copy_regular(&decision, &root.join("expected-primary.json"))?;
            fs::remove_file(&decision).map_err(|error| {
                format!("cannot remove primary vector decision staging: {error}")
            })?;
            fs::remove_file(&report)
                .map_err(|error| format!("cannot remove primary vector report staging: {error}"))?;
            Ok(VerifierOutcome::Admitted)
        }
        Err(error) => {
            let diagnostic = diagnostic_from_report(&report)?;
            write_expected_rejection(&root.join("expected-primary.json"), &diagnostic)?;
            fs::remove_file(&report).map_err(|remove| {
                format!(
                    "{error}; additionally, cannot remove primary vector report staging: {remove}"
                )
            })?;
            Ok(VerifierOutcome::Rejected {
                diagnostic,
                detail: error,
            })
        }
    }
}

fn run_independent(
    options: &MaterializeOptions,
    root: &Path,
    vector: &Vector,
) -> Result<VerifierOutcome, String> {
    let output = root.join("independent-output");
    let (plan, challenge) = verifier_plan_input(root, root, vector, "independent")?;
    let arguments = [
        OsString::from("verify"),
        OsString::from("--plan"),
        plan.into_os_string(),
        OsString::from("--conformance-plan"),
        root.join("conformance-plan.json").into_os_string(),
        OsString::from("--bundle"),
        root.join("bundle").into_os_string(),
        OsString::from("--protocol-projection"),
        options.protocol_projection.as_os_str().to_owned(),
        OsString::from("--governance-resolve"),
        root.join("governance-resolve.json").into_os_string(),
        OsString::from("--governance-post-assembly"),
        root.join("governance-post-assembly.json").into_os_string(),
        OsString::from("--governance-pre-attestation"),
        root.join("governance-pre-attestation.json")
            .into_os_string(),
        OsString::from("--output"),
        output.clone().into_os_string(),
    ];
    let mut command = CommandSpec::trusted_absolute(
        fs::canonicalize(&options.independent_verifier)
            .map_err(|error| format!("cannot canonicalize independent verifier: {error}"))?,
        Duration::from_mins(30),
    )?
    .arguments(arguments);
    command.clear_environment = true;
    let result = command
        .run()
        .map_err(|error| format!("cannot run independent release vector verifier: {error}"));
    remove_verifier_challenge(challenge, result.as_ref().err())?;
    let result = result?;
    let report = output.join("independent-verifier-report.json");
    if result.status.success()
        && !result.timed_out
        && vector.mutation == "malformed-platform-report-count"
    {
        let Err(error) = verify_platform_count_independently(root) else {
            return Err(
                "malformed platform report vector passed independent verification".to_owned(),
            );
        };
        let diagnostic = "release.platform.forged-count".to_owned();
        write_expected_rejection(&root.join("expected-independent.json"), &diagnostic)?;
        fs::remove_dir_all(output).map_err(|remove| {
            format!("{error}; additionally, cannot remove independent vector output: {remove}")
        })?;
        return Ok(VerifierOutcome::Rejected {
            diagnostic,
            detail: error,
        });
    }
    if result.status.success() && !result.timed_out {
        copy_regular(
            &output.join("independent-verifier-decision.json"),
            &root.join("expected-independent.json"),
        )?;
        fs::remove_dir_all(output)
            .map_err(|error| format!("cannot remove independent vector output: {error}"))?;
        return Ok(VerifierOutcome::Admitted);
    }
    let diagnostic = diagnostic_from_report(&report)?;
    write_expected_rejection(&root.join("expected-independent.json"), &diagnostic)?;
    fs::remove_dir_all(output)
        .map_err(|error| format!("cannot remove rejected independent vector output: {error}"))?;
    Ok(VerifierOutcome::Rejected {
        diagnostic,
        detail: "independent verifier rejected vector".to_owned(),
    })
}

fn write_expected_rejection(path: &Path, diagnostic: &str) -> Result<(), String> {
    write_json(
        path,
        &object([
            ("admitted", JsonValue::Bool(false)),
            ("diagnosticCode", string(diagnostic)),
            ("schemaVersion", number(1)),
            ("state", string("blocked")),
        ]),
    )
    .map(|_| ())
}

enum VerifierOutcome {
    Admitted,
    Rejected { diagnostic: String, detail: String },
}

fn require_expected_outcome(
    vector: &Vector,
    primary: VerifierOutcome,
    independent: VerifierOutcome,
) -> Result<(), String> {
    match (vector.valid, primary, independent) {
        (true, VerifierOutcome::Admitted, VerifierOutcome::Admitted) => Ok(()),
        (false, VerifierOutcome::Admitted, VerifierOutcome::Rejected { .. })
            if vector.mutation == "primary-accepts-independent-rejects" =>
        {
            Ok(())
        }
        (false, VerifierOutcome::Rejected { .. }, VerifierOutcome::Admitted)
            if vector.mutation == "independent-accepts-primary-rejects" =>
        {
            Ok(())
        }
        (
            false,
            VerifierOutcome::Rejected {
                diagnostic: primary,
                ..
            },
            VerifierOutcome::Rejected {
                diagnostic: independent,
                ..
            },
        ) if vector.diagnostic.as_deref() == Some(primary.as_str())
            && vector.diagnostic.as_deref() == Some(independent.as_str()) =>
        {
            Ok(())
        }
        (_, VerifierOutcome::Rejected { detail, .. }, _) => Err(format!(
            "primary release vector outcome differs for {:?}: {detail}",
            vector.id
        )),
        (_, _, VerifierOutcome::Rejected { detail, .. }) => Err(format!(
            "independent release vector outcome differs for {:?}: {detail}",
            vector.id
        )),
        _ => Err(format!(
            "release vector outcome differs from manifest for {:?}",
            vector.id
        )),
    }
}

fn is_disagreement_vector(vector: &Vector) -> bool {
    matches!(
        vector.mutation.as_str(),
        "primary-accepts-independent-rejects" | "independent-accepts-primary-rejects"
    )
}

fn verifier_plan_input(
    root: &Path,
    challenge_parent: &Path,
    vector: &Vector,
    implementation: &str,
) -> Result<(PathBuf, Option<PathBuf>), String> {
    let challenged = matches!(
        (vector.mutation.as_str(), implementation),
        ("primary-accepts-independent-rejects", "independent")
            | ("independent-accepts-primary-rejects", "primary")
    );
    if !challenged {
        return Ok((root.join("plan.json"), None));
    }
    let path = challenge_parent.join(format!(
        ".{}-{implementation}-rejection-plan.json",
        vector.id
    ));
    let mut bytes = read_regular(&root.join("plan.json"))?;
    bytes.extend_from_slice(b"null\n");
    write_atomic(&path, &bytes)?;
    Ok((path.clone(), Some(path)))
}

fn remove_verifier_challenge(
    challenge: Option<PathBuf>,
    primary: Option<&String>,
) -> Result<(), String> {
    let Some(challenge) = challenge else {
        return Ok(());
    };
    fs::remove_file(&challenge).map_err(|error| {
        primary.map_or_else(
            || format!("cannot remove verifier rejection challenge: {error}"),
            |primary| {
                format!(
                    "{primary}; additionally, cannot remove verifier rejection challenge: {error}"
                )
            },
        )
    })
}

fn diagnostic_from_report(path: &Path) -> Result<String, String> {
    let report = read_json(path)?;
    let fields = report.object()?;
    for name in ["diagnosticCode", "diagnostic"] {
        if let Some(JsonValue::String(value)) = fields.get(name) {
            return Ok(value.clone());
        }
    }
    Err("verifier rejection report lacks a stable diagnostic code".to_owned())
}

fn verify_platform_vector_input(root: &Path) -> Result<(), String> {
    let plan = ReleasePlan::parse(&read_json(&root.join("plan.json"))?)?;
    let conformance = crate::conformance::ConformancePlan::parse(&read_json(
        &root.join("conformance-plan.json"),
    )?)?;
    for (platform, id) in [
        (super::schema::ReleasePlatform::LinuxX86_64, "linux-x86_64"),
        (
            super::schema::ReleasePlatform::MacosAarch64,
            "macos-aarch64",
        ),
        (
            super::schema::ReleasePlatform::WindowsX86_64,
            "windows-x86_64",
        ),
    ] {
        super::assemble::verify_platform_report(
            &root
                .join("platform-input")
                .join(id)
                .join("platform-report.json"),
            &plan,
            &conformance,
            platform,
        )?;
    }
    Ok(())
}

fn verify_platform_count_independently(root: &Path) -> Result<(), String> {
    for id in ["linux-x86_64", "macos-aarch64", "windows-x86_64"] {
        let platform = root.join("platform-input").join(id);
        let report = read_json(&platform.join("platform-report.json"))?;
        let report = report.object()?;
        let manifest = read_json(&platform.join("conformance-evidence-manifest.json"))?;
        let manifest = manifest.object()?;
        if report
            .get("assignedObligationCount")
            .ok_or_else(|| "platform report lacks assigned obligation count".to_owned())?
            .number()?
            != manifest
                .get("assignedObligations")
                .ok_or_else(|| "evidence manifest lacks assigned obligation count".to_owned())?
                .number()?
            || report
                .get("producedEvidenceRecordCount")
                .ok_or_else(|| "platform report lacks produced evidence count".to_owned())?
                .number()?
                != manifest
                    .get("producedRecords")
                    .ok_or_else(|| "evidence manifest lacks produced record count".to_owned())?
                    .number()?
        {
            return Err(format!("platform report evidence counts differ for {id}"));
        }
    }
    Ok(())
}

fn governance_receipt_digests_from_root(
    root: &Path,
) -> Result<super::verify::GovernanceReceiptDigests, String> {
    fn canonical_receipt_digest(path: &Path) -> Result<String, String> {
        read_json(path)?;
        Ok(hell_testkit::sha256_bytes(&read_regular(path)?).hex())
    }

    Ok(super::verify::GovernanceReceiptDigests {
        resolve: canonical_receipt_digest(&root.join("governance-resolve.json"))?,
        post_assembly: canonical_receipt_digest(&root.join("governance-post-assembly.json"))?,
        pre_attestation: canonical_receipt_digest(&root.join("governance-pre-attestation.json"))?,
    })
}

fn apply_mutation(root: &Path, vector: &Vector) -> Result<(), String> {
    match vector.mutation.as_str() {
        "none" if vector.valid => Ok(()),
        "duplicate-json-key" => {
            insert_after_object_start(&root.join("plan.json"), b"\"schemaVersion\":2,")
        }
        "unknown-field" => {
            insert_after_object_start(&root.join("plan.json"), b"\"unknownField\":null,")
        }
        "trailing-json-bytes" => {
            let path = root.join("plan.json");
            let mut bytes = read_regular(&path)?;
            bytes.extend_from_slice(b"null\n");
            write_atomic(&path, &bytes)
        }
        "noncanonical-integer" => mutate_integer_leading_zero(&root.join("plan.json"), "runId"),
        "wrong-candidate-sha" => mutate_json_text(
            &root.join("conformance-plan.json"),
            &["candidateSha"],
            &"0".repeat(40),
        ),
        "wrong-workflow-sha" => mutate_json_text(
            &root.join("conformance-plan.json"),
            &["workflowSha"],
            &"0".repeat(40),
        ),
        "wrong-source-inventory-digest" => mutate_json_text(
            &root.join("conformance-plan.json"),
            &["sourceInventorySha256"],
            &"0".repeat(64),
        ),
        "wrong-oracle-identity" => mutate_evidence_manifest(
            root,
            "linux-x86_64",
            &["oracle", "repository"],
            JsonValue::String("wrong/oracle".to_owned()),
        ),
        "wrong-executable-digest" => mutate_evidence_manifest(
            root,
            "linux-x86_64",
            &["candidateExecutableSha256"],
            JsonValue::String("0".repeat(64)),
        ),
        "linux-evidence-relabeled-as-windows" => mutate_evidence_manifest(
            root,
            "linux-x86_64",
            &["platform"],
            JsonValue::String("windows-x86_64".to_owned()),
        ),
        "evidence-replayed-into-another-case" => mutate_first_evidence_record(root, |record| {
            replace_json_path(
                record,
                &["caseId"],
                JsonValue::String("release-vector-replayed-case".to_owned()),
            )
        }),
        "missing-cell" => remove_first_evidence_record(root),
        "duplicate-cell" => duplicate_first_evidence_record(root),
        "unused-authoritative-evidence" => mutate_observation_inventory(root, false),
        "contradictory-evidence-for-one-cell" => mutate_observation_inventory(root, true),
        "exemption-with-mismatched-selector" => {
            mutate_conformance_exemption(root, ExemptionMutation::Selector)
        }
        "expired-exemption" => mutate_conformance_exemption(root, ExemptionMutation::Expired),
        "exemption-uses-wall-clock-time" => {
            mutate_conformance_exemption(root, ExemptionMutation::EvaluationInstant)
        }
        "subject-omitted-from-manifest" => {
            remove_subject_line(&root.join("bundle/SUBJECTS.sha256"), "release-notes.md")
        }
        "unlisted-extra-subject" => write_atomic(
            &root.join("bundle/unlisted-extra-subject.bin"),
            b"release vector extra subject\n",
        ),
        "release-gate-bound-to-another-subject-manifest" => {
            mutate_release_gate_subject_binding(&root.join("bundle/release-gate.json"))
        }
        "blocked-count-hidden-by-forged-summary" => mutate_report_count(root),
        "wrong-native-environment-receipt" => mutate_native_environment_receipt(root),
        "wrong-governance-profile" => mutate_release_gate_field(
            &root.join("bundle/release-gate.json"),
            "governanceProfileSha256",
            JsonValue::String("0".repeat(64)),
        ),
        "malformed-platform-report-count" => mutate_platform_report_count(root),
        "protocol-downgrade" => mutate_json_value(
            &root.join("plan.json"),
            &["schemaVersion"],
            JsonValue::Number(1),
        ),
        other => TarMutation::from_id(other).map_or_else(
            || {
                Err(format!(
                    "release vector mutation {other:?} has no production materializer"
                ))
            },
            |mutation| mutate_evidence_tar(root, mutation),
        ),
    }
}

#[derive(Clone, Copy)]
enum TarMutation {
    ExtraMember,
    DuplicateMember,
    PathTraversal,
    AbsolutePath,
    SymbolicLink,
    MalformedChecksum,
    TrailingGzipMember,
    ExpandedLimit,
}

impl TarMutation {
    fn from_id(id: &str) -> Option<Self> {
        match id {
            "extra-archive-member" => Some(Self::ExtraMember),
            "duplicate-archive-member" => Some(Self::DuplicateMember),
            "archive-path-traversal" => Some(Self::PathTraversal),
            "absolute-archive-path" => Some(Self::AbsolutePath),
            "archive-symbolic-link" => Some(Self::SymbolicLink),
            "malformed-tar-checksum" => Some(Self::MalformedChecksum),
            "trailing-gzip-member" => Some(Self::TrailingGzipMember),
            "decompression-limit-exceeded" => Some(Self::ExpandedLimit),
            _ => None,
        }
    }
}

fn mutate_evidence_tar(root: &Path, mutation: TarMutation) -> Result<(), String> {
    let plan = ReleasePlan::parse(&read_json(&root.join("plan.json"))?)?;
    let path = root.join("bundle/conformance-evidence.tar.gz");
    let compressed = read_regular(&path)?;
    let mutated = match mutation {
        TarMutation::TrailingGzipMember => {
            let mut output = compressed;
            output.extend_from_slice(&canonical_gzip(&[])?);
            output
        }
        TarMutation::ExpandedLimit => {
            let mut output = compressed;
            let trailer = output
                .len()
                .checked_sub(4)
                .ok_or_else(|| "release vector gzip trailer is absent".to_owned())?;
            output[trailer..].copy_from_slice(&1_073_741_825_u32.to_le_bytes());
            output
        }
        _ => {
            let mut tar = Vec::new();
            GzDecoder::new(compressed.as_slice())
                .read_to_end(&mut tar)
                .map_err(|error| format!("cannot expand release vector evidence: {error}"))?;
            mutate_tar_bytes(&mut tar, mutation, plan.source_date_epoch)?;
            canonical_gzip(&tar)?
        }
    };
    write_atomic(&path, &mutated)?;
    let digest = hell_testkit::sha256_bytes(&mutated).hex();
    update_subject_digest(
        &root.join("bundle/SUBJECTS.sha256"),
        "conformance-evidence.tar.gz",
        &digest,
    )
}

fn mutate_tar_bytes(
    tar: &mut Vec<u8>,
    mutation: TarMutation,
    source_date_epoch: u64,
) -> Result<(), String> {
    const BLOCK: usize = 512;
    if tar.len() < BLOCK * 3 || !tar.len().is_multiple_of(BLOCK) {
        return Err("release vector tar is not block aligned".to_owned());
    }
    match mutation {
        TarMutation::ExtraMember => {
            let end = tar_end_marker(tar)?;
            let payload = b"release vector extra archive member\n";
            let mut header = Header::new_gnu();
            header
                .set_path("zz-release-vector-extra.json")
                .map_err(|error| format!("cannot set release vector tar path: {error}"))?;
            header.set_entry_type(EntryType::Regular);
            header.set_size(
                u64::try_from(payload.len())
                    .map_err(|_| "release vector payload size overflow".to_owned())?,
            );
            header.set_uid(0);
            header.set_gid(0);
            header.set_mode(0o644);
            header.set_mtime(source_date_epoch);
            header.set_cksum();
            let mut member = header.as_bytes().to_vec();
            member.extend_from_slice(payload);
            let padded = payload
                .len()
                .checked_add(BLOCK - 1)
                .ok_or_else(|| "release vector tar padding overflow".to_owned())?
                / BLOCK
                * BLOCK;
            member.resize(BLOCK + padded, 0);
            tar.splice(end..end, member);
        }
        TarMutation::DuplicateMember => {
            let end = tar_end_marker(tar)?;
            let first = tar[..BLOCK].to_vec();
            tar.splice(end..end, first);
        }
        TarMutation::PathTraversal => {
            replace_tar_header_path(&mut tar[..BLOCK], "../release-vector")?;
        }
        TarMutation::AbsolutePath => {
            replace_tar_header_path(&mut tar[..BLOCK], "/release-vector")?;
        }
        TarMutation::SymbolicLink => {
            tar[156] = b'2';
            set_tar_checksum(&mut tar[..BLOCK])?;
        }
        TarMutation::MalformedChecksum => {
            tar[0] ^= 1;
        }
        TarMutation::TrailingGzipMember | TarMutation::ExpandedLimit => {
            return Err("gzip-only vector mutation reached tar mutation".to_owned());
        }
    }
    Ok(())
}

fn tar_end_marker(tar: &[u8]) -> Result<usize, String> {
    const BLOCK: usize = 512;
    for (index, blocks) in tar
        .chunks_exact(BLOCK)
        .collect::<Vec<_>>()
        .windows(2)
        .enumerate()
    {
        if blocks[0].iter().all(|byte| *byte == 0) && blocks[1].iter().all(|byte| *byte == 0) {
            return index
                .checked_mul(BLOCK)
                .ok_or_else(|| "release vector tar end offset overflow".to_owned());
        }
    }
    Err("release vector tar lacks an end marker".to_owned())
}

fn replace_tar_header_path(header: &mut [u8], path: &str) -> Result<(), String> {
    if header.len() != 512 || path.len() >= 100 {
        return Err("release vector tar header or replacement path is invalid".to_owned());
    }
    header[..100].fill(0);
    header[..path.len()].copy_from_slice(path.as_bytes());
    set_tar_checksum(header)
}

fn set_tar_checksum(header: &mut [u8]) -> Result<(), String> {
    if header.len() != 512 {
        return Err("release vector tar header size differs".to_owned());
    }
    header[148..156].fill(b' ');
    let checksum = header.iter().try_fold(0_u64, |sum, byte| {
        sum.checked_add(u64::from(*byte))
            .ok_or_else(|| "release vector tar checksum overflow".to_owned())
    })?;
    let encoded = format!("{checksum:06o}\0 ");
    if encoded.len() != 8 {
        return Err("release vector tar checksum width differs".to_owned());
    }
    header[148..156].copy_from_slice(encoded.as_bytes());
    Ok(())
}

fn canonical_gzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(&mut output, Compression::new(9));
    encoder
        .write_all(bytes)
        .map_err(|error| format!("cannot encode release vector gzip: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("cannot finish release vector gzip: {error}"))?;
    Ok(output)
}

fn remove_subject_line(path: &Path, subject: &str) -> Result<(), String> {
    let bytes = read_regular(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "release vector subject manifest is not UTF-8".to_owned())?;
    let mut removed = 0_usize;
    let mut output = String::new();
    for line in text.lines() {
        let (_, name) = line
            .split_once("  ")
            .ok_or_else(|| "release vector subject manifest line is malformed".to_owned())?;
        if name == subject {
            removed = removed
                .checked_add(1)
                .ok_or_else(|| "release vector subject removal overflow".to_owned())?;
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if removed != 1 {
        return Err(format!(
            "release vector subject {subject:?} is absent or duplicated"
        ));
    }
    write_atomic(path, output.as_bytes())
}

fn mutate_release_gate_subject_binding(path: &Path) -> Result<(), String> {
    mutate_release_gate_field(path, "subjectsSha256", JsonValue::String("0".repeat(64)))
}

fn mutate_release_gate_field(
    path: &Path,
    field: &str,
    replacement: JsonValue,
) -> Result<(), String> {
    let mut gate = read_json(path)?;
    replace_json_path(&mut gate, &[field], replacement)?;
    let JsonValue::Object(fields) = &mut gate else {
        return Err("release vector gate is not an object".to_owned());
    };
    fields.remove("releaseGateSha256");
    let digest = hell_testkit::sha256_bytes(&crate::json::canonical_json_bytes(&gate)?).hex();
    match &mut gate {
        JsonValue::Object(fields) => {
            fields.insert("releaseGateSha256".to_owned(), string(&digest));
        }
        _ => return Err("release vector gate is not an object".to_owned()),
    }
    write_json(path, &gate).map(|_| ())
}

fn mutate_report_count(root: &Path) -> Result<(), String> {
    let path = root.join("bundle/conformance-report.json");
    let mut report = read_json(&path)?;
    let current = report
        .object()?
        .get("partition")
        .ok_or_else(|| "release vector report lacks partition".to_owned())?
        .object()?
        .get("verifiedExact")
        .ok_or_else(|| "release vector report lacks verifiedExact".to_owned())?
        .number()?;
    let forged = current
        .checked_add(1)
        .ok_or_else(|| "release vector forged count overflow".to_owned())?;
    replace_json_path(
        &mut report,
        &["partition", "verifiedExact"],
        JsonValue::Number(forged),
    )?;
    replace_self_digest(&mut report, "reportSha256")?;
    write_json(&path, &report)?;
    update_subject_digest(
        &root.join("bundle/SUBJECTS.sha256"),
        "conformance-report.json",
        &hell_testkit::sha256_bytes(&read_regular(&path)?).hex(),
    )
}

fn mutate_platform_report_count(root: &Path) -> Result<(), String> {
    let path = root.join("platform-input/linux-x86_64/platform-report.json");
    let mut report = read_json(&path)?;
    let count = report
        .object()?
        .get("assignedObligationCount")
        .ok_or_else(|| "release vector platform report lacks assigned count".to_owned())?
        .number()?
        .checked_add(1)
        .ok_or_else(|| "release vector platform count overflow".to_owned())?;
    replace_json_path(
        &mut report,
        &["assignedObligationCount"],
        JsonValue::Number(count),
    )?;
    write_json(&path, &report).map(|_| ())
}

fn mutate_native_environment_receipt(root: &Path) -> Result<(), String> {
    let path = root.join("bundle/native-environment-set.json");
    let mut set = read_json(&path)?;
    let records = match &mut set {
        JsonValue::Object(fields) => match fields
            .get_mut("receipts")
            .ok_or_else(|| "native environment set lacks receipts".to_owned())?
        {
            JsonValue::Array(records) => records,
            _ => return Err("native environment set receipts is not an array".to_owned()),
        },
        _ => return Err("native environment set is not an object".to_owned()),
    };
    let first = records
        .first_mut()
        .ok_or_else(|| "native environment set has no receipt".to_owned())?;
    replace_json_path(
        first,
        &["receipt", "logicalPlatformId"],
        JsonValue::String("windows-x86_64".to_owned()),
    )?;
    write_json(&path, &set)?;
    update_subject_digest(
        &root.join("bundle/SUBJECTS.sha256"),
        "native-environment-set.json",
        &hell_testkit::sha256_bytes(&read_regular(&path)?).hex(),
    )
}

fn replace_self_digest(value: &mut JsonValue, field: &str) -> Result<(), String> {
    let JsonValue::Object(object) = value else {
        return Err("self-digested release vector value is not an object".to_owned());
    };
    object.remove(field);
    let digest = hell_testkit::sha256_bytes(&crate::json::canonical_json_bytes(value)?).hex();
    let JsonValue::Object(object) = value else {
        return Err("self-digested release vector value changed type".to_owned());
    };
    object.insert(field.to_owned(), string(&digest));
    Ok(())
}

fn mutate_json_text(path: &Path, fields: &[&str], replacement: &str) -> Result<(), String> {
    mutate_json_value(path, fields, JsonValue::String(replacement.to_owned()))
}

fn mutate_json_value(path: &Path, fields: &[&str], replacement: JsonValue) -> Result<(), String> {
    let mut value = read_json(path)?;
    replace_json_path(&mut value, fields, replacement)?;
    write_json(path, &value).map(|_| ())
}

fn replace_json_path(
    value: &mut JsonValue,
    fields: &[&str],
    replacement: JsonValue,
) -> Result<(), String> {
    let (name, tail) = fields
        .split_first()
        .ok_or_else(|| "release vector JSON path is empty".to_owned())?;
    let JsonValue::Object(object) = value else {
        return Err("release vector JSON path crosses a non-object".to_owned());
    };
    if tail.is_empty() {
        let target = object
            .get_mut(*name)
            .ok_or_else(|| format!("release vector JSON field {name:?} is absent"))?;
        *target = replacement;
        return Ok(());
    }
    let child = object
        .get_mut(*name)
        .ok_or_else(|| format!("release vector JSON field {name:?} is absent"))?;
    replace_json_path(child, tail, replacement)
}

fn mutate_evidence_manifest(
    root: &Path,
    platform: &str,
    fields: &[&str],
    replacement: JsonValue,
) -> Result<(), String> {
    let plan = ReleasePlan::parse(&read_json(&root.join("plan.json"))?)?;
    let archive_path = root.join("bundle/conformance-evidence.tar.gz");
    let mut members = super::archive::read_evidence(&archive_path, plan.source_date_epoch)?;
    let manifest_path = format!("platform-manifests/{platform}.json");
    let bytes = members
        .get(&manifest_path)
        .ok_or_else(|| format!("release vector evidence lacks {manifest_path}"))?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "release vector evidence manifest is not UTF-8".to_owned())?;
    let mut manifest = crate::json::parse_json(text)?;
    if crate::json::canonical_json_bytes(&manifest)? != *bytes {
        return Err("release vector evidence manifest is not canonical".to_owned());
    }
    replace_json_path(&mut manifest, fields, replacement)?;
    match &mut manifest {
        JsonValue::Object(object) => {
            object.remove("manifestSha256");
        }
        _ => return Err("release vector platform manifest is not an object".to_owned()),
    }
    let digest = hell_testkit::sha256_bytes(&crate::json::canonical_json_bytes(&manifest)?).hex();
    match &mut manifest {
        JsonValue::Object(object) => {
            object.insert("manifestSha256".to_owned(), string(&digest));
        }
        _ => return Err("release vector platform manifest is not an object".to_owned()),
    }
    members.insert(manifest_path, crate::json::canonical_json_bytes(&manifest)?);
    let evidence_digest =
        super::archive::create_evidence(&archive_path, plan.source_date_epoch, &members)?;
    update_subject_digest(
        &root.join("bundle/SUBJECTS.sha256"),
        "conformance-evidence.tar.gz",
        &evidence_digest,
    )
}

fn mutate_first_evidence_record(
    root: &Path,
    mutate: impl FnOnce(&mut JsonValue) -> Result<(), String>,
) -> Result<(), String> {
    let plan = ReleasePlan::parse(&read_json(&root.join("plan.json"))?)?;
    let archive_path = root.join("bundle/conformance-evidence.tar.gz");
    let mut members = super::archive::read_evidence(&archive_path, plan.source_date_epoch)?;
    let manifest_path = "platform-manifests/linux-x86_64.json";
    let mut manifest = parse_canonical_value(
        members
            .get(manifest_path)
            .ok_or_else(|| "release vector lacks Linux evidence manifest".to_owned())?,
    )?;
    let records = match &mut manifest {
        JsonValue::Object(fields) => match fields
            .get_mut("records")
            .ok_or_else(|| "release vector evidence manifest lacks records".to_owned())?
        {
            JsonValue::Array(records) => records,
            _ => return Err("release vector evidence manifest records is not an array".to_owned()),
        },
        _ => return Err("release vector evidence manifest is not an object".to_owned()),
    };
    let member = records
        .first_mut()
        .ok_or_else(|| "release vector evidence manifest has no record".to_owned())?;
    let old_id = member
        .object()?
        .get("id")
        .ok_or_else(|| "release vector evidence member lacks ID".to_owned())?
        .string()?
        .to_owned();
    let old_path = format!("records/{old_id}.json");
    let mut record = parse_canonical_value(
        members
            .get(&old_path)
            .ok_or_else(|| "release vector evidence record is absent".to_owned())?,
    )?;
    mutate(&mut record)?;
    let JsonValue::Object(record_fields) = &mut record else {
        return Err("release vector evidence record is not an object".to_owned());
    };
    record_fields.remove("recordId");
    let id = format!(
        "ev-{}",
        hell_testkit::sha256_bytes(&crate::json::canonical_json_bytes(&record)?).hex()
    );
    let JsonValue::Object(record_fields) = &mut record else {
        return Err("release vector evidence record changed type".to_owned());
    };
    record_fields.insert("recordId".to_owned(), string(&id));
    let record_bytes = crate::json::canonical_json_bytes(&record)?;
    let record_sha256 = hell_testkit::sha256_bytes(&record_bytes).hex();
    members.remove(&old_path);
    members.insert(format!("records/{id}.json"), record_bytes);
    let JsonValue::Object(member_fields) = member else {
        return Err("release vector evidence member is not an object".to_owned());
    };
    member_fields.insert("id".to_owned(), string(&id));
    member_fields.insert(
        "path".to_owned(),
        string(&format!("conformance-evidence/{id}.json")),
    );
    member_fields.insert("sha256".to_owned(), string(&record_sha256));
    records.sort_by(|left, right| {
        let left = left
            .object()
            .ok()
            .and_then(|fields| fields.get("path"))
            .and_then(|value| value.string().ok());
        let right = right
            .object()
            .ok()
            .and_then(|fields| fields.get("path"))
            .and_then(|value| value.string().ok());
        left.cmp(&right)
    });
    replace_self_digest(&mut manifest, "manifestSha256")?;
    members.insert(
        manifest_path.to_owned(),
        crate::json::canonical_json_bytes(&manifest)?,
    );
    let evidence_digest =
        super::archive::create_evidence(&archive_path, plan.source_date_epoch, &members)?;
    update_subject_digest(
        &root.join("bundle/SUBJECTS.sha256"),
        "conformance-evidence.tar.gz",
        &evidence_digest,
    )
}

fn remove_first_evidence_record(root: &Path) -> Result<(), String> {
    let plan = ReleasePlan::parse(&read_json(&root.join("plan.json"))?)?;
    let archive_path = root.join("bundle/conformance-evidence.tar.gz");
    let mut members = super::archive::read_evidence(&archive_path, plan.source_date_epoch)?;
    let manifest_path = "platform-manifests/linux-x86_64.json";
    let mut manifest = parse_canonical_value(
        members
            .get(manifest_path)
            .ok_or_else(|| "release vector lacks Linux evidence manifest".to_owned())?,
    )?;
    let removed = {
        let JsonValue::Object(fields) = &mut manifest else {
            return Err("release vector evidence manifest is not an object".to_owned());
        };
        let JsonValue::Array(records) = fields
            .get_mut("records")
            .ok_or_else(|| "release vector evidence manifest lacks records".to_owned())?
        else {
            return Err("release vector evidence manifest records is not an array".to_owned());
        };
        let Some(first) = records.first() else {
            return Err("release vector evidence manifest has no record".to_owned());
        };
        let removed = first.clone();
        records.remove(0);
        let record_count = u64::try_from(records.len())
            .map_err(|_| "release vector record count overflow".to_owned())?;
        fields.insert(
            "producedRecords".to_owned(),
            JsonValue::Number(record_count),
        );
        removed
    };
    let removed_id = removed
        .object()?
        .get("id")
        .ok_or_else(|| "removed evidence record lacks ID".to_owned())?
        .string()?;
    members.remove(&format!("records/{removed_id}.json"));
    remove_unreferenced_observations(&mut manifest, &mut members)?;
    replace_self_digest(&mut manifest, "manifestSha256")?;
    members.insert(
        manifest_path.to_owned(),
        crate::json::canonical_json_bytes(&manifest)?,
    );
    rewrite_evidence_archive(root, &plan, &archive_path, &members)
}

fn duplicate_first_evidence_record(root: &Path) -> Result<(), String> {
    let plan = ReleasePlan::parse(&read_json(&root.join("plan.json"))?)?;
    let archive_path = root.join("bundle/conformance-evidence.tar.gz");
    let mut members = super::archive::read_evidence(&archive_path, plan.source_date_epoch)?;
    let manifest_path = "platform-manifests/linux-x86_64.json";
    let mut manifest = parse_canonical_value(
        members
            .get(manifest_path)
            .ok_or_else(|| "release vector lacks Linux evidence manifest".to_owned())?,
    )?;
    let (source_id, replacement_observation) = {
        let fields = manifest.object()?;
        let records = fields
            .get("records")
            .ok_or_else(|| "release vector evidence manifest lacks records".to_owned())?
            .array()?;
        let source_id = records
            .first()
            .ok_or_else(|| "release vector evidence manifest has no record".to_owned())?
            .object()?
            .get("id")
            .ok_or_else(|| "release vector evidence member lacks ID".to_owned())?
            .string()?
            .to_owned();
        let source = parse_canonical_value(
            members
                .get(&format!("records/{source_id}.json"))
                .ok_or_else(|| "release vector evidence record is absent".to_owned())?,
        )?;
        let current = source
            .object()?
            .get("candidateObservationSha256")
            .ok_or_else(|| "evidence record lacks candidate observation".to_owned())?
            .string()?;
        let replacement = fields
            .get("observations")
            .ok_or_else(|| "release vector manifest lacks observations".to_owned())?
            .array()?
            .iter()
            .filter_map(|entry| entry.object().ok()?.get("sha256")?.string().ok())
            .find(|digest| *digest != current)
            .ok_or_else(|| "release vector needs a second observation for duplication".to_owned())?
            .to_owned();
        (source_id, replacement)
    };
    let source_path = format!("records/{source_id}.json");
    let mut record = parse_canonical_value(
        members
            .get(&source_path)
            .ok_or_else(|| "release vector evidence record is absent".to_owned())?,
    )?;
    replace_json_path(
        &mut record,
        &["candidateObservationSha256"],
        string(&replacement_observation),
    )?;
    let JsonValue::Object(fields) = &mut record else {
        return Err("release vector evidence record is not an object".to_owned());
    };
    fields.remove("recordId");
    let duplicate_id = format!(
        "ev-{}",
        hell_testkit::sha256_bytes(&crate::json::canonical_json_bytes(&record)?).hex()
    );
    let JsonValue::Object(fields) = &mut record else {
        return Err("release vector evidence record changed type".to_owned());
    };
    fields.insert("recordId".to_owned(), string(&duplicate_id));
    let bytes = crate::json::canonical_json_bytes(&record)?;
    let sha256 = hell_testkit::sha256_bytes(&bytes).hex();
    members.insert(format!("records/{duplicate_id}.json"), bytes);
    let JsonValue::Object(fields) = &mut manifest else {
        return Err("release vector evidence manifest changed type".to_owned());
    };
    let JsonValue::Array(records) = fields
        .get_mut("records")
        .ok_or_else(|| "release vector evidence manifest lacks records".to_owned())?
    else {
        return Err("release vector evidence manifest records is not an array".to_owned());
    };
    records.push(object([
        ("id", string(&duplicate_id)),
        (
            "path",
            string(&format!("conformance-evidence/{duplicate_id}.json")),
        ),
        ("sha256", string(&sha256)),
    ]));
    records.sort_by(|left, right| member_path(left).cmp(&member_path(right)));
    let record_count = u64::try_from(records.len())
        .map_err(|_| "release vector record count overflow".to_owned())?;
    fields.insert(
        "producedRecords".to_owned(),
        JsonValue::Number(record_count),
    );
    replace_self_digest(&mut manifest, "manifestSha256")?;
    members.insert(
        manifest_path.to_owned(),
        crate::json::canonical_json_bytes(&manifest)?,
    );
    rewrite_evidence_archive(root, &plan, &archive_path, &members)
}

fn member_path(value: &JsonValue) -> Option<&str> {
    value
        .object()
        .ok()
        .and_then(|fields| fields.get("path"))
        .and_then(|value| value.string().ok())
}

fn remove_unreferenced_observations(
    manifest: &mut JsonValue,
    members: &mut std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let fields = manifest.object()?.clone();
    let mut referenced = BTreeSet::new();
    for entry in ["records", "exploratoryRecords"] {
        for member in fields
            .get(entry)
            .ok_or_else(|| format!("release vector manifest lacks {entry}"))?
            .array()?
        {
            let id = member
                .object()?
                .get("id")
                .ok_or_else(|| "release vector record member lacks ID".to_owned())?
                .string()?;
            let record = parse_canonical_value(
                members
                    .get(&format!("records/{id}.json"))
                    .ok_or_else(|| "release vector record member is absent".to_owned())?,
            )?;
            let record = record.object()?;
            for name in ["candidateObservationSha256", "oracleObservationSha256"] {
                referenced.insert(
                    record
                        .get(name)
                        .ok_or_else(|| format!("release vector record lacks {name}"))?
                        .string()?
                        .to_owned(),
                );
            }
        }
    }
    let observations = match manifest {
        JsonValue::Object(fields) => match fields
            .get_mut("observations")
            .ok_or_else(|| "release vector manifest lacks observations".to_owned())?
        {
            JsonValue::Array(observations) => observations,
            _ => return Err("release vector observations is not an array".to_owned()),
        },
        _ => return Err("release vector manifest is not an object".to_owned()),
    };
    let removed = observations
        .iter()
        .filter_map(|entry| {
            let digest = entry.object().ok()?.get("sha256")?.string().ok()?;
            (!referenced.contains(digest)).then(|| digest.to_owned())
        })
        .collect::<Vec<_>>();
    observations.retain(|entry| {
        entry
            .object()
            .ok()
            .and_then(|fields| fields.get("sha256"))
            .and_then(|value| value.string().ok())
            .is_some_and(|digest| referenced.contains(digest))
    });
    for digest in removed {
        let mut referenced_elsewhere = false;
        for (path, bytes) in members.iter().filter(|(path, _)| {
            path.starts_with("platform-manifests/")
                && path.as_str() != "platform-manifests/linux-x86_64.json"
        }) {
            let other = parse_canonical_value(bytes)
                .map_err(|error| format!("cannot inspect {path}: {error}"))?;
            if other
                .object()?
                .get("observations")
                .ok_or_else(|| "release vector manifest lacks observations".to_owned())?
                .array()?
                .iter()
                .any(|entry| {
                    entry
                        .object()
                        .ok()
                        .and_then(|fields| fields.get("sha256"))
                        .and_then(|value| value.string().ok())
                        == Some(digest.as_str())
                })
            {
                referenced_elsewhere = true;
                break;
            }
        }
        if !referenced_elsewhere {
            members.remove(&format!("observations/{digest}.json"));
        }
    }
    Ok(())
}

fn rewrite_evidence_archive(
    root: &Path,
    plan: &ReleasePlan,
    archive_path: &Path,
    members: &std::collections::BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let evidence_digest =
        super::archive::create_evidence(archive_path, plan.source_date_epoch, members)?;
    update_subject_digest(
        &root.join("bundle/SUBJECTS.sha256"),
        "conformance-evidence.tar.gz",
        &evidence_digest,
    )
}

fn mutate_observation_inventory(root: &Path, referenced: bool) -> Result<(), String> {
    let plan = ReleasePlan::parse(&read_json(&root.join("plan.json"))?)?;
    let archive_path = root.join("bundle/conformance-evidence.tar.gz");
    let mut members = super::archive::read_evidence(&archive_path, plan.source_date_epoch)?;
    let manifest_path = "platform-manifests/linux-x86_64.json";
    let mut manifest = parse_canonical_value(
        members
            .get(manifest_path)
            .ok_or_else(|| "release vector lacks Linux evidence manifest".to_owned())?,
    )?;
    let source_digest = manifest
        .object()?
        .get("observations")
        .ok_or_else(|| "release vector manifest lacks observations".to_owned())?
        .array()?
        .first()
        .ok_or_else(|| "release vector manifest has no observation".to_owned())?
        .object()?
        .get("sha256")
        .ok_or_else(|| "release vector observation member lacks digest".to_owned())?
        .string()?
        .to_owned();
    let mut observation = parse_canonical_value(
        members
            .get(&format!("observations/{source_digest}.json"))
            .ok_or_else(|| "release vector observation is absent".to_owned())?,
    )?;
    replace_json_path(
        &mut observation,
        &["diagnostic"],
        string(if referenced {
            "release-vector-contradictory-evidence"
        } else {
            "release-vector-unused-authoritative-evidence"
        }),
    )?;
    let observation_bytes = crate::json::canonical_json_bytes(&observation)?;
    let digest = hell_testkit::sha256_bytes(&observation_bytes).hex();
    members.insert(format!("observations/{digest}.json"), observation_bytes);
    append_manifest_observation(&mut manifest, &digest)?;
    if referenced {
        retarget_exploratory_record(&mut manifest, &mut members, &digest)?;
    }
    if referenced {
        remove_unreferenced_observations(&mut manifest, &mut members)?;
    }
    replace_self_digest(&mut manifest, "manifestSha256")?;
    members.insert(
        manifest_path.to_owned(),
        crate::json::canonical_json_bytes(&manifest)?,
    );
    rewrite_evidence_archive(root, &plan, &archive_path, &members)
}

fn append_manifest_observation(manifest: &mut JsonValue, digest: &str) -> Result<(), String> {
    let JsonValue::Object(fields) = manifest else {
        return Err("release vector evidence manifest changed type".to_owned());
    };
    let JsonValue::Array(observations) = fields
        .get_mut("observations")
        .ok_or_else(|| "release vector manifest lacks observations".to_owned())?
    else {
        return Err("release vector observations is not an array".to_owned());
    };
    observations.push(object([
        (
            "path",
            string(&format!("conformance-observations/{digest}.json")),
        ),
        ("sha256", string(digest)),
    ]));
    observations.sort_by(|left, right| member_path(left).cmp(&member_path(right)));
    Ok(())
}

fn retarget_exploratory_record(
    manifest: &mut JsonValue,
    members: &mut std::collections::BTreeMap<String, Vec<u8>>,
    digest: &str,
) -> Result<(), String> {
    let JsonValue::Object(fields) = manifest else {
        return Err("release vector evidence manifest changed type".to_owned());
    };
    let JsonValue::Array(exploratory) = fields
        .get_mut("exploratoryRecords")
        .ok_or_else(|| "release vector manifest lacks exploratory records".to_owned())?
    else {
        return Err("release vector exploratory records is not an array".to_owned());
    };
    let member = exploratory
        .first_mut()
        .ok_or_else(|| "release vector manifest has no exploratory record".to_owned())?;
    let old_id = member
        .object()?
        .get("id")
        .ok_or_else(|| "release vector exploratory record lacks ID".to_owned())?
        .string()?
        .to_owned();
    let mut record = parse_canonical_value(
        members
            .get(&format!("records/{old_id}.json"))
            .ok_or_else(|| "release vector exploratory record is absent".to_owned())?,
    )?;
    replace_json_path(&mut record, &["candidateObservationSha256"], string(digest))?;
    let JsonValue::Object(record_fields) = &mut record else {
        return Err("release vector exploratory record is not an object".to_owned());
    };
    record_fields.remove("recordId");
    let new_id = format!(
        "gx-{}",
        hell_testkit::sha256_bytes(&crate::json::canonical_json_bytes(&record)?).hex()
    );
    let JsonValue::Object(record_fields) = &mut record else {
        return Err("release vector exploratory record changed type".to_owned());
    };
    record_fields.insert("recordId".to_owned(), string(&new_id));
    let bytes = crate::json::canonical_json_bytes(&record)?;
    let sha256 = hell_testkit::sha256_bytes(&bytes).hex();
    members.remove(&format!("records/{old_id}.json"));
    members.insert(format!("records/{new_id}.json"), bytes);
    let JsonValue::Object(member) = member else {
        return Err("release vector exploratory member is not an object".to_owned());
    };
    member.insert("id".to_owned(), string(&new_id));
    member.insert(
        "path".to_owned(),
        string(&format!("conformance-evidence/{new_id}.json")),
    );
    member.insert("sha256".to_owned(), string(&sha256));
    exploratory.sort_by(|left, right| member_path(left).cmp(&member_path(right)));
    Ok(())
}

#[derive(Clone, Copy)]
enum ExemptionMutation {
    Selector,
    Expired,
    EvaluationInstant,
}

struct ExemptionContext {
    candidate_sha: String,
    standard: String,
    baseline: String,
    evaluation_date: String,
}

fn exemption_context(plan: &JsonValue) -> Result<ExemptionContext, String> {
    let fields = plan.object()?;
    let field = |name: &str, description: &str| {
        fields
            .get(name)
            .ok_or_else(|| format!("release vector conformance plan lacks {description}"))?
            .string()
            .map(str::to_owned)
    };
    let evaluation_instant = field("releaseEvaluationInstant", "evaluation instant")?;
    let evaluation_date = evaluation_instant
        .split_once('T')
        .ok_or_else(|| "release vector evaluation instant lacks date".to_owned())?
        .0
        .to_owned();
    Ok(ExemptionContext {
        candidate_sha: field("candidateSha", "candidate SHA")?,
        standard: field("standard", "standard")?,
        baseline: field("baseline", "baseline")?,
        evaluation_date,
    })
}

fn mutate_conformance_exemption(root: &Path, mutation: ExemptionMutation) -> Result<(), String> {
    let path = root.join("conformance-plan.json");
    let mut plan = read_json(&path)?;
    let context = exemption_context(&plan)?;
    let cells = match &mut plan {
        JsonValue::Object(fields) => match fields
            .get_mut("cells")
            .ok_or_else(|| "release vector conformance plan lacks cells".to_owned())?
        {
            JsonValue::Array(cells) => cells,
            _ => return Err("release vector conformance cells is not an array".to_owned()),
        },
        _ => return Err("release vector conformance plan is not an object".to_owned()),
    };
    let cell = cells
        .iter_mut()
        .find(|cell| {
            cell.object()
                .ok()
                .and_then(|fields| fields.get("obligations"))
                .and_then(|value| value.array().ok())
                .is_some_and(|obligations| !obligations.is_empty())
        })
        .ok_or_else(|| "release vector conformance plan has no required cell".to_owned())?;
    let cell_fields = cell.object()?.clone();
    let key = cell_fields
        .get("key")
        .ok_or_else(|| "release vector cell lacks key".to_owned())?
        .clone();
    let obligation_id = cell_fields
        .get("obligations")
        .ok_or_else(|| "release vector cell lacks obligations".to_owned())?
        .array()?
        .first()
        .ok_or_else(|| "release vector cell has no obligation".to_owned())?
        .object()?
        .get("id")
        .ok_or_else(|| "release vector obligation lacks ID".to_owned())?
        .string()?
        .to_owned();
    let selector = if matches!(mutation, ExemptionMutation::Selector) {
        let mut selector = key.clone();
        replace_json_path(
            &mut selector,
            &["builtin"],
            string("release-vector-wrong-selector"),
        )?;
        selector
    } else {
        key
    };
    let expires_on = if matches!(mutation, ExemptionMutation::Expired) {
        context.evaluation_date
    } else {
        "9999-12-31".to_owned()
    };
    let exemption = object([
        ("baseline", string(&context.baseline)),
        ("candidateSha", string(&context.candidate_sha)),
        ("cell", selector),
        ("expiresOn", string(&expires_on)),
        ("expectedMismatchSha256", JsonValue::Null),
        ("id", string("release-vector-exemption")),
        ("issue", string("COMPAT-RELEASE-VECTOR")),
        ("kind", string("evidence-gap")),
        ("obligationId", string(&obligation_id)),
        (
            "rationale",
            string("release protocol exemption negative vector"),
        ),
        ("reviewGroup", string("release-conformance")),
        ("standard", string(&context.standard)),
    ]);
    match cell {
        JsonValue::Object(fields) => {
            fields.insert("exemptions".to_owned(), JsonValue::Array(vec![exemption]));
        }
        _ => return Err("release vector cell changed type".to_owned()),
    }
    if matches!(mutation, ExemptionMutation::EvaluationInstant) {
        replace_json_path(
            &mut plan,
            &["releaseEvaluationInstant"],
            string("2099-01-01T00:00:00Z"),
        )?;
    }
    replace_self_digest(&mut plan, "planSha256")?;
    write_json(&path, &plan)?;
    let bundled = root.join("bundle/conformance-plan.json");
    write_json(&bundled, &plan)?;
    update_subject_digest(
        &root.join("bundle/SUBJECTS.sha256"),
        "conformance-plan.json",
        &hell_testkit::sha256_bytes(&read_regular(&bundled)?).hex(),
    )
}

fn parse_canonical_value(bytes: &[u8]) -> Result<JsonValue, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "release vector JSON member is not UTF-8".to_owned())?;
    let value = crate::json::parse_json(text)?;
    if crate::json::canonical_json_bytes(&value)? != bytes {
        return Err("release vector JSON member is not canonical".to_owned());
    }
    Ok(value)
}

fn update_subject_digest(path: &Path, subject: &str, digest: &str) -> Result<(), String> {
    let bytes = read_regular(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "release vector subject manifest is not UTF-8".to_owned())?;
    let mut found = false;
    let mut output = String::new();
    for line in text.lines() {
        let Some((_, name)) = line.split_once("  ") else {
            return Err("release vector subject manifest line is malformed".to_owned());
        };
        if name == subject {
            if found {
                return Err("release vector subject is duplicated".to_owned());
            }
            found = true;
            output.push_str(digest);
            output.push_str("  ");
            output.push_str(name);
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    if !found {
        return Err(format!("release vector subject {subject:?} is absent"));
    }
    write_atomic(path, output.as_bytes())
}

fn insert_after_object_start(path: &Path, inserted: &[u8]) -> Result<(), String> {
    let bytes = read_regular(path)?;
    let suffix = bytes
        .strip_prefix(b"{")
        .ok_or_else(|| "release vector JSON does not start with an object".to_owned())?;
    let mut mutated = Vec::with_capacity(bytes.len().saturating_add(inserted.len()));
    mutated.push(b'{');
    mutated.extend_from_slice(inserted);
    mutated.extend_from_slice(suffix);
    write_atomic(path, &mutated)
}

fn mutate_integer_leading_zero(path: &Path, field: &str) -> Result<(), String> {
    let bytes = read_regular(path)?;
    let prefix = format!("\"{field}\":");
    let (head, tail) = split_once_bytes(&bytes, prefix.as_bytes())?;
    let digits = tail.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if digits == 0 {
        return Err("release vector integer field is absent or not numeric".to_owned());
    }
    let mut mutated = Vec::with_capacity(bytes.len().saturating_add(1));
    mutated.extend_from_slice(head);
    mutated.extend_from_slice(prefix.as_bytes());
    mutated.push(b'0');
    mutated.extend_from_slice(tail);
    write_atomic(path, &mutated)
}

fn split_once_bytes<'a>(bytes: &'a [u8], needle: &[u8]) -> Result<(&'a [u8], &'a [u8]), String> {
    if needle.is_empty() {
        return Err("release vector byte delimiter is empty".to_owned());
    }
    let mut match_index = None;
    for index in 0..=bytes.len().saturating_sub(needle.len()) {
        if bytes.get(index..index.saturating_add(needle.len())) == Some(needle)
            && match_index.replace(index).is_some()
        {
            return Err("release vector byte delimiter is not unique".to_owned());
        }
    }
    let index = match_index.ok_or_else(|| "release vector byte delimiter is absent".to_owned())?;
    Ok((&bytes[..index], &bytes[index + needle.len()..]))
}

fn vector_root(vectors_root: &Path, vector: &Vector) -> PathBuf {
    vectors_root
        .join(if vector.valid { "valid" } else { "invalid" })
        .join(&vector.id)
}

fn require_corpus_inventory(vectors_root: &Path, manifest: &Manifest) -> Result<(), String> {
    require_real_directory(vectors_root)?;
    let root_entries = directory_names(vectors_root)?;
    if root_entries
        != BTreeSet::from([
            "invalid".to_owned(),
            "materialization-report.json".to_owned(),
            "valid".to_owned(),
        ])
    {
        return Err("release vector corpus root inventory differs".to_owned());
    }
    let expected_valid = manifest
        .vectors
        .iter()
        .filter(|vector| vector.valid)
        .map(|vector| vector.id.clone())
        .collect::<BTreeSet<_>>();
    let expected_invalid = manifest
        .vectors
        .iter()
        .filter(|vector| !vector.valid)
        .map(|vector| vector.id.clone())
        .collect::<BTreeSet<_>>();
    if directory_names(&vectors_root.join("valid"))? != expected_valid
        || directory_names(&vectors_root.join("invalid"))? != expected_invalid
    {
        return Err("release vector corpus directory inventory differs".to_owned());
    }
    Ok(())
}

fn require_vector_inventory(root: &Path) -> Result<(), String> {
    let expected = BTreeSet::from([
        "bundle".to_owned(),
        "conformance-plan.json".to_owned(),
        "expected-independent.json".to_owned(),
        "expected-primary.json".to_owned(),
        "governance-post-assembly.json".to_owned(),
        "governance-pre-attestation.json".to_owned(),
        "governance-resolve.json".to_owned(),
        "plan.json".to_owned(),
        "platform-input".to_owned(),
        "vector.toml".to_owned(),
    ]);
    if directory_names(root)? != expected {
        return Err(format!(
            "release vector {:?} exact inventory differs",
            root.file_name()
        ));
    }
    Ok(())
}

fn directory_names(root: &Path) -> Result<BTreeSet<String>, String> {
    require_real_directory(root)?;
    fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate release vector directory: {error}"))?
        .map(|entry| {
            let entry = entry
                .map_err(|error| format!("cannot inspect release vector directory: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect release vector entry: {error}"))?;
            if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
                return Err("release vector contains an unsupported entry".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "release vector entry name is not UTF-8".to_owned())
        })
        .collect()
}

fn parse_single_vector(path: &Path) -> Result<Vector, String> {
    let bytes = read_regular(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "release vector descriptor is not UTF-8".to_owned())?;
    let mut values = crate::strict_toml::assignments(text)?;
    if crate::strict_toml::take(&mut values, "schema-version")? != "1" {
        return Err("release vector descriptor schema differs".to_owned());
    }
    parse_vector_values(values)
}

fn require_same_vector(expected: &Vector, observed: &Vector) -> Result<(), String> {
    if expected.id != observed.id
        || expected.valid != observed.valid
        || expected.mutation != observed.mutation
        || expected.diagnostic != observed.diagnostic
    {
        return Err(format!(
            "release vector descriptor differs from manifest for {:?}",
            expected.id
        ));
    }
    Ok(())
}

fn parse_manifest(path: &Path) -> Result<Manifest, String> {
    let bytes = read_regular(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "release vector manifest is not UTF-8".to_owned())?;
    let mut root = String::new();
    let mut vectors = Vec::new();
    let mut current = None::<String>;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[vector]]" {
            if let Some(table) = current.replace(String::new()) {
                vectors.push(parse_vector_table(&table)?);
            }
        } else if trimmed.starts_with('[') {
            return Err("release vector manifest contains an unknown table".to_owned());
        } else if let Some(table) = current.as_mut() {
            table.push_str(line);
            table.push('\n');
        } else {
            root.push_str(line);
            root.push('\n');
        }
    }
    if let Some(table) = current {
        vectors.push(parse_vector_table(&table)?);
    }
    let mut root = crate::strict_toml::assignments(&root)?;
    if crate::strict_toml::take(&mut root, "schema-version")? != "1" {
        return Err("release vector manifest schema differs".to_owned());
    }
    let protocol_version =
        crate::strict_toml::string(&crate::strict_toml::take(&mut root, "protocol-version")?)?;
    let protocol_projection = PathBuf::from(crate::strict_toml::string(
        &crate::strict_toml::take(&mut root, "protocol-projection")?,
    )?);
    if !root.is_empty() {
        return Err("release vector manifest has unknown root fields".to_owned());
    }
    let mut ids = BTreeSet::new();
    for vector in &vectors {
        if !ids.insert(vector.id.as_str()) {
            return Err("release vector manifest repeats an ID".to_owned());
        }
    }
    if vectors.len() != VECTOR_REGISTRY.len()
        || vectors
            .iter()
            .zip(VECTOR_REGISTRY)
            .any(|(vector, registration)| {
                vector.id != registration.id
                    || vector.mutation != registration.mutation
                    || vector.valid != registration.diagnostic.is_none()
                    || vector.diagnostic.as_deref() != registration.diagnostic
            })
    {
        return Err(
            "release vector manifest differs from the exact ordered production registry".to_owned(),
        );
    }
    Ok(Manifest {
        protocol_version,
        protocol_projection,
        vectors,
    })
}

fn parse_vector_table(table: &str) -> Result<Vector, String> {
    parse_vector_values(crate::strict_toml::assignments(table)?)
}

fn parse_vector_values(
    mut values: std::collections::BTreeMap<String, String>,
) -> Result<Vector, String> {
    let id = crate::strict_toml::string(&crate::strict_toml::take(&mut values, "id")?)?;
    require_safe_id(&id)?;
    let valid = crate::strict_toml::boolean(&crate::strict_toml::take(&mut values, "valid")?)?;
    let mutation = crate::strict_toml::string(&crate::strict_toml::take(&mut values, "mutation")?)?;
    require_safe_id(&mutation)?;
    let diagnostic = values
        .remove("diagnostic")
        .map(|value| crate::strict_toml::string(&value))
        .transpose()?;
    if valid == diagnostic.is_some() || !values.is_empty() {
        return Err("release vector table has invalid or unknown fields".to_owned());
    }
    Ok(Vector {
        id,
        valid,
        mutation,
        diagnostic,
    })
}

fn write_vector(path: &Path, vector: &Vector) -> Result<(), String> {
    let mut bytes = format!(
        "schema-version = 1\nid = {:?}\nvalid = {}\nmutation = {:?}\n",
        vector.id, vector.valid, vector.mutation
    )
    .into_bytes();
    if let Some(diagnostic) = &vector.diagnostic {
        bytes.extend_from_slice(format!("diagnostic = {diagnostic:?}\n").as_bytes());
    }
    write_atomic(path, &bytes)
}

fn require_safe_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("release vector ID is not a safe lowercase token".to_owned());
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    copy_tree_inner(source, destination, 0, &mut entries, &mut bytes)
}

fn copy_tree_inner(
    source: &Path,
    destination: &Path,
    depth: usize,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<(), String> {
    if depth > MAX_COPY_DEPTH {
        return Err("release vector source exceeds directory depth limit".to_owned());
    }
    require_real_directory(source)?;
    fs::create_dir(destination)
        .map_err(|error| format!("cannot create release vector directory: {error}"))?;
    let mut children = fs::read_dir(source)
        .map_err(|error| format!("cannot enumerate release vector source: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect release vector source: {error}"))?;
    children.sort_by_key(fs::DirEntry::file_name);
    for child in children {
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "release vector entry count overflow".to_owned())?;
        if *entries > MAX_COPY_ENTRIES {
            return Err("release vector source exceeds entry limit".to_owned());
        }
        let name = child.file_name();
        require_safe_component(&name)?;
        let kind = child
            .file_type()
            .map_err(|error| format!("cannot inspect release vector entry: {error}"))?;
        if kind.is_dir() && !kind.is_symlink() {
            copy_tree_inner(
                &child.path(),
                &destination.join(name),
                depth.saturating_add(1),
                entries,
                bytes,
            )?;
        } else if kind.is_file() && !kind.is_symlink() {
            let size = child
                .metadata()
                .map_err(|error| format!("cannot inspect release vector file: {error}"))?
                .len();
            *bytes = bytes
                .checked_add(size)
                .ok_or_else(|| "release vector byte count overflow".to_owned())?;
            if *bytes > MAX_COPY_BYTES {
                return Err("release vector source exceeds byte limit".to_owned());
            }
            copy_regular(&child.path(), &destination.join(name))?;
        } else {
            return Err("release vector source contains a link or unsupported entry".to_owned());
        }
    }
    Ok(())
}

fn copy_regular(source: &Path, destination: &Path) -> Result<(), String> {
    let bytes = read_regular(source)?;
    write_atomic(destination, &bytes)
}

fn require_real_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect release vector directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("release vector input is not a real directory".to_owned());
    }
    Ok(())
}

fn require_safe_component(name: &OsStr) -> Result<(), String> {
    let path = Path::new(name);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err("release vector entry name is unsafe".to_owned());
    }
    Ok(())
}

fn require_safe_relative(relative: &Path) -> Result<(), String> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err("release vector manifest path is not safe and relative".to_owned());
    }
    Ok(())
}

fn staging_path(output: &Path) -> Result<PathBuf, String> {
    let parent = output
        .parent()
        .ok_or_else(|| "release vector output has no parent".to_owned())?;
    let name = output
        .file_name()
        .ok_or_else(|| "release vector output has no filename".to_owned())?;
    let mut staging = OsString::from(".release-vectors-");
    staging.push(name);
    staging.push(format!("-{}", std::process::id()));
    let staging = parent.join(staging);
    if staging.exists() {
        return Err("release vector staging already exists".to_owned());
    }
    Ok(staging)
}
