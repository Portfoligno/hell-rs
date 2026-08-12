use std::ffi::OsString;
use std::path::PathBuf;

use hell_testkit::Digest;

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .and_then(|value| value.to_str())
        .is_some_and(|command| command == "collection-authority")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let root = std::env::current_dir()
        .map_err(|error| format!("cannot determine repository root: {error}"))?;
    if crate::collection_transport::recognizes(arguments) {
        return crate::collection_transport::run(&root, arguments);
    }
    let options = parse_options(arguments)?;
    if matches!(
        options.action.as_str(),
        "verify-checkout" | "build-native" | "collect" | "subject"
    ) {
        run_producer(&root, options)
    } else {
        run_authority(&root, options)
    }
}

fn run_producer(root: &std::path::Path, options: CollectionOptions) -> Result<String, String> {
    if producer_has_authority_options(&options) {
        return Err(usage().to_owned());
    }
    let action = options.action.clone();
    match action.as_str() {
        "verify-checkout" => run_checkout_verification(root, options),
        "build-native" => run_native_build(options),
        "collect" => run_collection(root, options),
        "subject" => run_collection_subject(root, options),
        _ => Err(usage().to_owned()),
    }
}

fn producer_has_authority_options(options: &CollectionOptions) -> bool {
    options.verified_report.is_some()
        || options.package.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.integration_proof.is_some()
        || options.integration_review.is_some()
        || options.worm_custody.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
}

fn run_checkout_verification(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.output.is_some()
        || options.provider.is_some()
        || options.report.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = options
        .input
        .ok_or_else(|| "collection checkout verification requires --input".to_owned())?;
    let candidate = options
        .candidate_commit
        .ok_or_else(|| "collection checkout verification requires --candidate-commit".to_owned())?;
    verify_checkout(root, &input, &candidate)?;
    Ok(format!(
        "verified exact collection checkout {} at {candidate}",
        input.display()
    ))
}

fn run_native_build(options: CollectionOptions) -> Result<String, String> {
    if options.input.is_some()
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.provider.is_some()
        || options.report.is_some()
    {
        return Err(usage().to_owned());
    }
    let platform = options
        .platform
        .as_deref()
        .ok_or_else(|| "collection native build requires --platform".to_owned())?;
    let output = options
        .output
        .as_deref()
        .ok_or_else(|| "collection native build requires --output".to_owned())?;
    let source = options
        .source
        .ok_or_else(|| "collection native build requires --source".to_owned())?;
    let executable = crate::suite::collection_authority_build_native(&source, platform, output)?;
    Ok(format!(
        "built exact collection native oracle {}",
        executable.display()
    ))
}

fn run_collection(root: &std::path::Path, options: CollectionOptions) -> Result<String, String> {
    if options.input.is_some()
        || options.source.is_some()
        || options.provider.is_some()
        || options.report.is_some()
    {
        return Err(usage().to_owned());
    }
    run_collect(
        root,
        options.oracle,
        options.oracle_sha256,
        options.candidate_executable,
        options.candidate_commit,
        options.platform.as_deref(),
        options.output.as_deref(),
    )
}

fn run_collection_subject(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.provider.is_some()
        || options.report.is_some()
    {
        return Err(usage().to_owned());
    }
    let platform = options
        .platform
        .as_deref()
        .ok_or_else(|| "collection subject requires --platform".to_owned())?;
    let output = options
        .output
        .as_deref()
        .ok_or_else(|| "collection subject requires --output".to_owned())?;
    let input = options
        .input
        .ok_or_else(|| "collection subject requires --input".to_owned())?;
    crate::suite::collection_authority_subject(root, &input, platform, output)?;
    Ok(format!(
        "wrote exact collection provider subject {}",
        output.display()
    ))
}

fn verify_checkout(
    root: &std::path::Path,
    input: &std::path::Path,
    expected: &str,
) -> Result<(), String> {
    if !(input == std::path::Path::new(".")
        || input == std::path::Path::new("ci-work").join("candidate"))
        || !is_full_lowercase_commit(expected)
    {
        return Err("collection checkout identity is invalid".to_owned());
    }
    let checkout = std::process::Command::new("git")
        .arg("-C")
        .arg(root.join(input))
        .args(["rev-parse", "--verify", "HEAD^{commit}"])
        .output()
        .map_err(|error| format!("cannot inspect collection checkout: {error}"))?;
    let stdout = std::str::from_utf8(&checkout.stdout)
        .map_err(|_| "collection checkout identity is not UTF-8".to_owned())?;
    let lines = stdout.lines().collect::<Vec<_>>();
    if !checkout.status.success() || !checkout.stderr.is_empty() || lines != [expected] {
        return Err("collection checkout differs from exact required commit".to_owned());
    }
    Ok(())
}

fn is_full_lowercase_commit(value: &str) -> bool {
    let nibble = |digit| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut chunks = value.as_bytes().chunks_exact(2);
    let decoded = chunks
        .by_ref()
        .map(|digits| Some((nibble(digits[0])? << 4) | nibble(digits[1])?))
        .collect::<Option<Vec<_>>>();
    chunks.remainder().is_empty()
        && decoded
            .as_deref()
            .and_then(|bytes| <&[u8; 20]>::try_from(bytes).ok())
            .is_some()
}

fn run_authority(root: &std::path::Path, options: CollectionOptions) -> Result<String, String> {
    match options.action.as_str() {
        "verify" => run_verify(root, options),
        "prepare-custody-review" => run_prepare_custody_review(root, options),
        "prepare-worm-custody" => run_prepare_worm_custody(root, options),
        "verify-worm-artifact" => run_verify_worm_artifact(root, options),
        "verify-activation-artifact" => run_verify_activation_token(root, options),
        "prepare-activation" => run_prepare_activation(root, options),
        "verify-activation-preparation" => run_verify_activation_preparation(root, options),
        "verify-activation-review-subject" => run_verify_activation_review_subject(root, options),
        "finalize-activation" => run_finalize_activation(root, options),
        "assemble-custody-payload-overlay" => run_assemble_custody_payload(root, options),
        "assemble-custody-review-overlay" => run_assemble_custody_review(root, options),
        "verify-custody-review-preparation" => run_verify_custody_review_preparation(root, options),
        "verify-custody" => run_verify_custody(root, options),
        "compact" => run_compact(root, options),
        "retain-custody-attestation" => run_retain(root, options),
        _ => Err(usage().to_owned()),
    }
}

fn run_verify_activation_review_subject(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "verify-activation-review-subject"
        || options.output.is_some()
        || options.report.is_some()
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.provider.is_some()
        || options.verified_report.is_some()
        || options.package.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.signature.is_some()
        || options.integration_proof.is_some()
        || options.integration_review.is_some()
        || options.worm_custody.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
        || options.run_id.is_some()
        || options.run_attempt.is_some()
        || options.artifact_id.is_some()
        || options.expected_archive_sha256.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = options
        .input
        .ok_or_else(|| "activation review subject verification requires --input".to_owned())?;
    let directory = options.expected_directory_sha256.ok_or_else(|| {
        "activation review subject verification requires --expected-directory-sha256".to_owned()
    })?;
    crate::collection_custody::verify_activation_review_subject_selection(
        root, &input, &directory,
    )?;
    Ok("verified exact immutable collection activation review subject".to_owned())
}

fn run_assemble_custody_payload(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    let package = options
        .package
        .ok_or_else(|| "payload overlay requires --package".to_owned())?;
    let signature = options
        .signature
        .ok_or_else(|| "payload overlay requires --signature".to_owned())?;
    let output = options
        .output
        .ok_or_else(|| "payload overlay requires --output".to_owned())?;
    let digest = crate::collection_custody::assemble_custody_payload_overlay(
        root, &package, &signature, &output,
    )?;
    Ok(format!(
        "assembled exact collection custody payload overlay {digest}"
    ))
}

fn run_assemble_custody_review(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    let input = options
        .input
        .ok_or_else(|| "review overlay requires --input".to_owned())?;
    let review = options
        .integration_review
        .ok_or_else(|| "review overlay requires --integration-review".to_owned())?;
    let output = options
        .output
        .ok_or_else(|| "review overlay requires --output".to_owned())?;
    let digest =
        crate::collection_custody::assemble_custody_review_overlay(root, &input, &review, &output)?;
    Ok(format!(
        "assembled exact collection custody review overlay {digest}"
    ))
}

fn run_finalize_activation(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "finalize-activation"
        || options.report.is_some()
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.provider.is_some()
        || options.verified_report.is_some()
        || options.package.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.integration_proof.is_some()
        || options.worm_custody.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = options
        .input
        .ok_or_else(|| "collection activation finalization requires --input".to_owned())?;
    let author = options.signature.ok_or_else(|| {
        "collection activation finalization requires --signature claim-author DSSE".to_owned()
    })?;
    let review = options.integration_review.ok_or_else(|| {
        "collection activation finalization requires --integration-review".to_owned()
    })?;
    let output = options
        .output
        .ok_or_else(|| "collection activation finalization requires --output".to_owned())?;
    crate::collection_custody::finalize_activation(root, &input, &author, &review, &output)?;
    Ok("finalized reviewed non-authoritative collection activation tree".to_owned())
}

fn run_verify_activation_preparation(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "verify-activation-preparation"
        || options.output.is_some()
        || options.report.is_some()
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.provider.is_some()
        || options.verified_report.is_some()
        || options.package.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.signature.is_some()
        || options.integration_proof.is_some()
        || options.integration_review.is_some()
        || options.worm_custody.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = options.input.ok_or_else(|| {
        "collection activation preparation verification requires --input".to_owned()
    })?;
    let expected = options.expected_directory_sha256.ok_or_else(|| {
        "collection activation preparation verification requires --expected-directory-sha256"
            .to_owned()
    })?;
    Digest::from_hex(&expected)
        .map_err(|_| "collection activation preparation directory digest is invalid".to_owned())?;
    let observed = crate::custody_ops::verified_directory_digest(&root.join(&input))?;
    if observed != expected {
        return Err("collection activation preparation directory digest differs".to_owned());
    }
    let run_id = required_positive_option(options.run_id.as_deref(), "--run-id")?;
    let run_attempt = required_positive_option(options.run_attempt.as_deref(), "--run-attempt")?;
    let artifact_id = required_positive_option(options.artifact_id.as_deref(), "--artifact-id")?;
    let archive = options.expected_archive_sha256.ok_or_else(|| {
        "collection activation preparation verification requires --expected-archive-sha256"
            .to_owned()
    })?;
    let digest = crate::collection_custody::verify_activation_proposal_source(
        root,
        &input,
        run_id,
        run_attempt,
        artifact_id,
        &archive,
    )?;
    Ok(format!(
        "verified non-authoritative collection activation proposal {digest}"
    ))
}

fn run_prepare_activation(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "prepare-activation"
        || options.report.is_some()
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.provider.is_some()
        || options.verified_report.is_some()
        || options.package.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.signature.is_some()
        || options.integration_proof.is_some()
        || options.integration_review.is_some()
        || options.worm_custody.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = options
        .input
        .ok_or_else(|| "collection activation preparation requires --input".to_owned())?;
    let output = options
        .output
        .ok_or_else(|| "collection activation preparation requires --output".to_owned())?;
    let run_id = required_positive_option(options.run_id.as_deref(), "--run-id")?;
    let run_attempt = required_positive_option(options.run_attempt.as_deref(), "--run-attempt")?;
    let artifact_id = required_positive_option(options.artifact_id.as_deref(), "--artifact-id")?;
    let directory = options.expected_directory_sha256.ok_or_else(|| {
        "collection activation preparation requires --expected-directory-sha256".to_owned()
    })?;
    let archive = options.expected_archive_sha256.ok_or_else(|| {
        "collection activation preparation requires --expected-archive-sha256".to_owned()
    })?;
    crate::collection_custody::prepare_activation(
        root,
        &crate::collection_custody::PrepareActivationInput {
            artifact: &input,
            output: &output,
            run_id,
            run_attempt,
            artifact_id,
            expected_directory_sha256: &directory,
            expected_archive_sha256: &archive,
        },
    )?;
    Ok("prepared non-authoritative collection activation proposal".to_owned())
}

fn required_positive_option(value: Option<&str>, label: &str) -> Result<u64, String> {
    let value = value
        .ok_or_else(|| format!("collection activation preparation requires {label}"))?
        .parse::<u64>()
        .map_err(|_| format!("{label} is not an integer"))?;
    if value == 0 {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(value)
}

fn run_verify_activation_token(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "verify-activation-artifact"
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.output.is_some()
        || options.provider.is_some()
        || options.verified_report.is_some()
        || options.package.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.signature.is_some()
        || options.integration_proof.is_some()
        || options.integration_review.is_some()
        || options.worm_custody.is_some()
        || options.expected_directory_sha256.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let token = options.input.ok_or_else(|| {
        "collection activation token verification requires --input token".to_owned()
    })?;
    let report = options.report.ok_or_else(|| {
        "collection activation token verification requires --report admission".to_owned()
    })?;
    let directory = std::path::Path::new("ci-in/collection-custody-activation");
    if token != directory.join("collection-custody-activation-token.json")
        || report != directory.join("collection-custody-admission.json")
    {
        return Err("collection activation token inputs are not canonical".to_owned());
    }
    let verified = crate::collection_custody::verify_activation_preparation_token(
        &root.join(report),
        &root.join(token),
    )?;
    Ok(format!(
        "verified non-authoritative collection activation preparation token {}",
        verified.token_sha256
    ))
}

fn run_verify_worm_artifact(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "verify-worm-artifact"
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.output.is_some()
        || options.provider.is_some()
        || options.report.is_some()
        || options.verified_report.is_some()
        || options.package.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.signature.is_some()
        || options.integration_proof.is_some()
        || options.integration_review.is_some()
        || options.worm_custody.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = options
        .input
        .ok_or_else(|| "collection WORM artifact verification requires --input".to_owned())?;
    let digest = options.expected_directory_sha256.ok_or_else(|| {
        "collection WORM artifact verification requires --expected-directory-sha256".to_owned()
    })?;
    let archive = options.expected_archive_sha256.ok_or_else(|| {
        "collection WORM artifact verification requires --expected-archive-sha256".to_owned()
    })?;
    let positive = |value: Option<String>, label: &str| -> Result<u64, String> {
        value
            .ok_or_else(|| format!("collection WORM artifact verification requires {label}"))?
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or_else(|| format!("collection WORM {label} must be nonzero"))
    };
    crate::collection_custody::verify_worm_provider_artifact(
        root,
        &input,
        &digest,
        &archive,
        positive(options.run_id, "--run-id")?,
        positive(options.run_attempt, "--run-attempt")?,
        positive(options.artifact_id, "--artifact-id")?,
    )?;
    Ok(format!(
        "verified exact collection WORM custody artifact {}",
        input.display()
    ))
}

fn run_prepare_worm_custody(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "prepare-worm-custody"
        || options.input.is_some()
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.provider.is_some()
        || options.report.is_some()
        || options.verified_report.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.worm_custody.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let required = |value: Option<PathBuf>, name| {
        value.ok_or_else(|| format!("collection WORM custody preparation requires --{name}"))
    };
    let package = required(options.package, "package")?;
    let signature = required(options.signature, "signature")?;
    let candidate_executable = required(options.candidate_executable, "candidate-executable")?;
    let integration_proof = required(options.integration_proof, "integration-proof")?;
    let integration_review = required(options.integration_review, "integration-review")?;
    let output = required(options.output, "output")?;
    crate::collection_custody::prepare_worm_custody(
        root,
        &crate::collection_custody::PrepareWormCustodyInput {
            package: &package,
            signature: &signature,
            candidate_executable: &candidate_executable,
            integration_proof: &integration_proof,
            integration_review: &integration_review,
            output: &output,
        },
    )?;
    Ok(format!(
        "prepared non-authoritative collection WORM custody package {}",
        output.display()
    ))
}

fn run_verify_custody_review_preparation(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "verify-custody-review-preparation"
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_executable.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.output.is_some()
        || options.provider.is_some()
        || options.report.is_some()
        || options.verified_report.is_some()
        || options.package.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.signature.is_some()
        || options.integration_proof.is_some()
        || options.integration_review.is_some()
        || options.worm_custody.is_some()
        || options.reviewer.is_some()
        || options.issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = options.input.ok_or_else(|| {
        "collection custody review preparation verification requires --input".to_owned()
    })?;
    crate::collection_custody::verify_prepared_custody_review(root, &input)?;
    Ok(format!(
        "verified exact unsigned collection custody review preparation {}",
        input.display()
    ))
}

fn run_prepare_custody_review(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    if options.action != "prepare-custody-review"
        || options.input.is_some()
        || options.oracle.is_some()
        || options.oracle_sha256.is_some()
        || options.candidate_commit.is_some()
        || options.source.is_some()
        || options.platform.is_some()
        || options.provider.is_some()
        || options.report.is_some()
        || options.verified_report.is_some()
        || options.bundle.is_some()
        || options.trusted_root.is_some()
        || options.trusted_root_provenance.is_some()
        || options.online_verification.is_some()
        || options.gh_install_manifest.is_some()
        || options.integration_proof.is_some()
        || options.integration_review.is_some()
        || options.worm_custody.is_some()
    {
        return Err(usage().to_owned());
    }
    let required_path = |value: Option<PathBuf>, name| {
        value.ok_or_else(|| format!("collection custody review preparation requires --{name}"))
    };
    let required_text = |value: Option<String>, name| {
        value.ok_or_else(|| format!("collection custody review preparation requires --{name}"))
    };
    let package = required_path(options.package, "package")?;
    let signature = required_path(options.signature, "signature")?;
    let candidate_executable = required_path(options.candidate_executable, "candidate-executable")?;
    let reviewer = required_text(options.reviewer, "reviewer")?;
    let issued_at = required_text(options.issued_at, "issued-at")?;
    let output = required_path(options.output, "output")?;
    crate::collection_custody::prepare_custody_review(
        root,
        &crate::collection_custody::PrepareCustodyReviewInput {
            package: &package,
            signature: &signature,
            candidate_executable: &candidate_executable,
            reviewer: &reviewer,
            issued_at: &issued_at,
            output: &output,
        },
    )?;
    Ok(format!(
        "prepared deterministic unsigned collection custody review material {}",
        output.display()
    ))
}

fn run_verify(root: &std::path::Path, options: CollectionOptions) -> Result<String, String> {
    let CollectionOptions {
        action,
        input,
        oracle,
        oracle_sha256,
        candidate_executable,
        candidate_commit,
        source,
        platform,
        output,
        provider,
        report,
        verified_report,
        package,
        bundle,
        trusted_root,
        trusted_root_provenance,
        online_verification,
        gh_install_manifest,
        signature,
        integration_proof,
        integration_review,
        worm_custody,
        expected_directory_sha256,
        expected_archive_sha256,
        run_id,
        run_attempt,
        artifact_id,
        reviewer,
        issued_at,
    } = options;
    if action != "verify"
        || oracle.is_some()
        || oracle_sha256.is_some()
        || candidate_executable.is_some()
        || candidate_commit.is_some()
        || source.is_some()
        || platform.is_some()
        || output.is_some()
        || verified_report.is_some()
        || package.is_some()
        || bundle.is_some()
        || trusted_root.is_some()
        || trusted_root_provenance.is_some()
        || online_verification.is_some()
        || gh_install_manifest.is_some()
        || signature.is_some()
        || integration_proof.is_some()
        || integration_review.is_some()
        || worm_custody.is_some()
        || expected_directory_sha256.is_some()
        || expected_archive_sha256.is_some()
        || run_id.is_some()
        || run_attempt.is_some()
        || artifact_id.is_some()
        || reviewer.is_some()
        || issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = input.ok_or_else(|| "collection verify requires --input".to_owned())?;
    let provider = provider.ok_or_else(|| "collection verify requires --provider".to_owned())?;
    let report = report.ok_or_else(|| "collection verify requires --report".to_owned())?;
    crate::suite::collection_authority_verify(root, &input, &provider, &report)?;
    Ok(format!(
        "verified exact collection campaign and wrote {}",
        report.display()
    ))
}

fn run_verify_custody(
    root: &std::path::Path,
    options: CollectionOptions,
) -> Result<String, String> {
    let CollectionOptions {
        action,
        input,
        oracle,
        oracle_sha256,
        candidate_executable,
        candidate_commit,
        source,
        platform,
        output,
        provider,
        report,
        verified_report,
        package,
        bundle,
        trusted_root,
        trusted_root_provenance,
        online_verification,
        gh_install_manifest,
        signature,
        integration_proof,
        integration_review,
        worm_custody,
        expected_directory_sha256,
        expected_archive_sha256,
        run_id,
        run_attempt,
        artifact_id,
        reviewer,
        issued_at,
    } = options;
    if action != "verify-custody"
        || input.is_some()
        || oracle.is_some()
        || oracle_sha256.is_some()
        || candidate_commit.is_some()
        || source.is_some()
        || platform.is_some()
        || output.is_some()
        || provider.is_some()
        || verified_report.is_some()
        || bundle.is_some()
        || trusted_root.is_some()
        || trusted_root_provenance.is_some()
        || online_verification.is_some()
        || gh_install_manifest.is_some()
        || reviewer.is_some()
        || expected_directory_sha256.is_some()
        || expected_archive_sha256.is_some()
        || run_id.is_some()
        || run_attempt.is_some()
        || artifact_id.is_some()
        || issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let required = |value: Option<PathBuf>, name| {
        value.ok_or_else(|| format!("collection custody verification requires --{name}"))
    };
    let package = required(package, "package")?;
    let signature = required(signature, "signature")?;
    let candidate_executable = required(candidate_executable, "candidate-executable")?;
    let integration_proof = required(integration_proof, "integration-proof")?;
    let integration_review = required(integration_review, "integration-review")?;
    let report = required(report, "report")?;
    crate::collection_custody::verify_durable_admission(
        root,
        &crate::collection_custody::VerifyCustodyInput {
            package: &package,
            signature: &signature,
            candidate_executable: &candidate_executable,
            integration_proof: &integration_proof,
            integration_review: &integration_review,
            worm_custody: worm_custody.as_deref(),
            report: &report,
        },
    )?;
    Ok(format!(
        "verified current durable collection custody and wrote {}",
        report.display()
    ))
}

fn run_compact(root: &std::path::Path, options: CollectionOptions) -> Result<String, String> {
    let CollectionOptions {
        action,
        input,
        oracle,
        oracle_sha256,
        candidate_executable,
        candidate_commit,
        source,
        platform,
        output,
        provider,
        report,
        verified_report,
        package,
        bundle,
        trusted_root,
        trusted_root_provenance,
        online_verification,
        gh_install_manifest,
        signature,
        integration_proof,
        integration_review,
        worm_custody,
        expected_directory_sha256,
        expected_archive_sha256,
        run_id,
        run_attempt,
        artifact_id,
        reviewer,
        issued_at,
    } = options;
    if action != "compact"
        || oracle.is_some()
        || oracle_sha256.is_some()
        || candidate_executable.is_some()
        || candidate_commit.is_some()
        || source.is_some()
        || platform.is_some()
        || report.is_some()
        || package.is_some()
        || bundle.is_some()
        || trusted_root.is_some()
        || trusted_root_provenance.is_some()
        || online_verification.is_some()
        || gh_install_manifest.is_some()
        || signature.is_some()
        || integration_proof.is_some()
        || integration_review.is_some()
        || worm_custody.is_some()
        || expected_directory_sha256.is_some()
        || expected_archive_sha256.is_some()
        || run_id.is_some()
        || run_attempt.is_some()
        || artifact_id.is_some()
        || reviewer.is_some()
        || issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    let input = input.ok_or_else(|| "collection compact requires --input".to_owned())?;
    let provider = provider.ok_or_else(|| "collection compact requires --provider".to_owned())?;
    let verified_report = verified_report
        .ok_or_else(|| "collection compact requires --verified-report".to_owned())?;
    let output = output.ok_or_else(|| "collection compact requires --output".to_owned())?;
    let custody =
        crate::collection_custody::compact(root, &input, &provider, &verified_report, &output)?;
    Ok(format!(
        "wrote non-authoritative collection custody payload {} with root {}",
        output.display(),
        custody.payload_merkle_root.hex()
    ))
}

fn run_retain(root: &std::path::Path, options: CollectionOptions) -> Result<String, String> {
    let CollectionOptions {
        action,
        input,
        oracle,
        oracle_sha256,
        candidate_executable,
        candidate_commit,
        source,
        platform,
        output,
        provider,
        report,
        verified_report,
        package,
        bundle,
        trusted_root,
        trusted_root_provenance,
        online_verification,
        gh_install_manifest,
        signature,
        integration_proof,
        integration_review,
        worm_custody,
        expected_directory_sha256,
        expected_archive_sha256,
        run_id,
        run_attempt,
        artifact_id,
        reviewer,
        issued_at,
    } = options;
    if action != "retain-custody-attestation"
        || input.is_some()
        || oracle.is_some()
        || oracle_sha256.is_some()
        || candidate_executable.is_some()
        || candidate_commit.is_some()
        || source.is_some()
        || platform.is_some()
        || provider.is_some()
        || report.is_some()
        || verified_report.is_some()
        || signature.is_some()
        || integration_proof.is_some()
        || integration_review.is_some()
        || worm_custody.is_some()
        || expected_directory_sha256.is_some()
        || expected_archive_sha256.is_some()
        || run_id.is_some()
        || run_attempt.is_some()
        || artifact_id.is_some()
        || reviewer.is_some()
        || issued_at.is_some()
    {
        return Err(usage().to_owned());
    }
    run_retain_attestation(
        root,
        (
            package,
            bundle,
            trusted_root,
            trusted_root_provenance,
            online_verification,
            gh_install_manifest,
            output,
        ),
    )
}

type RetainAttestationOptions = (
    Option<PathBuf>,
    Option<PathBuf>,
    Option<PathBuf>,
    Option<PathBuf>,
    Option<PathBuf>,
    Option<PathBuf>,
    Option<PathBuf>,
);

fn run_retain_attestation(
    root: &std::path::Path,
    options: RetainAttestationOptions,
) -> Result<String, String> {
    let (package, bundle, trusted_root, provenance, verification, gh_manifest, output) = options;
    let required = |value: Option<PathBuf>, name| {
        value.ok_or_else(|| format!("collection custody finalizer requires --{name}"))
    };
    let package = required(package, "package")?;
    let bundle = required(bundle, "bundle")?;
    let trusted_root = required(trusted_root, "trusted-root")?;
    let provenance = required(provenance, "trusted-root-provenance")?;
    let verification = required(verification, "online-verification")?;
    let gh_manifest = required(gh_manifest, "gh-install-manifest")?;
    let output = required(output, "output")?;
    crate::collection_custody::retain_attestation(
        root,
        &crate::collection_custody::RetainAttestationInput {
            package: &package,
            bundle: &bundle,
            trusted_root: &trusted_root,
            trusted_root_provenance: &provenance,
            online_verification: &verification,
            gh_install_manifest: &gh_manifest,
            output: &output,
        },
    )?;
    Ok(format!(
        "retained prepared non-authoritative custody signature {}",
        output.display()
    ))
}

fn run_collect(
    root: &std::path::Path,
    oracle: Option<PathBuf>,
    oracle_sha256: Option<Digest>,
    candidate_executable: Option<PathBuf>,
    candidate_commit: Option<String>,
    platform: Option<&str>,
    output: Option<&std::path::Path>,
) -> Result<String, String> {
    let platform = platform.ok_or_else(|| "collection collect requires --platform".to_owned())?;
    let output = output.ok_or_else(|| "collection collect requires --output".to_owned())?;
    let oracle = oracle.ok_or_else(|| "collection collect requires --oracle".to_owned())?;
    let oracle_sha256 =
        oracle_sha256.ok_or_else(|| "collection collect requires --oracle-sha256".to_owned())?;
    let candidate_executable = candidate_executable
        .ok_or_else(|| "collection collect requires --candidate-executable".to_owned())?;
    let candidate_commit = candidate_commit
        .ok_or_else(|| "collection collect requires --candidate-commit".to_owned())?;
    crate::suite::collection_authority_collect(
        root,
        &oracle,
        oracle_sha256,
        &candidate_executable,
        &candidate_commit,
        platform,
        output,
    )?;
    Ok(format!(
        "wrote exact dormant collection campaign {}",
        output.join("collection-evidence").display()
    ))
}

struct CollectionOptions {
    action: String,
    input: Option<PathBuf>,
    oracle: Option<PathBuf>,
    oracle_sha256: Option<Digest>,
    candidate_executable: Option<PathBuf>,
    candidate_commit: Option<String>,
    source: Option<PathBuf>,
    platform: Option<String>,
    output: Option<PathBuf>,
    provider: Option<PathBuf>,
    report: Option<PathBuf>,
    verified_report: Option<PathBuf>,
    package: Option<PathBuf>,
    bundle: Option<PathBuf>,
    trusted_root: Option<PathBuf>,
    trusted_root_provenance: Option<PathBuf>,
    online_verification: Option<PathBuf>,
    gh_install_manifest: Option<PathBuf>,
    signature: Option<PathBuf>,
    integration_proof: Option<PathBuf>,
    integration_review: Option<PathBuf>,
    worm_custody: Option<PathBuf>,
    expected_directory_sha256: Option<String>,
    expected_archive_sha256: Option<String>,
    run_id: Option<String>,
    run_attempt: Option<String>,
    artifact_id: Option<String>,
    reviewer: Option<String>,
    issued_at: Option<String>,
}

impl CollectionOptions {
    fn empty(action: &str) -> Self {
        Self {
            action: action.to_owned(),
            input: None,
            oracle: None,
            oracle_sha256: None,
            candidate_executable: None,
            candidate_commit: None,
            source: None,
            platform: None,
            output: None,
            provider: None,
            report: None,
            verified_report: None,
            package: None,
            bundle: None,
            trusted_root: None,
            trusted_root_provenance: None,
            online_verification: None,
            gh_install_manifest: None,
            signature: None,
            integration_proof: None,
            integration_review: None,
            worm_custody: None,
            expected_directory_sha256: None,
            expected_archive_sha256: None,
            run_id: None,
            run_attempt: None,
            artifact_id: None,
            reviewer: None,
            issued_at: None,
        }
    }

    fn set(&mut self, flag: &OsString, value: &OsString) -> Result<(), String> {
        let set_path = |slot: &mut Option<PathBuf>| {
            if slot.is_some() {
                return Err(usage().to_owned());
            }
            *slot = Some(PathBuf::from(value));
            Ok(())
        };
        let set_text = |slot: &mut Option<String>, label: &str| {
            if slot.is_some() {
                return Err(usage().to_owned());
            }
            *slot = Some(
                value
                    .to_str()
                    .ok_or_else(|| format!("{label} must be UTF-8"))?
                    .to_owned(),
            );
            Ok(())
        };
        match flag.to_str() {
            Some("--input") => set_path(&mut self.input),
            Some("--oracle") => set_path(&mut self.oracle),
            Some("--source") => set_path(&mut self.source),
            Some("--candidate-executable") => set_path(&mut self.candidate_executable),
            Some("--candidate-commit") => set_text(&mut self.candidate_commit, "candidate commit"),
            Some("--platform") => set_text(&mut self.platform, "collection platform"),
            Some("--reviewer") => set_text(&mut self.reviewer, "collection reviewer"),
            Some("--issued-at") => set_text(&mut self.issued_at, "collection review timestamp"),
            Some("--output") => set_path(&mut self.output),
            Some("--provider") => set_path(&mut self.provider),
            Some("--report") => set_path(&mut self.report),
            Some("--verified-report") => set_path(&mut self.verified_report),
            Some("--package") => set_path(&mut self.package),
            Some("--bundle") => set_path(&mut self.bundle),
            Some("--trusted-root") => set_path(&mut self.trusted_root),
            Some("--trusted-root-provenance") => set_path(&mut self.trusted_root_provenance),
            Some("--online-verification") => set_path(&mut self.online_verification),
            Some("--gh-install-manifest") => set_path(&mut self.gh_install_manifest),
            Some("--signature") => set_path(&mut self.signature),
            Some("--integration-proof") => set_path(&mut self.integration_proof),
            Some("--integration-review") => set_path(&mut self.integration_review),
            Some("--worm-custody") => set_path(&mut self.worm_custody),
            Some("--expected-directory-sha256") => set_text(
                &mut self.expected_directory_sha256,
                "collection WORM directory digest",
            ),
            Some("--expected-archive-sha256") => set_text(
                &mut self.expected_archive_sha256,
                "collection activation archive digest",
            ),
            Some("--run-id") => set_text(&mut self.run_id, "provider run ID"),
            Some("--run-attempt") => set_text(&mut self.run_attempt, "provider run attempt"),
            Some("--artifact-id") => set_text(&mut self.artifact_id, "provider artifact ID"),
            Some("--oracle-sha256") if self.oracle_sha256.is_none() => {
                self.oracle_sha256 = Some(
                    Digest::from_hex(
                        value
                            .to_str()
                            .ok_or_else(|| "oracle digest must be UTF-8".to_owned())?,
                    )
                    .map_err(str::to_owned)?,
                );
                Ok(())
            }
            _ => Err(usage().to_owned()),
        }
    }
}

fn parse_options(arguments: &[OsString]) -> Result<CollectionOptions, String> {
    let (action, rest) = parse_collection_action(arguments)?;
    let mut options = CollectionOptions::empty(action);
    let mut fields = rest.iter();
    while let Some(flag) = fields.next() {
        let value = fields
            .next()
            .ok_or_else(|| format!("{} requires a value", flag.to_string_lossy()))?;
        options.set(flag, value)?;
    }
    Ok(options)
}

fn parse_collection_action(arguments: &[OsString]) -> Result<(&str, &[OsString]), String> {
    let [command, action, rest @ ..] = arguments else {
        return Err(usage().to_owned());
    };
    if command != "collection-authority"
        || !matches!(
            action.to_str(),
            Some(
                "build-native"
                    | "verify-checkout"
                    | "collect"
                    | "subject"
                    | "verify"
                    | "prepare-custody-review"
                    | "prepare-worm-custody"
                    | "verify-worm-artifact"
                    | "verify-activation-artifact"
                    | "prepare-activation"
                    | "verify-activation-preparation"
                    | "verify-activation-review-subject"
                    | "finalize-activation"
                    | "assemble-custody-payload-overlay"
                    | "assemble-custody-review-overlay"
                    | "verify-custody-review-preparation"
                    | "verify-custody"
                    | "compact"
                    | "retain-custody-attestation"
            )
        )
    {
        return Err(usage().to_owned());
    }
    Ok((action.to_str().expect("validated action is UTF-8"), rest))
}

fn usage() -> &'static str {
    "usage: hell-ci collection-authority verify-checkout --input .|ci-work/candidate --candidate-commit 40HEX\n       hell-ci collection-authority build-native --source UPSTREAM --platform macos-arm64|windows-amd64 --output SHARD\n       hell-ci collection-authority collect --oracle PATH --oracle-sha256 HEX --candidate-executable PATH --candidate-commit 40HEX --platform PLATFORM --output SHARD\n       hell-ci collection-authority subject --input SHARD --platform PLATFORM --output SHARD/collection-evidence/provider-subject.json\n       hell-ci collection-authority verify --input SHARDS --provider PROVIDER --report REPORT\n       hell-ci collection-authority compact --input SHARDS --provider PROVIDER --verified-report REPORT --output PACKAGE\n       hell-ci collection-authority retain-custody-attestation --package PACKAGE --bundle BUNDLE --trusted-root ROOT --trusted-root-provenance PROVENANCE --online-verification VERIFICATION --gh-install-manifest MANIFEST --output SIGNATURE\n       hell-ci collection-authority prepare-custody-review --package compat/collection-custody/payload --signature compat/collection-custody/signature --candidate-executable PATH --reviewer custody-reviewer:SUBJECT --issued-at UTC --output ci-out/DIRECTORY\n       hell-ci collection-authority verify-custody-review-preparation --input ci-in/collection-custody-review\n       hell-ci collection-authority prepare-worm-custody --package PACKAGE --signature SIGNATURE --candidate-executable PATH --integration-proof PROOF --integration-review REVIEW --output ci-out/DIRECTORY\n       hell-ci collection-authority verify-activation-artifact --input ci-in/collection-custody-activation/collection-custody-activation-token.json --report ci-in/collection-custody-activation/collection-custody-admission.json\n       hell-ci collection-authority verify-custody --package PACKAGE --signature SIGNATURE --candidate-executable PATH --integration-proof PROOF --integration-review REVIEW [--worm-custody ci-in/collection-worm-custody] --report REPORT"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_CHECKOUT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn collection_collect_requires_explicit_candidate_subject_inputs() {
        let complete = arguments(&[
            "collection-authority",
            "collect",
            "--oracle",
            "oracle",
            "--oracle-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--candidate-executable",
            "isolated/candidate/hell",
            "--candidate-commit",
            "cccccccccccccccccccccccccccccccccccccccc",
            "--platform",
            "linux-amd64",
            "--output",
            "shard",
        ]);
        let parsed = parse_options(&complete).unwrap();
        assert_eq!(
            parsed.candidate_executable.as_deref(),
            Some(PathBuf::from("isolated/candidate/hell").as_path())
        );
        assert_eq!(
            parsed.candidate_commit.as_deref(),
            Some("cccccccccccccccccccccccccccccccccccccccc")
        );

        for omitted in ["--candidate-executable", "--candidate-commit"] {
            let mut mutation = complete.clone();
            let index = mutation.iter().position(|value| value == omitted).unwrap();
            mutation.drain(index..=index + 1);
            assert!(run(&mutation).is_err());
        }
    }

    #[test]
    fn checkout_verification_rejects_non_exact_commit_identities_and_paths() {
        for (input, candidate) in [
            ("../outside", "cccccccccccccccccccccccccccccccccccccccc"),
            (".", "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
            (".", "ccccccccccccccccccccccccccccccccccccccc"),
            (".", "cccccccccccccccccccccccccccccccccccccccg"),
        ] {
            assert!(verify_checkout(std::path::Path::new("."), input.as_ref(), candidate).is_err());
        }
    }

    fn fixture_git(repository: &std::path::Path, arguments: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn checkout_verification_requires_head_equality_not_ancestry() {
        let temporary = std::env::temp_dir().join(format!(
            "hell-collection-checkout-test-{}-{}",
            std::process::id(),
            NEXT_CHECKOUT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        let repository = temporary.join("ci-work").join("candidate");
        std::fs::create_dir_all(&repository).unwrap();
        fixture_git(&repository, &["init", "--quiet"]);
        std::fs::create_dir(repository.join(".fixture-no-hooks")).unwrap();
        fixture_git(
            &repository,
            &["config", "core.hooksPath", ".fixture-no-hooks"],
        );
        fixture_git(
            &repository,
            &["config", "user.name", "Collection Checkout Fixture"],
        );
        fixture_git(
            &repository,
            &[
                "config",
                "user.email",
                "collection-checkout@example.invalid",
            ],
        );
        std::fs::write(repository.join("subject"), b"first\n").unwrap();
        fixture_git(&repository, &["add", "--", "subject"]);
        fixture_git(&repository, &["commit", "--quiet", "-m", "first"]);
        let first = fixture_git(&repository, &["rev-parse", "HEAD"]);
        std::fs::write(repository.join("subject"), b"second\n").unwrap();
        fixture_git(&repository, &["add", "--", "subject"]);
        fixture_git(&repository, &["commit", "--quiet", "-m", "second"]);
        let second = fixture_git(&repository, &["rev-parse", "HEAD"]);
        let input = std::path::Path::new("ci-work").join("candidate");
        assert!(verify_checkout(&temporary, &input, &second).is_ok());
        assert!(verify_checkout(&temporary, &input, &first).is_err());
        fixture_git(&repository, &["checkout", "--quiet", "--detach", &first]);
        assert!(verify_checkout(&temporary, &input, &second).is_err());
        assert!(verify_checkout(&temporary, &input, &"d".repeat(first.len())).is_err());
        std::fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn durable_custody_verifier_requires_its_exact_path_set() {
        let complete = arguments(&[
            "collection-authority",
            "verify-custody",
            "--package",
            "compat/collection-custody/payload",
            "--signature",
            "compat/collection-custody/signature",
            "--candidate-executable",
            "target/release/hell",
            "--integration-proof",
            "compat/collection-custody/integration-proof",
            "--integration-review",
            "compat/collection-custody/integration-review.dsse.json",
            "--report",
            "ci-out/collection-custody-admission.json",
        ]);
        let parsed = parse_options(&complete).unwrap();
        assert_eq!(
            parsed.integration_proof.as_deref(),
            Some(std::path::Path::new(
                "compat/collection-custody/integration-proof"
            ))
        );
        for omitted in [
            "--package",
            "--signature",
            "--candidate-executable",
            "--integration-proof",
            "--integration-review",
            "--report",
        ] {
            let mut mutation = complete.clone();
            let index = mutation.iter().position(|value| value == omitted).unwrap();
            mutation.drain(index..=index + 1);
            assert!(run(&mutation).is_err());
        }
        let mut extra = complete;
        extra.extend(arguments(&["--input", "unreviewed"]));
        assert!(run(&extra).is_err());

        let mut worm = arguments(&[
            "collection-authority",
            "verify-custody",
            "--package",
            "compat/collection-custody/payload",
            "--signature",
            "compat/collection-custody/signature",
            "--candidate-executable",
            "target/release/hell",
            "--integration-proof",
            "compat/collection-custody/integration-proof",
            "--integration-review",
            "compat/collection-custody/integration-review.dsse.json",
            "--report",
            "ci-out/collection-custody-admission.json",
        ]);
        worm.extend(arguments(&[
            "--worm-custody",
            "ci-in/collection-worm-custody",
        ]));
        assert_eq!(
            parse_options(&worm).unwrap().worm_custody.as_deref(),
            Some(std::path::Path::new("ci-in/collection-worm-custody"))
        );
    }

    #[test]
    fn worm_custody_preparation_requires_exact_typed_inputs() {
        let complete = arguments(&[
            "collection-authority",
            "prepare-worm-custody",
            "--package",
            "compat/collection-custody/payload",
            "--signature",
            "compat/collection-custody/signature",
            "--candidate-executable",
            "target/release/hell",
            "--integration-proof",
            "compat/collection-custody/integration-proof.tsv",
            "--integration-review",
            "compat/collection-custody/integration-review.dsse.json",
            "--output",
            "ci-out/collection-worm-custody-preparation",
        ]);
        let parsed = parse_options(&complete).unwrap();
        assert_eq!(parsed.action, "prepare-worm-custody");
        assert_eq!(
            parsed.output.as_deref(),
            Some(std::path::Path::new(
                "ci-out/collection-worm-custody-preparation"
            ))
        );
        for omitted in [
            "--package",
            "--signature",
            "--candidate-executable",
            "--integration-proof",
            "--integration-review",
            "--output",
        ] {
            let mut mutation = complete.clone();
            let index = mutation.iter().position(|value| value == omitted).unwrap();
            mutation.drain(index..=index + 1);
            assert!(run(&mutation).is_err());
        }
    }

    #[test]
    fn worm_artifact_verifier_requires_canonical_directory_digest() {
        let complete = arguments(&[
            "collection-authority",
            "verify-worm-artifact",
            "--input",
            "ci-in/collection-worm-custody",
            "--expected-directory-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--expected-archive-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--run-id",
            "41",
            "--run-attempt",
            "2",
            "--artifact-id",
            "73",
        ]);
        let parsed = parse_options(&complete).unwrap();
        assert_eq!(parsed.action, "verify-worm-artifact");
        assert_eq!(
            parsed.expected_directory_sha256.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        for omitted in [
            "--input",
            "--expected-directory-sha256",
            "--expected-archive-sha256",
            "--run-id",
            "--run-attempt",
            "--artifact-id",
        ] {
            let mut mutation = complete.clone();
            let index = mutation.iter().position(|value| value == omitted).unwrap();
            mutation.drain(index..=index + 1);
            assert!(run(&mutation).is_err());
        }
    }

    #[test]
    fn activation_token_verifier_requires_exact_pair_paths() {
        let complete = arguments(&[
            "collection-authority",
            "verify-activation-artifact",
            "--input",
            "ci-in/collection-custody-activation/collection-custody-activation-token.json",
            "--report",
            "ci-in/collection-custody-activation/collection-custody-admission.json",
        ]);
        let parsed = parse_options(&complete).unwrap();
        assert_eq!(parsed.action, "verify-activation-artifact");
        for omitted in ["--input", "--report"] {
            let mut mutation = complete.clone();
            let index = mutation.iter().position(|value| value == omitted).unwrap();
            mutation.drain(index..=index + 1);
            assert!(run(&mutation).is_err());
        }
        let mut substituted = complete;
        let input = substituted
            .iter()
            .position(|value| value == "--input")
            .unwrap();
        substituted[input + 1] = OsString::from("ci-in/substituted/token.json");
        assert!(run(&substituted).is_err());
    }

    #[test]
    fn custody_review_preparation_requires_exact_typed_inputs_and_derives_review_id() {
        let complete = arguments(&[
            "collection-authority",
            "prepare-custody-review",
            "--package",
            "compat/collection-custody/payload",
            "--signature",
            "compat/collection-custody/signature",
            "--candidate-executable",
            "target/release/hell",
            "--reviewer",
            "custody-reviewer:alice",
            "--issued-at",
            "2026-08-12T00:00:00Z",
            "--output",
            "ci-out/custody-review",
        ]);
        let parsed = parse_options(&complete).unwrap();
        assert_eq!(parsed.reviewer.as_deref(), Some("custody-reviewer:alice"));
        assert_eq!(parsed.issued_at.as_deref(), Some("2026-08-12T00:00:00Z"));
        for omitted in [
            "--package",
            "--signature",
            "--candidate-executable",
            "--reviewer",
            "--issued-at",
            "--output",
        ] {
            let mut mutation = complete.clone();
            let index = mutation.iter().position(|value| value == omitted).unwrap();
            mutation.drain(index..=index + 1);
            assert!(run(&mutation).is_err());
        }
        let mut review_id = complete.clone();
        review_id.extend(arguments(&["--review-id", "forbidden"]));
        assert!(parse_options(&review_id).is_err());
        for forbidden in ["--integration-proof", "--report"] {
            let mut mutation = complete.clone();
            mutation.extend(arguments(&[forbidden, "forbidden"]));
            assert!(run(&mutation).is_err());
        }
    }
}
