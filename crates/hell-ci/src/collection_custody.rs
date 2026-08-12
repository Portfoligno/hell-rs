//! Durable, content-addressed custody for the collection authority campaign.
//!
//! The compact package is an attested transformation. It deliberately does
//! not claim that the expired provider ZIPs can be replayed from the package.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use hell_builtins::ClaimPlatform;
use hell_testkit::{
    CollectionBlackBoxShard, CollectionCompletion, CollectionDependencyAuthority,
    CollectionNativeBuildAuthority, CollectionOracleSubject, Digest,
    canonical_process_status_bytes, sha256_bytes, sha256_file,
};

const RECORD_HEADER: &str = "platform\tcaseId\toperation\tpath\tprofile\tsourceSha256\targumentsSha256\tenvironmentSha256\tstdinSha256\texecutionInputSha256\tdescriptorSha256\ttargetBuiltin\tinstanceTarget\tcomparatorContractSha256\tsourceAuthorityManifestSha256\texpectedTypedResultSha256\texpectedCompletion\toracleSubject\toracleSourceCommit\toracleExecutableSha256\toracleReceiptSha256\toracleAttestationSha256\tproviderRepositoryId\tproviderRunId\tproviderRunAttempt\tproviderArtifactId\tproviderWorkflowRef\tproviderEvent\tproviderCampaignRootSha256\toracleBuildRecordSha256\tdependencyAuthority\tbundleSha256\toracleObservationSha256\tcandidateObservationSha256\toracleStdoutSha256\toracleStderrSha256\toracleStatusSha256\tcandidateStdoutSha256\tcandidateStderrSha256\tcandidateStatusSha256\tcandidateTypedResultSha256\tcandidateComparatorTraceSha256\toracleCompletion\tcandidateCompletion\tcandidateCommit\tcandidateExecutableSha256\tstdinBlobSha256\toracleStatusBlobSha256\tcandidateStatusBlobSha256\tcandidateTypedBytesSha256\toracleTypedBytesSha256\tcandidateResourceAuditSha256\trecordLeafSha256";
const RECORD_FIELD_COUNT: usize = 53;
const EXACT_RECORD_COUNT: usize = 3_573;
const EXACT_TRANSFORMATION_COUNT: usize = 3_576;
const PACKAGE_DOMAIN: &str = "hell-collection-durable-custody-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedCollectionCustodyCore {
    pub(crate) payload_merkle_root: Digest,
    pub(crate) subject_sha256: Digest,
    pub(crate) candidate_commit: String,
    pub(crate) provider_head: String,
    pub(crate) repository_id: u64,
    pub(crate) run_id: u64,
    pub(crate) run_attempt: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CollectionCustodyReplay {
    pub(crate) current_candidate_commit: String,
    pub(crate) candidate_executable_sha256: Digest,
    pub(crate) replay_root_sha256: Digest,
    pub(crate) map_cases: usize,
    pub(crate) set_cases: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct VerifyCustodyInput<'a> {
    pub(crate) package: &'a Path,
    pub(crate) signature: &'a Path,
    pub(crate) candidate_executable: &'a Path,
    pub(crate) integration_proof: &'a Path,
    pub(crate) integration_review: &'a Path,
    pub(crate) worm_custody: Option<&'a Path>,
    pub(crate) report: &'a Path,
}

#[derive(Clone, Copy)]
pub(crate) struct PrepareWormCustodyInput<'a> {
    pub(crate) package: &'a Path,
    pub(crate) signature: &'a Path,
    pub(crate) candidate_executable: &'a Path,
    pub(crate) integration_proof: &'a Path,
    pub(crate) integration_review: &'a Path,
    pub(crate) output: &'a Path,
}

#[derive(Clone, Copy)]
pub(crate) struct PrepareCustodyReviewInput<'a> {
    pub(crate) package: &'a Path,
    pub(crate) signature: &'a Path,
    pub(crate) candidate_executable: &'a Path,
    pub(crate) reviewer: &'a str,
    pub(crate) issued_at: &'a str,
    pub(crate) output: &'a Path,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedActivationPreparationToken {
    pub(crate) candidate_commit: String,
    pub(crate) current_candidate_commit: String,
    pub(crate) payload_merkle_root: String,
    pub(crate) worm_custody_identity_sha256: String,
    pub(crate) token_sha256: String,
}

#[derive(Clone, Copy)]
pub(crate) struct PrepareActivationInput<'a> {
    pub(crate) artifact: &'a Path,
    pub(crate) output: &'a Path,
    pub(crate) run_id: u64,
    pub(crate) run_attempt: u64,
    pub(crate) artifact_id: u64,
    pub(crate) expected_directory_sha256: &'a str,
    pub(crate) expected_archive_sha256: &'a str,
}

const DORMANT_ACTIVATION_MANIFEST: &[u8] = concat!(
    "schema_version = 1\n",
    "domain = \"hell.collection-activation.v1\"\n",
    "scopes = [\"Map.adjust|pure-runtime|upstream|linux,macos,windows\", \"Map.delete|pure-runtime|upstream|linux,macos,windows\", \"Map.fromList|pure-runtime|upstream|linux,macos,windows\", \"Map.insert|pure-runtime|upstream|linux,macos,windows\", \"Map.insertWith|pure-runtime|upstream|linux,macos,windows\", \"Map.lookup|pure-runtime|upstream|linux,macos,windows\", \"Map.unionWith|pure-runtime|upstream|linux,macos,windows\", \"Set.delete|pure-runtime|upstream|linux,macos,windows\", \"Set.difference|pure-runtime|upstream|linux,macos,windows\", \"Set.fromList|pure-runtime|upstream|linux,macos,windows\", \"Set.insert|pure-runtime|upstream|linux,macos,windows\", \"Set.intersection|pure-runtime|upstream|linux,macos,windows\", \"Set.member|pure-runtime|upstream|linux,macos,windows\", \"Set.union|pure-runtime|upstream|linux,macos,windows\"]\n",
    "fresh_collection_required = true\n",
    "map712 = false\n",
    "set479 = false\n",
)
.as_bytes();
const ACTIVE_ACTIVATION_MANIFEST: &[u8] = concat!(
    "schema_version = 1\n",
    "domain = \"hell.collection-activation.v1\"\n",
    "scopes = [\"Map.adjust|pure-runtime|upstream|linux,macos,windows\", \"Map.delete|pure-runtime|upstream|linux,macos,windows\", \"Map.fromList|pure-runtime|upstream|linux,macos,windows\", \"Map.insert|pure-runtime|upstream|linux,macos,windows\", \"Map.insertWith|pure-runtime|upstream|linux,macos,windows\", \"Map.lookup|pure-runtime|upstream|linux,macos,windows\", \"Map.unionWith|pure-runtime|upstream|linux,macos,windows\", \"Set.delete|pure-runtime|upstream|linux,macos,windows\", \"Set.difference|pure-runtime|upstream|linux,macos,windows\", \"Set.fromList|pure-runtime|upstream|linux,macos,windows\", \"Set.insert|pure-runtime|upstream|linux,macos,windows\", \"Set.intersection|pure-runtime|upstream|linux,macos,windows\", \"Set.member|pure-runtime|upstream|linux,macos,windows\", \"Set.union|pure-runtime|upstream|linux,macos,windows\"]\n",
    "fresh_collection_required = true\n",
    "map712 = true\n",
    "set479 = true\n",
)
.as_bytes();

pub(crate) fn prepare_activation(
    root: &Path,
    input: &PrepareActivationInput<'_>,
) -> Result<(), String> {
    let artifact_relative = canonical_checkout_relative(root, input.artifact)?;
    let output_relative = canonical_checkout_relative(root, input.output)?;
    if artifact_relative != Path::new("ci-in/collection-custody-activation")
        || output_relative != Path::new("ci-out/collection-activation-proposal")
        || input.run_id == 0
        || input.run_attempt == 0
        || input.artifact_id == 0
    {
        return Err(
            "collection activation preparation paths or provider IDs are not canonical".to_owned(),
        );
    }
    Digest::from_hex(input.expected_directory_sha256)
        .map_err(|_| "collection activation directory digest is invalid".to_owned())?;
    Digest::from_hex(input.expected_archive_sha256)
        .map_err(|_| "collection activation archive digest is invalid".to_owned())?;
    let artifact = root.join(artifact_relative);
    let report = artifact.join("collection-custody-admission.json");
    let token = artifact.join("collection-custody-activation-token.json");
    let verified = verify_activation_preparation_token(&report, &token)?;
    let head = current_head(root)?;
    if head != verified.current_candidate_commit {
        return Err(
            "collection activation base HEAD differs from admitted current candidate".to_owned(),
        );
    }
    require_clean_activation_base(root)?;
    if read_file(&root.join("compat/collection-activation.toml"))? != DORMANT_ACTIVATION_MANIFEST {
        return Err("collection activation base is not exactly dormant".to_owned());
    }
    let output = root.join(output_relative);
    if fs::symlink_metadata(&output).is_ok() {
        return Err("collection activation proposal output already exists".to_owned());
    }
    let selection_directory = output.join("provider-selection");
    let artifact_name = format!(
        "collection-custody-admission-{}-{}",
        input.run_id, input.run_attempt
    );
    let selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root,
            input_directory: &artifact,
            output_directory: &selection_directory,
            artifact_name: &artifact_name,
            workflow_path: ".github/workflows/collection-custody-integration.yml",
            event_name: "workflow_dispatch",
            run_id: input.run_id,
            run_attempt: input.run_attempt,
            artifact_id: input.artifact_id,
            provider_head: &head,
            candidate: &head,
            expected_directory_sha256: input.expected_directory_sha256,
            expected_archive_sha256: input.expected_archive_sha256,
        },
    )?;
    let selection_json = crate::assurance::parse_json(&selection)?;
    let selection_fields = selection_json.object()?;
    if selection_fields
        .get("providerArchiveSha256")
        .ok_or_else(|| "activation provider selection omits archive digest".to_owned())?
        .string()?
        != input.expected_archive_sha256
    {
        return Err("activation provider archive digest differs from dispatch".to_owned());
    }
    write_file(
        &selection_directory.join("provider-selection.json"),
        selection.as_bytes(),
    )?;
    let claims = render_active_collection_claims(&hell_testkit::reviewed_collection_cases()?)?;
    let (catalog_lock, epoch_lock) =
        crate::catalog_lock::prospective_collection_activation_locks_with_claims(
            root,
            ACTIVE_ACTIVATION_MANIFEST,
            &claims,
        )?;
    write_activation_proposal(&WriteActivationProposal {
        root,
        output: &output,
        verified: &verified,
        head: &head,
        input,
        selection: &selection,
        claims: &claims,
        catalog_lock: &catalog_lock,
        epoch_lock: &epoch_lock,
    })
}

#[cfg(test)]
pub(crate) fn write_activation_admission_test_fixture(
    root: &Path,
    candidate: &str,
) -> Result<PathBuf, String> {
    let digest = sha256_bytes(b"activation end-to-end fixture");
    let verified = VerifiedAdmissionAuthority {
        core: VerifiedCollectionCustodyCore {
            payload_merkle_root: digest,
            subject_sha256: digest,
            candidate_commit: candidate.to_owned(),
            provider_head: candidate.to_owned(),
            repository_id: 1_327_351_238,
            run_id: 2,
            run_attempt: 3,
        },
        package_root: digest,
        signature_root: digest,
        revocations: digest,
        review_governance: ReviewGovernance {
            allowed_signers: digest,
            review_revocations: digest,
            surveillance_policy: digest,
            trust_roots: digest,
        },
        replay: CollectionCustodyReplay {
            current_candidate_commit: candidate.to_owned(),
            candidate_executable_sha256: digest,
            replay_root_sha256: digest,
            map_cases: 712,
            set_cases: 479,
        },
        integration: VerifiedIntegrationReview {
            proof_sha256: digest,
            review_sha256: digest,
            subject: "custody-reviewer:activation-e2e".to_owned(),
            signer_fingerprint: digest.hex(),
        },
        custody_policy: digest,
    };
    let report = render_admission_report(&verified, Some(digest))?;
    let token = render_activation_preparation_token(&verified, digest, &report)?;
    let artifact = root.join("ci-in/collection-custody-activation");
    fs::create_dir_all(&artifact)
        .map_err(|error| format!("cannot create activation test fixture: {error}"))?;
    for (name, bytes) in [
        ("collection-custody-admission.json", report.as_bytes()),
        ("collection-custody-activation-token.json", token.as_slice()),
    ] {
        write_file(&artifact.join(name), bytes)?;
        write_file(
            &artifact.join(format!("{name}.sha256")),
            format!("{}  {name}\n", sha256_bytes(bytes).hex()).as_bytes(),
        )?;
    }
    Ok(artifact)
}

pub(crate) fn verify_activation_proposal(root: &Path, input: &Path) -> Result<String, String> {
    let relative = canonical_checkout_relative(root, input)?;
    if relative != Path::new("ci-in/collection-activation-proposal") {
        return Err("collection activation proposal input path is not canonical".to_owned());
    }
    let input = root.join(relative);
    verify_activation_proposal_directory(root, &input)
}

fn verify_activation_proposal_directory(root: &Path, input: &Path) -> Result<String, String> {
    require_activation_proposal_inventory(input)?;
    let manifest = read_file(&input.join("proposal-manifest.tsv"))?;
    if read_file(&input.join("root.sha256"))?
        != format!("{}\n", sha256_bytes(&manifest).hex()).as_bytes()
    {
        return Err("collection activation proposal root digest is invalid".to_owned());
    }
    verify_activation_manifest_entries(input, &manifest)?;
    let retained_admission = verify_activation_preparation_token(
        &input.join("custody-admission/collection-custody-admission.json"),
        &input.join("custody-admission/collection-custody-activation-token.json"),
    )?;
    if read_file(&input.join("tree/compat/collection-activation.toml"))?
        != ACTIVE_ACTIVATION_MANIFEST
    {
        return Err("collection activation proposal manifest is not exactly active".to_owned());
    }
    let claims = read_file(&input.join("tree/compat/collection-activation-claims.json"))?;
    if claims != render_active_collection_claims(&hell_testkit::reviewed_collection_cases()?)? {
        return Err(
            "collection activation proposal claims are not the exact reviewed scopes".to_owned(),
        );
    }
    let proposal_bytes = read_file(&input.join("activation-proposal.json"))?;
    let proposal = crate::assurance::parse_json(
        std::str::from_utf8(&proposal_bytes)
            .map_err(|_| "collection activation proposal is not UTF-8".to_owned())?,
    )?;
    if crate::assurance::canonical_json_bytes(&proposal)? != proposal_bytes {
        return Err("collection activation proposal is not canonical JSON".to_owned());
    }
    verify_activation_proposal_document(
        root,
        input,
        proposal.object()?,
        &proposal_bytes,
        &claims,
        &retained_admission,
    )?;
    Ok(sha256_bytes(&proposal_bytes).hex())
}

fn verify_activation_proposal_document(
    root: &Path,
    input: &Path,
    fields: &BTreeMap<String, crate::assurance::JsonValue>,
    proposal_bytes: &[u8],
    claims: &[u8],
    retained: &VerifiedActivationPreparationToken,
) -> Result<(), String> {
    require_activation_proposal_keys(fields)?;
    let member = |key| {
        fields
            .get(key)
            .ok_or_else(|| format!("collection activation proposal omits {key}"))
    };
    if member("domain")?.string()? != "hell.collection-activation.proposal.v1"
        || member("state")?.string()? != "prepared-for-protected-human-review"
        || member("worktreeMutated")?.boolean()?
        || member("activationAuthority")?.boolean()?
        || member("promotionAuthority")?.boolean()?
    {
        return Err("collection activation proposal claims unsupported authority".to_owned());
    }
    let head = current_head(root)?;
    let (_, current_epoch) = crate::assurance::epoch(root)?;
    if member("baseCandidateCommit")?.string()? != head
        || member("baseAssuranceEpochSha256")?.string()? != current_epoch.hex()
    {
        return Err("collection activation proposal base identity differs".to_owned());
    }
    verify_activation_proposal_provider(root, input, fields, &head, retained)?;
    verify_activation_proposal_content(root, input, fields, proposal_bytes, claims, &head, retained)
}

fn require_activation_proposal_keys(
    fields: &BTreeMap<String, crate::assurance::JsonValue>,
) -> Result<(), String> {
    crate::assurance::require_exact_json_keys(
        fields,
        &[
            "activationAuthority",
            "activationClaimsSha256",
            "activationManifestSha256",
            "activationTokenSha256",
            "baseAssuranceEpochSha256",
            "baseCandidateCommit",
            "corpusMappingSha256",
            "coverageDeltaSha256",
            "domain",
            "historicalCollectionCandidateCommit",
            "payloadMerkleRoot",
            "promotionAuthority",
            "prospectiveCatalogLockSha256",
            "prospectiveEpochLockSha256",
            "providerArchiveSha256",
            "providerArtifactId",
            "providerDirectorySha256",
            "providerRunAttempt",
            "providerRunId",
            "providerSelectionSha256",
            "reviewedArtifacts",
            "schemaVersion",
            "state",
            "worktreeMutated",
            "wormCustodyIdentitySha256",
        ],
    )
}

fn verify_activation_proposal_provider(
    root: &Path,
    input: &Path,
    fields: &BTreeMap<String, crate::assurance::JsonValue>,
    head: &str,
    retained: &VerifiedActivationPreparationToken,
) -> Result<(), String> {
    let selection = crate::assurance::verify_retained_collection_activation_selection(
        root,
        &input.join("provider-selection"),
        &format!(
            "collection-custody-admission-{}-{}",
            fields["providerRunId"].number()?,
            fields["providerRunAttempt"].number()?
        ),
        head,
    )?;
    if fields["providerSelectionSha256"].string()?
        != sha256_file(&input.join("provider-selection/provider-selection.json"))
            .map_err(|error| error.to_string())?
            .hex()
        || fields["providerRunId"].number()? != selection["providerRunId"].number()?
        || fields["providerRunAttempt"].number()? != selection["providerRunAttempt"].number()?
        || fields["providerArtifactId"].number()? != selection["providerArtifactId"].number()?
        || fields["providerArchiveSha256"].string()?
            != selection["providerArchiveSha256"].string()?
        || fields["providerDirectorySha256"].string()? != selection["directorySha256"].string()?
        || fields["activationTokenSha256"].string()? != retained.token_sha256
        || fields["wormCustodyIdentitySha256"].string()? != retained.worm_custody_identity_sha256
        || fields["baseCandidateCommit"].string()? != retained.current_candidate_commit
        || fields["historicalCollectionCandidateCommit"].string()? != retained.candidate_commit
        || fields["payloadMerkleRoot"].string()? != retained.payload_merkle_root
    {
        return Err("collection activation proposal provider binding differs".to_owned());
    }
    Ok(())
}

fn verify_activation_proposal_content(
    root: &Path,
    input: &Path,
    fields: &BTreeMap<String, crate::assurance::JsonValue>,
    proposal_bytes: &[u8],
    claims: &[u8],
    head: &str,
    retained: &VerifiedActivationPreparationToken,
) -> Result<(), String> {
    let (catalog, epoch) =
        crate::catalog_lock::prospective_collection_activation_locks_with_claims(
            root,
            ACTIVE_ACTIVATION_MANIFEST,
            claims,
        )?;
    if read_file(&input.join("tree/compat/locks/catalog-digests.json"))? != catalog.as_bytes()
        || read_file(&input.join("tree/compat/locks/assurance-epoch.json"))? != epoch.as_bytes()
    {
        return Err("collection activation proposal prospective locks do not reproduce".to_owned());
    }
    for (field, path) in [
        (
            "activationManifestSha256",
            "tree/compat/collection-activation.toml",
        ),
        (
            "activationClaimsSha256",
            "tree/compat/collection-activation-claims.json",
        ),
        (
            "prospectiveCatalogLockSha256",
            "tree/compat/locks/catalog-digests.json",
        ),
        (
            "prospectiveEpochLockSha256",
            "tree/compat/locks/assurance-epoch.json",
        ),
        ("corpusMappingSha256", "corpus-mapping.json"),
        ("coverageDeltaSha256", "coverage-delta.json"),
    ] {
        if fields[field].string()?
            != sha256_file(&input.join(path))
                .map_err(|error| error.to_string())?
                .hex()
        {
            return Err(format!("collection activation proposal {field} differs"));
        }
    }
    verify_activation_mapping(root, &input.join("corpus-mapping.json"), head)?;
    verify_activation_coverage(&input.join("coverage-delta.json"))?;
    verify_supplemental_coverage_delta(&hell_testkit::reviewed_collection_cases()?)?;
    verify_activation_proposal_artifacts(input, fields, retained)?;
    verify_activation_authorship(
        &input.join("authorship-subject.json"),
        proposal_bytes,
        head,
        &fields["reviewedArtifacts"],
    )
}

fn verify_activation_proposal_artifacts(
    input: &Path,
    fields: &BTreeMap<String, crate::assurance::JsonValue>,
    retained: &VerifiedActivationPreparationToken,
) -> Result<(), String> {
    let selection = read_file(&input.join("provider-selection/provider-selection.json"))?;
    let expected = activation_review_artifacts(
        input,
        std::str::from_utf8(&selection)
            .map_err(|_| "activation provider selection is not UTF-8".to_owned())?,
        retained,
        &PrepareActivationInput {
            artifact: Path::new("custody-admission"),
            output: Path::new("."),
            run_id: fields["providerRunId"].number()?,
            run_attempt: fields["providerRunAttempt"].number()?,
            artifact_id: fields["providerArtifactId"].number()?,
            expected_directory_sha256: fields["providerDirectorySha256"].string()?,
            expected_archive_sha256: fields["providerArchiveSha256"].string()?,
        },
    )?;
    let array = fields["reviewedArtifacts"].array()?;
    let observed = array
        .iter()
        .map(|value| value.string().map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed.len() != array.len() || observed != expected {
        return Err("collection activation proposal reviewed artifact set differs".to_owned());
    }
    Ok(())
}

pub(crate) fn verify_activation_proposal_source(
    root: &Path,
    input: &Path,
    run_id: u64,
    run_attempt: u64,
    artifact_id: u64,
    archive_sha256: &str,
) -> Result<String, String> {
    let digest = verify_activation_proposal(root, input)?;
    Digest::from_hex(archive_sha256)
        .map_err(|_| "collection activation source archive digest is invalid".to_owned())?;
    let input = root.join(canonical_checkout_relative(root, input)?);
    let output = root.join("ci-out/collection-activation-review-subject");
    if fs::symlink_metadata(&output).is_ok() {
        return Err("collection activation review subject already exists".to_owned());
    }
    let selection_directory = output.join("source-selection");
    let directory_sha256 = crate::custody_ops::verified_directory_digest(&input)?;
    let artifact_name = format!("collection-activation-proposal-{run_id}-{run_attempt}");
    let selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root,
            input_directory: &input,
            output_directory: &selection_directory,
            artifact_name: &artifact_name,
            workflow_path: ".github/workflows/collection-activation-preparation.yml",
            event_name: "workflow_dispatch",
            run_id,
            run_attempt,
            artifact_id,
            provider_head: &current_head(root)?,
            candidate: &current_head(root)?,
            expected_directory_sha256: &directory_sha256,
            expected_archive_sha256: archive_sha256,
        },
    )?;
    write_file(
        &selection_directory.join("provider-selection.json"),
        selection.as_bytes(),
    )?;
    let selection_document = crate::assurance::parse_json(&selection)?;
    if selection_document.object()?["providerArchiveSha256"].string()? != archive_sha256 {
        return Err("collection activation outer provider archive differs".to_owned());
    }
    copy_regular_tree(&input, &output.join("proposal"))?;
    seal_activation_review_subject(root, &output, &digest, &selection)?;
    Ok(digest)
}

fn seal_activation_review_subject(
    root: &Path,
    output: &Path,
    proposal_sha256: &str,
    selection: &str,
) -> Result<(), String> {
    let selection_document = crate::assurance::parse_json(selection)?;
    let selection_fields = selection_document.object()?;
    let member = |key| {
        selection_fields
            .get(key)
            .ok_or_else(|| format!("activation outer selection omits {key}"))
    };
    let subject = crate::assurance::JsonValue::Object(BTreeMap::from([
        (
            "activationAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "baseCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(current_head(root)?),
        ),
        (
            "domain".to_owned(),
            crate::assurance::JsonValue::String(
                "hell.collection-activation.review-subject.v1".to_owned(),
            ),
        ),
        (
            "outerArchiveSha256".to_owned(),
            crate::assurance::JsonValue::String(
                member("providerArchiveSha256")?.string()?.to_owned(),
            ),
        ),
        (
            "outerArtifactId".to_owned(),
            member("providerArtifactId")?.clone(),
        ),
        (
            "outerDirectorySha256".to_owned(),
            crate::assurance::JsonValue::String(member("directorySha256")?.string()?.to_owned()),
        ),
        (
            "outerRunAttempt".to_owned(),
            member("providerRunAttempt")?.clone(),
        ),
        ("outerRunId".to_owned(), member("providerRunId")?.clone()),
        (
            "outerSelectionSha256".to_owned(),
            crate::assurance::JsonValue::String(sha256_bytes(selection.as_bytes()).hex()),
        ),
        (
            "promotionAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "proposalSha256".to_owned(),
            crate::assurance::JsonValue::String(proposal_sha256.to_owned()),
        ),
        (
            "schemaVersion".to_owned(),
            crate::assurance::JsonValue::Number(1),
        ),
        (
            "state".to_owned(),
            crate::assurance::JsonValue::String("sealed-for-distinct-protected-reviews".to_owned()),
        ),
    ]));
    write_file(
        &output.join("review-subject.json"),
        &crate::assurance::canonical_json_bytes(&subject)?,
    )?;
    seal_regular_tree(output, "review-subject-manifest.tsv", "root.sha256")
}

fn seal_regular_tree(output: &Path, manifest_name: &str, root_name: &str) -> Result<(), String> {
    let mut manifest = String::from("sha256\tbytes\tpath\n");
    for path in collect_regular_relative_files(output, output)? {
        if path == manifest_name || path == root_name {
            return Err("sealed activation subject reserved path already exists".to_owned());
        }
        let bytes = read_file(&output.join(&path))?;
        writeln!(
            manifest,
            "{}\t{}\t{path}",
            sha256_bytes(&bytes).hex(),
            bytes.len()
        )
        .expect("writing to String cannot fail");
    }
    write_file(&output.join(manifest_name), manifest.as_bytes())?;
    write_file(
        &output.join(root_name),
        format!("{}\n", sha256_bytes(manifest.as_bytes()).hex()).as_bytes(),
    )
}

pub(crate) fn verify_activation_review_subject(
    root: &Path,
    input: &Path,
) -> Result<PathBuf, String> {
    let relative = canonical_checkout_relative(root, input)?;
    if relative != Path::new("ci-in/collection-activation-review-subject") {
        return Err("collection activation review subject path is not canonical".to_owned());
    }
    let input = root.join(relative);
    let metadata = fs::symlink_metadata(&input)
        .map_err(|error| format!("cannot inspect activation review subject: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("collection activation review subject is not a real directory".to_owned());
    }
    let manifest_path = input.join("review-subject-manifest.tsv");
    let root_path = input.join("root.sha256");
    let observed = collect_regular_relative_files(&input, &input)?;
    let manifest = read_file(&manifest_path)?;
    if read_file(&root_path)? != format!("{}\n", sha256_bytes(&manifest).hex()).as_bytes() {
        return Err("collection activation review subject root differs".to_owned());
    }
    verify_sealed_regular_tree_manifest(&input, &manifest, &observed)?;
    let proposal = input.join("proposal");
    let proposal_sha256 = verify_activation_proposal_directory(root, &proposal)?;
    let selection_path = input.join("source-selection/provider-selection.json");
    let selection = read_file(&selection_path)?;
    let selection_document = crate::assurance::parse_json(
        std::str::from_utf8(&selection)
            .map_err(|_| "activation outer selection is not UTF-8".to_owned())?,
    )?;
    let selection_fields = selection_document.object()?;
    let retained_selection =
        crate::assurance::verify_retained_activation_proposal_source_selection(
            root,
            &proposal,
            &input.join("source-selection"),
            &current_head(root)?,
        )?;
    let subject_bytes = read_file(&input.join("review-subject.json"))?;
    let subject = crate::assurance::parse_json(
        std::str::from_utf8(&subject_bytes)
            .map_err(|_| "activation review subject is not UTF-8".to_owned())?,
    )?;
    if crate::assurance::canonical_json_bytes(&subject)? != subject_bytes {
        return Err("activation review subject is not canonical JSON".to_owned());
    }
    let fields = subject.object()?;
    crate::assurance::require_exact_json_keys(
        fields,
        &[
            "activationAuthority",
            "baseCandidateCommit",
            "domain",
            "outerArchiveSha256",
            "outerArtifactId",
            "outerDirectorySha256",
            "outerRunAttempt",
            "outerRunId",
            "outerSelectionSha256",
            "promotionAuthority",
            "proposalSha256",
            "schemaVersion",
            "state",
        ],
    )?;
    let member = |key| {
        fields
            .get(key)
            .ok_or_else(|| format!("activation review subject omits {key}"))
    };
    if member("schemaVersion")?.number()? != 1
        || member("domain")?.string()? != "hell.collection-activation.review-subject.v1"
        || member("state")?.string()? != "sealed-for-distinct-protected-reviews"
        || member("activationAuthority")?.boolean()?
        || member("promotionAuthority")?.boolean()?
        || member("baseCandidateCommit")?.string()? != current_head(root)?
        || member("proposalSha256")?.string()? != proposal_sha256
        || member("outerSelectionSha256")?.string()? != sha256_bytes(&selection).hex()
        || member("outerRunId")?.number()? != selection_fields["providerRunId"].number()?
        || member("outerRunAttempt")?.number()?
            != selection_fields["providerRunAttempt"].number()?
        || member("outerArtifactId")?.number()?
            != selection_fields["providerArtifactId"].number()?
        || member("outerArchiveSha256")?.string()?
            != selection_fields["providerArchiveSha256"].string()?
        || member("outerDirectorySha256")?.string()?
            != selection_fields["directorySha256"].string()?
        || retained_selection != *selection_fields
    {
        return Err("activation review subject binding differs".to_owned());
    }
    Ok(proposal)
}

pub(crate) fn activation_review_subject_artifacts(
    root: &Path,
    subject: &Path,
) -> Result<BTreeSet<String>, String> {
    let proposal = verify_activation_review_subject(root, subject)?;
    let subject = root.join(canonical_checkout_relative(root, subject)?);
    let proposal_bytes = read_file(&proposal.join("activation-proposal.json"))?;
    let proposal_document = crate::assurance::parse_json(
        std::str::from_utf8(&proposal_bytes)
            .map_err(|_| "activation proposal is not UTF-8".to_owned())?,
    )?;
    let mut artifacts = proposal_document.object()?["reviewedArtifacts"]
        .array()?
        .iter()
        .map(|value| value.string().map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for path in [
        proposal.join("activation-proposal.json"),
        proposal.join("authorship-subject.json"),
        proposal.join("proposal-manifest.tsv"),
        proposal.join("root.sha256"),
        subject.join("review-subject.json"),
        subject.join("review-subject-manifest.tsv"),
        subject.join("root.sha256"),
        subject.join("source-selection/provider-selection.json"),
    ] {
        if !artifacts.insert(sha256_file(&path).map_err(|error| error.to_string())?.hex()) {
            return Err("activation review subject artifacts duplicate a root".to_owned());
        }
    }
    Ok(artifacts)
}

pub(crate) fn verify_activation_review_subject_selection(
    root: &Path,
    subject: &Path,
    directory_sha256: &str,
) -> Result<(), String> {
    Digest::from_hex(directory_sha256)
        .map_err(|_| "activation review subject directory digest is invalid".to_owned())?;
    verify_activation_review_subject(root, subject)?;
    let subject = root.join(canonical_checkout_relative(root, subject)?);
    let observed = crate::custody_ops::verified_directory_digest(&subject)?;
    if observed != directory_sha256 {
        return Err("activation review subject immutable selection differs".to_owned());
    }
    Ok(())
}

fn verify_sealed_regular_tree_manifest(
    input: &Path,
    manifest: &[u8],
    observed: &BTreeSet<String>,
) -> Result<(), String> {
    let text = std::str::from_utf8(manifest)
        .map_err(|_| "sealed activation subject manifest is not UTF-8".to_owned())?;
    let mut lines = text.lines();
    if lines.next() != Some("sha256\tbytes\tpath") {
        return Err("sealed activation subject manifest header differs".to_owned());
    }
    let mut listed = BTreeSet::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        let [digest, size, path] = fields.as_slice() else {
            return Err("sealed activation subject manifest row is malformed".to_owned());
        };
        Digest::from_hex(digest).map_err(str::to_owned)?;
        let size = size
            .parse::<usize>()
            .map_err(|_| "sealed activation subject size is invalid".to_owned())?;
        if path.starts_with('/') || path.split('/').any(|part| part.is_empty() || part == "..") {
            return Err("sealed activation subject path is invalid".to_owned());
        }
        let bytes = read_file(&input.join(path))?;
        if bytes.len() != size
            || sha256_bytes(&bytes).hex() != *digest
            || !listed.insert((*path).to_owned())
        {
            return Err("sealed activation subject manifest entry differs".to_owned());
        }
    }
    let mut expected = observed.clone();
    expected.remove("review-subject-manifest.tsv");
    expected.remove("root.sha256");
    if listed != expected {
        return Err("sealed activation subject inventory differs".to_owned());
    }
    Ok(())
}

pub(crate) fn finalize_activation(
    root: &Path,
    input: &Path,
    author: &Path,
    review: &Path,
    output: &Path,
) -> Result<(), String> {
    let input_relative = canonical_checkout_relative(root, input)?;
    let author_relative = canonical_checkout_relative(root, author)?;
    let review_relative = canonical_checkout_relative(root, review)?;
    let output_relative = canonical_checkout_relative(root, output)?;
    if input_relative != Path::new("ci-in/collection-activation-review-subject")
        || author_relative != Path::new("ci-in/collection-activation-review/claim-author")
        || review_relative != Path::new("ci-in/collection-activation-review/claim-reviewer")
        || output_relative != Path::new("ci-out/collection-activation-tree")
    {
        return Err("collection activation finalization paths are not canonical".to_owned());
    }
    let review_subject_root = root.join(input_relative);
    let proposal_root = verify_activation_review_subject(root, input)?;
    let proposal_digest = verify_activation_proposal_directory(root, &proposal_root)?;
    let proposal_bytes = read_file(&proposal_root.join("activation-proposal.json"))?;
    let proposal = crate::assurance::parse_json(
        std::str::from_utf8(&proposal_bytes)
            .map_err(|_| "collection activation proposal is not UTF-8".to_owned())?,
    )?;
    let fields = proposal.object()?;
    let string = |key| {
        fields
            .get(key)
            .ok_or_else(|| format!("collection activation proposal omits {key}"))?
            .string()
    };
    if current_head(root)? != string("baseCandidateCommit")? {
        return Err(
            "collection activation finalization checkout differs from reviewed base".to_owned(),
        );
    }
    require_clean_activation_base(root)?;
    if read_file(&root.join("compat/collection-activation.toml"))? != DORMANT_ACTIVATION_MANIFEST
        || read_file(&root.join("compat/collection-activation-provenance.json"))?
            != b"{\"activationAuthority\":false,\"domain\":\"hell.collection-activation.provenance.v1\",\"freshCollectionRequired\":true,\"promotionAuthority\":false,\"schemaVersion\":1,\"state\":\"dormant-no-reviewed-activation\"}\n"
    {
        return Err("collection activation finalization base is not canonical dormant state".to_owned());
    }
    let author_package = root.join(author_relative);
    let reviewer_package = root.join(review_relative);
    let author = crate::assurance::verify_activation_review_package(
        root,
        &author_package,
        &review_subject_root.join("review-subject.json"),
        "claim-author",
    )?;
    let reviewer = crate::assurance::verify_activation_review_package(
        root,
        &reviewer_package,
        &review_subject_root.join("review-subject.json"),
        "claim-reviewer",
    )?;
    if author.subject == reviewer.subject
        || author.signer_fingerprint == reviewer.signer_fingerprint
    {
        return Err("collection activation author and reviewer are not independent".to_owned());
    }
    let provenance = render_activation_provenance(
        fields,
        &proposal_digest,
        &review_subject_root,
        &author,
        &reviewer,
    )?;
    let claims = read_file(&proposal_root.join("tree/compat/collection-activation-claims.json"))?;
    let (catalog, epoch) =
        crate::catalog_lock::prospective_collection_activation_locks_with_reviews(
            root,
            ACTIVE_ACTIVATION_MANIFEST,
            &claims,
            &provenance,
            &review_subject_root,
            &author_package,
            &reviewer_package,
        )?;
    write_final_activation_tree(
        root,
        output_relative.to_path_buf(),
        &claims,
        &provenance,
        &catalog,
        &epoch,
        &review_subject_root,
        &author_package,
        &reviewer_package,
    )
}

fn render_activation_provenance(
    fields: &BTreeMap<String, crate::assurance::JsonValue>,
    proposal_digest: &str,
    review_subject_root: &Path,
    author: &crate::assurance::VerifiedActivationReviewPackage,
    reviewer: &crate::assurance::VerifiedActivationReviewPackage,
) -> Result<Vec<u8>, String> {
    let mut provenance = activation_provenance_base_fields(fields, proposal_digest)?;
    provenance.extend(activation_extended_provenance_fields(review_subject_root)?);
    provenance.extend(activation_review_provenance_fields("Author", author));
    provenance.extend(activation_review_provenance_fields("Review", reviewer));
    provenance.extend([
        (
            "freshCollectionRequired".to_owned(),
            crate::assurance::JsonValue::Bool(true),
        ),
        (
            "activationAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "promotionAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
    ]);
    crate::assurance::canonical_json_bytes(&crate::assurance::JsonValue::Object(provenance))
}

fn activation_extended_provenance_fields(
    review_subject_root: &Path,
) -> Result<BTreeMap<String, crate::assurance::JsonValue>, String> {
    let proposal = review_subject_root.join("proposal");
    let (_, report) = read_canonical_activation_json(
        &proposal.join("custody-admission/collection-custody-admission.json"),
        "retained activation admission report",
    )?;
    let (_, subject) = read_canonical_activation_json(
        &review_subject_root.join("review-subject.json"),
        "retained activation review subject",
    )?;
    let string = |fields: &BTreeMap<String, crate::assurance::JsonValue>, key| {
        activation_field(fields, key, "retained provenance source")
            .and_then(crate::assurance::JsonValue::string)
            .map(str::to_owned)
    };
    Ok(BTreeMap::from([
        (
            "activationClaimsSha256".to_owned(),
            crate::assurance::JsonValue::String(
                sha256_file(&proposal.join("tree/compat/collection-activation-claims.json"))
                    .map_err(|error| error.to_string())?
                    .hex(),
            ),
        ),
        (
            "historicalCollectionCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(string(&report, "candidateCommit")?),
        ),
        (
            "integrationProofSha256".to_owned(),
            crate::assurance::JsonValue::String(string(&report, "integrationProofSha256")?),
        ),
        (
            "integrationReviewSha256".to_owned(),
            crate::assurance::JsonValue::String(string(&report, "integrationReviewSha256")?),
        ),
        ("mapCaseCount".to_owned(), report["mapCaseCount"].clone()),
        (
            "outerArchiveSha256".to_owned(),
            crate::assurance::JsonValue::String(string(&subject, "outerArchiveSha256")?),
        ),
        (
            "outerArtifactId".to_owned(),
            subject["outerArtifactId"].clone(),
        ),
        (
            "outerCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(string(&subject, "baseCandidateCommit")?),
        ),
        (
            "outerDirectorySha256".to_owned(),
            crate::assurance::JsonValue::String(string(&subject, "outerDirectorySha256")?),
        ),
        (
            "outerRunAttempt".to_owned(),
            subject["outerRunAttempt"].clone(),
        ),
        ("outerRunId".to_owned(), subject["outerRunId"].clone()),
        (
            "outerSelectionSha256".to_owned(),
            crate::assurance::JsonValue::String(string(&subject, "outerSelectionSha256")?),
        ),
        (
            "outerWorkflowPath".to_owned(),
            crate::assurance::JsonValue::String(
                ".github/workflows/collection-activation-preparation.yml".to_owned(),
            ),
        ),
        (
            "packageTreeSha256".to_owned(),
            crate::assurance::JsonValue::String(string(&report, "packageTreeSha256")?),
        ),
        (
            "payloadMerkleRoot".to_owned(),
            crate::assurance::JsonValue::String(string(&report, "payloadMerkleRoot")?),
        ),
        (
            "providerWorkflowPath".to_owned(),
            crate::assurance::JsonValue::String(
                ".github/workflows/collection-custody-integration.yml".to_owned(),
            ),
        ),
        (
            "replayCaseCount".to_owned(),
            report["replayCaseCount"].clone(),
        ),
        (
            "replayObservationRootSha256".to_owned(),
            crate::assurance::JsonValue::String(string(&report, "replayObservationRootSha256")?),
        ),
        ("setCaseCount".to_owned(), report["setCaseCount"].clone()),
        (
            "signatureTreeSha256".to_owned(),
            crate::assurance::JsonValue::String(string(&report, "signatureTreeSha256")?),
        ),
    ]))
}

fn activation_provenance_base_fields(
    fields: &BTreeMap<String, crate::assurance::JsonValue>,
    proposal_digest: &str,
) -> Result<BTreeMap<String, crate::assurance::JsonValue>, String> {
    let string = |key: &str| {
        fields
            .get(key)
            .ok_or_else(|| format!("collection activation proposal omits {key}"))?
            .string()
    };
    Ok(BTreeMap::from([
        (
            "schemaVersion".to_owned(),
            crate::assurance::JsonValue::Number(1),
        ),
        (
            "domain".to_owned(),
            crate::assurance::JsonValue::String(
                "hell.collection-activation.provenance.v1".to_owned(),
            ),
        ),
        (
            "state".to_owned(),
            crate::assurance::JsonValue::String(
                "reviewed-activation-requires-fresh-collection".to_owned(),
            ),
        ),
        (
            "baseCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(string("baseCandidateCommit")?.to_owned()),
        ),
        (
            "activationProposalSha256".to_owned(),
            crate::assurance::JsonValue::String(proposal_digest.to_owned()),
        ),
        (
            "activationTokenSha256".to_owned(),
            crate::assurance::JsonValue::String(string("activationTokenSha256")?.to_owned()),
        ),
        (
            "wormCustodyIdentitySha256".to_owned(),
            crate::assurance::JsonValue::String(string("wormCustodyIdentitySha256")?.to_owned()),
        ),
        ("providerRunId".to_owned(), fields["providerRunId"].clone()),
        (
            "providerRunAttempt".to_owned(),
            fields["providerRunAttempt"].clone(),
        ),
        (
            "providerArtifactId".to_owned(),
            fields["providerArtifactId"].clone(),
        ),
        (
            "providerArchiveSha256".to_owned(),
            crate::assurance::JsonValue::String(string("providerArchiveSha256")?.to_owned()),
        ),
        (
            "providerDirectorySha256".to_owned(),
            crate::assurance::JsonValue::String(string("providerDirectorySha256")?.to_owned()),
        ),
        (
            "providerSelectionSha256".to_owned(),
            crate::assurance::JsonValue::String(string("providerSelectionSha256")?.to_owned()),
        ),
        (
            "corpusMappingSha256".to_owned(),
            crate::assurance::JsonValue::String(string("corpusMappingSha256")?.to_owned()),
        ),
    ]))
}

fn activation_review_provenance_fields(
    label: &str,
    review: &crate::assurance::VerifiedActivationReviewPackage,
) -> [(String, crate::assurance::JsonValue); 5] {
    [
        (
            format!("activation{label}Sha256"),
            crate::assurance::JsonValue::String(sha256_bytes(&review.envelope).hex()),
        ),
        (
            format!("activation{label}Subject"),
            crate::assurance::JsonValue::String(review.subject.clone()),
        ),
        (
            format!("activation{label}SignerFingerprint"),
            crate::assurance::JsonValue::String(review.signer_fingerprint.clone()),
        ),
        (
            format!("activation{label}AuthorizationSha256"),
            crate::assurance::JsonValue::String(review.authorization_sha256.clone()),
        ),
        (
            format!("activation{label}PacketSha256"),
            crate::assurance::JsonValue::String(review.packet_sha256.clone()),
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn write_final_activation_tree(
    root: &Path,
    output_relative: PathBuf,
    claims: &[u8],
    provenance: &[u8],
    catalog: &str,
    epoch: &str,
    review_subject_root: &Path,
    author_package: &Path,
    reviewer_package: &Path,
) -> Result<(), String> {
    let output = root.join(output_relative);
    if fs::symlink_metadata(&output).is_ok() {
        return Err("collection activation final tree already exists".to_owned());
    }
    fs::create_dir_all(output.join("compat/locks"))
        .map_err(|error| format!("cannot create collection activation final tree: {error}"))?;
    write_file(
        &output.join("compat/collection-activation.toml"),
        ACTIVE_ACTIVATION_MANIFEST,
    )?;
    write_file(
        &output.join("compat/collection-activation-claims.json"),
        claims,
    )?;
    write_file(
        &output.join("compat/collection-activation-provenance.json"),
        provenance,
    )?;
    fs::create_dir_all(output.join("compat/collection-activation-reviews"))
        .map_err(|error| format!("cannot create retained activation reviews: {error}"))?;
    copy_regular_tree(
        review_subject_root,
        &output.join("compat/collection-activation-review-subject"),
    )?;
    copy_regular_tree(
        author_package,
        &output.join("compat/collection-activation-reviews/claim-author"),
    )?;
    copy_regular_tree(
        reviewer_package,
        &output.join("compat/collection-activation-reviews/claim-reviewer"),
    )?;
    write_file(
        &output.join("compat/locks/catalog-digests.json"),
        catalog.as_bytes(),
    )?;
    write_file(
        &output.join("compat/locks/assurance-epoch.json"),
        epoch.as_bytes(),
    )
}

pub(crate) fn verify_active_collection_activation_repository(root: &Path) -> Result<(), String> {
    let manifest = read_file(&root.join("compat/collection-activation.toml"))?;
    let provenance_bytes = read_file(&root.join("compat/collection-activation-provenance.json"))?;
    let claims = read_file(&root.join("compat/collection-activation-claims.json"))?;
    if !hell_testkit::verify_collection_activation_state(&manifest, &provenance_bytes, &claims)? {
        return Err("collection activation repository is not active".to_owned());
    }
    crate::catalog_lock::verify_repository_locks(root)?;
    let subject = root.join("compat/collection-activation-review-subject");
    let proposal = subject.join("proposal");
    let retained = parse_retained_activation_proposal(&proposal)?;
    verify_retained_activation_proposal_content(root, &proposal, &retained)?;
    let candidate = retained.fields["baseCandidateCommit"].string()?;
    let epoch = retained.fields["baseAssuranceEpochSha256"].string()?;
    let artifacts = verify_retained_activation_subject(root, &subject, &retained)?;
    verify_retained_activation_decisions(
        root,
        &provenance_bytes,
        &retained,
        candidate,
        epoch,
        &artifacts,
    )
}

struct RetainedActivationProposal {
    bytes: Vec<u8>,
    fields: BTreeMap<String, crate::assurance::JsonValue>,
}

fn parse_retained_activation_proposal(
    proposal: &Path,
) -> Result<RetainedActivationProposal, String> {
    require_activation_proposal_inventory(proposal)?;
    let proposal_bytes = read_file(&proposal.join("activation-proposal.json"))?;
    let proposal_document = crate::assurance::parse_json(
        std::str::from_utf8(&proposal_bytes)
            .map_err(|_| "retained activation proposal is not UTF-8".to_owned())?,
    )?;
    let proposal_fields = proposal_document.object()?.clone();
    crate::assurance::require_exact_json_keys(
        &proposal_fields,
        &[
            "activationAuthority",
            "activationClaimsSha256",
            "activationManifestSha256",
            "activationTokenSha256",
            "baseAssuranceEpochSha256",
            "baseCandidateCommit",
            "corpusMappingSha256",
            "coverageDeltaSha256",
            "domain",
            "historicalCollectionCandidateCommit",
            "payloadMerkleRoot",
            "promotionAuthority",
            "prospectiveCatalogLockSha256",
            "prospectiveEpochLockSha256",
            "providerArchiveSha256",
            "providerArtifactId",
            "providerDirectorySha256",
            "providerRunAttempt",
            "providerRunId",
            "providerSelectionSha256",
            "reviewedArtifacts",
            "schemaVersion",
            "state",
            "worktreeMutated",
            "wormCustodyIdentitySha256",
        ],
    )?;
    let candidate = proposal_fields["baseCandidateCommit"].string()?;
    let epoch = proposal_fields["baseAssuranceEpochSha256"].string()?;
    require_lower_git_commit(candidate)?;
    Digest::from_hex(epoch).map_err(str::to_owned)?;
    if proposal_fields["schemaVersion"].number()? != 1
        || proposal_fields["domain"].string()? != "hell.collection-activation.proposal.v1"
        || proposal_fields["state"].string()? != "prepared-for-protected-human-review"
        || proposal_fields["worktreeMutated"].boolean()?
        || proposal_fields["activationAuthority"].boolean()?
        || proposal_fields["promotionAuthority"].boolean()?
    {
        return Err("retained activation proposal authority state differs".to_owned());
    }
    let manifest_bytes = read_file(&proposal.join("proposal-manifest.tsv"))?;
    if read_file(&proposal.join("root.sha256"))?
        != format!("{}\n", sha256_bytes(&manifest_bytes).hex()).as_bytes()
    {
        return Err("retained activation proposal root differs".to_owned());
    }
    verify_activation_manifest_entries(proposal, &manifest_bytes)?;
    Ok(RetainedActivationProposal {
        bytes: proposal_bytes,
        fields: proposal_fields,
    })
}

fn verify_retained_activation_proposal_content(
    root: &Path,
    proposal: &Path,
    retained: &RetainedActivationProposal,
) -> Result<(), String> {
    let proposal_fields = &retained.fields;
    let candidate = proposal_fields["baseCandidateCommit"].string()?;
    let retained_admission = verify_activation_preparation_token(
        &proposal.join("custody-admission/collection-custody-admission.json"),
        &proposal.join("custody-admission/collection-custody-activation-token.json"),
    )?;
    if retained_admission.current_candidate_commit != candidate
        || retained_admission.token_sha256 != proposal_fields["activationTokenSha256"].string()?
        || retained_admission.worm_custody_identity_sha256
            != proposal_fields["wormCustodyIdentitySha256"].string()?
        || retained_admission.candidate_commit
            != proposal_fields["historicalCollectionCandidateCommit"].string()?
        || retained_admission.payload_merkle_root
            != proposal_fields["payloadMerkleRoot"].string()?
    {
        return Err("retained activation custody admission differs from proposal".to_owned());
    }
    verify_retained_activation_proposal_file_digests(proposal, proposal_fields)?;
    verify_activation_mapping(root, &proposal.join("corpus-mapping.json"), candidate)?;
    verify_activation_coverage(&proposal.join("coverage-delta.json"))?;
    verify_supplemental_coverage_delta(&hell_testkit::reviewed_collection_cases()?)?;
    let selection_path = proposal.join("provider-selection/provider-selection.json");
    let selection_bytes = read_file(&selection_path)?;
    let selection_text = std::str::from_utf8(&selection_bytes)
        .map_err(|_| "retained inner provider selection is not UTF-8".to_owned())?;
    let selection = crate::assurance::verify_historical_collection_activation_selection(
        root,
        &proposal.join("provider-selection"),
        &format!(
            "collection-custody-admission-{}-{}",
            proposal_fields["providerRunId"].number()?,
            proposal_fields["providerRunAttempt"].number()?
        ),
        candidate,
        ".github/workflows/collection-custody-integration.yml",
    )?;
    if proposal_fields["providerSelectionSha256"].string()? != sha256_bytes(&selection_bytes).hex()
        || proposal_fields["providerArtifactId"].number()?
            != selection["providerArtifactId"].number()?
        || proposal_fields["providerRunId"].number()? != selection["providerRunId"].number()?
        || proposal_fields["providerRunAttempt"].number()?
            != selection["providerRunAttempt"].number()?
        || proposal_fields["providerArchiveSha256"].string()?
            != selection["providerArchiveSha256"].string()?
        || proposal_fields["providerDirectorySha256"].string()?
            != selection["directorySha256"].string()?
        || selection["directorySha256"].string()?
            != crate::custody_ops::verified_directory_digest(&proposal.join("custody-admission"))?
    {
        return Err("retained activation inner provider selection differs".to_owned());
    }
    let expected_artifacts = activation_review_artifacts(
        proposal,
        selection_text,
        &retained_admission,
        &PrepareActivationInput {
            artifact: Path::new("custody-admission"),
            output: Path::new("."),
            run_id: proposal_fields["providerRunId"].number()?,
            run_attempt: proposal_fields["providerRunAttempt"].number()?,
            artifact_id: proposal_fields["providerArtifactId"].number()?,
            expected_directory_sha256: proposal_fields["providerDirectorySha256"].string()?,
            expected_archive_sha256: proposal_fields["providerArchiveSha256"].string()?,
        },
    )?;
    let observed_artifacts = proposal_fields["reviewedArtifacts"]
        .array()?
        .iter()
        .map(|value| value.string().map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed_artifacts.len() != proposal_fields["reviewedArtifacts"].array()?.len()
        || observed_artifacts != expected_artifacts
    {
        return Err("retained activation proposal reviewed artifacts differ".to_owned());
    }
    verify_activation_authorship(
        &proposal.join("authorship-subject.json"),
        &retained.bytes,
        candidate,
        &proposal_fields["reviewedArtifacts"],
    )
}

fn verify_retained_activation_proposal_file_digests(
    proposal: &Path,
    fields: &BTreeMap<String, crate::assurance::JsonValue>,
) -> Result<(), String> {
    for (field, path) in [
        (
            "activationManifestSha256",
            "tree/compat/collection-activation.toml",
        ),
        (
            "activationClaimsSha256",
            "tree/compat/collection-activation-claims.json",
        ),
        (
            "prospectiveCatalogLockSha256",
            "tree/compat/locks/catalog-digests.json",
        ),
        (
            "prospectiveEpochLockSha256",
            "tree/compat/locks/assurance-epoch.json",
        ),
        ("corpusMappingSha256", "corpus-mapping.json"),
        ("coverageDeltaSha256", "coverage-delta.json"),
    ] {
        if fields[field].string()?
            != sha256_file(&proposal.join(path))
                .map_err(|error| error.to_string())?
                .hex()
        {
            return Err(format!("retained activation proposal {field} differs"));
        }
    }
    Ok(())
}

fn verify_retained_activation_subject(
    root: &Path,
    subject: &Path,
    retained: &RetainedActivationProposal,
) -> Result<BTreeSet<String>, String> {
    let proposal_fields = &retained.fields;
    let candidate = proposal_fields["baseCandidateCommit"].string()?;
    let subject_bytes = read_file(&subject.join("review-subject.json"))?;
    let subject_document = crate::assurance::parse_json(
        std::str::from_utf8(&subject_bytes)
            .map_err(|_| "retained activation review subject is not UTF-8".to_owned())?,
    )?;
    let subject_fields = subject_document.object()?;
    crate::assurance::require_exact_json_keys(
        subject_fields,
        &[
            "activationAuthority",
            "baseCandidateCommit",
            "domain",
            "outerArchiveSha256",
            "outerArtifactId",
            "outerDirectorySha256",
            "outerRunAttempt",
            "outerRunId",
            "outerSelectionSha256",
            "promotionAuthority",
            "proposalSha256",
            "schemaVersion",
            "state",
        ],
    )?;
    if subject_fields["schemaVersion"].number()? != 1
        || subject_fields["domain"].string()? != "hell.collection-activation.review-subject.v1"
        || subject_fields["state"].string()? != "sealed-for-distinct-protected-reviews"
        || subject_fields["activationAuthority"].boolean()?
        || subject_fields["promotionAuthority"].boolean()?
        || subject_fields["baseCandidateCommit"].string()? != candidate
        || subject_fields["proposalSha256"].string()? != sha256_bytes(&retained.bytes).hex()
    {
        return Err("retained activation review subject differs from proposal".to_owned());
    }
    let subject_manifest = read_file(&subject.join("review-subject-manifest.tsv"))?;
    if read_file(&subject.join("root.sha256"))?
        != format!("{}\n", sha256_bytes(&subject_manifest).hex()).as_bytes()
    {
        return Err("retained activation review subject root differs".to_owned());
    }
    verify_sealed_regular_tree_manifest(
        subject,
        &subject_manifest,
        &collect_regular_relative_files(subject, subject)?,
    )?;
    verify_retained_outer_selection(root, subject, candidate, subject_fields)?;
    retained_activation_review_artifacts(subject, proposal_fields)
}

fn verify_retained_activation_decisions(
    root: &Path,
    provenance_bytes: &[u8],
    retained: &RetainedActivationProposal,
    candidate: &str,
    epoch: &str,
    artifacts: &BTreeSet<String>,
) -> Result<(), String> {
    let author = root.join("compat/collection-activation-reviews/claim-author");
    let reviewer = root.join("compat/collection-activation-reviews/claim-reviewer");
    let author_binding =
        historical_activation_review(root, &author, "claim-author", candidate, epoch, artifacts)?;
    let reviewer_binding = historical_activation_review(
        root,
        &reviewer,
        "claim-reviewer",
        candidate,
        epoch,
        artifacts,
    )?;
    if author_binding.0 == reviewer_binding.0 || author_binding.1 == reviewer_binding.1 {
        return Err("retained activation author and reviewer are not independent".to_owned());
    }
    let provenance = crate::assurance::parse_json(
        std::str::from_utf8(provenance_bytes)
            .map_err(|_| "activation provenance is not UTF-8".to_owned())?,
    )?;
    provenance.object()?;
    let expected = render_retained_activation_provenance(
        retained,
        &root.join("compat/collection-activation-review-subject"),
        &author,
        &reviewer,
        &author_binding,
        &reviewer_binding,
    )?;
    if crate::assurance::canonical_json_bytes(&provenance)? != expected {
        return Err("activation provenance differs from retained signed decisions".to_owned());
    }
    Ok(())
}

fn render_retained_activation_provenance(
    retained: &RetainedActivationProposal,
    review_subject_root: &Path,
    author: &Path,
    reviewer: &Path,
    author_binding: &(String, String),
    reviewer_binding: &(String, String),
) -> Result<Vec<u8>, String> {
    let mut fields =
        activation_provenance_base_fields(&retained.fields, &sha256_bytes(&retained.bytes).hex())?;
    fields.extend(activation_extended_provenance_fields(review_subject_root)?);
    for (label, directory, binding) in [
        ("Author", author, author_binding),
        ("Review", reviewer, reviewer_binding),
    ] {
        fields.extend(retained_review_provenance_fields(
            label, directory, binding,
        )?);
    }
    fields.extend([
        (
            "freshCollectionRequired".to_owned(),
            crate::assurance::JsonValue::Bool(true),
        ),
        (
            "activationAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "promotionAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
    ]);
    crate::assurance::canonical_json_bytes(&crate::assurance::JsonValue::Object(fields))
}

fn retained_review_provenance_fields(
    label: &str,
    directory: &Path,
    binding: &(String, String),
) -> Result<[(String, crate::assurance::JsonValue); 5], String> {
    let digest = |name| {
        sha256_file(&directory.join(name))
            .map(hell_testkit::Digest::hex)
            .map_err(|error| error.to_string())
    };
    Ok([
        (
            format!("activation{label}Sha256"),
            crate::assurance::JsonValue::String(digest("review.dsse.json")?),
        ),
        (
            format!("activation{label}Subject"),
            crate::assurance::JsonValue::String(binding.0.clone()),
        ),
        (
            format!("activation{label}SignerFingerprint"),
            crate::assurance::JsonValue::String(binding.1.clone()),
        ),
        (
            format!("activation{label}AuthorizationSha256"),
            crate::assurance::JsonValue::String(digest("authorization.json")?),
        ),
        (
            format!("activation{label}PacketSha256"),
            crate::assurance::JsonValue::String(digest("review-packet.json")?),
        ),
    ])
}

fn verify_retained_outer_selection(
    root: &Path,
    subject: &Path,
    candidate: &str,
    subject_fields: &BTreeMap<String, crate::assurance::JsonValue>,
) -> Result<(), String> {
    let selection_document = crate::assurance::parse_json(
        std::str::from_utf8(&read_file(
            &subject.join("source-selection/provider-selection.json"),
        )?)
        .map_err(|_| "retained activation outer selection is not UTF-8".to_owned())?,
    )?;
    let run_id = selection_document.object()?["providerRunId"].number()?;
    let run_attempt = selection_document.object()?["providerRunAttempt"].number()?;
    let retained = crate::assurance::verify_historical_collection_activation_selection(
        root,
        &subject.join("source-selection"),
        &format!("collection-activation-proposal-{run_id}-{run_attempt}"),
        candidate,
        ".github/workflows/collection-activation-preparation.yml",
    )?;
    let selection_path = subject.join("source-selection/provider-selection.json");
    let selection_bytes = read_file(&selection_path)?;
    let selection_document = crate::assurance::parse_json(
        std::str::from_utf8(&selection_bytes)
            .map_err(|_| "retained activation outer selection is not UTF-8".to_owned())?,
    )?;
    if crate::assurance::canonical_json_bytes(&selection_document)? != selection_bytes {
        return Err("retained activation outer selection is not canonical".to_owned());
    }
    let selection = selection_document.object()?;
    if retained != *selection
        || selection["schemaVersion"].number()? != 1
        || selection["selectionState"].string()? != "exact-provider-object"
        || selection["candidateCommit"].string()? != candidate
        || selection["workflowPath"].string()?
            != ".github/workflows/collection-activation-preparation.yml"
        || selection["event"].string()? != "workflow_dispatch"
        || selection["directorySha256"].string()?
            != crate::custody_ops::verified_directory_digest(&subject.join("proposal"))?
        || subject_fields["outerSelectionSha256"].string()? != sha256_bytes(&selection_bytes).hex()
        || subject_fields["outerRunId"].number()? != selection["providerRunId"].number()?
        || subject_fields["outerRunAttempt"].number()?
            != selection["providerRunAttempt"].number()?
        || subject_fields["outerArtifactId"].number()?
            != selection["providerArtifactId"].number()?
        || subject_fields["outerArchiveSha256"].string()?
            != selection["providerArchiveSha256"].string()?
        || subject_fields["outerDirectorySha256"].string()?
            != selection["directorySha256"].string()?
    {
        return Err("retained activation outer selection binding differs".to_owned());
    }
    for (path, field) in [
        (
            "source-selection/provider-selected-artifact.json",
            "providerArtifactApiSha256",
        ),
        (
            "source-selection/provider-selected-run.json",
            "providerRunApiSha256",
        ),
    ] {
        if sha256_file(&subject.join(path))
            .map_err(|error| error.to_string())?
            .hex()
            != selection[field].string()?
        {
            return Err("retained activation outer provider API digest differs".to_owned());
        }
    }
    Ok(())
}

fn retained_activation_review_artifacts(
    subject: &Path,
    proposal_fields: &BTreeMap<String, crate::assurance::JsonValue>,
) -> Result<BTreeSet<String>, String> {
    let proposal = subject.join("proposal");
    let mut artifacts = proposal_fields["reviewedArtifacts"]
        .array()?
        .iter()
        .map(|value| value.string().map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    for path in [
        proposal.join("activation-proposal.json"),
        proposal.join("authorship-subject.json"),
        proposal.join("proposal-manifest.tsv"),
        proposal.join("root.sha256"),
        subject.join("review-subject.json"),
        subject.join("review-subject-manifest.tsv"),
        subject.join("root.sha256"),
        subject.join("source-selection/provider-selection.json"),
    ] {
        if !artifacts.insert(sha256_file(&path).map_err(|error| error.to_string())?.hex()) {
            return Err("retained activation review artifacts duplicate a root".to_owned());
        }
    }
    Ok(artifacts)
}

fn historical_activation_review(
    root: &Path,
    directory: &Path,
    role: &str,
    candidate: &str,
    epoch: &str,
    subject_artifacts: &BTreeSet<String>,
) -> Result<(String, String), String> {
    crate::assurance::require_real_activation_review_tree(directory, directory)?;
    let authorization = directory.join("authorization.json");
    let reviewed_at = crate::assurance::verify_historical_activation_authorization(
        root,
        &authorization,
        role,
        candidate,
        &root.join("compat/collection-activation-review-subject/review-subject.json"),
    )?;
    let authorization_sha256 = sha256_file(&authorization)
        .map_err(|error| error.to_string())?
        .hex();
    let mut required = subject_artifacts.clone();
    if !required.insert(authorization_sha256) {
        return Err("retained activation authorization duplicates a subject root".to_owned());
    }
    let packet = directory.join("review-packet.json");
    let packet_bytes = read_file(&packet)?;
    let packet_document = crate::assurance::parse_json(
        std::str::from_utf8(&packet_bytes)
            .map_err(|_| "retained activation packet is not UTF-8".to_owned())?,
    )?;
    let packet_fields = packet_document.object()?;
    let packet_artifacts = packet_fields["reviewedArtifacts"]
        .array()?
        .iter()
        .map(|value| value.string().map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if packet_fields["role"].string()? != role
        || packet_fields["candidateCommit"].string()? != candidate
        || packet_fields["assuranceEpochSha256"].string()? != epoch
        || packet_fields["issuedAt"].string()? != reviewed_at
        || packet_artifacts != required
    {
        return Err("retained activation packet binding differs".to_owned());
    }
    let packet_sha256 = sha256_bytes(&packet_bytes).hex();
    if read_file(&directory.join("review-packet.json.sha256"))?
        != format!("{packet_sha256}\n").as_bytes()
    {
        return Err("retained activation packet digest differs".to_owned());
    }
    crate::assurance::verify_historical_activation_review_binding(
        &crate::assurance::HistoricalActivationReviewBinding {
            input: &directory.join("review.dsse.json"),
            policy: &directory.join("reviewer.allowed_signers"),
            current_revocations: &root.join("compat/review-revocations.toml"),
            role,
            candidate,
            epoch,
            required_artifacts: &required,
            current_trust_roots: &root.join("compat/trust-roots.toml"),
        },
    )
}

pub(crate) fn assemble_custody_payload_overlay(
    root: &Path,
    package: &Path,
    signature: &Path,
    output: &Path,
) -> Result<String, String> {
    if canonical_checkout_relative(root, package)?
        != Path::new("ci-in/collection-custody-merge/collection-custody")
        || canonical_checkout_relative(root, signature)?
            != Path::new("ci-in/collection-custody-merge/collection-custody-signature")
        || canonical_checkout_relative(root, output)?
            != Path::new("ci-out/collection-custody-payload-overlay")
    {
        return Err("collection custody payload overlay paths are not canonical".to_owned());
    }
    let output = root.join(canonical_checkout_relative(root, output)?);
    if fs::symlink_metadata(&output).is_ok() {
        return Err("collection custody payload overlay already exists".to_owned());
    }
    let tree = output.join("tree/compat/collection-custody");
    fs::create_dir_all(&tree)
        .map_err(|error| format!("cannot create collection custody payload overlay: {error}"))?;
    copy_regular_tree(&root.join(package), &tree.join("payload"))?;
    copy_regular_tree(&root.join(signature), &tree.join("signature"))?;
    let core = verify_core(root, &tree.join("payload"))?;
    verify_retained_attestation(&core, &tree.join("signature"))?;
    let digest = crate::custody_ops::verified_directory_digest(&tree)?;
    write_file(
        &output.join("directory.sha256"),
        format!("{digest}\n").as_bytes(),
    )?;
    Ok(digest)
}

pub(crate) fn assemble_custody_review_overlay(
    root: &Path,
    input: &Path,
    review: &Path,
    output: &Path,
) -> Result<String, String> {
    if canonical_checkout_relative(root, input)? != Path::new("ci-in/collection-custody-review")
        || canonical_checkout_relative(root, review)?
            != Path::new("ci-in/collection-custody-review-signed/integration-review.dsse.json")
        || canonical_checkout_relative(root, output)?
            != Path::new("ci-out/collection-custody-review-overlay")
    {
        return Err("collection custody review overlay paths are not canonical".to_owned());
    }
    let prepared = read_prepared_review_files(root, input)?;
    verify_prepared_custody_review(root, input)?;
    let review_bytes = read_file(&root.join(review))?;
    let output = root.join(canonical_checkout_relative(root, output)?);
    if fs::symlink_metadata(&output).is_ok() {
        return Err("collection custody review overlay already exists".to_owned());
    }
    let tree = output.join("tree/compat/collection-custody");
    fs::create_dir_all(&tree)
        .map_err(|error| format!("cannot create collection custody review overlay: {error}"))?;
    write_file(&tree.join("integration-proof.tsv"), &prepared.proof)?;
    write_file(&tree.join("integration-review.dsse.json"), &review_bytes)?;
    let proof_digest = sha256_bytes(&prepared.proof);
    let payload = crate::assurance::verify_unsigned_custody_review_payload(
        &root.join("compat/reviews.allowed_signers"),
        &prepared.payload,
    )?;
    crate::assurance::verify_review_binding_payload(
        &tree.join("integration-review.dsse.json"),
        &root.join(input).join("integration-review-payload.json"),
        &root.join("compat/reviews.allowed_signers"),
        "custody-reviewer",
        &payload.candidate,
        &payload.epoch,
        &payload.reviewed_artifacts,
    )?;
    if !payload.reviewed_artifacts.contains(&proof_digest.hex()) {
        return Err("signed collection custody review does not bind integration proof".to_owned());
    }
    let digest = crate::custody_ops::verified_directory_digest(&tree)?;
    write_file(
        &output.join("directory.sha256"),
        format!("{digest}\n").as_bytes(),
    )?;
    Ok(digest)
}

fn verify_activation_mapping(root: &Path, path: &Path, head: &str) -> Result<(), String> {
    let bytes = read_file(path)?;
    if bytes != expected_activation_mapping(root, head)? {
        return Err("activation mapping is not the exact rederived reviewed mapping".to_owned());
    }
    Ok(())
}

fn expected_activation_mapping(root: &Path, head: &str) -> Result<Vec<u8>, String> {
    let source = hell_testkit::verify_collection_source_authority(root)
        .map_err(|error| error.to_string())?;
    let authorities = hell_testkit::reviewed_collection_case_authorities(&source)?;
    if authorities.len() != 1_191 {
        return Err("collection activation mapping is not exactly Map712/Set479".to_owned());
    }
    let mut mapping_root = b"hell-collection-activation-mapping-v1\0".to_vec();
    for authority in &authorities {
        for value in [
            authority.case_id.as_bytes(),
            authority.target_builtin.as_bytes(),
            authority.descriptor_sha256.hex().as_bytes(),
            authority.comparator_contract_sha256.hex().as_bytes(),
        ] {
            push_frame(&mut mapping_root, value);
        }
    }
    let corpus_sha256 = sha256_file(&root.join("crates/hell-testkit/src/corpus.rs"))
        .map_err(|error| error.to_string())?;
    crate::assurance::canonical_json_bytes(&crate::assurance::JsonValue::Object(BTreeMap::from([
        (
            "schemaVersion".to_owned(),
            crate::assurance::JsonValue::Number(1),
        ),
        (
            "domain".to_owned(),
            crate::assurance::JsonValue::String("hell.collection-activation.mapping.v1".to_owned()),
        ),
        (
            "baseCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(head.to_owned()),
        ),
        (
            "corpusSourcePath".to_owned(),
            crate::assurance::JsonValue::String("crates/hell-testkit/src/corpus.rs".to_owned()),
        ),
        (
            "corpusSourceSha256".to_owned(),
            crate::assurance::JsonValue::String(corpus_sha256.hex()),
        ),
        (
            "corpusSourceChanged".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "mappingRootSha256".to_owned(),
            crate::assurance::JsonValue::String(sha256_bytes(&mapping_root).hex()),
        ),
        (
            "mapCaseCount".to_owned(),
            crate::assurance::JsonValue::Number(712),
        ),
        (
            "setCaseCount".to_owned(),
            crate::assurance::JsonValue::Number(479),
        ),
        (
            "caseCount".to_owned(),
            crate::assurance::JsonValue::Number(1_191),
        ),
    ])))
}

fn verify_activation_coverage(path: &Path) -> Result<(), String> {
    let bytes = read_file(path)?;
    let json = crate::assurance::parse_json(
        std::str::from_utf8(&bytes).map_err(|_| "activation coverage is not UTF-8".to_owned())?,
    )?;
    if crate::assurance::canonical_json_bytes(&json)? != bytes {
        return Err("activation coverage is not canonical JSON".to_owned());
    }
    let fields = json.object()?;
    crate::assurance::require_exact_json_keys(
        fields,
        &[
            "afterBoundaryGaps",
            "afterIncompleteCells",
            "beforeBoundaryGaps",
            "beforeIncompleteCells",
            "interactionGaps",
            "mapOnlyBoundaryGaps",
            "mapOnlyIncompleteCells",
            "schemaVersion",
            "setOnlyBoundaryGaps",
            "setOnlyIncompleteCells",
        ],
    )?;
    let number = |key| {
        fields
            .get(key)
            .ok_or_else(|| format!("activation coverage omits {key}"))?
            .number()
    };
    if number("schemaVersion")? != 1
        || number("beforeIncompleteCells")? != 134
        || number("beforeBoundaryGaps")? != 14
        || number("mapOnlyIncompleteCells")? != 127
        || number("mapOnlyBoundaryGaps")? != 7
        || number("setOnlyIncompleteCells")? != 127
        || number("setOnlyBoundaryGaps")? != 7
        || number("afterIncompleteCells")? != 120
        || number("afterBoundaryGaps")? != 0
        || number("interactionGaps")? != 0
    {
        return Err("activation coverage delta is not exact".to_owned());
    }
    Ok(())
}

fn verify_activation_authorship(
    path: &Path,
    proposal: &[u8],
    candidate: &str,
    reviewed_artifacts: &crate::assurance::JsonValue,
) -> Result<(), String> {
    let bytes = read_file(path)?;
    let json = crate::assurance::parse_json(
        std::str::from_utf8(&bytes).map_err(|_| "activation authorship is not UTF-8".to_owned())?,
    )?;
    if crate::assurance::canonical_json_bytes(&json)? != bytes {
        return Err("activation authorship is not canonical JSON".to_owned());
    }
    let fields = json.object()?;
    crate::assurance::require_exact_json_keys(
        fields,
        &[
            "actionKind",
            "activationAuthority",
            "candidateCommit",
            "domain",
            "promotionAuthority",
            "proposalSha256",
            "requiredRole",
            "reviewedArtifacts",
            "schemaVersion",
        ],
    )?;
    let member = |key| {
        fields
            .get(key)
            .ok_or_else(|| format!("activation authorship omits {key}"))
    };
    if member("schemaVersion")?.number()? != 1
        || member("domain")?.string()? != "hell.collection-activation.authorship-subject.v1"
        || member("candidateCommit")?.string()? != candidate
        || member("actionKind")?.string()? != "authored-claim-change"
        || member("requiredRole")?.string()? != "claim-author"
        || member("proposalSha256")?.string()? != sha256_bytes(proposal).hex()
        || member("reviewedArtifacts")? != reviewed_artifacts
        || member("activationAuthority")?.boolean()?
        || member("promotionAuthority")?.boolean()?
    {
        return Err("activation authorship subject is invalid".to_owned());
    }
    Ok(())
}

fn require_activation_proposal_inventory(input: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(input)
        .map_err(|error| format!("cannot inspect collection activation proposal: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("collection activation proposal is not a real directory".to_owned());
    }
    let expected = [
        "activation-proposal.json",
        "authorship-subject.json",
        "corpus-mapping.json",
        "coverage-delta.json",
        "custody-admission/collection-custody-activation-token.json",
        "custody-admission/collection-custody-activation-token.json.sha256",
        "custody-admission/collection-custody-admission.json",
        "custody-admission/collection-custody-admission.json.sha256",
        "proposal-manifest.tsv",
        "provider-selection/provider-selected-artifact.json",
        "provider-selection/provider-selected-run.json",
        "provider-selection/provider-selection.json",
        "root.sha256",
        "tree/compat/collection-activation-claims.json",
        "tree/compat/collection-activation.toml",
        "tree/compat/locks/assurance-epoch.json",
        "tree/compat/locks/catalog-digests.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let observed = collect_regular_relative_files(input, input)?;
    if observed != expected {
        return Err("collection activation proposal inventory is not exact".to_owned());
    }
    Ok(())
}

fn collect_regular_relative_files(
    root: &Path,
    directory: &Path,
) -> Result<BTreeSet<String>, String> {
    let mut files = BTreeSet::new();
    collect_regular_relative_files_into(root, directory, &mut files)?;
    Ok(files)
}

fn collect_regular_relative_files_into(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate collection activation proposal: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("cannot enumerate collection activation proposal: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            format!("cannot inspect collection activation proposal entry: {error}")
        })?;
        if metadata.file_type().is_symlink() {
            return Err("collection activation proposal contains a symlink".to_owned());
        }
        if metadata.is_dir() {
            collect_regular_relative_files_into(root, &entry.path(), files)?;
        } else if metadata.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| "activation proposal path escapes root".to_owned())?
                .to_str()
                .ok_or_else(|| "activation proposal path is not UTF-8".to_owned())?
                .replace(std::path::MAIN_SEPARATOR, "/");
            files.insert(relative);
        } else {
            return Err("collection activation proposal contains a non-regular node".to_owned());
        }
    }
    Ok(())
}

fn verify_activation_manifest_entries(input: &Path, manifest: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(manifest)
        .map_err(|_| "collection activation proposal manifest is not UTF-8".to_owned())?;
    let mut observed = BTreeSet::new();
    let mut lines = text.lines();
    if lines.next() != Some("sha256\tbytes\tpath") {
        return Err("collection activation proposal manifest header is invalid".to_owned());
    }
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        let [digest, size, path] = fields.as_slice() else {
            return Err("collection activation proposal manifest row is malformed".to_owned());
        };
        Digest::from_hex(digest).map_err(str::to_owned)?;
        let size = size
            .parse::<usize>()
            .map_err(|_| "collection activation proposal manifest size is invalid".to_owned())?;
        if path.starts_with('/') || path.split('/').any(|part| part.is_empty() || part == "..") {
            return Err("collection activation proposal manifest path is invalid".to_owned());
        }
        let bytes = read_file(&input.join(path))?;
        if bytes.len() != size || sha256_bytes(&bytes).hex() != *digest || !observed.insert(*path) {
            return Err("collection activation proposal manifest entry differs".to_owned());
        }
    }
    let expected = BTreeSet::from([
        "activation-proposal.json",
        "authorship-subject.json",
        "corpus-mapping.json",
        "coverage-delta.json",
        "custody-admission/collection-custody-activation-token.json",
        "custody-admission/collection-custody-activation-token.json.sha256",
        "custody-admission/collection-custody-admission.json",
        "custody-admission/collection-custody-admission.json.sha256",
        "provider-selection/provider-selected-artifact.json",
        "provider-selection/provider-selected-run.json",
        "provider-selection/provider-selection.json",
        "tree/compat/collection-activation-claims.json",
        "tree/compat/collection-activation.toml",
        "tree/compat/locks/assurance-epoch.json",
        "tree/compat/locks/catalog-digests.json",
    ]);
    if observed != expected {
        return Err("collection activation proposal manifest entry count differs".to_owned());
    }
    Ok(())
}

fn require_clean_activation_base(root: &Path) -> Result<(), String> {
    crate::catalog_lock::require_clean_repository_lock_inputs(root)?;
    let paths = [
        "compat/collection-activation.toml",
        "compat/locks/catalog-digests.json",
        "compat/locks/assurance-epoch.json",
        "crates/hell-testkit/src/corpus.rs",
        "crates/hell-ci/src/assurance.rs",
        "crates/hell-ci/src/catalog_lock.rs",
    ];
    for path in paths {
        let tracked = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["ls-files", "--error-unmatch", "--", path])
            .output()
            .map_err(|error| format!("cannot inspect activation input tracking: {error}"))?;
        if !tracked.status.success() {
            return Err(format!("collection activation input {path} is not tracked"));
        }
    }
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain=v2", "--untracked-files=all", "--"])
        .args(paths)
        .output()
        .map_err(|error| format!("cannot inspect activation base cleanliness: {error}"))?;
    if !status.status.success() || !status.stdout.is_empty() || !status.stderr.is_empty() {
        return Err("collection activation inputs are not clean at exact HEAD".to_owned());
    }
    Ok(())
}

struct WriteActivationProposal<'a> {
    root: &'a Path,
    output: &'a Path,
    verified: &'a VerifiedActivationPreparationToken,
    head: &'a str,
    input: &'a PrepareActivationInput<'a>,
    selection: &'a str,
    claims: &'a [u8],
    catalog_lock: &'a str,
    epoch_lock: &'a str,
}

fn write_activation_proposal(request: &WriteActivationProposal<'_>) -> Result<(), String> {
    let WriteActivationProposal {
        root,
        output,
        verified,
        head,
        input,
        selection,
        claims,
        catalog_lock,
        epoch_lock,
    } = request;
    write_activation_proposal_inputs(root, output, input, claims, catalog_lock, epoch_lock)?;
    write_activation_mapping(root, output, head)?;
    write_activation_coverage(output)?;
    write_activation_proposal_documents(root, output, verified, head, input, selection)
}

fn write_activation_proposal_inputs(
    root: &Path,
    output: &Path,
    input: &PrepareActivationInput<'_>,
    claims: &[u8],
    catalog_lock: &str,
    epoch_lock: &str,
) -> Result<(), String> {
    require_report_outside_authority(root, &output.join("activation-proposal.json"))?;
    fs::create_dir_all(output.join("tree/compat/locks"))
        .map_err(|error| format!("cannot create collection activation proposal: {error}"))?;
    copy_regular_tree(
        &root.join(input.artifact),
        &output.join("custody-admission"),
    )?;
    verify_activation_preparation_token(
        &output.join("custody-admission/collection-custody-admission.json"),
        &output.join("custody-admission/collection-custody-activation-token.json"),
    )?;
    write_file(
        &output.join("tree/compat/collection-activation.toml"),
        ACTIVE_ACTIVATION_MANIFEST,
    )?;
    write_file(
        &output.join("tree/compat/collection-activation-claims.json"),
        claims,
    )?;
    write_file(
        &output.join("tree/compat/locks/catalog-digests.json"),
        catalog_lock.as_bytes(),
    )?;
    write_file(
        &output.join("tree/compat/locks/assurance-epoch.json"),
        epoch_lock.as_bytes(),
    )
}

fn write_activation_mapping(root: &Path, output: &Path, head: &str) -> Result<(), String> {
    let cases = hell_testkit::reviewed_collection_cases()?;
    verify_supplemental_coverage_delta(&cases)?;
    let source = hell_testkit::verify_collection_source_authority(root)
        .map_err(|error| error.to_string())?;
    let authorities = hell_testkit::reviewed_collection_case_authorities(&source)?;
    if authorities.len() != 1_191 {
        return Err("collection activation mapping is not exactly Map712/Set479".to_owned());
    }
    let mut mapping_root = b"hell-collection-activation-mapping-v1\0".to_vec();
    for authority in &authorities {
        for value in [
            authority.case_id.as_bytes(),
            authority.target_builtin.as_bytes(),
            authority.descriptor_sha256.hex().as_bytes(),
            authority.comparator_contract_sha256.hex().as_bytes(),
        ] {
            push_frame(&mut mapping_root, value);
        }
    }
    let corpus_source = root.join("crates/hell-testkit/src/corpus.rs");
    let corpus_sha256 = sha256_file(&corpus_source).map_err(|error| error.to_string())?;
    let mapping = crate::assurance::JsonValue::Object(BTreeMap::from([
        (
            "schemaVersion".to_owned(),
            crate::assurance::JsonValue::Number(1),
        ),
        (
            "domain".to_owned(),
            crate::assurance::JsonValue::String("hell.collection-activation.mapping.v1".to_owned()),
        ),
        (
            "baseCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(head.to_owned()),
        ),
        (
            "corpusSourcePath".to_owned(),
            crate::assurance::JsonValue::String("crates/hell-testkit/src/corpus.rs".to_owned()),
        ),
        (
            "corpusSourceSha256".to_owned(),
            crate::assurance::JsonValue::String(corpus_sha256.hex()),
        ),
        (
            "corpusSourceChanged".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "mappingRootSha256".to_owned(),
            crate::assurance::JsonValue::String(sha256_bytes(&mapping_root).hex()),
        ),
        (
            "mapCaseCount".to_owned(),
            crate::assurance::JsonValue::Number(712),
        ),
        (
            "setCaseCount".to_owned(),
            crate::assurance::JsonValue::Number(479),
        ),
        (
            "caseCount".to_owned(),
            crate::assurance::JsonValue::Number(1_191),
        ),
    ]));
    write_file(
        &output.join("corpus-mapping.json"),
        &crate::assurance::canonical_json_bytes(&mapping)?,
    )
}

fn write_activation_coverage(output: &Path) -> Result<(), String> {
    let coverage = crate::assurance::JsonValue::Object(BTreeMap::from([
        (
            "schemaVersion".to_owned(),
            crate::assurance::JsonValue::Number(1),
        ),
        (
            "beforeIncompleteCells".to_owned(),
            crate::assurance::JsonValue::Number(134),
        ),
        (
            "beforeBoundaryGaps".to_owned(),
            crate::assurance::JsonValue::Number(14),
        ),
        (
            "mapOnlyIncompleteCells".to_owned(),
            crate::assurance::JsonValue::Number(127),
        ),
        (
            "mapOnlyBoundaryGaps".to_owned(),
            crate::assurance::JsonValue::Number(7),
        ),
        (
            "setOnlyIncompleteCells".to_owned(),
            crate::assurance::JsonValue::Number(127),
        ),
        (
            "setOnlyBoundaryGaps".to_owned(),
            crate::assurance::JsonValue::Number(7),
        ),
        (
            "afterIncompleteCells".to_owned(),
            crate::assurance::JsonValue::Number(120),
        ),
        (
            "afterBoundaryGaps".to_owned(),
            crate::assurance::JsonValue::Number(0),
        ),
        (
            "interactionGaps".to_owned(),
            crate::assurance::JsonValue::Number(0),
        ),
    ]));
    write_file(
        &output.join("coverage-delta.json"),
        &crate::assurance::canonical_json_bytes(&coverage)?,
    )
}

fn write_activation_proposal_documents(
    root: &Path,
    output: &Path,
    verified: &VerifiedActivationPreparationToken,
    head: &str,
    input: &PrepareActivationInput<'_>,
    selection: &str,
) -> Result<(), String> {
    let artifacts = activation_review_artifacts(output, selection, verified, input)?;
    let (_, base_epoch) = crate::assurance::epoch(root)?;
    let proposal = activation_proposal_document(
        output,
        selection,
        verified,
        head,
        input,
        &base_epoch.hex(),
        &artifacts,
    )?;
    write_file(
        &output.join("activation-proposal.json"),
        &crate::assurance::canonical_json_bytes(&proposal)?,
    )?;
    let proposal_sha256 = sha256_file(&output.join("activation-proposal.json"))
        .map_err(|error| error.to_string())?
        .hex();
    let subject = crate::assurance::JsonValue::Object(BTreeMap::from([
        (
            "schemaVersion".to_owned(),
            crate::assurance::JsonValue::Number(1),
        ),
        (
            "domain".to_owned(),
            crate::assurance::JsonValue::String(
                "hell.collection-activation.authorship-subject.v1".to_owned(),
            ),
        ),
        (
            "candidateCommit".to_owned(),
            crate::assurance::JsonValue::String(head.to_owned()),
        ),
        (
            "actionKind".to_owned(),
            crate::assurance::JsonValue::String("authored-claim-change".to_owned()),
        ),
        (
            "requiredRole".to_owned(),
            crate::assurance::JsonValue::String("claim-author".to_owned()),
        ),
        (
            "proposalSha256".to_owned(),
            crate::assurance::JsonValue::String(proposal_sha256),
        ),
        (
            "reviewedArtifacts".to_owned(),
            crate::assurance::JsonValue::Array(
                artifacts
                    .into_iter()
                    .map(crate::assurance::JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "activationAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "promotionAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
    ]));
    write_file(
        &output.join("authorship-subject.json"),
        &crate::assurance::canonical_json_bytes(&subject)?,
    )?;
    seal_activation_proposal(output)
}

fn activation_review_artifacts(
    output: &Path,
    selection: &str,
    verified: &VerifiedActivationPreparationToken,
    input: &PrepareActivationInput<'_>,
) -> Result<BTreeSet<String>, String> {
    let mut artifacts = BTreeSet::from([
        verified.token_sha256.clone(),
        verified.worm_custody_identity_sha256.clone(),
        sha256_bytes(selection.as_bytes()).hex(),
        input.expected_directory_sha256.to_owned(),
        input.expected_archive_sha256.to_owned(),
    ]);
    for path in [
        "custody-admission/collection-custody-admission.json",
        "custody-admission/collection-custody-admission.json.sha256",
        "custody-admission/collection-custody-activation-token.json",
        "custody-admission/collection-custody-activation-token.json.sha256",
        "tree/compat/collection-activation-claims.json",
        "tree/compat/collection-activation.toml",
        "tree/compat/locks/catalog-digests.json",
        "tree/compat/locks/assurance-epoch.json",
        "corpus-mapping.json",
        "coverage-delta.json",
    ] {
        artifacts.insert(
            sha256_file(&output.join(path))
                .map_err(|error| error.to_string())?
                .hex(),
        );
    }
    Ok(artifacts)
}

fn activation_proposal_document(
    output: &Path,
    selection: &str,
    verified: &VerifiedActivationPreparationToken,
    head: &str,
    input: &PrepareActivationInput<'_>,
    base_epoch: &str,
    artifacts: &BTreeSet<String>,
) -> Result<crate::assurance::JsonValue, String> {
    let mut fields = BTreeMap::from([
        (
            "schemaVersion".to_owned(),
            crate::assurance::JsonValue::Number(1),
        ),
        (
            "domain".to_owned(),
            crate::assurance::JsonValue::String(
                "hell.collection-activation.proposal.v1".to_owned(),
            ),
        ),
        (
            "state".to_owned(),
            crate::assurance::JsonValue::String("prepared-for-protected-human-review".to_owned()),
        ),
        (
            "baseCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(head.to_owned()),
        ),
        (
            "baseAssuranceEpochSha256".to_owned(),
            crate::assurance::JsonValue::String(base_epoch.to_owned()),
        ),
        (
            "historicalCollectionCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(verified.candidate_commit.clone()),
        ),
        (
            "payloadMerkleRoot".to_owned(),
            crate::assurance::JsonValue::String(verified.payload_merkle_root.clone()),
        ),
        (
            "activationTokenSha256".to_owned(),
            crate::assurance::JsonValue::String(verified.token_sha256.clone()),
        ),
        (
            "wormCustodyIdentitySha256".to_owned(),
            crate::assurance::JsonValue::String(verified.worm_custody_identity_sha256.clone()),
        ),
        (
            "providerRunId".to_owned(),
            crate::assurance::JsonValue::Number(input.run_id),
        ),
        (
            "providerRunAttempt".to_owned(),
            crate::assurance::JsonValue::Number(input.run_attempt),
        ),
        (
            "providerArtifactId".to_owned(),
            crate::assurance::JsonValue::Number(input.artifact_id),
        ),
        (
            "providerDirectorySha256".to_owned(),
            crate::assurance::JsonValue::String(input.expected_directory_sha256.to_owned()),
        ),
        (
            "providerArchiveSha256".to_owned(),
            crate::assurance::JsonValue::String(input.expected_archive_sha256.to_owned()),
        ),
        (
            "providerSelectionSha256".to_owned(),
            crate::assurance::JsonValue::String(sha256_bytes(selection.as_bytes()).hex()),
        ),
    ]);
    fields.extend(activation_proposal_content_fields(output, artifacts)?);
    Ok(crate::assurance::JsonValue::Object(fields))
}

fn activation_proposal_content_fields(
    output: &Path,
    artifacts: &BTreeSet<String>,
) -> Result<BTreeMap<String, crate::assurance::JsonValue>, String> {
    let digest = |path: &str| {
        sha256_file(&output.join(path))
            .map(hell_testkit::Digest::hex)
            .map_err(|error| error.to_string())
    };
    Ok(BTreeMap::from([
        (
            "activationClaimsSha256".to_owned(),
            crate::assurance::JsonValue::String(digest(
                "tree/compat/collection-activation-claims.json",
            )?),
        ),
        (
            "activationManifestSha256".to_owned(),
            crate::assurance::JsonValue::String(digest("tree/compat/collection-activation.toml")?),
        ),
        (
            "prospectiveCatalogLockSha256".to_owned(),
            crate::assurance::JsonValue::String(digest("tree/compat/locks/catalog-digests.json")?),
        ),
        (
            "prospectiveEpochLockSha256".to_owned(),
            crate::assurance::JsonValue::String(digest("tree/compat/locks/assurance-epoch.json")?),
        ),
        (
            "corpusMappingSha256".to_owned(),
            crate::assurance::JsonValue::String(digest("corpus-mapping.json")?),
        ),
        (
            "coverageDeltaSha256".to_owned(),
            crate::assurance::JsonValue::String(digest("coverage-delta.json")?),
        ),
        (
            "reviewedArtifacts".to_owned(),
            crate::assurance::JsonValue::Array(
                artifacts
                    .iter()
                    .cloned()
                    .map(crate::assurance::JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "worktreeMutated".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "activationAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "promotionAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
    ]))
}

fn seal_activation_proposal(output: &Path) -> Result<(), String> {
    let expected = [
        "activation-proposal.json",
        "authorship-subject.json",
        "corpus-mapping.json",
        "coverage-delta.json",
        "custody-admission/collection-custody-activation-token.json",
        "custody-admission/collection-custody-activation-token.json.sha256",
        "custody-admission/collection-custody-admission.json",
        "custody-admission/collection-custody-admission.json.sha256",
        "provider-selection/provider-selected-artifact.json",
        "provider-selection/provider-selected-run.json",
        "provider-selection/provider-selection.json",
        "tree/compat/collection-activation-claims.json",
        "tree/compat/collection-activation.toml",
        "tree/compat/locks/assurance-epoch.json",
        "tree/compat/locks/catalog-digests.json",
    ];
    let mut manifest = String::from("sha256\tbytes\tpath\n");
    for path in expected {
        let bytes = read_file(&output.join(path))?;
        writeln!(
            manifest,
            "{}\t{}\t{path}",
            sha256_bytes(&bytes).hex(),
            bytes.len()
        )
        .expect("writing to String cannot fail");
    }
    write_file(&output.join("proposal-manifest.tsv"), manifest.as_bytes())?;
    write_file(
        &output.join("root.sha256"),
        format!("{}\n", sha256_bytes(manifest.as_bytes()).hex()).as_bytes(),
    )
}

/// Replays the exact current candidate and emits deterministic unsigned review material.
///
/// The output has no signature or promotion authority. A role-qualified reviewer must sign the
/// emitted payload before the resulting DSSE envelope can be committed and admitted.
pub(crate) fn prepare_custody_review(
    root: &Path,
    input: &PrepareCustodyReviewInput<'_>,
) -> Result<(), String> {
    require_tracked_preparation_inputs(root, input)?;
    let review_governance = review_governance(root)?;
    let core = verify_core(root, input.package)?;
    let signature_root = verify_retained_attestation(&core, input.signature)?;
    let revocations = read_file(&root.join("compat/collection-authority-revocations.toml"))?;
    verify_current_revocations(&core, &revocations)?;
    let replay = replay_current_candidate(root, input.package, input.candidate_executable)?;
    require_controlled_preparation_delta(root, &core.candidate_commit)?;
    let authority = IntegrationAuthority {
        core: &core,
        package_root: Digest::from_hex(&crate::assurance::record_digest(input.package)?)
            .map_err(str::to_owned)?,
        signature_root,
        revocations: sha256_bytes(&revocations),
        review_governance,
        replay: &replay,
    };
    let proof = render_integration_proof(&authority);
    let proof_sha256 = sha256_bytes(proof.as_bytes());
    let artifacts = integration_review_artifacts(&authority, proof_sha256);
    let (payload, review_id) = crate::assurance::render_unsigned_custody_review_payload(
        &root.join("compat/reviews.allowed_signers"),
        &crate::assurance::UnsignedReviewPayloadInput {
            reviewer: input.reviewer,
            issued_at: input.issued_at,
            candidate: &core.candidate_commit,
            epoch: &core.payload_merkle_root.hex(),
            reviewed_artifacts: &artifacts,
        },
    )?;
    let proof_output = input.output.join("integration-proof.tsv");
    require_report_outside_authority(root, &proof_output)?;
    let output_relative = canonical_checkout_relative(root, input.output)?;
    let output = root.join(output_relative);
    match fs::symlink_metadata(&output) {
        Ok(_) => {
            return Err("collection custody review preparation output already exists".to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect collection custody review preparation output: {error}"
            ));
        }
    }
    let payload_sha256 = sha256_bytes(&payload);
    let unsigned_dsse = format!(
        "{{\"payloadType\":\"application/vnd.hell-rs.assurance+json\",\"payload\":\"{}\",\"signatures\":[]}}\n",
        crate::assurance::encode_base64(&payload)
    );
    let request = render_review_request(
        &authority,
        input.reviewer,
        input.issued_at,
        proof_sha256,
        payload_sha256,
        &review_id,
    );
    let output_parent = output
        .parent()
        .ok_or_else(|| "collection custody review output has no parent".to_owned())?;
    fs::create_dir_all(output_parent)
        .map_err(|error| format!("cannot create collection custody review parent: {error}"))?;
    fs::create_dir(&output)
        .map_err(|error| format!("cannot create collection custody review output: {error}"))?;
    write_file(&output.join("integration-proof.tsv"), proof.as_bytes())?;
    write_file(&output.join("integration-review-payload.json"), &payload)?;
    write_file(
        &output.join("integration-review-unsigned.dsse.json"),
        unsigned_dsse.as_bytes(),
    )?;
    write_file(
        &output.join("integration-review-request.tsv"),
        request.as_bytes(),
    )
}

fn render_review_request(
    authority: &IntegrationAuthority<'_>,
    reviewer: &str,
    issued_at: &str,
    proof_sha256: Digest,
    payload_sha256: Digest,
    review_id: &str,
) -> String {
    format!(
        concat!(
            "schemaVersion\t1\n",
            "domain\thell.collection-custody.review-request.v1\n",
            "state\tunsigned-requires-custody-reviewer\n",
            "role\tcustody-reviewer\n",
            "reviewer\t{}\n",
            "issuedAt\t{}\n",
            "candidateCommit\t{}\n",
            "payloadMerkleRoot\t{}\n",
            "packageTreeSha256\t{}\n",
            "signatureTreeSha256\t{}\n",
            "integrationProofSha256\t{}\n",
            "reviewPayloadSha256\t{}\n",
            "reviewId\t{}\n",
            "promotionAuthority\tfalse\n"
        ),
        reviewer,
        issued_at,
        authority.core.candidate_commit,
        authority.core.payload_merkle_root.hex(),
        authority.package_root.hex(),
        authority.signature_root.hex(),
        proof_sha256.hex(),
        payload_sha256.hex(),
        review_id,
    )
}

pub(crate) fn verify_prepared_custody_review(root: &Path, input: &Path) -> Result<(), String> {
    let files = read_prepared_review_files(root, input)?;
    require_tracked_review_governance(root)?;
    let proof_fields = parse_assignments(&files.proof)?;
    let request_fields = parse_assignments(&files.request)?;
    let review = crate::assurance::verify_unsigned_custody_review_payload(
        &root.join("compat/reviews.allowed_signers"),
        &files.payload,
    )?;
    let required = |fields: &BTreeMap<&str, &str>, key| {
        fields
            .get(key)
            .map(|value| (*value).to_owned())
            .ok_or_else(|| format!("prepared custody review omits {key}"))
    };
    let proof_sha256 = sha256_bytes(&files.proof).hex();
    let payload_sha256 = sha256_bytes(&files.payload).hex();
    let reviewed_artifacts = BTreeSet::from([
        required(&proof_fields, "packageTreeSha256")?,
        required(&proof_fields, "signatureTreeSha256")?,
        required(&proof_fields, "revocationPolicySha256")?,
        required(&proof_fields, "allowedSignersSha256")?,
        required(&proof_fields, "reviewRevocationsSha256")?,
        required(&proof_fields, "surveillancePolicySha256")?,
        required(&proof_fields, "trustRootsSha256")?,
        required(&proof_fields, "replayObservationRootSha256")?,
        proof_sha256.clone(),
    ]);
    verify_prepared_review_bindings(&PreparedReviewBindings {
        proof_fields: &proof_fields,
        request_fields: &request_fields,
        review: &review,
        reviewed_artifacts: &reviewed_artifacts,
        proof_sha256: &proof_sha256,
        payload_sha256: &payload_sha256,
        payload: &files.payload,
        unsigned: &files.unsigned,
    })
}

pub(crate) fn verify_worm_artifact(
    root: &Path,
    input: &Path,
    expected_directory_sha256: &str,
) -> Result<(), String> {
    let relative = canonical_checkout_relative(root, input)?;
    if relative != Path::new("ci-in/collection-worm-custody") {
        return Err("collection WORM custody artifact path is not canonical".to_owned());
    }
    Digest::from_hex(expected_directory_sha256)
        .map_err(|_| "collection WORM custody directory digest is invalid".to_owned())?;
    let directory = root.join(relative);
    let observed = crate::custody_ops::verified_directory_digest(&directory)?;
    if observed != expected_directory_sha256 {
        return Err("collection WORM custody artifact directory digest mismatch".to_owned());
    }
    require_exact_collection_worm_subject_inventory(&directory.join("subject"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_worm_provider_artifact(
    root: &Path,
    input: &Path,
    expected_directory_sha256: &str,
    expected_archive_sha256: &str,
    run_id: u64,
    run_attempt: u64,
    artifact_id: u64,
) -> Result<(), String> {
    verify_worm_artifact(root, input, expected_directory_sha256)?;
    Digest::from_hex(expected_archive_sha256)
        .map_err(|_| "collection WORM provider archive digest is invalid".to_owned())?;
    if run_id == 0 || run_attempt == 0 || artifact_id == 0 {
        return Err("collection WORM provider identifiers must be nonzero".to_owned());
    }
    let relative = canonical_checkout_relative(root, input)?;
    let directory = root.join(relative);
    let output = root.join("ci-out/collection-worm-provider-selection");
    if fs::symlink_metadata(&output).is_ok() {
        return Err("collection WORM provider selection output already exists".to_owned());
    }
    let head = current_head(root)?;
    let selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root,
            input_directory: &directory,
            output_directory: &output,
            artifact_name: &format!("collection-worm-custody-{run_id}-{run_attempt}"),
            workflow_path: ".github/workflows/evidence-custody.yml",
            event_name: "workflow_dispatch",
            run_id,
            run_attempt,
            artifact_id,
            provider_head: &head,
            candidate: &head,
            expected_directory_sha256,
            expected_archive_sha256,
        },
    )?;
    write_file(&output.join("selection.json"), selection.as_bytes())
}

struct PreparedReviewFiles {
    proof: Vec<u8>,
    payload: Vec<u8>,
    request: Vec<u8>,
    unsigned: Vec<u8>,
}

fn read_prepared_review_files(root: &Path, input: &Path) -> Result<PreparedReviewFiles, String> {
    if canonical_checkout_relative(root, input)? != Path::new("ci-in/collection-custody-review") {
        return Err("prepared custody review input path is not canonical".to_owned());
    }
    let directory = root.join("ci-in/collection-custody-review");
    let metadata = fs::symlink_metadata(&directory)
        .map_err(|error| format!("cannot inspect prepared custody review: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("prepared custody review is not a real directory".to_owned());
    }
    let expected_files = [
        "integration-proof.tsv",
        "integration-review-payload.json",
        "integration-review-request.tsv",
        "integration-review-unsigned.dsse.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let mut files = BTreeSet::new();
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("cannot enumerate prepared custody review: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot read prepared review entry: {error}"))?;
        let entry_metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect prepared review entry: {error}"))?;
        if entry_metadata.file_type().is_symlink() || !entry_metadata.is_file() {
            return Err("prepared custody review contains a non-regular file".to_owned());
        }
        files.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "prepared custody review filename is not UTF-8".to_owned())?,
        );
    }
    if files != expected_files {
        return Err("prepared custody review inventory is not exact".to_owned());
    }
    Ok(PreparedReviewFiles {
        proof: read_file(&directory.join("integration-proof.tsv"))?,
        payload: read_file(&directory.join("integration-review-payload.json"))?,
        request: read_file(&directory.join("integration-review-request.tsv"))?,
        unsigned: read_file(&directory.join("integration-review-unsigned.dsse.json"))?,
    })
}

struct PreparedReviewBindings<'a> {
    proof_fields: &'a BTreeMap<&'a str, &'a str>,
    request_fields: &'a BTreeMap<&'a str, &'a str>,
    review: &'a crate::assurance::VerifiedUnsignedCustodyReview,
    reviewed_artifacts: &'a BTreeSet<String>,
    proof_sha256: &'a str,
    payload_sha256: &'a str,
    payload: &'a [u8],
    unsigned: &'a [u8],
}

fn verify_prepared_review_bindings(bindings: &PreparedReviewBindings<'_>) -> Result<(), String> {
    let proof_fields = bindings.proof_fields;
    let request_fields = bindings.request_fields;
    let review = bindings.review;
    let expected_request_keys = BTreeSet::from([
        "schemaVersion",
        "domain",
        "state",
        "role",
        "reviewer",
        "issuedAt",
        "candidateCommit",
        "payloadMerkleRoot",
        "packageTreeSha256",
        "signatureTreeSha256",
        "integrationProofSha256",
        "reviewPayloadSha256",
        "reviewId",
        "promotionAuthority",
    ]);
    let expected_unsigned = format!(
        "{{\"payloadType\":\"application/vnd.hell-rs.assurance+json\",\"payload\":\"{}\",\"signatures\":[]}}\n",
        crate::assurance::encode_base64(bindings.payload)
    );
    if proof_fields.get("domain") != Some(&"hell.collection-custody.integration.v1")
        || proof_fields.get("state") != Some(&"controlled-custody-overlay-pending-review")
        || proof_fields.get("promotionAuthority") != Some(&"false")
        || request_fields.keys().copied().collect::<BTreeSet<_>>() != expected_request_keys
        || request_fields.get("schemaVersion") != Some(&"1")
        || request_fields.get("domain") != Some(&"hell.collection-custody.review-request.v1")
        || request_fields.get("state") != Some(&"unsigned-requires-custody-reviewer")
        || request_fields.get("role") != Some(&"custody-reviewer")
        || request_fields.get("reviewer") != Some(&review.reviewer.as_str())
        || request_fields.get("issuedAt") != Some(&review.issued_at.as_str())
        || request_fields.get("reviewId") != Some(&review.review_id.as_str())
        || request_fields.get("candidateCommit") != Some(&review.candidate.as_str())
        || request_fields.get("payloadMerkleRoot") != Some(&review.epoch.as_str())
        || request_fields.get("candidateCommit") != proof_fields.get("candidateCommit")
        || request_fields.get("payloadMerkleRoot") != proof_fields.get("payloadMerkleRoot")
        || request_fields.get("packageTreeSha256") != proof_fields.get("packageTreeSha256")
        || request_fields.get("signatureTreeSha256") != proof_fields.get("signatureTreeSha256")
        || request_fields.get("integrationProofSha256") != Some(&bindings.proof_sha256)
        || request_fields.get("reviewPayloadSha256") != Some(&bindings.payload_sha256)
        || request_fields.get("promotionAuthority") != Some(&"false")
        || review.reviewed_artifacts != *bindings.reviewed_artifacts
        || bindings.unsigned != expected_unsigned.as_bytes()
    {
        return Err("prepared custody review is not internally exact and bound".to_owned());
    }
    Ok(())
}

/// Revalidates durable collection custody and replays the current candidate.
///
/// This is deliberately a verifier, not an authority generator. The package,
/// signature, and protected integration proof must already be tracked in the
/// current checkout. No compatibility claim or catalog count is changed here.
pub(crate) fn verify_durable_admission(
    root: &Path,
    input: &VerifyCustodyInput<'_>,
) -> Result<(), String> {
    let verified = verify_admission_authority(root, input)?;
    let worm_custody = input
        .worm_custody
        .map(|evidence| verify_worm_custody(root, evidence, &verified))
        .transpose()?;
    require_report_outside_authority(root, input.report)?;
    let report = render_admission_report(&verified, worm_custody)?;
    if input.report.exists() || input.report.with_extension("json.sha256").exists() {
        return Err("collection custody admission report already exists".to_owned());
    }
    if let Some(parent) = input.report.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create collection custody report: {error}"))?;
    }
    write_file(input.report, report.as_bytes())?;
    write_file(
        &input.report.with_extension("json.sha256"),
        format!(
            "{}  {}\n",
            sha256_bytes(report.as_bytes()).hex(),
            input
                .report
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| "collection custody report filename is not UTF-8".to_owned())?
        )
        .as_bytes(),
    )?;
    if let Some(worm_identity) = worm_custody {
        let token = render_activation_preparation_token(&verified, worm_identity, &report)?;
        let token_path = input
            .report
            .with_file_name("collection-custody-activation-token.json");
        let token_digest_path = token_path.with_extension("json.sha256");
        for path in [&token_path, &token_digest_path] {
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(
                        "collection custody activation preparation token already exists".to_owned(),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "cannot inspect collection custody activation token: {error}"
                    ));
                }
            }
        }
        write_file(&token_path, &token)?;
        write_file(
            &token_digest_path,
            format!(
                "{}  collection-custody-activation-token.json\n",
                sha256_bytes(&token).hex()
            )
            .as_bytes(),
        )?;
    }
    Ok(())
}

struct VerifiedAdmissionAuthority {
    core: VerifiedCollectionCustodyCore,
    package_root: Digest,
    signature_root: Digest,
    revocations: Digest,
    review_governance: ReviewGovernance,
    replay: CollectionCustodyReplay,
    integration: VerifiedIntegrationReview,
    custody_policy: Digest,
}

pub(crate) fn prepare_worm_custody(
    root: &Path,
    input: &PrepareWormCustodyInput<'_>,
) -> Result<(), String> {
    let verification = VerifyCustodyInput {
        package: input.package,
        signature: input.signature,
        candidate_executable: input.candidate_executable,
        integration_proof: input.integration_proof,
        integration_review: input.integration_review,
        worm_custody: None,
        report: Path::new("ci-out/unused-collection-custody-report.json"),
    };
    verify_admission_authority(root, &verification)?;
    let output_relative = canonical_checkout_relative(root, input.output)?;
    if output_relative.components().next()
        != Some(std::path::Component::Normal(std::ffi::OsStr::new("ci-out")))
        || output_relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("collection WORM custody output must be under ci-out".to_owned());
    }
    let output = root.join(output_relative);
    let source = output.join("subject");
    prepare_worm_output_parent(&output, &source)?;
    fs::create_dir(&source)
        .map_err(|error| format!("cannot create collection WORM subject: {error}"))?;
    for (path, name) in [(input.package, "payload"), (input.signature, "signature")] {
        copy_regular_tree(path, &source.join(name))?;
    }
    for (path, name) in [
        (input.integration_proof, "integration-proof.tsv"),
        (input.integration_review, "integration-review.dsse.json"),
    ] {
        let bytes = read_file(path)?;
        write_file(&source.join(name), &bytes)?;
    }
    let (current, epoch) = collection_worm_envelope_identity(root)?;
    crate::custody_ops::package_directory(
        &source,
        &output.join("custody-package"),
        &current,
        &epoch.hex(),
    )
}

fn prepare_worm_output_parent(output: &Path, source: &Path) -> Result<(), String> {
    match fs::symlink_metadata(output) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err("collection WORM custody output parent is not a real directory".to_owned());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(output)
                .map_err(|error| format!("cannot create collection WORM output: {error}"))?;
        }
        Err(error) => return Err(format!("cannot inspect collection WORM output: {error}")),
    }
    let custody_package = output.join("custody-package");
    for child in [source, custody_package.as_path()] {
        match fs::symlink_metadata(child) {
            Ok(_) => return Err("collection WORM custody output child already exists".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect collection WORM output child: {error}"
                ));
            }
        }
    }
    Ok(())
}

fn copy_regular_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect collection WORM subject: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("collection WORM subject input is not a real directory".to_owned());
    }
    fs::create_dir(destination)
        .map_err(|error| format!("cannot create collection WORM subject tree: {error}"))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("cannot enumerate collection WORM subject: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot read collection WORM entry: {error}"))?;
        let metadata = entry
            .file_type()
            .map_err(|error| format!("cannot inspect collection WORM entry: {error}"))?;
        let target = destination.join(entry.file_name());
        if metadata.is_dir() {
            copy_regular_tree(&entry.path(), &target)?;
        } else if metadata.is_file() && !metadata.is_symlink() {
            fs::copy(entry.path(), target)
                .map_err(|error| format!("cannot copy collection WORM subject: {error}"))?;
        } else {
            return Err("collection WORM subject contains a non-regular entry".to_owned());
        }
    }
    Ok(())
}

fn verify_worm_custody(
    root: &Path,
    evidence: &Path,
    verified: &VerifiedAdmissionAuthority,
) -> Result<Digest, String> {
    let relative = canonical_checkout_relative(root, evidence)?;
    if relative != Path::new("ci-in/collection-worm-custody") {
        return Err("collection WORM custody evidence path is not canonical".to_owned());
    }
    let evidence = root.join(relative);
    let subject = evidence.join("subject");
    require_collection_worm_subject(&subject, verified)?;
    let (current, epoch) = collection_worm_envelope_identity(root)?;
    crate::custody_ops::verify_current_scrub_subject(
        &evidence,
        &root.join("compat/reviews.allowed_signers"),
        &root.join("compat/custody-policy.toml"),
        &subject,
        &current,
        &epoch.hex(),
    )
}

fn collection_worm_envelope_identity(root: &Path) -> Result<(String, Digest), String> {
    let current = current_head(root)?;
    let (_, epoch) = crate::assurance::epoch(root)?;
    Ok((current, epoch))
}

fn require_collection_worm_subject(
    subject: &Path,
    verified: &VerifiedAdmissionAuthority,
) -> Result<(), String> {
    require_exact_collection_worm_subject_inventory(subject)?;
    let payload = subject.join("payload");
    let signature = subject.join("signature");
    let proof = subject.join("integration-proof.tsv");
    let review = subject.join("integration-review.dsse.json");
    if crate::assurance::record_digest(&payload)? != verified.package_root.hex()
        || crate::assurance::record_digest(&signature)? != verified.signature_root.hex()
        || sha256_file(&proof).map_err(|error| error.to_string())?
            != verified.integration.proof_sha256
        || sha256_file(&review).map_err(|error| error.to_string())?
            != verified.integration.review_sha256
    {
        return Err("collection WORM custody subject differs from admitted overlay".to_owned());
    }
    Ok(())
}

fn require_exact_collection_worm_subject_inventory(subject: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(subject)
        .map_err(|error| format!("cannot inspect collection WORM subject: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("collection WORM custody subject is not a real directory".to_owned());
    }
    let expected = BTreeSet::from([
        "integration-proof.tsv".to_owned(),
        "integration-review.dsse.json".to_owned(),
        "payload".to_owned(),
        "signature".to_owned(),
    ]);
    let observed = fs::read_dir(subject)
        .map_err(|error| format!("cannot enumerate collection WORM subject: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot read collection WORM subject entry: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "collection WORM subject filename is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed != expected {
        return Err("collection WORM custody subject inventory is not exact".to_owned());
    }
    for (name, directory) in [
        ("payload", true),
        ("signature", true),
        ("integration-proof.tsv", false),
        ("integration-review.dsse.json", false),
    ] {
        let metadata = fs::symlink_metadata(subject.join(name))
            .map_err(|error| format!("cannot inspect collection WORM subject: {error}"))?;
        if metadata.file_type().is_symlink()
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            return Err("collection WORM custody subject contains a noncanonical node".to_owned());
        }
    }
    Ok(())
}

fn verify_admission_authority(
    root: &Path,
    input: &VerifyCustodyInput<'_>,
) -> Result<VerifiedAdmissionAuthority, String> {
    require_tracked_custody_inputs(root, input)?;
    let review_governance = review_governance(root)?;
    let custody_policy_path = root.join("compat/custody-policy.toml");
    require_tracked_paths(
        root,
        &[(
            custody_policy_path.as_path(),
            "compat/custody-policy.toml",
            false,
        )],
    )?;
    let custody_policy = sha256_file(&custody_policy_path).map_err(|error| error.to_string())?;
    let core = verify_core(root, input.package)?;
    let signature_root = verify_retained_attestation(&core, input.signature)?;
    let revocations_path = root.join("compat/collection-authority-revocations.toml");
    let revocations = read_file(&revocations_path)?;
    verify_current_revocations(&core, &revocations)?;
    let replay = replay_current_candidate(root, input.package, input.candidate_executable)?;
    require_controlled_integration_delta(root, &core.candidate_commit)?;
    let package_root = Digest::from_hex(&crate::assurance::record_digest(input.package)?)
        .map_err(str::to_owned)?;
    let integration_authority = IntegrationAuthority {
        core: &core,
        package_root,
        signature_root,
        revocations: sha256_bytes(&revocations),
        review_governance,
        replay: &replay,
    };
    verify_integration_proof(root, input.integration_proof, &integration_authority)?;
    let integration = verify_signed_integration_review(
        root,
        input.integration_proof,
        input.integration_review,
        &integration_authority,
    )?;
    Ok(VerifiedAdmissionAuthority {
        core,
        package_root,
        signature_root,
        revocations: sha256_bytes(&revocations),
        review_governance,
        replay,
        integration,
        custody_policy,
    })
}

fn verify_retained_attestation(
    core: &VerifiedCollectionCustodyCore,
    signature: &Path,
) -> Result<Digest, String> {
    let expected = BTreeSet::from([
        "attestation-bundle.json",
        "custody-handoff.tsv",
        "gh-install-manifest.json",
        "online-verification.json",
        "online-verification.raw.json",
        "trusted-root-provenance.json",
        "trusted-root.jsonl",
    ]);
    let observed = regular_inventory(signature)?;
    if observed != expected.into_iter().map(str::to_owned).collect() {
        return Err("collection custody signature inventory is missing or extra".to_owned());
    }
    let bundle = read_file(&signature.join("attestation-bundle.json"))?;
    let trusted_root = read_file(&signature.join("trusted-root.jsonl"))?;
    let provenance = read_file(&signature.join("trusted-root-provenance.json"))?;
    let raw = read_file(&signature.join("online-verification.raw.json"))?;
    let verification = read_file(&signature.join("online-verification.json"))?;
    let install = read_file(&signature.join("gh-install-manifest.json"))?;
    verify_gh_install_manifest(&install)?;
    verify_online_attestation_records(
        core,
        sha256_bytes(&bundle),
        sha256_bytes(&trusted_root),
        &raw,
        &provenance,
        &verification,
        sha256_bytes(&install),
    )?;
    verify_custody_handoff(core, signature)?;
    Digest::from_hex(&crate::assurance::record_digest(signature)?).map_err(str::to_owned)
}

fn verify_custody_handoff(
    core: &VerifiedCollectionCustodyCore,
    signature: &Path,
) -> Result<(), String> {
    let handoff = read_file(&signature.join("custody-handoff.tsv"))?;
    let fields = parse_assignments(&handoff)?;
    let expected_keys = BTreeSet::from([
        "schemaVersion",
        "domain",
        "state",
        "candidateCommit",
        "providerHeadCommit",
        "repositoryId",
        "providerRunId",
        "providerRunAttempt",
        "payloadMerkleRoot",
        "subjectSha256",
        "bundleSha256",
        "trustedRootSha256",
        "trustedRootProvenanceSha256",
        "rawVerificationSha256",
        "onlineVerificationSha256",
        "ghInstallManifestSha256",
        "packageDestination",
        "signatureDestination",
        "requiredVerifyCommand",
        "integrationPolicyVersion",
    ]);
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected_keys
        || fields.get("schemaVersion") != Some(&"1")
        || fields.get("domain") != Some(&"hell.collection-custody.handoff.v1")
        || fields.get("state") != Some(&"prepared/unintegrated/non-authoritative")
        || fields.get("candidateCommit") != Some(&core.candidate_commit.as_str())
        || fields.get("providerHeadCommit") != Some(&core.provider_head.as_str())
        || required_u64(&fields, "repositoryId")? != core.repository_id
        || required_u64(&fields, "providerRunId")? != core.run_id
        || required_u64(&fields, "providerRunAttempt")? != core.run_attempt
        || fields.get("payloadMerkleRoot") != Some(&core.payload_merkle_root.hex().as_str())
        || fields.get("subjectSha256") != Some(&core.subject_sha256.hex().as_str())
        || fields.get("packageDestination") != Some(&"compat/collection-custody/payload")
        || fields.get("signatureDestination") != Some(&"compat/collection-custody/signature")
        || fields.get("integrationPolicyVersion") != Some(&"1")
        || fields.get("requiredVerifyCommand")
            != Some(
                &"hell-ci collection-authority verify-custody --package compat/collection-custody/payload --signature compat/collection-custody/signature --candidate-executable <trusted-current-candidate> --integration-proof compat/collection-custody/integration-proof.tsv --integration-review compat/collection-custody/integration-review.dsse.json --report <report>",
            )
    {
        return Err("collection custody handoff is not exact".to_owned());
    }
    for (field, relative) in [
        ("bundleSha256", "attestation-bundle.json"),
        ("trustedRootSha256", "trusted-root.jsonl"),
        (
            "trustedRootProvenanceSha256",
            "trusted-root-provenance.json",
        ),
        ("rawVerificationSha256", "online-verification.raw.json"),
        ("onlineVerificationSha256", "online-verification.json"),
        ("ghInstallManifestSha256", "gh-install-manifest.json"),
    ] {
        if fields.get(field).copied()
            != Some(
                sha256_file(&signature.join(relative))
                    .map_err(|error| error.to_string())?
                    .hex()
                    .as_str(),
            )
        {
            return Err(format!("collection custody handoff {field} differs"));
        }
    }
    Ok(())
}

fn regular_inventory(directory: &Path) -> Result<BTreeSet<String>, String> {
    fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("cannot inspect custody entry: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect custody entry type: {error}"))?;
            if !kind.is_file() || kind.is_symlink() {
                return Err("collection custody signature contains a nonregular entry".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "collection custody signature filename is not UTF-8".to_owned())
        })
        .collect()
}

fn verify_current_revocations(
    core: &VerifiedCollectionCustodyCore,
    bytes: &[u8],
) -> Result<(), String> {
    let expected = concat!(
        "schema_version = 1\n",
        "state = \"active\"\n",
        "revoked_subject_sha256 = []\n",
        "revoked_payload_merkle_roots = []\n",
        "revoked_candidate_commits = []\n",
        "revoked_provider_head_commits = []\n",
        "revoked_provider_run_ids = []\n",
    );
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection authority revocations are not UTF-8".to_owned())?;
    if document == expected {
        return Ok(());
    }
    let values = parse_revocation_document(document)?;
    for (field, value) in [
        ("revoked_subject_sha256", core.subject_sha256.hex()),
        (
            "revoked_payload_merkle_roots",
            core.payload_merkle_root.hex(),
        ),
        ("revoked_candidate_commits", core.candidate_commit.clone()),
        ("revoked_provider_head_commits", core.provider_head.clone()),
        ("revoked_provider_run_ids", core.run_id.to_string()),
    ] {
        if values
            .get(field)
            .is_some_and(|entries| entries.iter().any(|entry| entry == &value))
        {
            return Err(format!(
                "collection custody authority is revoked by {field}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn parse_revocation_document(
    document: &str,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut lines = document.lines();
    if lines.next() != Some("schema_version = 1") || lines.next() != Some("state = \"active\"") {
        return Err("collection authority revocation header is noncanonical".to_owned());
    }
    let expected = [
        "revoked_subject_sha256",
        "revoked_payload_merkle_roots",
        "revoked_candidate_commits",
        "revoked_provider_head_commits",
        "revoked_provider_run_ids",
    ];
    let mut parsed = BTreeMap::new();
    for key in expected {
        let line = lines
            .next()
            .ok_or_else(|| "collection authority revocation field is missing".to_owned())?;
        let prefix = format!("{key} = [");
        let encoded = line
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(']'))
            .ok_or_else(|| "collection authority revocation field is noncanonical".to_owned())?;
        let mut values = Vec::new();
        if !encoded.is_empty() {
            for entry in encoded.split(", ") {
                let value = entry
                    .strip_prefix('"')
                    .and_then(|entry| entry.strip_suffix('"'))
                    .filter(|entry| !entry.is_empty())
                    .ok_or_else(|| {
                        "collection authority revocation value is noncanonical".to_owned()
                    })?;
                atom(value)?;
                values.push(value.to_owned());
            }
        }
        if values.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("collection authority revocations are duplicated or unsorted".to_owned());
        }
        parsed.insert(key.to_owned(), values);
    }
    if lines.next().is_some() {
        return Err("collection authority revocations contain extra fields".to_owned());
    }
    Ok(parsed)
}

struct CurrentReplaySetup {
    current_candidate_commit: String,
    identity: hell_testkit::ExecutableIdentity,
    authorities: BTreeMap<String, hell_testkit::CollectionCaseAuthority>,
    records: BTreeMap<String, Vec<String>>,
    cases: Vec<hell_testkit::DifferentialCase>,
}

fn replay_current_candidate(
    root: &Path,
    package: &Path,
    candidate_executable: &Path,
) -> Result<CollectionCustodyReplay, String> {
    let current_candidate_commit = current_head(root)?;
    let core = verify_core(root, package)?;
    require_ancestor(root, &core.candidate_commit, &current_candidate_commit)?;
    let identity = hell_testkit::verify_executable(
        candidate_executable,
        hell_testkit::ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("current collection candidate identity is invalid: {error}"))?;
    let built_commit = identity
        .build_info
        .as_ref()
        .and_then(|build| {
            build
                .lines
                .iter()
                .find_map(|line| line.strip_prefix("source commit "))
        })
        .ok_or_else(|| "current collection candidate has no source commit".to_owned())?;
    if built_commit != current_candidate_commit
        || !identity.build_info.as_ref().is_some_and(|build| {
            build
                .lines
                .iter()
                .any(|line| line.as_ref() == "compatibility evidence schema 1")
        })
    {
        return Err("current collection candidate executable is not built from HEAD".to_owned());
    }
    let source = hell_testkit::verify_collection_source_authority(root)
        .map_err(|error| error.to_string())?;
    let authorities = hell_testkit::reviewed_collection_case_authorities(&source)?
        .into_iter()
        .map(|case| (case.case_id.to_string(), case))
        .collect::<BTreeMap<_, _>>();
    let records = linux_replay_records(package)?;
    if authorities.len() != 1_191 || records.len() != 1_191 {
        return Err("current collection replay inventory is not exact Map712/Set479".to_owned());
    }
    let mut cases = hell_testkit::reviewed_collection_cases()?;
    verify_supplemental_coverage_delta(&cases)?;
    crate::suite::bind_runtime_process_helper(&mut cases)?;
    cases.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    execute_current_replay(CurrentReplaySetup {
        current_candidate_commit,
        identity,
        authorities,
        records,
        cases,
    })
}

fn execute_current_replay(setup: CurrentReplaySetup) -> Result<CollectionCustodyReplay, String> {
    let scratch = ReplayScratch::new()?;
    let mut root_bytes = b"hell-collection-current-candidate-replay-v1\0".to_vec();
    let mut map_cases = 0_usize;
    let mut set_cases = 0_usize;
    for case in &setup.cases {
        let authority = setup
            .authorities
            .get(case.id.as_ref())
            .ok_or_else(|| "current collection replay contains an extra case".to_owned())?;
        let record = setup
            .records
            .get(case.id.as_ref())
            .ok_or_else(|| "current collection replay lacks a retained Linux record".to_owned())?;
        verify_replay_case_authority(authority, record)?;
        let verified = hell_testkit::observe_verified_executable_profile(
            &setup.identity,
            case,
            hell_builtins::ExecutionProfile::Upstream,
        )
        .map_err(|error| format!("current collection replay case {} failed: {error}", case.id))?;
        let observation = &verified.observation;
        hell_testkit::retain_verified_profile_observation(
            &scratch.path.join(case.id.as_ref()),
            case,
            &verified,
        )
        .map_err(|error| {
            format!(
                "current collection replay case {} failed production semantic validation: {error}",
                case.id
            )
        })?;
        let status = sha256_bytes(&canonical_process_status_bytes(
            observation.status.success,
            observation.status.code,
        ));
        let typed = observation
            .semantic
            .as_ref()
            .and_then(|semantic| semantic.typed_result_sha256)
            .ok_or_else(|| "current collection replay lacks a typed result".to_owned())?;
        if observation.timed_out
            || observation
                .resource_audit
                .as_ref()
                .map_or(usize::MAX, hell_testkit::ResourceAudit::failure_count)
                != 0
            || observation.stdout.sha256.hex() != record[37]
            || observation.raw_stderr.sha256.hex() != record[38]
            || status.hex() != record[39]
            || typed.hex() != record[40]
            || authority.comparator_contract_sha256.hex() != record[41]
            || completion(authority.expected_completion) != record[43]
        {
            return Err(format!(
                "current collection replay case {} differs from durable authority",
                case.id
            ));
        }
        let family = if authority.target_builtin.starts_with("Map.") {
            map_cases = map_cases.saturating_add(1);
            "map"
        } else if authority.target_builtin.starts_with("Set.") {
            set_cases = set_cases.saturating_add(1);
            "set"
        } else {
            return Err("current collection replay target is not Map or Set".to_owned());
        };
        for value in [
            case.id.as_bytes(),
            family.as_bytes(),
            verified.source_sha256.hex().as_bytes(),
            verified.execution_input_sha256.hex().as_bytes(),
            observation.stdout.sha256.hex().as_bytes(),
            observation.raw_stderr.sha256.hex().as_bytes(),
            status.hex().as_bytes(),
            typed.hex().as_bytes(),
            authority.comparator_contract_sha256.hex().as_bytes(),
        ] {
            push_frame(&mut root_bytes, value);
        }
    }
    if map_cases != 712 || set_cases != 479 {
        return Err("current collection replay does not close the exact supplemental delta".into());
    }
    Ok(CollectionCustodyReplay {
        current_candidate_commit: setup.current_candidate_commit,
        candidate_executable_sha256: setup.identity.sha256,
        replay_root_sha256: sha256_bytes(&root_bytes),
        map_cases,
        set_cases,
    })
}

fn linux_replay_records(package: &Path) -> Result<BTreeMap<String, Vec<String>>, String> {
    let records = read_file(&package.join("records.tsv"))?;
    let document = std::str::from_utf8(&records)
        .map_err(|_| "collection custody records are not UTF-8".to_owned())?;
    let mut result = BTreeMap::new();
    for line in document.lines().skip(1) {
        let fields = line.split('\t').map(str::to_owned).collect::<Vec<_>>();
        if fields.len() != RECORD_FIELD_COUNT {
            return Err("collection custody replay record is malformed".to_owned());
        }
        if fields[0] == "linux-amd64" && result.insert(fields[1].clone(), fields).is_some() {
            return Err("collection custody replay record is duplicated".to_owned());
        }
    }
    Ok(result)
}

fn verify_replay_case_authority(
    authority: &hell_testkit::CollectionCaseAuthority,
    record: &[String],
) -> Result<(), String> {
    if authority.operation.as_ref() != record[2]
        || authority.path.as_ref() != record[3]
        || authority.profile.as_str() != record[4]
        || authority.source_sha256.hex() != record[5]
        || authority.arguments_sha256.hex() != record[6]
        || authority.environment_sha256.hex() != record[7]
        || authority.stdin_sha256.hex() != record[8]
        || authority.execution_input_sha256.hex() != record[9]
        || authority.descriptor_sha256.hex() != record[10]
        || authority.target_builtin.as_ref() != record[11]
        || authority.instance_target.as_ref() != record[12]
        || authority.comparator_contract_sha256.hex() != record[13]
        || authority.source_authority_manifest_sha256.hex() != record[14]
        || optional_digest(authority.expected_candidate_typed_result_sha256) != record[15]
        || completion(authority.expected_completion) != record[16]
    {
        return Err("current collection case authority differs from durable record".to_owned());
    }
    Ok(())
}

fn verify_supplemental_coverage_delta(
    collection: &[hell_testkit::DifferentialCase],
) -> Result<(), String> {
    let baseline = hell_testkit::dormant_committed_differential_cases();
    require_coverage_counts(&baseline, 134, 14)?;
    require_exact_collection_scope_mapping(collection)?;
    let map = collection
        .iter()
        .filter(|case| case.id.starts_with("runtime-ord-map-"))
        .cloned()
        .collect::<Vec<_>>();
    let set = collection
        .iter()
        .filter(|case| case.id.starts_with("runtime-ord-set-"))
        .cloned()
        .collect::<Vec<_>>();
    if map.len() != 712 || set.len() != 479 {
        return Err("supplemental collection case partition is not exact".to_owned());
    }
    let mut map_only = baseline.clone();
    map_only.extend(map.iter().cloned());
    require_coverage_counts(&map_only, 127, 7)?;
    let mut set_only = baseline.clone();
    set_only.extend(set.iter().cloned());
    require_coverage_counts(&set_only, 127, 7)?;
    let mut combined = baseline;
    combined.extend(map);
    combined.extend(set);
    require_coverage_counts(&combined, 120, 0)
}

fn require_exact_collection_scope_mapping(
    collection: &[hell_testkit::DifferentialCase],
) -> Result<(), String> {
    let scopes = collection_scope_mapping(collection)?;
    let dormant = hell_testkit::dormant_committed_differential_cases();
    let mut activated = dormant.clone();
    activated.extend(collection.iter().cloned());
    for case in collection {
        let descriptor = case
            .claim_evidence
            .as_ref()
            .ok_or_else(|| "collection activation case lacks claim evidence".to_owned())?;
        let [target] = descriptor.semantic_targets.as_slice() else {
            return Err("collection activation case does not map to one exact scope".to_owned());
        };
        if descriptor.profile != hell_builtins::ExecutionProfile::Upstream
            || !descriptor.claim_normalizers.is_empty()
            || target.dimension != hell_builtins::CompatibilityDimension::PureRuntime
            || target.platforms
                != [
                    ClaimPlatform::Linux,
                    ClaimPlatform::MacOs,
                    ClaimPlatform::Windows,
                ]
        {
            return Err(
                "collection activation case scope is not upstream native PureRuntime".to_owned(),
            );
        }
    }
    let expected = BTreeSet::from([
        "Map.adjust",
        "Map.delete",
        "Map.fromList",
        "Map.insert",
        "Map.insertWith",
        "Map.lookup",
        "Map.unionWith",
        "Set.delete",
        "Set.difference",
        "Set.fromList",
        "Set.insert",
        "Set.intersection",
        "Set.member",
        "Set.union",
    ]);
    if scopes.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected
        || scopes.values().any(BTreeSet::is_empty)
    {
        return Err(
            "collection activation scope mapping is not the exact reviewed 14 cells".to_owned(),
        );
    }
    for builtin in expected {
        let instances = collection
            .iter()
            .filter_map(|case| case.claim_evidence.as_ref())
            .flat_map(|descriptor| &descriptor.semantic_targets)
            .filter(|target| target.builtin.as_ref() == builtin)
            .map(|target| target.expected_instance_target.as_deref())
            .collect::<BTreeSet<_>>();
        if instances.is_empty() || instances.contains(&None) {
            return Err("collection activation scope lacks an explicit instance target".to_owned());
        }
        let instance = instances
            .into_iter()
            .flatten()
            .next()
            .ok_or_else(|| "collection activation scope lacks an instance target".to_owned())?;
        if hell_testkit::runtime_obligation_scope_complete(
            &dormant,
            builtin,
            hell_builtins::CompatibilityDimension::PureRuntime,
            instance,
        )? || !hell_testkit::runtime_obligation_scope_complete(
            &activated,
            builtin,
            hell_builtins::CompatibilityDimension::PureRuntime,
            instance,
        )? {
            return Err(
                "collection activation scope does not change incomplete to complete".to_owned(),
            );
        }
    }
    Ok(())
}

fn collection_scope_mapping(
    collection: &[hell_testkit::DifferentialCase],
) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut scopes = BTreeMap::<String, BTreeSet<String>>::new();
    for case in collection {
        let descriptor = case
            .claim_evidence
            .as_ref()
            .ok_or_else(|| "collection activation case lacks claim evidence".to_owned())?;
        let [target] = descriptor.semantic_targets.as_slice() else {
            return Err("collection activation case does not map to one exact scope".to_owned());
        };
        scopes
            .entry(target.builtin.to_string())
            .or_default()
            .insert(case.id.to_string());
    }
    Ok(scopes)
}

fn render_active_collection_claims(
    collection: &[hell_testkit::DifferentialCase],
) -> Result<Vec<u8>, String> {
    require_exact_collection_scope_mapping(collection)?;
    hell_testkit::render_active_collection_claims()
}

fn require_coverage_counts(
    cases: &[hell_testkit::DifferentialCase],
    incomplete: usize,
    boundaries: usize,
) -> Result<(), String> {
    let error = match hell_testkit::validate_runtime_obligation_coverage(cases) {
        Ok(()) => {
            return Err(
                "supplemental collection catalog unexpectedly closes every runtime cell".to_owned(),
            );
        }
        Err(error) => error,
    };
    let expected = format!(
        "runtime obligation coverage has {incomplete} incomplete cells, {boundaries} boundary gaps, and 0 interaction gaps:"
    );
    if !error.starts_with(&expected) {
        return Err(format!(
            "supplemental collection coverage delta differs: {error}"
        ));
    }
    Ok(())
}

struct ReplayScratch {
    path: std::path::PathBuf,
}

impl ReplayScratch {
    fn new() -> Result<Self, String> {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock predates collection replay".to_owned())?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hell-collection-current-replay-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .map_err(|error| format!("cannot create current collection replay root: {error}"))?;
        Ok(Self { path })
    }
}

impl Drop for ReplayScratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct IntegrationAuthority<'a> {
    core: &'a VerifiedCollectionCustodyCore,
    package_root: Digest,
    signature_root: Digest,
    revocations: Digest,
    review_governance: ReviewGovernance,
    replay: &'a CollectionCustodyReplay,
}

#[derive(Clone, Copy)]
struct ReviewGovernance {
    allowed_signers: Digest,
    review_revocations: Digest,
    surveillance_policy: Digest,
    trust_roots: Digest,
}

fn render_integration_proof(authority: &IntegrationAuthority<'_>) -> String {
    let core = authority.core;
    format!(
        concat!(
            "schemaVersion\t1\n",
            "domain\thell.collection-custody.integration.v1\n",
            "state\tcontrolled-custody-overlay-pending-review\n",
            "candidateCommit\t{}\n",
            "providerHeadCommit\t{}\n",
            "repositoryId\t{}\n",
            "providerRunId\t{}\n",
            "providerRunAttempt\t{}\n",
            "payloadMerkleRoot\t{}\n",
            "subjectSha256\t{}\n",
            "packageTreeSha256\t{}\n",
            "signatureTreeSha256\t{}\n",
            "revocationPolicySha256\t{}\n",
            "allowedSignersSha256\t{}\n",
            "reviewRevocationsSha256\t{}\n",
            "surveillancePolicySha256\t{}\n",
            "trustRootsSha256\t{}\n",
            "replayCaseCount\t1191\n",
            "replayObservationRootSha256\t{}\n",
            "mapCaseCount\t712\n",
            "setCaseCount\t479\n",
            "beforeIncompleteCells\t134\n",
            "beforeBoundaryGaps\t14\n",
            "afterIncompleteCells\t120\n",
            "afterBoundaryGaps\t0\n",
            "supplementalClaimGate\tpassed-without-registry-mutation\n",
            "integratedPathsPolicy\tcustody-payload-signature-proof-review-only-v1\n",
            "promotionAuthority\tfalse\n"
        ),
        core.candidate_commit,
        core.provider_head,
        core.repository_id,
        core.run_id,
        core.run_attempt,
        core.payload_merkle_root.hex(),
        core.subject_sha256.hex(),
        authority.package_root.hex(),
        authority.signature_root.hex(),
        authority.revocations.hex(),
        authority.review_governance.allowed_signers.hex(),
        authority.review_governance.review_revocations.hex(),
        authority.review_governance.surveillance_policy.hex(),
        authority.review_governance.trust_roots.hex(),
        authority.replay.replay_root_sha256.hex(),
    )
}

fn verify_integration_proof(
    root: &Path,
    path: &Path,
    authority: &IntegrationAuthority<'_>,
) -> Result<(), String> {
    let IntegrationAuthority {
        core,
        package_root,
        signature_root,
        revocations,
        review_governance,
        replay,
    } = authority;
    let bytes = read_file(path)?;
    let fields = parse_assignments(&bytes)?;
    let expected_keys = BTreeSet::from([
        "schemaVersion",
        "domain",
        "state",
        "candidateCommit",
        "providerHeadCommit",
        "repositoryId",
        "providerRunId",
        "providerRunAttempt",
        "payloadMerkleRoot",
        "subjectSha256",
        "packageTreeSha256",
        "signatureTreeSha256",
        "revocationPolicySha256",
        "allowedSignersSha256",
        "reviewRevocationsSha256",
        "surveillancePolicySha256",
        "trustRootsSha256",
        "replayCaseCount",
        "replayObservationRootSha256",
        "mapCaseCount",
        "setCaseCount",
        "beforeIncompleteCells",
        "beforeBoundaryGaps",
        "afterIncompleteCells",
        "afterBoundaryGaps",
        "supplementalClaimGate",
        "integratedPathsPolicy",
        "promotionAuthority",
    ]);
    let current = current_head(root)?;
    if fields.keys().copied().collect::<BTreeSet<_>>() != expected_keys
        || fields.get("schemaVersion") != Some(&"1")
        || fields.get("domain") != Some(&"hell.collection-custody.integration.v1")
        || fields.get("state") != Some(&"controlled-custody-overlay-pending-review")
        || fields.get("candidateCommit") != Some(&core.candidate_commit.as_str())
        || fields.get("providerHeadCommit") != Some(&core.provider_head.as_str())
        || required_u64(&fields, "repositoryId")? != core.repository_id
        || required_u64(&fields, "providerRunId")? != core.run_id
        || required_u64(&fields, "providerRunAttempt")? != core.run_attempt
        || fields.get("payloadMerkleRoot") != Some(&core.payload_merkle_root.hex().as_str())
        || fields.get("subjectSha256") != Some(&core.subject_sha256.hex().as_str())
        || fields.get("packageTreeSha256") != Some(&package_root.hex().as_str())
        || fields.get("signatureTreeSha256") != Some(&signature_root.hex().as_str())
        || fields.get("revocationPolicySha256") != Some(&revocations.hex().as_str())
        || fields.get("allowedSignersSha256")
            != Some(&review_governance.allowed_signers.hex().as_str())
        || fields.get("reviewRevocationsSha256")
            != Some(&review_governance.review_revocations.hex().as_str())
        || fields.get("surveillancePolicySha256")
            != Some(&review_governance.surveillance_policy.hex().as_str())
        || fields.get("trustRootsSha256") != Some(&review_governance.trust_roots.hex().as_str())
        || required_u64(&fields, "replayCaseCount")? != 1_191
        || fields.get("replayObservationRootSha256")
            != Some(&replay.replay_root_sha256.hex().as_str())
        || required_u64(&fields, "mapCaseCount")? != 712
        || required_u64(&fields, "setCaseCount")? != 479
        || required_u64(&fields, "beforeIncompleteCells")? != 134
        || required_u64(&fields, "beforeBoundaryGaps")? != 14
        || required_u64(&fields, "afterIncompleteCells")? != 120
        || required_u64(&fields, "afterBoundaryGaps")? != 0
        || fields.get("supplementalClaimGate") != Some(&"passed-without-registry-mutation")
        || fields.get("integratedPathsPolicy")
            != Some(&"custody-payload-signature-proof-review-only-v1")
        || fields.get("promotionAuthority") != Some(&"false")
        || replay.current_candidate_commit != current
    {
        return Err("collection custody integration proof is not exact or current".to_owned());
    }
    Ok(())
}

fn require_controlled_integration_delta(root: &Path, candidate: &str) -> Result<(), String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["diff", "--name-only", candidate, "HEAD", "--"])
        .output()
        .map_err(|error| format!("cannot inspect collection custody integration delta: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("cannot inspect collection custody integration delta".to_owned());
    }
    let paths = std::str::from_utf8(&output.stdout)
        .map_err(|_| "collection custody integration delta is not UTF-8".to_owned())?
        .lines()
        .collect::<BTreeSet<_>>();
    if paths.is_empty()
        || !paths.iter().all(|path| {
            path.starts_with("compat/collection-custody/payload/")
                || path.starts_with("compat/collection-custody/signature/")
                || *path == "compat/collection-custody/integration-proof.tsv"
                || *path == "compat/collection-custody/integration-review.dsse.json"
        })
        || !paths.contains("compat/collection-custody/integration-proof.tsv")
        || !paths.contains("compat/collection-custody/integration-review.dsse.json")
        || !paths
            .iter()
            .any(|path| path.starts_with("compat/collection-custody/payload/"))
        || !paths
            .iter()
            .any(|path| path.starts_with("compat/collection-custody/signature/"))
    {
        return Err(
            "current candidate contains changes outside controlled custody integration".into(),
        );
    }
    Ok(())
}

fn require_controlled_preparation_delta(root: &Path, candidate: &str) -> Result<(), String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["diff", "--name-only", candidate, "HEAD", "--"])
        .output()
        .map_err(|error| format!("cannot inspect collection custody preparation delta: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("cannot inspect collection custody preparation delta".to_owned());
    }
    let paths = std::str::from_utf8(&output.stdout)
        .map_err(|_| "collection custody preparation delta is not UTF-8".to_owned())?
        .lines()
        .collect::<BTreeSet<_>>();
    if paths.is_empty()
        || !paths.iter().all(|path| {
            path.starts_with("compat/collection-custody/payload/")
                || path.starts_with("compat/collection-custody/signature/")
        })
        || !paths
            .iter()
            .any(|path| path.starts_with("compat/collection-custody/payload/"))
        || !paths
            .iter()
            .any(|path| path.starts_with("compat/collection-custody/signature/"))
    {
        return Err("current candidate is not the exact unsigned custody overlay".to_owned());
    }
    Ok(())
}

struct VerifiedIntegrationReview {
    proof_sha256: Digest,
    review_sha256: Digest,
    subject: String,
    signer_fingerprint: String,
}

fn verify_signed_integration_review(
    root: &Path,
    proof: &Path,
    review: &Path,
    authority: &IntegrationAuthority<'_>,
) -> Result<VerifiedIntegrationReview, String> {
    let core = authority.core;
    let proof_bytes = read_file(proof)?;
    let proof_sha256 = sha256_bytes(&proof_bytes);
    parse_assignments(&proof_bytes)?;
    let required = integration_review_artifacts(authority, proof_sha256);
    let policy = root.join("compat/reviews.allowed_signers");
    let (subject, signer_fingerprint) = crate::assurance::verify_review_binding(
        review,
        &policy,
        "custody-reviewer",
        &core.candidate_commit,
        &core.payload_merkle_root.hex(),
        &required,
    )?;
    Ok(VerifiedIntegrationReview {
        proof_sha256,
        review_sha256: sha256_file(review).map_err(|error| error.to_string())?,
        subject,
        signer_fingerprint,
    })
}

fn integration_review_artifacts(
    authority: &IntegrationAuthority<'_>,
    proof_sha256: Digest,
) -> BTreeSet<String> {
    BTreeSet::from([
        authority.package_root.hex(),
        authority.signature_root.hex(),
        authority.revocations.hex(),
        authority.review_governance.allowed_signers.hex(),
        authority.review_governance.review_revocations.hex(),
        authority.review_governance.surveillance_policy.hex(),
        authority.review_governance.trust_roots.hex(),
        authority.replay.replay_root_sha256.hex(),
        proof_sha256.hex(),
    ])
}

fn render_admission_report(
    verified: &VerifiedAdmissionAuthority,
    worm_custody: Option<Digest>,
) -> Result<String, String> {
    let core = &verified.core;
    let replay = &verified.replay;
    let integration = &verified.integration;
    let rendered = format!(
        concat!(
            "{{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"domain\": \"hell.collection-custody.admission.v1\",\n",
            "  \"state\": \"verified-current-supplemental-custody-overlay\",\n",
            "  \"candidateCommit\": {:?},\n",
            "  \"currentCandidateCommit\": {:?},\n",
            "  \"payloadMerkleRoot\": {:?},\n",
            "  \"subjectSha256\": {:?},\n",
            "  \"packageTreeSha256\": {:?},\n",
            "  \"signatureTreeSha256\": {:?},\n",
            "  \"revocationPolicySha256\": {:?},\n",
            "  \"allowedSignersSha256\": {:?},\n",
            "  \"reviewRevocationsSha256\": {:?},\n",
            "  \"surveillancePolicySha256\": {:?},\n",
            "  \"trustRootsSha256\": {:?},\n",
            "  \"custodyPolicySha256\": {:?},\n",
            "  \"integrationProofSha256\": {:?},\n",
            "  \"integrationReviewSha256\": {:?},\n",
            "  \"integrationReviewSubject\": {:?},\n",
            "  \"integrationSignerFingerprint\": {:?},\n",
            "  \"candidateExecutableSha256\": {:?},\n",
            "  \"replayObservationRootSha256\": {:?},\n",
            "  \"replayCaseCount\": 1191,\n",
            "  \"mapCaseCount\": 712,\n",
            "  \"setCaseCount\": 479,\n",
            "  \"beforeIncompleteCells\": 134,\n",
            "  \"beforeBoundaryGaps\": 14,\n",
            "  \"mapOnlyIncompleteCells\": 127,\n",
            "  \"mapOnlyBoundaryGaps\": 7,\n",
            "  \"setOnlyIncompleteCells\": 127,\n",
            "  \"setOnlyBoundaryGaps\": 7,\n",
            "  \"afterIncompleteCells\": 120,\n",
            "  \"afterBoundaryGaps\": 0,\n",
            "  \"registryMutated\": false,\n",
            "  \"compatibilityLocksWritten\": false,\n",
            "  \"wormCustodyIdentitySha256\": {},\n",
            "  \"twoProviderWormCustodySatisfied\": {},\n",
            "  \"promotionAuthority\": false\n",
            "}}\n"
        ),
        core.candidate_commit,
        replay.current_candidate_commit,
        core.payload_merkle_root.hex(),
        core.subject_sha256.hex(),
        verified.package_root.hex(),
        verified.signature_root.hex(),
        verified.revocations.hex(),
        verified.review_governance.allowed_signers.hex(),
        verified.review_governance.review_revocations.hex(),
        verified.review_governance.surveillance_policy.hex(),
        verified.review_governance.trust_roots.hex(),
        verified.custody_policy.hex(),
        integration.proof_sha256.hex(),
        integration.review_sha256.hex(),
        integration.subject,
        integration.signer_fingerprint,
        replay.candidate_executable_sha256.hex(),
        replay.replay_root_sha256.hex(),
        worm_custody.map_or_else(
            || "null".to_owned(),
            |identity| format!("{:?}", identity.hex())
        ),
        worm_custody.is_some(),
    );
    let parsed = crate::assurance::parse_json(&rendered)?;
    let canonical = crate::assurance::canonical_json_bytes(&parsed)?;
    String::from_utf8(canonical)
        .map_err(|_| "canonical collection admission report is not UTF-8".to_owned())
}

fn render_activation_preparation_token(
    verified: &VerifiedAdmissionAuthority,
    worm_identity: Digest,
    admission_report: &str,
) -> Result<Vec<u8>, String> {
    let mut fields = activation_token_identity_fields(verified, worm_identity, admission_report);
    fields.extend(activation_token_coverage_fields());
    crate::assurance::canonical_json_bytes(&crate::assurance::JsonValue::Object(fields))
}

fn activation_token_identity_fields(
    verified: &VerifiedAdmissionAuthority,
    worm_identity: Digest,
    admission_report: &str,
) -> BTreeMap<String, crate::assurance::JsonValue> {
    BTreeMap::from([
        (
            "schemaVersion".to_owned(),
            crate::assurance::JsonValue::Number(1),
        ),
        (
            "domain".to_owned(),
            crate::assurance::JsonValue::String(
                "hell.collection-custody.activation-preparation.v1".to_owned(),
            ),
        ),
        (
            "state".to_owned(),
            crate::assurance::JsonValue::String(
                "eligible-for-human-reviewed-preparation".to_owned(),
            ),
        ),
        (
            "admissionReportSha256".to_owned(),
            crate::assurance::JsonValue::String(sha256_bytes(admission_report.as_bytes()).hex()),
        ),
        (
            "candidateCommit".to_owned(),
            crate::assurance::JsonValue::String(verified.core.candidate_commit.clone()),
        ),
        (
            "currentCandidateCommit".to_owned(),
            crate::assurance::JsonValue::String(verified.replay.current_candidate_commit.clone()),
        ),
        (
            "payloadMerkleRoot".to_owned(),
            crate::assurance::JsonValue::String(verified.core.payload_merkle_root.hex()),
        ),
        (
            "packageTreeSha256".to_owned(),
            crate::assurance::JsonValue::String(verified.package_root.hex()),
        ),
        (
            "signatureTreeSha256".to_owned(),
            crate::assurance::JsonValue::String(verified.signature_root.hex()),
        ),
        (
            "integrationProofSha256".to_owned(),
            crate::assurance::JsonValue::String(verified.integration.proof_sha256.hex()),
        ),
        (
            "integrationReviewSha256".to_owned(),
            crate::assurance::JsonValue::String(verified.integration.review_sha256.hex()),
        ),
        (
            "replayObservationRootSha256".to_owned(),
            crate::assurance::JsonValue::String(verified.replay.replay_root_sha256.hex()),
        ),
        (
            "custodyPolicySha256".to_owned(),
            crate::assurance::JsonValue::String(verified.custody_policy.hex()),
        ),
        (
            "wormCustodyIdentitySha256".to_owned(),
            crate::assurance::JsonValue::String(worm_identity.hex()),
        ),
    ])
}

fn activation_token_coverage_fields() -> BTreeMap<String, crate::assurance::JsonValue> {
    BTreeMap::from([
        (
            "beforeIncompleteCells".to_owned(),
            crate::assurance::JsonValue::Number(134),
        ),
        (
            "beforeBoundaryGaps".to_owned(),
            crate::assurance::JsonValue::Number(14),
        ),
        (
            "mapOnlyIncompleteCells".to_owned(),
            crate::assurance::JsonValue::Number(127),
        ),
        (
            "mapOnlyBoundaryGaps".to_owned(),
            crate::assurance::JsonValue::Number(7),
        ),
        (
            "setOnlyIncompleteCells".to_owned(),
            crate::assurance::JsonValue::Number(127),
        ),
        (
            "setOnlyBoundaryGaps".to_owned(),
            crate::assurance::JsonValue::Number(7),
        ),
        (
            "afterIncompleteCells".to_owned(),
            crate::assurance::JsonValue::Number(120),
        ),
        (
            "afterBoundaryGaps".to_owned(),
            crate::assurance::JsonValue::Number(0),
        ),
        (
            "activationPreparationEligible".to_owned(),
            crate::assurance::JsonValue::Bool(true),
        ),
        (
            "activationAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
        (
            "promotionAuthority".to_owned(),
            crate::assurance::JsonValue::Bool(false),
        ),
    ])
}

pub(crate) fn verify_activation_preparation_token(
    admission_report: &Path,
    token: &Path,
) -> Result<VerifiedActivationPreparationToken, String> {
    verify_activation_artifact_inventory(admission_report, token)?;
    let (report_bytes, report_fields) =
        read_canonical_activation_json(admission_report, "collection admission report")?;
    let (token_bytes, token_fields) =
        read_canonical_activation_json(token, "collection activation token")?;
    verify_activation_artifact_keys(&report_fields, &token_fields)?;
    verify_activation_token_state(&token_fields, &report_fields, &report_bytes)?;
    verify_activation_token_digests(&token_fields, &report_fields)?;
    verify_activation_token_bindings(&token_fields, &report_fields)?;
    Ok(VerifiedActivationPreparationToken {
        candidate_commit: activation_field(&token_fields, "candidateCommit", "token")?
            .string()?
            .to_owned(),
        current_candidate_commit: activation_field(
            &token_fields,
            "currentCandidateCommit",
            "token",
        )?
        .string()?
        .to_owned(),
        payload_merkle_root: activation_field(&token_fields, "payloadMerkleRoot", "token")?
            .string()?
            .to_owned(),
        worm_custody_identity_sha256: activation_field(
            &token_fields,
            "wormCustodyIdentitySha256",
            "token",
        )?
        .string()?
        .to_owned(),
        token_sha256: sha256_bytes(&token_bytes).hex(),
    })
}

fn read_canonical_activation_json(
    path: &Path,
    label: &str,
) -> Result<(Vec<u8>, BTreeMap<String, crate::assurance::JsonValue>), String> {
    let bytes = read_file(path)?;
    let json = crate::assurance::parse_json(
        std::str::from_utf8(&bytes).map_err(|_| format!("{label} is not UTF-8"))?,
    )?;
    if crate::assurance::canonical_json_bytes(&json)? != bytes {
        return Err(format!("{label} is not canonical JSON"));
    }
    Ok((bytes, json.object()?.clone()))
}

fn verify_activation_artifact_keys(
    report_fields: &BTreeMap<String, crate::assurance::JsonValue>,
    token_fields: &BTreeMap<String, crate::assurance::JsonValue>,
) -> Result<(), String> {
    let expected_report_keys = BTreeSet::from([
        "afterBoundaryGaps",
        "afterIncompleteCells",
        "allowedSignersSha256",
        "beforeBoundaryGaps",
        "beforeIncompleteCells",
        "candidateCommit",
        "candidateExecutableSha256",
        "compatibilityLocksWritten",
        "currentCandidateCommit",
        "custodyPolicySha256",
        "domain",
        "integrationProofSha256",
        "integrationReviewSha256",
        "integrationReviewSubject",
        "integrationSignerFingerprint",
        "mapCaseCount",
        "mapOnlyBoundaryGaps",
        "mapOnlyIncompleteCells",
        "packageTreeSha256",
        "payloadMerkleRoot",
        "promotionAuthority",
        "registryMutated",
        "replayCaseCount",
        "replayObservationRootSha256",
        "reviewRevocationsSha256",
        "revocationPolicySha256",
        "schemaVersion",
        "setCaseCount",
        "setOnlyBoundaryGaps",
        "setOnlyIncompleteCells",
        "signatureTreeSha256",
        "state",
        "subjectSha256",
        "surveillancePolicySha256",
        "trustRootsSha256",
        "twoProviderWormCustodySatisfied",
        "wormCustodyIdentitySha256",
    ]);
    if report_fields
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_report_keys
    {
        return Err("collection admission report fields are missing or extra".to_owned());
    }
    let expected_keys = BTreeSet::from([
        "activationAuthority",
        "activationPreparationEligible",
        "admissionReportSha256",
        "afterBoundaryGaps",
        "afterIncompleteCells",
        "beforeBoundaryGaps",
        "beforeIncompleteCells",
        "candidateCommit",
        "currentCandidateCommit",
        "custodyPolicySha256",
        "domain",
        "integrationProofSha256",
        "integrationReviewSha256",
        "mapOnlyBoundaryGaps",
        "mapOnlyIncompleteCells",
        "packageTreeSha256",
        "payloadMerkleRoot",
        "promotionAuthority",
        "replayObservationRootSha256",
        "schemaVersion",
        "signatureTreeSha256",
        "state",
        "setOnlyBoundaryGaps",
        "setOnlyIncompleteCells",
        "wormCustodyIdentitySha256",
    ]);
    if token_fields
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_keys
    {
        return Err("collection activation token fields are missing or extra".to_owned());
    }
    Ok(())
}

fn activation_field<'a>(
    fields: &'a BTreeMap<String, crate::assurance::JsonValue>,
    key: &str,
    label: &str,
) -> Result<&'a crate::assurance::JsonValue, String> {
    fields
        .get(key)
        .ok_or_else(|| format!("collection activation {label} omits {key}"))
}

fn verify_activation_token_state(
    token_fields: &BTreeMap<String, crate::assurance::JsonValue>,
    report_fields: &BTreeMap<String, crate::assurance::JsonValue>,
    report_bytes: &[u8],
) -> Result<(), String> {
    let member = |key| activation_field(token_fields, key, "token");
    let report_member = |key| activation_field(report_fields, key, "admission report");
    if member("schemaVersion")?.number()? != 1
        || member("domain")?.string()? != "hell.collection-custody.activation-preparation.v1"
        || member("state")?.string()? != "eligible-for-human-reviewed-preparation"
        || !member("activationPreparationEligible")?.boolean()?
        || member("activationAuthority")?.boolean()?
        || member("promotionAuthority")?.boolean()?
        || member("beforeIncompleteCells")?.number()? != 134
        || member("beforeBoundaryGaps")?.number()? != 14
        || member("mapOnlyIncompleteCells")?.number()? != 127
        || member("mapOnlyBoundaryGaps")?.number()? != 7
        || member("setOnlyIncompleteCells")?.number()? != 127
        || member("setOnlyBoundaryGaps")?.number()? != 7
        || member("afterIncompleteCells")?.number()? != 120
        || member("afterBoundaryGaps")?.number()? != 0
        || member("admissionReportSha256")?.string()? != sha256_bytes(report_bytes).hex()
        || report_member("domain")?.string()? != "hell.collection-custody.admission.v1"
        || report_member("state")?.string()? != "verified-current-supplemental-custody-overlay"
        || report_member("schemaVersion")?.number()? != 1
        || !report_member("twoProviderWormCustodySatisfied")?.boolean()?
        || report_member("registryMutated")?.boolean()?
        || report_member("compatibilityLocksWritten")?.boolean()?
        || report_member("promotionAuthority")?.boolean()?
        || report_member("replayCaseCount")?.number()? != 1_191
        || report_member("mapCaseCount")?.number()? != 712
        || report_member("setCaseCount")?.number()? != 479
        || report_member("beforeIncompleteCells")?.number()? != 134
        || report_member("beforeBoundaryGaps")?.number()? != 14
        || report_member("mapOnlyIncompleteCells")?.number()? != 127
        || report_member("mapOnlyBoundaryGaps")?.number()? != 7
        || report_member("setOnlyIncompleteCells")?.number()? != 127
        || report_member("setOnlyBoundaryGaps")?.number()? != 7
        || report_member("afterIncompleteCells")?.number()? != 120
        || report_member("afterBoundaryGaps")?.number()? != 0
        || report_member("integrationReviewSubject")?
            .string()?
            .is_empty()
    {
        return Err("collection activation token state or admission binding is invalid".to_owned());
    }
    Ok(())
}

fn verify_activation_token_digests(
    token_fields: &BTreeMap<String, crate::assurance::JsonValue>,
    report_fields: &BTreeMap<String, crate::assurance::JsonValue>,
) -> Result<(), String> {
    let member = |key| activation_field(token_fields, key, "token");
    let report_member = |key| activation_field(report_fields, key, "admission report");
    for key in [
        "payloadMerkleRoot",
        "packageTreeSha256",
        "signatureTreeSha256",
        "integrationProofSha256",
        "integrationReviewSha256",
        "replayObservationRootSha256",
        "custodyPolicySha256",
        "wormCustodyIdentitySha256",
    ] {
        Digest::from_hex(member(key)?.string()?)
            .map_err(|_| format!("collection activation token {key} is invalid"))?;
    }
    for key in [
        "subjectSha256",
        "revocationPolicySha256",
        "allowedSignersSha256",
        "reviewRevocationsSha256",
        "surveillancePolicySha256",
        "trustRootsSha256",
        "candidateExecutableSha256",
        "integrationSignerFingerprint",
    ] {
        Digest::from_hex(report_member(key)?.string()?)
            .map_err(|_| format!("collection admission report {key} is invalid"))?;
    }
    require_lower_git_commit(member("candidateCommit")?.string()?)?;
    require_lower_git_commit(member("currentCandidateCommit")?.string()?)?;
    Ok(())
}

fn verify_activation_token_bindings(
    token_fields: &BTreeMap<String, crate::assurance::JsonValue>,
    report_fields: &BTreeMap<String, crate::assurance::JsonValue>,
) -> Result<(), String> {
    let member = |key| activation_field(token_fields, key, "token");
    let report_member = |key| activation_field(report_fields, key, "admission report");
    for (token_key, report_key) in [
        ("candidateCommit", "candidateCommit"),
        ("currentCandidateCommit", "currentCandidateCommit"),
        ("payloadMerkleRoot", "payloadMerkleRoot"),
        ("packageTreeSha256", "packageTreeSha256"),
        ("signatureTreeSha256", "signatureTreeSha256"),
        ("integrationProofSha256", "integrationProofSha256"),
        ("integrationReviewSha256", "integrationReviewSha256"),
        ("replayObservationRootSha256", "replayObservationRootSha256"),
        ("custodyPolicySha256", "custodyPolicySha256"),
        ("wormCustodyIdentitySha256", "wormCustodyIdentitySha256"),
    ] {
        if member(token_key)?.string()? != report_member(report_key)?.string()? {
            return Err(format!(
                "collection activation token differs from admission report {report_key}"
            ));
        }
    }
    for key in [
        "beforeIncompleteCells",
        "beforeBoundaryGaps",
        "mapOnlyIncompleteCells",
        "mapOnlyBoundaryGaps",
        "setOnlyIncompleteCells",
        "setOnlyBoundaryGaps",
        "afterIncompleteCells",
        "afterBoundaryGaps",
    ] {
        if member(key)?.number()? != report_member(key)?.number()? {
            return Err(format!(
                "collection activation token differs from admission report {key}"
            ));
        }
    }
    Ok(())
}

fn verify_activation_artifact_inventory(
    admission_report: &Path,
    token: &Path,
) -> Result<(), String> {
    let directory = admission_report
        .parent()
        .ok_or_else(|| "collection activation artifact has no directory".to_owned())?;
    if token.parent() != Some(directory)
        || admission_report.file_name().and_then(|name| name.to_str())
            != Some("collection-custody-admission.json")
        || token.file_name().and_then(|name| name.to_str())
            != Some("collection-custody-activation-token.json")
    {
        return Err("collection activation artifact paths are not canonical".to_owned());
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("cannot inspect collection activation artifact: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("collection activation artifact is not a real directory".to_owned());
    }
    let expected = BTreeSet::from([
        "collection-custody-activation-token.json".to_owned(),
        "collection-custody-activation-token.json.sha256".to_owned(),
        "collection-custody-admission.json".to_owned(),
        "collection-custody-admission.json.sha256".to_owned(),
    ]);
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate collection activation artifact: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("cannot enumerate collection activation artifact: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            format!("cannot inspect collection activation artifact file: {error}")
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("collection activation artifact contains a non-regular file".to_owned());
        }
        observed.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "collection activation artifact filename is not UTF-8".to_owned())?,
        );
    }
    if observed != expected {
        return Err("collection activation artifact inventory is not exact".to_owned());
    }
    for path in [admission_report, token] {
        let bytes = read_file(path)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "collection activation artifact filename is not UTF-8".to_owned())?;
        let expected_digest = format!("{}  {name}\n", sha256_bytes(&bytes).hex());
        if read_file(&path.with_extension("json.sha256"))? != expected_digest.as_bytes() {
            return Err("collection activation artifact digest sibling is invalid".to_owned());
        }
    }
    Ok(())
}

fn require_report_outside_authority(root: &Path, report: &Path) -> Result<(), String> {
    let relative = if report.is_absolute() {
        report
            .strip_prefix(root)
            .map_err(|_| "collection custody admission report is outside the checkout".to_owned())?
    } else {
        report
    };
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
        || relative.components().next()
            != Some(std::path::Component::Normal(std::ffi::OsStr::new("ci-out")))
    {
        return Err("collection custody admission report must be under ci-out".to_owned());
    }

    let parent = relative.parent().ok_or_else(|| {
        "collection custody admission report must have a parent directory".to_owned()
    })?;
    let mut checkout_parent = root.to_path_buf();
    for component in parent.components() {
        checkout_parent.push(component.as_os_str());
        match fs::symlink_metadata(&checkout_parent) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(
                    "collection custody admission report parent is not a real directory".to_owned(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect collection custody admission report parent: {error}"
                ));
            }
        }
    }
    let checkout_report = root.join(relative);
    for target in [
        checkout_report.clone(),
        checkout_report.with_extension("json.sha256"),
    ] {
        match fs::symlink_metadata(target) {
            Ok(_) => {
                return Err("collection custody admission report already exists".to_owned());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect collection custody admission report target: {error}"
                ));
            }
        }
    }
    Ok(())
}

fn require_tracked_custody_inputs(
    root: &Path,
    input: &VerifyCustodyInput<'_>,
) -> Result<(), String> {
    let revocations = root.join("compat/collection-authority-revocations.toml");
    let allowed_signers = root.join("compat/reviews.allowed_signers");
    let review_revocations = root.join("compat/review-revocations.toml");
    let surveillance_policy = root.join("compat/surveillance-policy.toml");
    let trust_roots = root.join("compat/trust-roots.toml");
    require_tracked_paths(
        root,
        &[
            (input.package, "compat/collection-custody/payload", true),
            (input.signature, "compat/collection-custody/signature", true),
            (
                input.integration_proof,
                "compat/collection-custody/integration-proof.tsv",
                false,
            ),
            (
                input.integration_review,
                "compat/collection-custody/integration-review.dsse.json",
                false,
            ),
            (
                revocations.as_path(),
                "compat/collection-authority-revocations.toml",
                false,
            ),
            (
                allowed_signers.as_path(),
                "compat/reviews.allowed_signers",
                false,
            ),
            (
                review_revocations.as_path(),
                "compat/review-revocations.toml",
                false,
            ),
            (
                surveillance_policy.as_path(),
                "compat/surveillance-policy.toml",
                false,
            ),
            (trust_roots.as_path(), "compat/trust-roots.toml", false),
        ],
    )
}

fn require_tracked_preparation_inputs(
    root: &Path,
    input: &PrepareCustodyReviewInput<'_>,
) -> Result<(), String> {
    let revocations = root.join("compat/collection-authority-revocations.toml");
    let allowed_signers = root.join("compat/reviews.allowed_signers");
    let review_revocations = root.join("compat/review-revocations.toml");
    let surveillance_policy = root.join("compat/surveillance-policy.toml");
    let trust_roots = root.join("compat/trust-roots.toml");
    require_tracked_paths(
        root,
        &[
            (input.package, "compat/collection-custody/payload", true),
            (input.signature, "compat/collection-custody/signature", true),
            (
                revocations.as_path(),
                "compat/collection-authority-revocations.toml",
                false,
            ),
            (
                allowed_signers.as_path(),
                "compat/reviews.allowed_signers",
                false,
            ),
            (
                review_revocations.as_path(),
                "compat/review-revocations.toml",
                false,
            ),
            (
                surveillance_policy.as_path(),
                "compat/surveillance-policy.toml",
                false,
            ),
            (trust_roots.as_path(), "compat/trust-roots.toml", false),
        ],
    )
}

fn require_tracked_review_governance(root: &Path) -> Result<(), String> {
    let allowed_signers = root.join("compat/reviews.allowed_signers");
    let review_revocations = root.join("compat/review-revocations.toml");
    let surveillance_policy = root.join("compat/surveillance-policy.toml");
    let trust_roots = root.join("compat/trust-roots.toml");
    require_tracked_paths(
        root,
        &[
            (
                allowed_signers.as_path(),
                "compat/reviews.allowed_signers",
                false,
            ),
            (
                review_revocations.as_path(),
                "compat/review-revocations.toml",
                false,
            ),
            (
                surveillance_policy.as_path(),
                "compat/surveillance-policy.toml",
                false,
            ),
            (trust_roots.as_path(), "compat/trust-roots.toml", false),
        ],
    )
}

fn require_tracked_paths(root: &Path, paths: &[(&Path, &str, bool)]) -> Result<(), String> {
    for &(path, expected, expected_directory) in paths {
        let relative = canonical_checkout_relative(root, path)?;
        if relative != Path::new(expected) {
            return Err("collection custody admission input path is not canonical".to_owned());
        }
        let metadata = fs::symlink_metadata(root.join(relative)).map_err(|error| {
            format!("cannot inspect collection custody admission input type: {error}")
        })?;
        if metadata.file_type().is_symlink()
            || expected_directory != metadata.file_type().is_dir()
            || !expected_directory && !metadata.file_type().is_file()
        {
            return Err("collection custody admission input has the wrong file type".to_owned());
        }
        let tracked = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["ls-files", "--error-unmatch", "--"])
            .arg(relative)
            .output()
            .map_err(|error| format!("cannot inspect tracked custody input: {error}"))?;
        if !tracked.status.success() || tracked.stdout.is_empty() {
            return Err("collection custody admission input is not tracked".to_owned());
        }
        let clean = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["diff", "--quiet", "HEAD", "--"])
            .arg(relative)
            .status()
            .map_err(|error| format!("cannot inspect custody input cleanliness: {error}"))?;
        if !clean.success() {
            return Err("collection custody admission input differs from HEAD".to_owned());
        }
    }
    Ok(())
}

fn review_governance(root: &Path) -> Result<ReviewGovernance, String> {
    let digest = |relative: &str| {
        sha256_file(&root.join(relative))
            .map_err(|error| format!("cannot hash collection review governance: {error}"))
    };
    Ok(ReviewGovernance {
        allowed_signers: digest("compat/reviews.allowed_signers")?,
        review_revocations: digest("compat/review-revocations.toml")?,
        surveillance_policy: digest("compat/surveillance-policy.toml")?,
        trust_roots: digest("compat/trust-roots.toml")?,
    })
}

fn canonical_checkout_relative<'a>(root: &Path, path: &'a Path) -> Result<&'a Path, String> {
    let relative = if path.is_absolute() {
        path.strip_prefix(root).map_err(|_| {
            "collection custody admission input is outside the current checkout".to_owned()
        })?
    } else {
        path
    };
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("collection custody admission input escapes the checkout".to_owned());
    }
    Ok(relative)
}

fn current_head(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("cannot inspect current collection candidate: {error}"))?;
    if !output.status.success() {
        return Err("cannot inspect current collection candidate".to_owned());
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| "current collection candidate is not UTF-8".to_owned())?;
    let value = value
        .strip_suffix('\n')
        .ok_or_else(|| "current collection candidate is noncanonical".to_owned())?
        .to_owned();
    require_lower_git_commit(&value)?;
    Ok(value)
}

fn require_ancestor(root: &Path, ancestor: &str, descendant: &str) -> Result<(), String> {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["merge-base", "--is-ancestor", ancestor, descendant])
        .status()
        .map_err(|error| format!("cannot inspect collection candidate ancestry: {error}"))?;
    if !status.success() {
        return Err("current candidate does not descend from collected candidate".to_owned());
    }
    Ok(())
}

pub(crate) fn compact(
    root: &Path,
    input: &Path,
    provider: &Path,
    verified_report: &Path,
    output: &Path,
) -> Result<VerifiedCollectionCustodyCore, String> {
    if output.exists() {
        return Err("collection custody output already exists".to_owned());
    }
    let campaign = crate::suite::verified_collection_campaign(root, input, provider)?;
    let expected_report = crate::suite::collection_authority_report(
        campaign.source_manifest,
        &campaign.providers,
        campaign.campaign_subject_sha256,
        &campaign.shards,
    );
    let report_bytes = read_file(verified_report)?;
    if report_bytes != expected_report.as_bytes() {
        return Err("collection custody input is not the exact successful verifier report".into());
    }
    let report_digest_record = read_file(&verified_report.with_extension("json.sha256"))?;
    let report_name = verified_report
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "collection verifier report filename is not UTF-8".to_owned())?;
    if report_digest_record
        != format!("{}  {report_name}\n", sha256_bytes(&report_bytes).hex()).as_bytes()
    {
        return Err("collection verifier report digest record is invalid".to_owned());
    }
    fs::create_dir_all(output.join("blobs/sha256"))
        .map_err(|error| format!("cannot create collection custody package: {error}"))?;
    let (records, evidence) = write_records_and_blobs(input, output, &campaign.shards)?;
    let provenance = write_provenance(output, &campaign.providers)?;
    let authority = write_authority(output, &campaign.source, &campaign.native_builds)?;
    let authority_files = write_authority_files(root, output, &campaign.source)?;
    let transformations =
        write_transformations(&campaign.shards, &campaign.providers, &records, &evidence)?;
    write_file(
        &output.join("transformation.tsv"),
        transformations.as_bytes(),
    )?;
    let input_roots = write_input_roots(&InputRootRequest {
        root,
        input,
        provider,
        report: verified_report,
        output,
        source_manifest: campaign.source_manifest,
        campaign_subject: campaign.campaign_subject_sha256,
        provider_head: &campaign.providers[0].0.provider_head_commit,
    })?;
    let blobs = write_blob_inventory(output)?;
    let roots = CustodyComponentRoots {
        records: sha256_bytes(records.as_bytes()),
        evidence: sha256_bytes(evidence.as_bytes()),
        blobs: sha256_bytes(blobs.as_bytes()),
        provenance: sha256_bytes(provenance.as_bytes()),
        authority: authority_component_sha256(authority.as_bytes(), authority_files.as_bytes()),
        transformations: sha256_bytes(transformations.as_bytes()),
        inputs: sha256_bytes(input_roots.as_bytes()),
    };
    let payload_merkle_root = roots.payload_merkle_root();
    let provider = &campaign.providers[0].0;
    let identity = CustodyIdentity {
        candidate: &provider.candidate_commit,
        provider_head: &provider.provider_head_commit,
        repository_id: provider.repository_id,
        run_id: provider.run_id,
        run_attempt: provider.run_attempt,
    };
    let manifest = render_manifest(&roots, payload_merkle_root, &identity);
    write_file(&output.join("manifest.tsv"), manifest.as_bytes())?;
    let manifest_sha256 = sha256_bytes(manifest.as_bytes());
    let subject =
        render_attestation_subject(payload_merkle_root, manifest_sha256, &roots, &identity);
    write_file(
        &output.join("custody-attestation-subject.json"),
        subject.as_bytes(),
    )?;
    write_file(
        &output.join("custody-attestation-subject.json.sha256"),
        format!(
            "{}  custody-attestation-subject.json\n",
            sha256_bytes(subject.as_bytes()).hex()
        )
        .as_bytes(),
    )?;
    verify_core(root, output)
}

pub(crate) struct RetainAttestationInput<'a> {
    pub(crate) package: &'a Path,
    pub(crate) bundle: &'a Path,
    pub(crate) trusted_root: &'a Path,
    pub(crate) trusted_root_provenance: &'a Path,
    pub(crate) online_verification: &'a Path,
    pub(crate) gh_install_manifest: &'a Path,
    pub(crate) output: &'a Path,
}

pub(crate) fn retain_attestation(
    root: &Path,
    input: &RetainAttestationInput<'_>,
) -> Result<(), String> {
    let RetainAttestationInput {
        package,
        bundle,
        trusted_root,
        trusted_root_provenance,
        online_verification,
        gh_install_manifest,
        output,
    } = input;
    if output.exists() {
        return Err("collection custody signature output already exists".to_owned());
    }
    let core = verify_core(root, package)?;
    let bundle_bytes = read_file(bundle)?;
    let trusted_root_bytes = read_file(trusted_root)?;
    let provenance_bytes = read_file(trusted_root_provenance)?;
    let verification_bytes = read_file(online_verification)?;
    let gh_install_manifest_bytes = read_file(gh_install_manifest)?;
    let raw_verification_path = online_verification
        .parent()
        .ok_or_else(|| "online verification path has no parent".to_owned())?
        .join("online-verification.raw.json");
    let raw_verification_bytes = read_file(&raw_verification_path)?;
    let bundle_sha256 = sha256_bytes(&bundle_bytes);
    let trusted_root_sha256 = sha256_bytes(&trusted_root_bytes);
    let provenance_sha256 = sha256_bytes(&provenance_bytes);
    let verification_sha256 = sha256_bytes(&verification_bytes);
    let raw_verification_sha256 = sha256_bytes(&raw_verification_bytes);
    let gh_install_manifest_sha256 = sha256_bytes(&gh_install_manifest_bytes);
    verify_gh_install_manifest(&gh_install_manifest_bytes)?;
    verify_online_attestation_records(
        &core,
        bundle_sha256,
        trusted_root_sha256,
        &raw_verification_bytes,
        &provenance_bytes,
        &verification_bytes,
        gh_install_manifest_sha256,
    )?;
    fs::create_dir_all(output)
        .map_err(|error| format!("cannot create collection custody signature: {error}"))?;
    for (name, bytes) in [
        ("attestation-bundle.json", bundle_bytes.as_slice()),
        ("trusted-root.jsonl", trusted_root_bytes.as_slice()),
        ("trusted-root-provenance.json", provenance_bytes.as_slice()),
        (
            "online-verification.raw.json",
            raw_verification_bytes.as_slice(),
        ),
        ("online-verification.json", verification_bytes.as_slice()),
        (
            "gh-install-manifest.json",
            gh_install_manifest_bytes.as_slice(),
        ),
    ] {
        write_file(&output.join(name), bytes)?;
    }
    let handoff = format!(
        concat!(
            "schemaVersion\t1\n",
            "domain\thell.collection-custody.handoff.v1\n",
            "state\tprepared/unintegrated/non-authoritative\n",
            "candidateCommit\t{}\n",
            "providerHeadCommit\t{}\n",
            "repositoryId\t{}\n",
            "providerRunId\t{}\n",
            "providerRunAttempt\t{}\n",
            "payloadMerkleRoot\t{}\n",
            "subjectSha256\t{}\n",
            "bundleSha256\t{}\n",
            "trustedRootSha256\t{}\n",
            "trustedRootProvenanceSha256\t{}\n",
            "rawVerificationSha256\t{}\n",
            "onlineVerificationSha256\t{}\n",
            "ghInstallManifestSha256\t{}\n",
            "packageDestination\tcompat/collection-custody/payload\n",
            "signatureDestination\tcompat/collection-custody/signature\n",
            "requiredVerifyCommand\thell-ci collection-authority verify-custody --package compat/collection-custody/payload --signature compat/collection-custody/signature --candidate-executable <trusted-current-candidate> --integration-proof compat/collection-custody/integration-proof.tsv --integration-review compat/collection-custody/integration-review.dsse.json --report <report>\n",
            "integrationPolicyVersion\t1\n"
        ),
        core.candidate_commit,
        core.provider_head,
        core.repository_id,
        core.run_id,
        core.run_attempt,
        core.payload_merkle_root.hex(),
        core.subject_sha256.hex(),
        bundle_sha256.hex(),
        trusted_root_sha256.hex(),
        provenance_sha256.hex(),
        raw_verification_sha256.hex(),
        verification_sha256.hex(),
        gh_install_manifest_sha256.hex(),
    );
    write_file(&output.join("custody-handoff.tsv"), handoff.as_bytes())?;
    Ok(())
}

pub(crate) fn verify_gh_install_manifest(bytes: &[u8]) -> Result<(), String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody gh install manifest is not UTF-8".to_owned())?;
    let value = crate::assurance::parse_json(document)?;
    if crate::assurance::canonical_json_bytes(&value)? != bytes {
        return Err("collection custody gh install manifest is noncanonical".to_owned());
    }
    let object = value.object()?;
    require_json_keys(
        object,
        &[
            "archiveInventorySha256",
            "archiveMemberCount",
            "binaryArchivePath",
            "binaryMode",
            "ghArchiveSha256",
            "ghArchiveUrl",
            "ghBinarySha256",
            "ghChecksumsEntry",
            "ghChecksumsSha256",
            "ghChecksumsUrl",
            "ghReleaseVersion",
            "schema",
        ],
    )?;
    let member = |name| crate::assurance::json_member(object, name);
    if member("schema")?.string()? != "hell.collection-custody.gh-install.v1"
        || member("ghReleaseVersion")?.string()? != "2.93.0"
        || member("binaryArchivePath")?.string()? != "gh_2.93.0_linux_amd64/bin/gh"
        || member("binaryMode")?.string()? != "0755"
        || member("ghArchiveSha256")?.string()?
            != "02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0"
        || member("ghBinarySha256")?.string()?
            != "014fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1"
        || member("ghChecksumsSha256")?.string()?
            != "f62a3bc9dedc88262c9c2b56eb653cb3ded6bde8076bdbb151f4cce9c8729da5"
        || member("ghArchiveUrl")?.string()?
            != "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_linux_amd64.tar.gz"
        || member("ghChecksumsUrl")?.string()?
            != "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_checksums.txt"
        || member("ghChecksumsEntry")?.string()?
            != "02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0  gh_2.93.0_linux_amd64.tar.gz"
        || member("archiveMemberCount")?.number()? == 0
    {
        return Err("collection custody gh install manifest differs from reviewed tool".to_owned());
    }
    parse_json_digest(member("archiveInventorySha256")?)?;
    Ok(())
}

struct CustodyComponentRoots {
    records: Digest,
    evidence: Digest,
    blobs: Digest,
    provenance: Digest,
    authority: Digest,
    transformations: Digest,
    inputs: Digest,
}

struct CustodyIdentity<'a> {
    candidate: &'a str,
    provider_head: &'a str,
    repository_id: u64,
    run_id: u64,
    run_attempt: u64,
}

fn verify_online_attestation_records(
    core: &VerifiedCollectionCustodyCore,
    bundle: Digest,
    trusted_root: Digest,
    raw_verification_bytes: &[u8],
    provenance: &[u8],
    verification: &[u8],
    gh_install_manifest: Digest,
) -> Result<(), String> {
    let provenance = std::str::from_utf8(provenance)
        .map_err(|_| "collection custody trusted-root provenance is not UTF-8".to_owned())?;
    let provenance_value = crate::assurance::parse_json(provenance)?;
    if crate::assurance::canonical_json_bytes(&provenance_value)? != provenance.as_bytes() {
        return Err("collection custody trusted-root provenance is not canonical JSON".to_owned());
    }
    let provenance = provenance_value.object()?;
    require_json_keys(
        provenance,
        &[
            "bundleSha256",
            "domain",
            "ghArchiveSha256",
            "ghArchiveUrl",
            "ghBinarySha256",
            "ghChecksumsSha256",
            "ghChecksumsUrl",
            "ghExecutableSha256",
            "ghInstallManifestSha256",
            "ghReleaseVersion",
            "ghVersion",
            "providerHead",
            "repository",
            "repositoryId",
            "runAttempt",
            "runId",
            "schema",
            "subjectSha256",
            "trustedRootAcquiredAt",
            "trustedRootAcquisitionArgv",
            "trustedRootRecordCount",
            "trustedRootRawSha256",
            "verificationCredentialsStripped",
            "verificationNetworkIsolation",
            "verifiedAt",
            "verifyArgv",
        ],
    )?;
    let member = |name| crate::assurance::json_member(provenance, name);
    let gh_executable = parse_json_digest(member("ghExecutableSha256")?)?;
    let gh_version = member("ghVersion")?;
    let verified_at = member("verifiedAt")?.string()?;
    if member("domain")?.string()? != "hell.collection-custody.attestation.v1"
        || member("schema")?.string()? != "hell.collection-custody.trusted-root-provenance.v1"
        || member("repository")?.string()? != "Portfoligno/hell-rs"
        || member("repositoryId")?.number()? != core.repository_id
        || member("providerHead")?.string()? != core.provider_head
        || member("runId")?.number()? != core.run_id
        || member("runAttempt")?.number()? != core.run_attempt
        || parse_json_digest(member("subjectSha256")?)? != core.subject_sha256
        || parse_json_digest(member("bundleSha256")?)? != bundle
        || parse_json_digest(member("trustedRootRawSha256")?)? != trusted_root
        || member("verificationNetworkIsolation")?.string()?
            != "credentialless-loopback-proxy-best-effort"
        || !member("verificationCredentialsStripped")?.boolean()?
        || member("trustedRootRecordCount")?.number()? == 0
        || member("ghVersion")?.array()?.is_empty()
        || member("ghReleaseVersion")?.string()? != "2.93.0"
        || member("ghArchiveUrl")?.string()?
            != "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_linux_amd64.tar.gz"
        || member("ghChecksumsUrl")?.string()?
            != "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_checksums.txt"
        || parse_json_digest(member("ghArchiveSha256")?)?.hex()
            != "02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0"
        || parse_json_digest(member("ghChecksumsSha256")?)?.hex()
            != "f62a3bc9dedc88262c9c2b56eb653cb3ded6bde8076bdbb151f4cce9c8729da5"
        || parse_json_digest(member("ghBinarySha256")?)?.hex()
            != "014fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1"
        || parse_json_digest(member("ghExecutableSha256")?)?
            != parse_json_digest(member("ghBinarySha256")?)?
        || parse_json_digest(member("ghInstallManifestSha256")?)? != gh_install_manifest
    {
        return Err("collection custody trusted-root provenance is not exact".to_owned());
    }
    verify_attestation_argv(member("trustedRootAcquisitionArgv")?, false, core)?;
    verify_attestation_argv(member("verifyArgv")?, true, core)?;
    crate::assurance::utc_timestamp_seconds(member("trustedRootAcquiredAt")?.string()?)?;
    crate::assurance::utc_timestamp_seconds(verified_at)?;
    let identity = OnlineWrapperIdentity {
        core,
        bundle,
        trusted_root,
        gh_executable,
        gh_version,
        verified_at,
    };
    verify_online_wrapper_for_identity(&identity, raw_verification_bytes, verification)
}

struct OnlineWrapperIdentity<'a> {
    core: &'a VerifiedCollectionCustodyCore,
    bundle: Digest,
    trusted_root: Digest,
    gh_executable: Digest,
    gh_version: &'a crate::assurance::JsonValue,
    verified_at: &'a str,
}

fn verify_online_wrapper_for_identity(
    identity: &OnlineWrapperIdentity<'_>,
    raw_verification_bytes: &[u8],
    verification: &[u8],
) -> Result<(), String> {
    let verification = std::str::from_utf8(verification)
        .map_err(|_| "collection custody online verification is not UTF-8".to_owned())?;
    let verification_value = crate::assurance::parse_json(verification)?;
    if crate::assurance::canonical_json_bytes(&verification_value)? != verification.as_bytes() {
        return Err("collection custody online verification is not canonical JSON".to_owned());
    }
    let verification = verification_value.object()?;
    require_json_keys(
        verification,
        &[
            "bundleSha256",
            "capturedAt",
            "domain",
            "ghExecutableSha256",
            "ghVersion",
            "rawVerificationPath",
            "rawVerificationSha256",
            "schema",
            "subjectSha256",
            "trustedRootSha256",
            "verificationResult",
        ],
    )?;
    let member = |name| crate::assurance::json_member(verification, name);
    let verification_result = member("verificationResult")?;
    if member("domain")?.string()? != "hell.collection-custody.attestation.v1"
        || member("schema")?.string()? != "hell.collection-custody.online-verification.v1"
        || parse_json_digest(member("subjectSha256")?)? != identity.core.subject_sha256
        || parse_json_digest(member("bundleSha256")?)? != identity.bundle
        || parse_json_digest(member("trustedRootSha256")?)? != identity.trusted_root
        || member("rawVerificationPath")?.string()? != "online-verification.raw.json"
        || parse_json_digest(member("rawVerificationSha256")?)?
            != sha256_bytes(raw_verification_bytes)
        || member("ghVersion")? != identity.gh_version
        || parse_json_digest(member("ghExecutableSha256")?)? != identity.gh_executable
        || member("capturedAt")?.string()? != identity.verified_at
        || !matches!(
            verification_result,
            crate::assurance::JsonValue::Object(value) if !value.is_empty()
        )
    {
        return Err("collection custody online verification wrapper is not exact".to_owned());
    }
    let raw = std::str::from_utf8(raw_verification_bytes)
        .map_err(|_| "collection custody raw verification is not UTF-8".to_owned())?;
    let raw = crate::assurance::parse_json(raw)?;
    let raw = raw.array()?;
    if raw.len() != 1 || &raw[0] != verification_result {
        return Err("collection custody raw verification differs from its wrapper".to_owned());
    }
    Ok(())
}

fn parse_json_digest(value: &crate::assurance::JsonValue) -> Result<Digest, String> {
    Digest::from_hex(value.string()?).map_err(str::to_owned)
}

fn require_json_keys(
    object: &BTreeMap<String, crate::assurance::JsonValue>,
    expected: &[&str],
) -> Result<(), String> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("collection custody attestation JSON fields are missing or extra".to_owned());
    }
    Ok(())
}

fn verify_attestation_argv(
    value: &crate::assurance::JsonValue,
    verification: bool,
    core: &VerifiedCollectionCustodyCore,
) -> Result<(), String> {
    let argv = value
        .array()?
        .iter()
        .map(crate::assurance::JsonValue::string)
        .collect::<Result<Vec<_>, _>>()?;
    if if verification {
        argv.len() != 27
            || argv[0..3] != ["gh", "attestation", "verify"]
            || !argv[3].ends_with("custody-attestation-subject.json")
            || argv[4..7] != ["--repo", "Portfoligno/hell-rs", "--bundle"]
            || argv[7].is_empty()
            || argv[8] != "--custom-trusted-root"
            || !argv[9].ends_with("trusted-root.jsonl")
            || argv[10..13]
                != [
                    "--signer-workflow",
                    "Portfoligno/hell-rs/.github/workflows/collection-authority.yml",
                    "--signer-digest",
                ]
            || argv[13] != core.provider_head
            || argv[14..16] != ["--source-digest", core.provider_head.as_str()]
            || argv[16..18] != ["--source-ref", "refs/heads/main"]
            || argv[18..20]
                != [
                    "--cert-identity",
                    "https://github.com/Portfoligno/hell-rs/.github/workflows/collection-authority.yml@refs/heads/main",
                ]
            || argv[20..22]
                != [
                    "--cert-oidc-issuer",
                    "https://token.actions.githubusercontent.com",
                ]
            || argv[22..24] != ["--predicate-type", "https://slsa.dev/provenance/v1"]
            || argv[24..] != ["--deny-self-hosted-runners", "--format", "json"]
    } else {
        argv != ["gh", "attestation", "trusted-root"]
    } {
        return Err("collection custody attestation argv is not exact".to_owned());
    }
    Ok(())
}

impl CustodyComponentRoots {
    fn payload_merkle_root(&self) -> Digest {
        let mut bytes = b"hell-collection-custody-payload-merkle-v1\0".to_vec();
        for (name, digest) in [
            ("records", self.records),
            ("evidence", self.evidence),
            ("blobs", self.blobs),
            ("provenance", self.provenance),
            ("authority", self.authority),
            ("transformations", self.transformations),
            ("inputs", self.inputs),
        ] {
            push_frame(&mut bytes, name.as_bytes());
            push_frame(&mut bytes, digest.hex().as_bytes());
        }
        sha256_bytes(&bytes)
    }
}

fn authority_component_sha256(authority: &[u8], files: &[u8]) -> Digest {
    let mut bytes = b"hell-collection-custody-authority-component-v1\0".to_vec();
    push_frame(&mut bytes, authority);
    push_frame(&mut bytes, files);
    sha256_bytes(&bytes)
}

struct RetainedCaseEvidence {
    mappings: Vec<(&'static str, Digest)>,
    stdin: Digest,
    oracle_status: Digest,
    candidate_status: Digest,
    candidate_typed: Digest,
    oracle_typed: Option<Digest>,
    candidate_resource: Digest,
}

fn write_records_and_blobs(
    input: &Path,
    output: &Path,
    shards: &[CollectionBlackBoxShard],
) -> Result<(String, String), String> {
    let mut lines = Vec::with_capacity(shards.len());
    let mut evidence = Vec::with_capacity(shards.len());
    for shard in shards {
        let (record, retained) = retain_case_evidence(input, output, shard)?;
        lines.push(record);
        evidence.push(retained);
    }
    lines.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if lines.len() != EXACT_RECORD_COUNT || lines.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("collection custody record inventory is not exact 3573".to_owned());
    }
    let mut document = format!("{RECORD_HEADER}\n");
    for line in lines {
        writeln!(document, "{line}").expect("writing to String cannot fail");
    }
    write_file(&output.join("records.tsv"), document.as_bytes())?;
    evidence.sort();
    let mut evidence_document = "platform\tcaseId\tretainedEvidenceBlobs\n".to_owned();
    for line in evidence {
        writeln!(evidence_document, "{line}").expect("writing to String cannot fail");
    }
    write_file(&output.join("evidence.tsv"), evidence_document.as_bytes())?;
    Ok((document, evidence_document))
}

fn retain_case_evidence(
    input: &Path,
    output: &Path,
    shard: &CollectionBlackBoxShard,
) -> Result<(String, String), String> {
    let platform = platform_name(shard.platform)?;
    let bundle = input
        .join(platform)
        .join("collection-evidence/observations")
        .join(shard.case.case_id.as_ref());
    let mut mappings = [
        ("source", "main.hell"),
        ("descriptor", "case.toml"),
        ("execution-input", "execution-input.json"),
        ("stdin", "stdin.bin"),
        ("bundle-manifest", "bundle-manifest.json"),
        ("oracle-observation", "oracle/observation.json"),
        ("oracle-stdout", "oracle/stdout.bin"),
        ("oracle-stderr", "oracle/stderr.raw.bin"),
        ("candidate-observation", "candidate/observation.json"),
        ("candidate-stdout", "candidate/stdout.bin"),
        ("candidate-stderr", "candidate/stderr.raw.bin"),
        ("candidate-typed", "candidate/semantic-typed-result.json"),
        ("candidate-resource", "candidate/resource-audit.json"),
    ]
    .map(|(kind, relative)| {
        let path = bundle.join(relative);
        let digest = sha256_bytes(&read_file(&path)?);
        retain_blob(output, &path, digest)?;
        Ok::<_, String>((kind, digest))
    })
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    let oracle_typed_path = bundle.join("oracle/semantic-typed-result.json");
    let oracle_typed = oracle_typed_path
        .is_file()
        .then(|| {
            let digest = sha256_bytes(&read_file(&oracle_typed_path)?);
            retain_blob(output, &oracle_typed_path, digest)?;
            mappings.push(("oracle-typed-replay", digest));
            Ok::<Digest, String>(digest)
        })
        .transpose()?;
    let oracle_status = retain_status_blob(
        output,
        &bundle.join("oracle/observation.json"),
        shard.oracle_status_sha256,
    )?;
    mappings.push(("oracle-status", oracle_status));
    let candidate_status = retain_status_blob(
        output,
        &bundle.join("candidate/observation.json"),
        shard.candidate_status_sha256,
    )?;
    mappings.push(("candidate-status", candidate_status));
    validate_retained_case_digests(shard, &bundle, &mappings, oracle_status, candidate_status)?;
    let retained = RetainedCaseEvidence {
        stdin: mappings[3].1,
        oracle_status,
        candidate_status,
        candidate_typed: mappings[11].1,
        oracle_typed,
        candidate_resource: mappings[12].1,
        mappings,
    };
    let base = record_base(shard, &retained)?;
    let record = format!("{base}\t{}", record_leaf_sha256(&base).hex());
    let evidence = format!(
        "{platform}\t{}\t{}",
        shard.case.case_id,
        retained
            .mappings
            .iter()
            .map(|(kind, digest)| format!("{kind}={}", digest.hex()))
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok((record, evidence))
}

fn validate_retained_case_digests(
    shard: &CollectionBlackBoxShard,
    bundle: &Path,
    retained: &[(&str, Digest)],
    oracle_status: Digest,
    candidate_status: Digest,
) -> Result<(), String> {
    if retained[0].1 != shard.case.source_sha256
        || retained[1].1 != shard.case.descriptor_sha256
        || retained[2].1 != shard.case.execution_input_sha256
        || retained[3].1 != shard.case.stdin_sha256
        || retained[5].1 != shard.oracle_observation_sha256
        || retained[6].1 != shard.oracle_stdout_sha256
        || retained[7].1 != shard.oracle_stderr_sha256
        || retained[8].1 != shard.candidate_observation_sha256
        || retained[9].1 != shard.candidate_stdout_sha256
        || retained[10].1 != shard.candidate_stderr_sha256
        || retained[11].1
            != retained_typed_digest(
                shard.candidate_typed_result_sha256,
                &bundle.join("candidate/semantic-typed-result.json"),
            )?
        || oracle_status != shard.oracle_status_sha256
        || candidate_status != shard.candidate_status_sha256
    {
        return Err("collection custody retained evidence differs from verified record".into());
    }
    Ok(())
}

fn record_base(
    shard: &CollectionBlackBoxShard,
    retained: &RetainedCaseEvidence,
) -> Result<String, String> {
    let case = &shard.case;
    let values = [
        platform_name(shard.platform)?.to_owned(),
        atom(&case.case_id)?,
        atom(&case.operation)?,
        atom(&case.path)?,
        case.profile.as_str().to_owned(),
        case.source_sha256.hex(),
        case.arguments_sha256.hex(),
        case.environment_sha256.hex(),
        case.stdin_sha256.hex(),
        case.execution_input_sha256.hex(),
        case.descriptor_sha256.hex(),
        atom(&case.target_builtin)?,
        atom(&case.instance_target)?,
        case.comparator_contract_sha256.hex(),
        case.source_authority_manifest_sha256.hex(),
        optional_digest(case.expected_candidate_typed_result_sha256),
        completion(case.expected_completion).to_owned(),
        oracle_subject(shard.oracle_subject).to_owned(),
        atom(&shard.oracle_source_commit)?,
        shard.oracle_executable_sha256.hex(),
        optional_digest(shard.oracle_acquisition_receipt_sha256),
        optional_digest(shard.oracle_provider_attestation_sha256),
        shard.provider_repository_id.to_string(),
        shard.provider_run_id.to_string(),
        shard.provider_run_attempt.to_string(),
        shard.provider_artifact_id.to_string(),
        atom(&shard.provider_workflow_ref)?,
        atom(&shard.provider_event)?,
        shard.provider_candidate_subject_sha256.hex(),
        optional_digest(shard.oracle_build_record_sha256),
        dependency(shard.dependency_authority).to_owned(),
        shard.bundle_sha256.hex(),
        shard.oracle_observation_sha256.hex(),
        shard.candidate_observation_sha256.hex(),
        shard.oracle_stdout_sha256.hex(),
        shard.oracle_stderr_sha256.hex(),
        shard.oracle_status_sha256.hex(),
        shard.candidate_stdout_sha256.hex(),
        shard.candidate_stderr_sha256.hex(),
        shard.candidate_status_sha256.hex(),
        optional_digest(shard.candidate_typed_result_sha256),
        shard.candidate_comparator_trace_sha256.hex(),
        completion(shard.oracle_completion).to_owned(),
        completion(shard.candidate_completion).to_owned(),
        atom(&shard.candidate_source_commit)?,
        shard.candidate_executable_sha256.hex(),
        retained.stdin.hex(),
        retained.oracle_status.hex(),
        retained.candidate_status.hex(),
        retained.candidate_typed.hex(),
        optional_digest(retained.oracle_typed),
        retained.candidate_resource.hex(),
    ];
    Ok(values.join("\t"))
}

fn write_provenance(
    output: &Path,
    providers: &[(crate::assurance::VerifiedCollectionProviderArtifact, String)],
) -> Result<String, String> {
    let mut document = "platform\trepositoryId\trunId\trunAttempt\tartifactId\tartifactName\tproviderHeadCommit\tcandidateCommit\tworkflowRef\tevent\tobservedAt\tselectionSha256\tartifactApiRootSha256\tjobApiRootSha256\trunApiSha256\tworkflowSha256\toriginalZipSha256\toriginalZipBytes\textractedTreeSha256\tproviderSubjectSha256\toriginalZipRetained\n".to_owned();
    for (provider, _) in providers {
        writeln!(
            document,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\tfalse",
            atom(&provider.platform)?,
            provider.repository_id,
            provider.run_id,
            provider.run_attempt,
            provider.artifact_id,
            atom(&provider.artifact_name)?,
            atom(&provider.provider_head_commit)?,
            atom(&provider.candidate_commit)?,
            atom(&provider.workflow_ref)?,
            atom(&provider.event)?,
            atom(&provider.observed_at)?,
            provider.selection_sha256.hex(),
            provider.artifact_api_sha256.hex(),
            provider.job_api_sha256.hex(),
            provider.run_api_sha256.hex(),
            provider.workflow_sha256.hex(),
            provider.archive_sha256.hex(),
            provider.archive_size,
            provider.tree_sha256.hex(),
            provider.provider_subject_sha256.hex(),
        )
        .expect("writing to String cannot fail");
    }
    write_file(&output.join("provenance.tsv"), document.as_bytes())?;
    Ok(document)
}

fn write_authority(
    output: &Path,
    source: &hell_testkit::CollectionSourceAuthority,
    native_builds: &[CollectionNativeBuildAuthority],
) -> Result<String, String> {
    if native_builds.len() != 2 {
        return Err("collection custody requires exact macOS and Windows build authority".into());
    }
    let mut rows = vec![format!(
        "source\t-\t{}\t{}\t{}\t{}\t-\t-\t-\t-\t-\t-\t-\t-",
        source.manifest_sha256().hex(),
        source.reviewed_model_sha256().hex(),
        source.map_source_sha256().hex(),
        source.set_source_sha256().hex(),
    )];
    for build in native_builds {
        rows.push(format!(
            "native-build\t{}\t{}\t-\t-\t-\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            platform_name(build.platform)?,
            build.source_authority_manifest_sha256.hex(),
            atom(&build.source_commit)?,
            atom(&build.stack_version)?,
            build.resolver_lock_sha256.hex(),
            atom(&build.ghc_version)?,
            atom(&build.containers_version)?,
            build.cabal_revision_sha256.hex(),
            build.oracle_executable_sha256.hex(),
            build.build_record_sha256.hex(),
        ));
    }
    rows.sort();
    let mut document = "kind\tplatform\tsourceManifestSha256\treviewedModelSha256\tmapSourceSha256\tsetSourceSha256\tsourceCommit\tstackVersion\tresolverLockSha256\tghcVersion\tcontainersVersion\tcabalRevisionSha256\toracleExecutableSha256\tbuildRecordSha256\n".to_owned();
    for row in rows {
        writeln!(document, "{row}").expect("writing to String cannot fail");
    }
    write_file(&output.join("authority.tsv"), document.as_bytes())?;
    Ok(document)
}

fn write_authority_files(
    root: &Path,
    output: &Path,
    source: &hell_testkit::CollectionSourceAuthority,
) -> Result<String, String> {
    let manifest_path = root.join("compat/oracle-sources/collection-source-authority.tsv");
    let manifest_bytes = read_file(&manifest_path)?;
    if sha256_bytes(&manifest_bytes) != source.manifest_sha256() {
        return Err("collection custody retained source manifest differs".to_owned());
    }
    let manifest = parse_assignments(&manifest_bytes)?;
    let specs = [
        ("stack-yaml", "stackYamlPath", "stackYamlSha256", "raw"),
        ("stack-lock", "stackLockPath", "stackLockSha256", "raw"),
        (
            "source-archive",
            "sourceArchivePath",
            "sourceArchiveSha256",
            "base64",
        ),
        (
            "cabal-revision",
            "cabalRevisionPath",
            "cabalRevisionSha256",
            "raw",
        ),
        ("license", "licensePath", "licenseSha256", "raw"),
        ("map-source", "mapSourcePath", "mapSourceSha256", "raw"),
        ("set-source", "setSourcePath", "setSourceSha256", "raw"),
        (
            "reviewed-model",
            "reviewedModelPath",
            "reviewedModelSha256",
            "raw",
        ),
    ];
    let mut rows = vec![format!(
        "manifest\tcompat/oracle-sources/collection-source-authority.tsv\t{}\t{}\traw",
        source.manifest_sha256().hex(),
        source.manifest_sha256().hex(),
    )];
    retain_blob(output, &manifest_path, source.manifest_sha256())?;
    for (role, path_field, semantic_field, encoding) in specs {
        let relative = required_atom(&manifest, path_field)?;
        let semantic =
            Digest::from_hex(required_atom(&manifest, semantic_field)?).map_err(str::to_owned)?;
        let path = root.join(relative);
        let bytes = read_file(&path)?;
        let blob = sha256_bytes(&bytes);
        if encoding == "raw" && blob != semantic {
            return Err("collection custody source-authority file digest differs".to_owned());
        }
        retain_blob(output, &path, blob)?;
        rows.push(format!(
            "{role}\t{}\t{}\t{}\t{encoding}",
            atom(relative)?,
            blob.hex(),
            semantic.hex(),
        ));
    }
    rows.sort();
    let mut document = "role\tpath\tblobSha256\tsemanticSha256\tencoding\n".to_owned();
    for row in rows {
        writeln!(document, "{row}").expect("writing to String cannot fail");
    }
    write_file(&output.join("authority-files.tsv"), document.as_bytes())?;
    Ok(document)
}

fn write_transformations(
    shards: &[CollectionBlackBoxShard],
    providers: &[(crate::assurance::VerifiedCollectionProviderArtifact, String)],
    records: &str,
    evidence: &str,
) -> Result<String, String> {
    let mut leaf_by_key = BTreeMap::new();
    for line in records.lines().skip(1) {
        let fields = line.split('\t').collect::<Vec<_>>();
        leaf_by_key.insert((fields[0], fields[1]), fields[52]);
    }
    let evidence_by_key = evidence
        .lines()
        .skip(1)
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            ((fields[0], fields[1]), fields[2])
        })
        .collect::<BTreeMap<_, _>>();
    let mut lines = Vec::new();
    for shard in shards {
        let platform = platform_name(shard.platform)?;
        let leaf = leaf_by_key
            .get(&(platform, shard.case.case_id.as_ref()))
            .ok_or_else(|| "collection custody record leaf join is missing".to_owned())?;
        let evidence = evidence_by_key
            .get(&(platform, shard.case.case_id.as_ref()))
            .ok_or_else(|| "collection custody evidence join is missing".to_owned())?;
        lines.push(format!(
            "bundle\t{platform}\t{}\t{}\t{leaf}\t{}\t{}\tomitted-after-attested-transformation",
            shard.case.case_id,
            shard.bundle_sha256.hex(),
            evidence_mapping_sha256(evidence).hex(),
            evidence,
        ));
    }
    for (provider, _) in providers {
        lines.push(format!(
            "provider-zip\t{}\t-\t{}\t{}\t-\t-\tomitted-after-attested-transformation",
            atom(&provider.platform)?,
            provider.archive_sha256.hex(),
            provider.tree_sha256.hex(),
        ));
    }
    lines.sort();
    if lines.len() != EXACT_TRANSFORMATION_COUNT {
        return Err("collection custody transformation inventory is not exact".to_owned());
    }
    let mut document = "kind\tplatform\tcaseId\toriginalRootSha256\tretainedRecordOrTreeSha256\tretainedEvidenceMapSha256\tretainedEvidenceBlobs\tdisposition\n".to_owned();
    for line in lines {
        writeln!(document, "{line}").expect("writing to String cannot fail");
    }
    Ok(document)
}

struct InputRootRequest<'a> {
    root: &'a Path,
    input: &'a Path,
    provider: &'a Path,
    report: &'a Path,
    output: &'a Path,
    source_manifest: Digest,
    campaign_subject: Digest,
    provider_head: &'a str,
}

fn write_input_roots(request: &InputRootRequest<'_>) -> Result<String, String> {
    let InputRootRequest {
        root,
        input,
        provider,
        report,
        output,
        source_manifest,
        campaign_subject,
        provider_head,
    } = request;
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("cannot locate collection custody verifier: {error}"))?;
    let workflow = git_show_bytes(
        root,
        provider_head,
        ".github/workflows/collection-authority.yml",
    )?;
    let workflow_sha256 = retain_bytes_blob(output, &workflow)?;
    let policy = git_show_bytes(root, provider_head, "compat/acquisition-sources.toml")?;
    let policy_sha256 = retain_bytes_blob(output, &policy)?;
    let source_manifest_path = root.join("compat/oracle-sources/collection-source-authority.tsv");
    let source_manifest_bytes = read_file(&source_manifest_path)?;
    if sha256_bytes(&source_manifest_bytes) != *source_manifest {
        return Err("collection custody source manifest differs from typed authority".into());
    }
    retain_blob(output, &source_manifest_path, *source_manifest)?;
    let reviewed_model_path = root.join("crates/hell-testkit/src/reviewed_set.rs");
    let reviewed_model = sha256_file(&reviewed_model_path).map_err(|error| error.to_string())?;
    retain_blob(output, &reviewed_model_path, reviewed_model)?;
    let report_digest = sha256_file(report).map_err(|error| error.to_string())?;
    retain_blob(output, report, report_digest)?;
    let verifier_digest = sha256_file(&current_exe).map_err(|error| error.to_string())?;
    retain_blob(output, &current_exe, verifier_digest)?;
    let rows = [
        (
            "authenticatedProviderTree",
            crate::assurance::record_digest(provider)?,
        ),
        (
            "authenticatedShardTree",
            crate::assurance::record_digest(input)?,
        ),
        ("campaignProviderRoot", campaign_subject.hex()),
        ("sourceAuthorityManifest", source_manifest.hex()),
        ("reviewedModel", reviewed_model.hex()),
        ("successfulVerifierReport", report_digest.hex()),
        ("trustedVerifierExecutable", verifier_digest.hex()),
        ("historicalProviderWorkflow", workflow_sha256.hex()),
        ("historicalAcquisitionPolicy", policy_sha256.hex()),
    ];
    let mut document = "name\tsha256\n".to_owned();
    for (name, digest) in rows {
        writeln!(document, "{name}\t{digest}").expect("writing to String cannot fail");
    }
    write_file(&output.join("input-roots.tsv"), document.as_bytes())?;
    Ok(document)
}

fn write_blob_inventory(output: &Path) -> Result<String, String> {
    let directory = output.join("blobs/sha256");
    let mut rows = fs::read_dir(&directory)
        .map_err(|error| format!("cannot enumerate custody blobs: {error}"))?
        .map(|entry| {
            let entry =
                entry.map_err(|error| format!("cannot enumerate custody blobs: {error}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "custody blob name is not UTF-8".to_owned())?;
            Digest::from_hex(&name).map_err(str::to_owned)?;
            let bytes = read_file(&entry.path())?;
            if sha256_bytes(&bytes).hex() != name {
                return Err("custody blob filename differs from its bytes".to_owned());
            }
            Ok(format!("{name}\t{}", bytes.len()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    rows.sort();
    let mut document = "sha256\tbytes\n".to_owned();
    for row in rows {
        writeln!(document, "{row}").expect("writing to String cannot fail");
    }
    write_file(&output.join("blobs.tsv"), document.as_bytes())?;
    Ok(document)
}

fn render_manifest(
    roots: &CustodyComponentRoots,
    payload: Digest,
    identity: &CustodyIdentity<'_>,
) -> String {
    format!(
        concat!(
            "schemaVersion\t1\n",
            "domain\t{PACKAGE_DOMAIN}\n",
            "state\tprepared-unattested-nonauthoritative\n",
            "originalProviderZipsRetained\tfalse\n",
            "historicalZipReplayAvailable\tfalse\n",
            "recordCount\t3573\n",
            "platformCount\t3\n",
            "candidateCommit\t{candidate}\n",
            "providerHeadCommit\t{provider_head}\n",
            "repositoryId\t{repository_id}\n",
            "providerRunId\t{run_id}\n",
            "providerRunAttempt\t{run_attempt}\n",
            "recordsSha256\t{records}\n",
            "evidenceSha256\t{evidence}\n",
            "blobsSha256\t{blobs}\n",
            "provenanceSha256\t{provenance}\n",
            "authoritySha256\t{authority}\n",
            "transformationSha256\t{transformations}\n",
            "inputRootsSha256\t{inputs}\n",
            "payloadMerkleRoot\t{payload}\n"
        ),
        records = roots.records.hex(),
        evidence = roots.evidence.hex(),
        blobs = roots.blobs.hex(),
        provenance = roots.provenance.hex(),
        authority = roots.authority.hex(),
        transformations = roots.transformations.hex(),
        inputs = roots.inputs.hex(),
        payload = payload.hex(),
        PACKAGE_DOMAIN = PACKAGE_DOMAIN,
        candidate = identity.candidate,
        provider_head = identity.provider_head,
        repository_id = identity.repository_id,
        run_id = identity.run_id,
        run_attempt = identity.run_attempt,
    )
}

fn render_attestation_subject(
    payload: Digest,
    manifest: Digest,
    roots: &CustodyComponentRoots,
    identity: &CustodyIdentity<'_>,
) -> String {
    format!(
        concat!(
            "{{\n  \"schemaVersion\": 1,\n",
            "  \"domain\": \"hell.collection-custody.attestation.v1\",\n",
            "  \"state\": \"prepared-unattested-nonauthoritative\",\n",
            "  \"originalProviderZipsRetained\": false,\n",
            "  \"historicalZipReplayAvailable\": false,\n",
            "  \"recordCount\": 3573,\n",
            "  \"candidateCommit\": {candidate:?},\n",
            "  \"providerHeadCommit\": {provider_head:?},\n",
            "  \"repositoryId\": {repository_id},\n",
            "  \"providerRunId\": {run_id},\n",
            "  \"providerRunAttempt\": {run_attempt},\n",
            "  \"payloadMerkleRoot\": {payload:?},\n",
            "  \"manifestSha256\": {manifest:?},\n",
            "  \"recordsSha256\": {records:?},\n",
            "  \"evidenceSha256\": {evidence:?},\n",
            "  \"blobsSha256\": {blobs:?},\n",
            "  \"provenanceSha256\": {provenance:?},\n",
            "  \"authoritySha256\": {authority:?},\n",
            "  \"transformationSha256\": {transformations:?},\n",
            "  \"inputRootsSha256\": {inputs:?}\n}}\n"
        ),
        payload = payload.hex(),
        manifest = manifest.hex(),
        records = roots.records.hex(),
        evidence = roots.evidence.hex(),
        blobs = roots.blobs.hex(),
        provenance = roots.provenance.hex(),
        authority = roots.authority.hex(),
        transformations = roots.transformations.hex(),
        inputs = roots.inputs.hex(),
        candidate = identity.candidate,
        provider_head = identity.provider_head,
        repository_id = identity.repository_id,
        run_id = identity.run_id,
        run_attempt = identity.run_attempt,
    )
}

pub(crate) fn verify_core(
    _root: &Path,
    package: &Path,
) -> Result<VerifiedCollectionCustodyCore, String> {
    verify_package_inventory(package)?;
    let manifest_bytes = read_file(&package.join("manifest.tsv"))?;
    let manifest = parse_assignments(&manifest_bytes)?;
    let expected_keys = BTreeSet::from([
        "schemaVersion",
        "domain",
        "state",
        "originalProviderZipsRetained",
        "historicalZipReplayAvailable",
        "recordCount",
        "platformCount",
        "candidateCommit",
        "providerHeadCommit",
        "repositoryId",
        "providerRunId",
        "providerRunAttempt",
        "recordsSha256",
        "blobsSha256",
        "provenanceSha256",
        "authoritySha256",
        "transformationSha256",
        "evidenceSha256",
        "inputRootsSha256",
        "payloadMerkleRoot",
    ]);
    if manifest.keys().copied().collect::<BTreeSet<_>>() != expected_keys
        || manifest.get("schemaVersion") != Some(&"1")
        || manifest.get("domain") != Some(&PACKAGE_DOMAIN)
        || manifest.get("state") != Some(&"prepared-unattested-nonauthoritative")
        || manifest.get("originalProviderZipsRetained") != Some(&"false")
        || manifest.get("historicalZipReplayAvailable") != Some(&"false")
        || manifest.get("recordCount") != Some(&"3573")
        || manifest.get("platformCount") != Some(&"3")
        || manifest.get("repositoryId") != Some(&"1327351238")
    {
        return Err("collection custody manifest is noncanonical".to_owned());
    }
    let records = read_file(&package.join("records.tsv"))?;
    let evidence = read_file(&package.join("evidence.tsv"))?;
    let blobs = read_file(&package.join("blobs.tsv"))?;
    let provenance = read_file(&package.join("provenance.tsv"))?;
    let authority = read_file(&package.join("authority.tsv"))?;
    let authority_files = read_file(&package.join("authority-files.tsv"))?;
    let transformations = read_file(&package.join("transformation.tsv"))?;
    let inputs = read_file(&package.join("input-roots.tsv"))?;
    let roots = CustodyComponentRoots {
        records: sha256_bytes(&records),
        evidence: sha256_bytes(&evidence),
        blobs: sha256_bytes(&blobs),
        provenance: sha256_bytes(&provenance),
        authority: authority_component_sha256(&authority, &authority_files),
        transformations: sha256_bytes(&transformations),
        inputs: sha256_bytes(&inputs),
    };
    for (field, actual) in [
        ("recordsSha256", roots.records),
        ("evidenceSha256", roots.evidence),
        ("blobsSha256", roots.blobs),
        ("provenanceSha256", roots.provenance),
        ("authoritySha256", roots.authority),
        ("transformationSha256", roots.transformations),
        ("inputRootsSha256", roots.inputs),
    ] {
        if manifest.get(field).copied() != Some(actual.hex().as_str()) {
            return Err(format!(
                "collection custody {field} differs from retained bytes"
            ));
        }
    }
    let payload_merkle_root = roots.payload_merkle_root();
    if manifest.get("payloadMerkleRoot").copied() != Some(payload_merkle_root.hex().as_str()) {
        return Err("collection custody payload Merkle root differs".to_owned());
    }
    verify_provenance(&provenance, &manifest)?;
    verify_records(&records, &provenance)?;
    verify_blobs(package, &blobs)?;
    verify_evidence(package, &records, &evidence)?;
    verify_transformations(&transformations, &records, &evidence, &provenance)?;
    verify_authority(&authority, &authority_files, &records, package)?;
    verify_input_roots(&inputs, &records, &provenance, &authority, package)?;
    verify_blob_conservation(&blobs, &evidence, &authority_files, &inputs)?;
    verify_subject(
        package,
        &manifest_bytes,
        &manifest,
        &roots,
        payload_merkle_root,
    )
}

fn verify_blob_conservation(
    blobs: &[u8],
    evidence: &[u8],
    authority_files: &[u8],
    inputs: &[u8],
) -> Result<(), String> {
    let inventory = std::str::from_utf8(blobs)
        .map_err(|_| "collection custody blob inventory is not UTF-8".to_owned())?
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once('\t').map(|(digest, _)| digest))
        .collect::<BTreeSet<_>>();
    let mut referenced = BTreeSet::new();
    for line in std::str::from_utf8(evidence)
        .map_err(|_| "collection custody evidence is not UTF-8".to_owned())?
        .lines()
        .skip(1)
    {
        let encoded = line
            .split('\t')
            .nth(2)
            .ok_or_else(|| "collection custody evidence row is malformed".to_owned())?;
        for mapping in encoded.split(',') {
            let (_, digest) = mapping
                .split_once('=')
                .ok_or_else(|| "collection custody evidence mapping is malformed".to_owned())?;
            referenced.insert(digest);
        }
    }
    for line in std::str::from_utf8(authority_files)
        .map_err(|_| "collection custody authority files are not UTF-8".to_owned())?
        .lines()
        .skip(1)
    {
        let digest = line
            .split('\t')
            .nth(2)
            .ok_or_else(|| "collection custody authority-file row is malformed".to_owned())?;
        referenced.insert(digest);
    }
    for line in std::str::from_utf8(inputs)
        .map_err(|_| "collection custody input roots are not UTF-8".to_owned())?
        .lines()
        .skip(1)
    {
        let (name, digest) = line
            .split_once('\t')
            .ok_or_else(|| "collection custody input-root row is malformed".to_owned())?;
        if matches!(
            name,
            "sourceAuthorityManifest"
                | "reviewedModel"
                | "successfulVerifierReport"
                | "trustedVerifierExecutable"
                | "historicalProviderWorkflow"
                | "historicalAcquisitionPolicy"
        ) {
            referenced.insert(digest);
        }
    }
    if inventory != referenced {
        return Err("collection custody blob inventory is not exactly conserved".to_owned());
    }
    Ok(())
}

fn verify_subject(
    package: &Path,
    manifest_bytes: &[u8],
    manifest: &BTreeMap<&str, &str>,
    roots: &CustodyComponentRoots,
    payload_merkle_root: Digest,
) -> Result<VerifiedCollectionCustodyCore, String> {
    let candidate_commit = required_atom(manifest, "candidateCommit")?.to_owned();
    let provider_head = required_atom(manifest, "providerHeadCommit")?.to_owned();
    require_lower_git_commit(&candidate_commit)?;
    require_lower_git_commit(&provider_head)?;
    let repository_id = required_u64(manifest, "repositoryId")?;
    let run_id = required_u64(manifest, "providerRunId")?;
    let run_attempt = required_u64(manifest, "providerRunAttempt")?;
    let identity = CustodyIdentity {
        candidate: &candidate_commit,
        provider_head: &provider_head,
        repository_id,
        run_id,
        run_attempt,
    };
    let expected_subject = render_attestation_subject(
        payload_merkle_root,
        sha256_bytes(manifest_bytes),
        roots,
        &identity,
    );
    let subject = read_file(&package.join("custody-attestation-subject.json"))?;
    if subject != expected_subject.as_bytes() {
        return Err("collection custody attestation subject is noncanonical".to_owned());
    }
    let subject_sha256 = sha256_bytes(&subject);
    let digest_record = read_file(&package.join("custody-attestation-subject.json.sha256"))?;
    if digest_record
        != format!(
            "{}  custody-attestation-subject.json\n",
            subject_sha256.hex()
        )
        .as_bytes()
    {
        return Err("collection custody subject digest record is invalid".to_owned());
    }
    Ok(VerifiedCollectionCustodyCore {
        payload_merkle_root,
        subject_sha256,
        candidate_commit,
        provider_head,
        repository_id,
        run_id,
        run_attempt,
    })
}

fn verify_package_inventory(package: &Path) -> Result<(), String> {
    let expected = BTreeSet::from([
        "authority-files.tsv",
        "authority.tsv",
        "blobs",
        "blobs.tsv",
        "custody-attestation-subject.json",
        "custody-attestation-subject.json.sha256",
        "evidence.tsv",
        "input-roots.tsv",
        "manifest.tsv",
        "provenance.tsv",
        "records.tsv",
        "transformation.tsv",
    ]);
    let observed = fs::read_dir(package)
        .map_err(|error| format!("cannot enumerate collection custody package: {error}"))?
        .map(|entry| {
            let entry = entry
                .map_err(|error| format!("cannot enumerate collection custody package: {error}"))?;
            if entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_symlink()
            {
                return Err("collection custody package contains a symlink".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "collection custody package filename is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed != expected.into_iter().map(str::to_owned).collect() {
        return Err("collection custody package inventory is missing or extra".to_owned());
    }
    Ok(())
}

fn verify_records(bytes: &[u8], provenance: &[u8]) -> Result<(), String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody records are not UTF-8".to_owned())?;
    let mut lines = document.lines();
    if lines.next() != Some(RECORD_HEADER) {
        return Err("collection custody record header is invalid".to_owned());
    }
    let provider_rows = provenance_rows(provenance)?;
    let mut seen = BTreeSet::new();
    let mut cases = BTreeMap::<String, Vec<String>>::new();
    let mut previous = None;
    for line in lines {
        if previous.is_some_and(|prior: &str| prior.as_bytes() >= line.as_bytes()) {
            return Err("collection custody records are not strictly sorted".to_owned());
        }
        previous = Some(line);
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != RECORD_FIELD_COUNT {
            return Err("collection custody record field count is invalid".to_owned());
        }
        let platform = fields[0];
        if !matches!(platform, "linux-amd64" | "macos-arm64" | "windows-amd64")
            || !seen.insert((fields[1].to_owned(), platform.to_owned()))
        {
            return Err("collection custody record identity is duplicate or invalid".to_owned());
        }
        let provider = provider_rows
            .get(platform)
            .ok_or_else(|| "collection custody record has no provider root".to_owned())?;
        let historical_case = validate_record_semantics(&fields, provider)?;
        if cases
            .entry(fields[1].to_owned())
            .or_insert_with(|| historical_case.clone())
            != &historical_case
        {
            return Err("collection custody historical case differs by platform".to_owned());
        }
    }
    if seen.len() != EXACT_RECORD_COUNT
        || cases.len() != 1_191
        || cases.keys().any(|case| {
            ["linux-amd64", "macos-arm64", "windows-amd64"]
                .iter()
                .any(|platform| !seen.contains(&(case.clone(), (*platform).to_owned())))
        })
    {
        return Err("collection custody records omit an exact case/platform".to_owned());
    }
    let map_count = cases
        .values()
        .filter(|case| case[1].starts_with("Map."))
        .count();
    let set_count = cases
        .values()
        .filter(|case| case[1].starts_with("Set."))
        .count();
    if map_count != 712
        || set_count != 479
        || cases.values().any(|case| {
            case[0].is_empty()
                || case[2].is_empty()
                || case[3].is_empty()
                || case[10].is_empty()
                || case[11].is_empty()
        })
    {
        return Err("collection custody historical Map712/Set479 split is invalid".to_owned());
    }
    Ok(())
}

fn validate_record_semantics(fields: &[&str], provider: &[&str]) -> Result<Vec<String>, String> {
    if fields[22] != provider[1]
        || fields[23] != provider[2]
        || fields[24] != provider[3]
        || fields[25] != provider[4]
        || fields[26] != provider[8]
        || fields[27] != provider[9]
        || fields[44] != provider[7]
        || fields[46] != fields[8]
        || fields[47] != fields[36]
        || fields[48] != fields[39]
        || fields[52] != record_leaf_sha256(&fields[..52].join("\t")).hex()
    {
        return Err("collection custody record differs from provider authority".to_owned());
    }
    for index in [
        5, 6, 7, 8, 9, 10, 13, 14, 19, 28, 31, 32, 33, 34, 35, 36, 37, 38, 39, 41, 45, 46, 47, 48,
        49, 51, 52,
    ] {
        Digest::from_hex(fields[index]).map_err(|_| format!("record digest {index} malformed"))?;
    }
    for index in [15, 20, 21, 29, 40, 50] {
        if fields[index] != "-" {
            Digest::from_hex(fields[index])
                .map_err(|_| format!("optional digest {index} malformed"))?;
        }
    }
    for index in [22, 23, 24, 25] {
        if fields[index]
            .parse::<u64>()
            .ok()
            .as_ref()
            .is_none_or(|value| *value == 0)
        {
            return Err(format!("record integer {index} is invalid"));
        }
    }
    if fields[42] != "success"
        || fields[43] != "success"
        || fields[16] != fields[43]
        || fields[41] != fields[13]
        || fields[40] == "-"
        || fields[40] != fields[15]
        || fields[22] != "1327351238"
    {
        return Err("collection custody record result joins are invalid".to_owned());
    }
    require_lower_git_commit(fields[18])?;
    require_lower_git_commit(fields[44])?;
    let valid_platform = if fields[0] == "linux-amd64" {
        fields[17] == "linux-result-only"
            && fields[20] != "-"
            && fields[21] != "-"
            && fields[29] == "-"
            && fields[30] == "unknown-result-only"
    } else {
        fields[17] == "native-source-build"
            && fields[20] == "-"
            && fields[21] == "-"
            && fields[29] != "-"
            && fields[30] == "reported-version-no-exact-source"
    };
    if !valid_platform {
        return Err("collection custody platform authority kind is invalid".to_owned());
    }
    Ok(fields[1..17]
        .iter()
        .map(|field| (*field).to_owned())
        .collect())
}

fn verify_blobs(package: &Path, bytes: &[u8]) -> Result<(), String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody blob inventory is not UTF-8".to_owned())?;
    let mut lines = document.lines();
    if lines.next() != Some("sha256\tbytes") {
        return Err("collection custody blob inventory header is invalid".to_owned());
    }
    let mut expected = BTreeSet::new();
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        let [digest, size] = fields.as_slice() else {
            return Err("collection custody blob inventory row is malformed".to_owned());
        };
        Digest::from_hex(digest).map_err(str::to_owned)?;
        let size = size
            .parse::<usize>()
            .map_err(|_| "collection custody blob size is malformed".to_owned())?;
        let path = package.join("blobs/sha256").join(digest);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect collection custody blob: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err("collection custody blob is not one regular file".to_owned());
        }
        let blob = read_file(&path)?;
        if blob.len() != size || sha256_bytes(&blob).hex() != *digest || !expected.insert(*digest) {
            return Err("collection custody blob differs from its content address".to_owned());
        }
    }
    let observed = fs::read_dir(package.join("blobs/sha256"))
        .map_err(|error| format!("cannot enumerate collection custody blobs: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot enumerate collection custody blobs: {error}"))
                .and_then(|entry| {
                    let file_type = entry.file_type().map_err(|error| {
                        format!("cannot inspect collection custody blob: {error}")
                    })?;
                    if file_type.is_symlink() || !file_type.is_file() {
                        return Err("collection custody blob directory has a non-file".to_owned());
                    }
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| "collection custody blob filename is not UTF-8".to_owned())
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed != expected.into_iter().map(str::to_owned).collect() {
        return Err("collection custody blob directory is missing or extra".to_owned());
    }
    Ok(())
}

fn verify_evidence(package: &Path, records: &[u8], evidence: &[u8]) -> Result<(), String> {
    let records = std::str::from_utf8(records)
        .map_err(|_| "collection custody records are not UTF-8".to_owned())?
        .lines()
        .skip(1)
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            ((fields[0], fields[1]), fields)
        })
        .collect::<BTreeMap<_, _>>();
    let document = std::str::from_utf8(evidence)
        .map_err(|_| "collection custody evidence inventory is not UTF-8".to_owned())?;
    let mut lines = document.lines();
    if lines.next() != Some("platform\tcaseId\tretainedEvidenceBlobs") {
        return Err("collection custody evidence header is invalid".to_owned());
    }
    let mut seen = BTreeSet::new();
    let mut previous = None;
    for line in lines {
        if previous.is_some_and(|prior: &str| prior >= line) {
            return Err("collection custody evidence rows are not strictly sorted".to_owned());
        }
        previous = Some(line);
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 3 || !seen.insert((fields[0], fields[1])) {
            return Err("collection custody evidence identity is invalid".to_owned());
        }
        let record = records
            .get(&(fields[0], fields[1]))
            .ok_or_else(|| "collection custody evidence has no record".to_owned())?;
        verify_evidence_row(package, fields[2], record)?;
    }
    if seen.len() != EXACT_RECORD_COUNT || seen.len() != records.len() {
        return Err("collection custody evidence does not cover every record".to_owned());
    }
    Ok(())
}

fn verify_evidence_row(package: &Path, encoded: &str, record: &[&str]) -> Result<(), String> {
    let mapping_rows = encoded
        .split(',')
        .map(|mapping| {
            mapping
                .split_once('=')
                .ok_or_else(|| "collection custody evidence mapping is malformed".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mappings = mapping_rows.iter().copied().collect::<BTreeMap<_, _>>();
    let mut expected_kinds = BTreeSet::from([
        "source",
        "descriptor",
        "execution-input",
        "stdin",
        "bundle-manifest",
        "oracle-observation",
        "oracle-stdout",
        "oracle-stderr",
        "oracle-status",
        "candidate-observation",
        "candidate-stdout",
        "candidate-stderr",
        "candidate-status",
        "candidate-typed",
        "candidate-resource",
    ]);
    if record[50] != "-" {
        expected_kinds.insert("oracle-typed-replay");
    }
    if mapping_rows.len() != mappings.len()
        || mappings.keys().copied().collect::<BTreeSet<_>>() != expected_kinds
    {
        return Err("collection custody evidence mapping is missing or extra".to_owned());
    }
    for digest in mappings.values() {
        Digest::from_hex(digest).map_err(str::to_owned)?;
        let blob = read_file(&package.join("blobs/sha256").join(digest))?;
        if sha256_bytes(&blob).hex() != *digest {
            return Err("collection custody evidence blob is corrupt".to_owned());
        }
    }
    for (kind, record_index) in [
        ("source", 5),
        ("descriptor", 10),
        ("execution-input", 9),
        ("stdin", 46),
        ("oracle-observation", 32),
        ("oracle-stdout", 34),
        ("oracle-stderr", 35),
        ("oracle-status", 47),
        ("candidate-observation", 33),
        ("candidate-stdout", 37),
        ("candidate-stderr", 38),
        ("candidate-status", 48),
        ("candidate-typed", 49),
        ("candidate-resource", 51),
    ] {
        if mappings.get(kind).copied() != Some(record[record_index]) {
            return Err("collection custody evidence digest differs from record".to_owned());
        }
    }
    if record[50] != "-" && mappings.get("oracle-typed-replay").copied() != Some(record[50]) {
        return Err("collection custody oracle typed replay digest differs".to_owned());
    }
    verify_evidence_semantics(package, &mappings, record)
}

fn verify_evidence_semantics(
    package: &Path,
    mappings: &BTreeMap<&str, &str>,
    record: &[&str],
) -> Result<(), String> {
    let expected_status = canonical_process_status_bytes(true, Some(0));
    for kind in ["oracle-status", "candidate-status"] {
        let status = read_file(&package.join("blobs/sha256").join(mappings[kind]))?;
        if status != expected_status {
            return Err("collection custody retained status is not exact success/code0".into());
        }
    }
    let typed = read_file(
        &package
            .join("blobs/sha256")
            .join(mappings["candidate-typed"]),
    )?;
    let canonical = typed
        .strip_suffix(b"\n")
        .ok_or_else(|| "collection custody typed-result blob is noncanonical".to_owned())?;
    if sha256_bytes(canonical).hex() != record[40] {
        return Err("collection custody typed-result bytes differ from semantic authority".into());
    }
    let resource = read_file(
        &package
            .join("blobs/sha256")
            .join(mappings["candidate-resource"]),
    )?;
    hell_testkit::verify_zero_resource_audit_bytes(&resource).map_err(|error| error.to_string())?;
    let bundle_manifest = read_file(
        &package
            .join("blobs/sha256")
            .join(mappings["bundle-manifest"]),
    )?;
    let declared = hell_testkit::verified_observation_bundle_manifest_files(&bundle_manifest)
        .map_err(|error| error.to_string())?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let mut expected_paths = vec![
        ("main.hell", "source"),
        ("case.toml", "descriptor"),
        ("execution-input.json", "execution-input"),
        ("stdin.bin", "stdin"),
        ("oracle/observation.json", "oracle-observation"),
        ("oracle/stdout.bin", "oracle-stdout"),
        ("oracle/stderr.raw.bin", "oracle-stderr"),
        ("candidate/observation.json", "candidate-observation"),
        ("candidate/stdout.bin", "candidate-stdout"),
        ("candidate/stderr.raw.bin", "candidate-stderr"),
        ("candidate/semantic-typed-result.json", "candidate-typed"),
        ("candidate/resource-audit.json", "candidate-resource"),
    ];
    if record[50] != "-" {
        expected_paths.push(("oracle/semantic-typed-result.json", "oracle-typed-replay"));
    }
    if expected_paths.iter().any(|(path, kind)| {
        declared.get(*path).map(|digest| digest.hex()).as_deref() != mappings.get(*kind).copied()
    }) {
        return Err("collection custody retained blobs drift from bundle manifest".into());
    }
    Ok(())
}

fn verify_transformations(
    bytes: &[u8],
    records: &[u8],
    evidence: &[u8],
    provenance: &[u8],
) -> Result<(), String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody transformation map is not UTF-8".to_owned())?;
    let lines = document.lines().collect::<Vec<_>>();
    if lines.first().copied()
        != Some(
            "kind\tplatform\tcaseId\toriginalRootSha256\tretainedRecordOrTreeSha256\tretainedEvidenceMapSha256\tretainedEvidenceBlobs\tdisposition",
        )
        || lines.len() != EXACT_TRANSFORMATION_COUNT + 1
        || lines[1..].windows(2).any(|pair| pair[0] >= pair[1])
        || lines[1..]
            .iter()
            .any(|line| !line.ends_with("\tomitted-after-attested-transformation"))
    {
        return Err("collection custody transformation map is noncanonical".to_owned());
    }
    let records = std::str::from_utf8(records)
        .map_err(|_| "collection custody records are not UTF-8".to_owned())?
        .lines()
        .skip(1)
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            ((fields[0], fields[1]), fields)
        })
        .collect::<BTreeMap<_, _>>();
    let evidence = std::str::from_utf8(evidence)
        .map_err(|_| "collection custody evidence is not UTF-8".to_owned())?
        .lines()
        .skip(1)
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            ((fields[0], fields[1]), fields[2])
        })
        .collect::<BTreeMap<_, _>>();
    let providers = provenance_rows(provenance)?;
    let mut bundles = BTreeSet::new();
    let mut zips = BTreeSet::new();
    for line in &lines[1..] {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 8 {
            return Err("collection custody transformation row is malformed".to_owned());
        }
        match fields[0] {
            "bundle" => {
                let key = (fields[1], fields[2]);
                let record = records.get(&key).ok_or_else(|| {
                    "collection custody bundle transformation has no record".to_owned()
                })?;
                let retained = evidence.get(&key).ok_or_else(|| {
                    "collection custody bundle transformation has no evidence".to_owned()
                })?;
                if !bundles.insert(key)
                    || fields[3] != record[31]
                    || fields[4] != record[52]
                    || fields[5] != evidence_mapping_sha256(retained).hex()
                    || fields[6] != *retained
                {
                    return Err(
                        "collection custody bundle transformation is not conservative".into(),
                    );
                }
            }
            "provider-zip" => {
                let provider = providers.get(fields[1]).ok_or_else(|| {
                    "collection custody ZIP transformation has no provider".to_owned()
                })?;
                if fields[2] != "-"
                    || !zips.insert(fields[1])
                    || fields[3] != provider[16]
                    || fields[4] != provider[18]
                    || fields[5] != "-"
                    || fields[6] != "-"
                {
                    return Err("collection custody ZIP transformation is not conservative".into());
                }
            }
            _ => return Err("collection custody transformation kind is invalid".to_owned()),
        }
    }
    if bundles.len() != records.len()
        || bundles.len() != evidence.len()
        || zips != providers.keys().copied().collect()
    {
        return Err("collection custody transformation inventory is incomplete".to_owned());
    }
    Ok(())
}

fn verify_provenance(bytes: &[u8], manifest: &BTreeMap<&str, &str>) -> Result<(), String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody provenance is not UTF-8".to_owned())?;
    let lines = document.lines().collect::<Vec<_>>();
    if lines.len() != 4
        || lines[0]
            != "platform\trepositoryId\trunId\trunAttempt\tartifactId\tartifactName\tproviderHeadCommit\tcandidateCommit\tworkflowRef\tevent\tobservedAt\tselectionSha256\tartifactApiRootSha256\tjobApiRootSha256\trunApiSha256\tworkflowSha256\toriginalZipSha256\toriginalZipBytes\textractedTreeSha256\tproviderSubjectSha256\toriginalZipRetained"
    {
        return Err("collection custody provider provenance is noncanonical".to_owned());
    }
    let mut platforms = BTreeSet::new();
    let mut artifact_ids = BTreeSet::new();
    for line in &lines[1..] {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 21
            || fields[1] != *manifest.get("repositoryId").unwrap_or(&"")
            || fields[2] != *manifest.get("providerRunId").unwrap_or(&"")
            || fields[3] != *manifest.get("providerRunAttempt").unwrap_or(&"")
            || fields[6] != *manifest.get("providerHeadCommit").unwrap_or(&"")
            || fields[7] != *manifest.get("candidateCommit").unwrap_or(&"")
            || fields[8]
                != "Portfoligno/hell-rs/.github/workflows/collection-authority.yml@refs/heads/main"
            || fields[9] != "workflow_dispatch"
            || crate::assurance::utc_timestamp_seconds(fields[10]).is_err()
            || fields[17]
                .parse::<u64>()
                .ok()
                .as_ref()
                .is_none_or(|size| *size == 0)
            || fields[20] != "false"
            || !platforms.insert(fields[0])
            || !artifact_ids.insert(fields[4])
        {
            return Err("collection custody provider provenance drifts by platform".to_owned());
        }
        let expected_name = format!(
            "collection-authority-{}-{}-{}",
            fields[0], fields[2], fields[3]
        );
        if fields[5] != expected_name
            || fields[1] != "1327351238"
            || require_lower_git_commit(fields[6]).is_err()
            || require_lower_git_commit(fields[7]).is_err()
            || [11, 12, 13, 14, 15, 16, 18, 19]
                .iter()
                .any(|index| Digest::from_hex(fields[*index]).is_err())
        {
            return Err("collection custody provider provenance digest/name is invalid".to_owned());
        }
    }
    if platforms != BTreeSet::from(["linux-amd64", "macos-arm64", "windows-amd64"]) {
        return Err("collection custody provider provenance omits a platform".to_owned());
    }
    Ok(())
}

fn provenance_rows(bytes: &[u8]) -> Result<BTreeMap<&str, Vec<&str>>, String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody provenance is not UTF-8".to_owned())?;
    if document.lines().next()
        != Some(
            "platform\trepositoryId\trunId\trunAttempt\tartifactId\tartifactName\tproviderHeadCommit\tcandidateCommit\tworkflowRef\tevent\tobservedAt\tselectionSha256\tartifactApiRootSha256\tjobApiRootSha256\trunApiSha256\tworkflowSha256\toriginalZipSha256\toriginalZipBytes\textractedTreeSha256\tproviderSubjectSha256\toriginalZipRetained",
        )
    {
        return Err("collection custody provenance header is invalid".to_owned());
    }
    let mut rows = BTreeMap::new();
    for line in document.lines().skip(1) {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 21 || rows.insert(fields[0], fields).is_some() {
            return Err("collection custody provenance row is malformed or duplicate".to_owned());
        }
    }
    if rows.len() != 3 {
        return Err("collection custody provenance does not contain three platforms".to_owned());
    }
    Ok(rows)
}

fn verify_authority(
    bytes: &[u8],
    files: &[u8],
    records: &[u8],
    package: &Path,
) -> Result<(), String> {
    let retained_files = verify_authority_files(files, package)?;
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody authority is not UTF-8".to_owned())?;
    let mut lines = document.lines();
    if lines.next()
        != Some(
            "kind\tplatform\tsourceManifestSha256\treviewedModelSha256\tmapSourceSha256\tsetSourceSha256\tsourceCommit\tstackVersion\tresolverLockSha256\tghcVersion\tcontainersVersion\tcabalRevisionSha256\toracleExecutableSha256\tbuildRecordSha256",
        )
    {
        return Err("collection custody authority header is invalid".to_owned());
    }
    let rows = lines
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    if rows.len() != 3
        || rows
            .windows(2)
            .any(|pair| pair[0].join("\t") >= pair[1].join("\t"))
    {
        return Err("collection custody authority inventory is noncanonical".to_owned());
    }
    let source = rows
        .iter()
        .find(|row| row.first() == Some(&"source"))
        .ok_or_else(|| "collection custody source authority is missing".to_owned())?;
    if source.len() != 14
        || source[1] != "-"
        || [2, 3, 4, 5]
            .iter()
            .any(|index| Digest::from_hex(source[*index]).is_err())
        || source[6..].iter().any(|field| *field != "-")
    {
        return Err("collection custody source authority is malformed".to_owned());
    }
    if source[2] != retained_files.manifest.hex()
        || source[3] != retained_files.reviewed_model.hex()
        || source[4] != retained_files.map_source.hex()
        || source[5] != retained_files.set_source.hex()
    {
        return Err("collection custody source authority differs from retained bytes".to_owned());
    }
    let records = std::str::from_utf8(records)
        .map_err(|_| "collection custody records are not UTF-8".to_owned())?
        .lines()
        .skip(1)
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    if records.iter().any(|record| record[14] != source[2]) {
        return Err("collection custody records drift from source authority".to_owned());
    }
    let mut native_platforms = BTreeSet::new();
    for row in rows
        .iter()
        .filter(|row| row.first() == Some(&"native-build"))
    {
        if row.len() != 14
            || !matches!(row[1], "macos-arm64" | "windows-amd64")
            || !native_platforms.insert(row[1])
            || row[2] != source[2]
            || row[3..6].iter().any(|field| *field != "-")
            || row[6].len() != 40
            || !row[6].bytes().all(|byte| byte.is_ascii_hexdigit())
            || row[7] != "3.11.1"
            || row[9] != "9.8.2"
            || row[10] != "0.6.8"
            || [8, 11, 12, 13]
                .iter()
                .any(|index| Digest::from_hex(row[*index]).is_err())
        {
            return Err("collection custody native build authority is malformed".to_owned());
        }
        if records
            .iter()
            .filter(|record| record[0] == row[1])
            .any(|record| {
                record[17] != "native-source-build"
                    || record[18] != row[6]
                    || record[19] != row[12]
                    || record[29] != row[13]
                    || record[30] != "reported-version-no-exact-source"
            })
        {
            return Err("collection custody native records drift from build authority".to_owned());
        }
    }
    if native_platforms != BTreeSet::from(["macos-arm64", "windows-amd64"]) {
        return Err("collection custody native build authority omits a platform".to_owned());
    }
    Ok(())
}

struct VerifiedAuthorityFiles {
    manifest: Digest,
    reviewed_model: Digest,
    map_source: Digest,
    set_source: Digest,
}

fn verify_authority_files(bytes: &[u8], package: &Path) -> Result<VerifiedAuthorityFiles, String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody authority-file inventory is not UTF-8".to_owned())?;
    let mut lines = document.lines();
    if lines.next() != Some("role\tpath\tblobSha256\tsemanticSha256\tencoding") {
        return Err("collection custody authority-file header is invalid".to_owned());
    }
    let mut roles = BTreeMap::new();
    let mut previous = None;
    for line in lines {
        if previous.is_some_and(|prior: &str| prior >= line) {
            return Err("collection custody authority files are not sorted".to_owned());
        }
        previous = Some(line);
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 5
            || roles.insert(fields[0], fields.clone()).is_some()
            || fields[1].starts_with('/')
            || fields[1].contains("..")
            || Digest::from_hex(fields[2]).is_err()
            || Digest::from_hex(fields[3]).is_err()
            || !matches!(fields[4], "raw" | "base64")
        {
            return Err("collection custody authority-file row is malformed".to_owned());
        }
        let blob = read_file(&package.join("blobs/sha256").join(fields[2]))?;
        if sha256_bytes(&blob).hex() != fields[2] || (fields[4] == "raw" && fields[2] != fields[3])
        {
            return Err("collection custody authority-file blob is corrupt".to_owned());
        }
    }
    let expected = BTreeSet::from([
        "manifest",
        "stack-yaml",
        "stack-lock",
        "source-archive",
        "cabal-revision",
        "license",
        "map-source",
        "set-source",
        "reviewed-model",
    ]);
    if roles.keys().copied().collect::<BTreeSet<_>>() != expected {
        return Err("collection custody authority-file inventory is missing or extra".to_owned());
    }
    let manifest_row = &roles["manifest"];
    let manifest_blob = read_file(&package.join("blobs/sha256").join(manifest_row[2]))?;
    let manifest = parse_assignments(&manifest_blob)?;
    let specs = [
        ("stack-yaml", "stackYamlPath", "stackYamlSha256", "raw"),
        ("stack-lock", "stackLockPath", "stackLockSha256", "raw"),
        (
            "source-archive",
            "sourceArchivePath",
            "sourceArchiveSha256",
            "base64",
        ),
        (
            "cabal-revision",
            "cabalRevisionPath",
            "cabalRevisionSha256",
            "raw",
        ),
        ("license", "licensePath", "licenseSha256", "raw"),
        ("map-source", "mapSourcePath", "mapSourceSha256", "raw"),
        ("set-source", "setSourcePath", "setSourceSha256", "raw"),
        (
            "reviewed-model",
            "reviewedModelPath",
            "reviewedModelSha256",
            "raw",
        ),
    ];
    for (role, path_field, semantic_field, encoding) in specs {
        let row = &roles[role];
        if row[1] != required_atom(&manifest, path_field)?
            || row[3] != required_atom(&manifest, semantic_field)?
            || row[4] != encoding
        {
            return Err("collection custody authority-file manifest join differs".to_owned());
        }
    }
    let archive = &roles["source-archive"];
    let archive_blob = read_file(&package.join("blobs/sha256").join(archive[2]))?;
    if hell_testkit::decoded_collection_source_archive_sha256(&archive_blob)
        .map_err(|error| error.to_string())?
        .hex()
        != archive[3]
    {
        return Err("collection custody decoded source archive digest differs".to_owned());
    }
    Ok(VerifiedAuthorityFiles {
        manifest: Digest::from_hex(manifest_row[2]).map_err(str::to_owned)?,
        reviewed_model: Digest::from_hex(roles["reviewed-model"][2]).map_err(str::to_owned)?,
        map_source: Digest::from_hex(roles["map-source"][2]).map_err(str::to_owned)?,
        set_source: Digest::from_hex(roles["set-source"][2]).map_err(str::to_owned)?,
    })
}

fn verify_input_roots(
    bytes: &[u8],
    records: &[u8],
    provenance: &[u8],
    authority: &[u8],
    package: &Path,
) -> Result<(), String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody input roots are not UTF-8".to_owned())?;
    let rows = document.lines().collect::<Vec<_>>();
    let expected_names = [
        "authenticatedProviderTree",
        "authenticatedShardTree",
        "campaignProviderRoot",
        "sourceAuthorityManifest",
        "reviewedModel",
        "successfulVerifierReport",
        "trustedVerifierExecutable",
        "historicalProviderWorkflow",
        "historicalAcquisitionPolicy",
    ];
    if rows.len() != expected_names.len() + 1 || rows[0] != "name\tsha256" {
        return Err("collection custody input-root inventory is noncanonical".to_owned());
    }
    let mut parsed = BTreeMap::new();
    for (line, expected_name) in rows[1..].iter().zip(expected_names) {
        let Some((name, digest)) = line.split_once('\t') else {
            return Err("collection custody input-root row is malformed".to_owned());
        };
        if name != expected_name
            || Digest::from_hex(digest).is_err()
            || parsed.insert(name, digest).is_some()
        {
            return Err("collection custody input-root identity is invalid".to_owned());
        }
    }
    let first_record = std::str::from_utf8(records)
        .map_err(|_| "collection custody records are not UTF-8".to_owned())?
        .lines()
        .nth(1)
        .ok_or_else(|| "collection custody records are empty".to_owned())?
        .split('\t')
        .collect::<Vec<_>>();
    let authority_source = std::str::from_utf8(authority)
        .map_err(|_| "collection custody authority is not UTF-8".to_owned())?
        .lines()
        .find(|line| line.starts_with("source\t"))
        .ok_or_else(|| "collection custody source authority row is missing".to_owned())?
        .split('\t')
        .collect::<Vec<_>>();
    let workflow = std::str::from_utf8(provenance)
        .map_err(|_| "collection custody provenance is not UTF-8".to_owned())?
        .lines()
        .nth(1)
        .ok_or_else(|| "collection custody provenance is empty".to_owned())?
        .split('\t')
        .collect::<Vec<_>>();
    if parsed.get("campaignProviderRoot").copied() != Some(first_record[28])
        || parsed.get("sourceAuthorityManifest").copied() != Some(first_record[14])
        || parsed.get("sourceAuthorityManifest").copied() != Some(authority_source[2])
        || parsed.get("reviewedModel").copied() != Some(authority_source[3])
        || parsed.get("historicalProviderWorkflow").copied() != Some(workflow[15])
    {
        return Err(
            "collection custody input roots differ from trusted/current authority".to_owned(),
        );
    }
    verify_input_root_blobs(package, &parsed)
}

fn verify_input_root_blobs(package: &Path, parsed: &BTreeMap<&str, &str>) -> Result<(), String> {
    for name in [
        "sourceAuthorityManifest",
        "reviewedModel",
        "successfulVerifierReport",
        "trustedVerifierExecutable",
        "historicalProviderWorkflow",
        "historicalAcquisitionPolicy",
    ] {
        let digest = parsed[name];
        let blob = read_file(&package.join("blobs/sha256").join(digest))?;
        if sha256_bytes(&blob).hex() != digest {
            return Err("collection custody input-root blob is corrupt".to_owned());
        }
    }
    let historical_workflow = read_file(
        &package
            .join("blobs/sha256")
            .join(parsed["historicalProviderWorkflow"]),
    )?;
    let historical_workflow = std::str::from_utf8(&historical_workflow)
        .map_err(|_| "collection custody historical workflow is not UTF-8".to_owned())?;
    if !historical_workflow.contains("name: Collection Authority\n")
        || !historical_workflow.contains("workflow_dispatch:")
    {
        return Err("collection custody historical workflow is not Collection Authority".into());
    }
    let historical_policy = read_file(
        &package
            .join("blobs/sha256")
            .join(parsed["historicalAcquisitionPolicy"]),
    )?;
    let historical_policy = std::str::from_utf8(&historical_policy)
        .map_err(|_| "collection custody historical acquisition policy is not UTF-8".to_owned())?;
    for exact in [
        "repository = \"Portfoligno/hell-rs\"",
        "repository_id = \"1327351238\"",
    ] {
        if historical_policy
            .lines()
            .filter(|line| *line == exact)
            .count()
            != 1
        {
            return Err(
                "collection custody historical acquisition policy trust root differs".into(),
            );
        }
    }
    Ok(())
}

fn retain_blob(output: &Path, source: &Path, expected: Digest) -> Result<(), String> {
    let bytes = read_file(source)?;
    if sha256_bytes(&bytes) != expected {
        return Err("collection custody source blob differs from verified campaign".to_owned());
    }
    let destination = output.join("blobs/sha256").join(expected.hex());
    if destination.exists() {
        if read_file(&destination)? != bytes {
            return Err("collection custody content address collides".to_owned());
        }
    } else {
        write_file(&destination, &bytes)?;
    }
    Ok(())
}

fn retain_bytes_blob(output: &Path, bytes: &[u8]) -> Result<Digest, String> {
    let digest = sha256_bytes(bytes);
    let destination = output.join("blobs/sha256").join(digest.hex());
    if destination.exists() {
        if read_file(&destination)? != bytes {
            return Err("collection custody content address collides".to_owned());
        }
    } else {
        write_file(&destination, bytes)?;
    }
    Ok(digest)
}

fn git_show_bytes(root: &Path, commit: &str, path: &str) -> Result<Vec<u8>, String> {
    require_lower_git_commit(commit)?;
    if Path::new(path)
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("collection custody historical path is noncanonical".to_owned());
    }
    let listing = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("ls-tree")
        .arg(commit)
        .arg("--")
        .arg(path)
        .output()
        .map_err(|error| format!("cannot inspect historical provider path: {error}"))?;
    if !listing.status.success() || !listing.stderr.is_empty() {
        return Err("cannot inspect historical provider path".to_owned());
    }
    let listing = std::str::from_utf8(&listing.stdout)
        .map_err(|_| "historical provider tree row is not UTF-8".to_owned())?;
    let rows = listing.lines().collect::<Vec<_>>();
    let [row] = rows.as_slice() else {
        return Err("historical provider tree row is not unique".to_owned());
    };
    let (identity, observed_path) = row
        .split_once('\t')
        .ok_or_else(|| "historical provider tree row is malformed".to_owned())?;
    let fields = identity.split_whitespace().collect::<Vec<_>>();
    let [mode, kind, object_id] = fields.as_slice() else {
        return Err("historical provider tree identity is malformed".to_owned());
    };
    if *mode != "100644"
        || *kind != "blob"
        || observed_path != path
        || object_id.len() != 40
        || !object_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("historical provider tree identity differs".to_owned());
    }
    let content = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "blob"])
        .arg(object_id)
        .output()
        .map_err(|error| format!("cannot read historical provider blob: {error}"))?;
    if !content.status.success() || !content.stderr.is_empty() {
        return Err("cannot read historical provider blob".to_owned());
    }
    Ok(content.stdout)
}

fn retained_typed_digest(expected: Option<Digest>, path: &Path) -> Result<Digest, String> {
    let expected = expected.ok_or_else(|| {
        "collection custody collection case lacks typed-result authority".to_owned()
    })?;
    let bytes = read_file(path)?;
    let canonical = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| "collection custody typed result lacks its canonical newline".to_owned())?;
    if sha256_bytes(canonical) != expected {
        return Err("collection custody retained typed result differs from verified digest".into());
    }
    Ok(sha256_bytes(&bytes))
}

fn retain_status_blob(
    output: &Path,
    observation: &Path,
    expected: Digest,
) -> Result<Digest, String> {
    let document = read_file(observation)?;
    let document = std::str::from_utf8(&document)
        .map_err(|_| "collection custody observation is not UTF-8".to_owned())?;
    let prefix = "  \"status\": {\"success\": ";
    let mut matches = document
        .lines()
        .filter_map(|line| line.strip_prefix(prefix));
    let status = matches
        .next()
        .and_then(|value| value.strip_suffix(','))
        .ok_or_else(|| "collection custody observation status is missing".to_owned())?;
    if matches.next().is_some() {
        return Err("collection custody observation status is repeated".to_owned());
    }
    let (success, code) = status
        .strip_suffix('}')
        .and_then(|value| value.split_once(", \"code\": "))
        .ok_or_else(|| "collection custody observation status is malformed".to_owned())?;
    let success = match success {
        "true" => true,
        "false" => false,
        _ => return Err("collection custody observation status success is malformed".to_owned()),
    };
    let code = if code == "null" {
        None
    } else {
        let parsed = code
            .parse::<i32>()
            .map_err(|_| "collection custody observation status code is malformed".to_owned())?;
        if parsed.to_string() != code {
            return Err("collection custody observation status code is noncanonical".to_owned());
        }
        Some(parsed)
    };
    let bytes = canonical_process_status_bytes(success, code);
    let digest = sha256_bytes(&bytes);
    if digest != expected {
        return Err("collection custody status bytes differ from verified status digest".into());
    }
    let destination = output.join("blobs/sha256").join(digest.hex());
    if destination.exists() {
        if read_file(&destination)? != bytes {
            return Err("collection custody status content address collides".to_owned());
        }
    } else {
        write_file(&destination, &bytes)?;
    }
    Ok(digest)
}

fn record_leaf_sha256(base: &str) -> Digest {
    let mut bytes = b"hell-collection-custody-record-v1\0".to_vec();
    push_frame(&mut bytes, base.as_bytes());
    sha256_bytes(&bytes)
}

fn evidence_mapping_sha256(mapping: &str) -> Digest {
    let mut bytes = b"hell-collection-custody-evidence-map-v1\0".to_vec();
    push_frame(&mut bytes, mapping.as_bytes());
    sha256_bytes(&bytes)
}

fn parse_assignments(bytes: &[u8]) -> Result<BTreeMap<&str, &str>, String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "collection custody manifest is not UTF-8".to_owned())?;
    let mut fields = BTreeMap::new();
    for line in document.lines() {
        let (key, value) = line
            .split_once('\t')
            .ok_or_else(|| "collection custody manifest row is malformed".to_owned())?;
        if key.is_empty() || value.is_empty() || fields.insert(key, value).is_some() {
            return Err("collection custody manifest field is empty or duplicated".to_owned());
        }
    }
    Ok(fields)
}

fn required_atom<'a>(fields: &'a BTreeMap<&str, &str>, key: &str) -> Result<&'a str, String> {
    let value = fields
        .get(key)
        .copied()
        .ok_or_else(|| format!("collection custody manifest lacks {key}"))?;
    atom(value)?;
    Ok(value)
}

fn required_u64(fields: &BTreeMap<&str, &str>, key: &str) -> Result<u64, String> {
    required_atom(fields, key)?
        .parse::<u64>()
        .map_err(|_| format!("collection custody manifest {key} is not an integer"))
}

fn require_lower_git_commit(value: &str) -> Result<(), String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("collection custody Git commit is not 40 lowercase hex bytes".to_owned());
    }
    Ok(())
}

fn atom(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| matches!(byte, b'\t' | b'\r' | b'\n' | 0))
    {
        return Err("collection custody value is not a canonical TSV atom".to_owned());
    }
    Ok(value.to_owned())
}

fn optional_digest(value: Option<Digest>) -> String {
    value.map_or_else(|| "-".to_owned(), Digest::hex)
}

const fn completion(value: CollectionCompletion) -> &'static str {
    match value {
        CollectionCompletion::Success => "success",
        CollectionCompletion::Failure => "failure",
    }
}

const fn oracle_subject(value: CollectionOracleSubject) -> &'static str {
    match value {
        CollectionOracleSubject::NativeSourceBuild => "native-source-build",
        CollectionOracleSubject::LinuxSignedReleaseResultOnly => "linux-result-only",
    }
}

const fn dependency(value: CollectionDependencyAuthority) -> &'static str {
    match value {
        CollectionDependencyAuthority::UnknownResultOnly => "unknown-result-only",
        CollectionDependencyAuthority::ReportedVersionNoExactSource => {
            "reported-version-no-exact-source"
        }
    }
}

fn platform_name(platform: ClaimPlatform) -> Result<&'static str, String> {
    match platform {
        ClaimPlatform::Linux => Ok("linux-amd64"),
        ClaimPlatform::MacOs => Ok("macos-arm64"),
        ClaimPlatform::Windows => Ok("windows-amd64"),
        ClaimPlatform::All => Err("collection custody record cannot use platform All".to_owned()),
    }
}

fn push_frame(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    fn temporary(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "hell-collection-custody-{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn repository_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    struct CoreFixture {
        root: PathBuf,
        package: PathBuf,
    }

    impl Drop for CoreFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Clone)]
    struct FixtureBlobs {
        source: Digest,
        descriptor: Digest,
        execution_input: Digest,
        stdin: Digest,
        bundle_manifest: Digest,
        oracle_observation: Digest,
        oracle_stdout: Digest,
        oracle_stderr: Digest,
        oracle_status: Digest,
        candidate_observation: Digest,
        candidate_stdout: Digest,
        candidate_stderr: Digest,
        candidate_status: Digest,
        candidate_typed: Digest,
        candidate_typed_semantic: Digest,
        candidate_resource: Digest,
    }

    fn fixture_blob(package: &Path, bytes: &[u8]) -> Digest {
        let digest = sha256_bytes(bytes);
        write_file(&package.join("blobs/sha256").join(digest.hex()), bytes).unwrap();
        digest
    }

    fn fixture_bundle_manifest(case: &str, files: &[(&str, Digest)]) -> Vec<u8> {
        let mut document = format!(
            concat!(
                "{{\n  \"schemaVersion\": 5,\n",
                "  \"caseId\": \"{case}\",\n",
                "  \"assuranceEpochSha256\": \"{}\",\n",
                "  \"profile\": \"upstream\",\n",
                "  \"processHelperPath\": null,\n",
                "  \"processHelperSha256\": null,\n",
                "  \"files\": {{\n"
            ),
            sha256_bytes(b"fixture epoch").hex(),
            case = case,
        );
        for (index, (path, digest)) in files.iter().enumerate() {
            writeln!(
                document,
                "    {path:?}: \"{}\"{}",
                digest.hex(),
                if index + 1 == files.len() { "" } else { "," }
            )
            .unwrap();
        }
        document.push_str("  }\n}\n");
        document.into_bytes()
    }

    fn write_fixture_blobs(package: &Path) -> FixtureBlobs {
        let source = fixture_blob(package, b"main = true\n");
        let descriptor = fixture_blob(package, b"fixture = true\n");
        let execution_input = fixture_blob(package, b"{}\n");
        let stdin = fixture_blob(package, b"");
        let oracle_observation = fixture_blob(package, b"{\"oracle\":true}\n");
        let oracle_stdout = fixture_blob(package, b"true\n");
        let oracle_stderr = fixture_blob(package, b"");
        let candidate_observation = fixture_blob(package, b"{\"candidate\":true}\n");
        let candidate_stdout = fixture_blob(package, b"true\n");
        let candidate_stderr = oracle_stderr;
        let status = canonical_process_status_bytes(true, Some(0));
        let oracle_status = fixture_blob(package, &status);
        let candidate_status = oracle_status;
        let typed = b"{\"type\":\"Bool\",\"value\":true}\n";
        let candidate_typed = fixture_blob(package, typed);
        let candidate_typed_semantic = sha256_bytes(&typed[..typed.len() - 1]);
        let resource = concat!(
            "{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"tasks\": 0,\n",
            "  \"handles\": 0,\n",
            "  \"processes\": 0,\n",
            "  \"httpBodies\": 0,\n",
            "  \"temporaryResources\": 0,\n",
            "  \"cleanupFailures\": 0\n",
            "}\n"
        );
        let candidate_resource = fixture_blob(package, resource.as_bytes());
        let files = [
            ("candidate/observation.json", candidate_observation),
            ("candidate/resource-audit.json", candidate_resource),
            ("candidate/semantic-typed-result.json", candidate_typed),
            ("candidate/stderr.raw.bin", candidate_stderr),
            ("candidate/stdout.bin", candidate_stdout),
            ("case.toml", descriptor),
            ("execution-input.json", execution_input),
            ("main.hell", source),
            ("oracle/observation.json", oracle_observation),
            ("oracle/stderr.raw.bin", oracle_stderr),
            ("oracle/stdout.bin", oracle_stdout),
            ("stdin.bin", stdin),
        ];
        let bundle_manifest =
            fixture_blob(package, &fixture_bundle_manifest("custody-fixture", &files));
        FixtureBlobs {
            source,
            descriptor,
            execution_input,
            stdin,
            bundle_manifest,
            oracle_observation,
            oracle_stdout,
            oracle_stderr,
            oracle_status,
            candidate_observation,
            candidate_stdout,
            candidate_stderr,
            candidate_status,
            candidate_typed,
            candidate_typed_semantic,
            candidate_resource,
        }
    }

    fn fixture_evidence_mapping(blobs: &FixtureBlobs) -> String {
        [
            ("source", blobs.source),
            ("descriptor", blobs.descriptor),
            ("execution-input", blobs.execution_input),
            ("stdin", blobs.stdin),
            ("bundle-manifest", blobs.bundle_manifest),
            ("oracle-observation", blobs.oracle_observation),
            ("oracle-stdout", blobs.oracle_stdout),
            ("oracle-stderr", blobs.oracle_stderr),
            ("candidate-observation", blobs.candidate_observation),
            ("candidate-stdout", blobs.candidate_stdout),
            ("candidate-stderr", blobs.candidate_stderr),
            ("candidate-typed", blobs.candidate_typed),
            ("candidate-resource", blobs.candidate_resource),
            ("oracle-status", blobs.oracle_status),
            ("candidate-status", blobs.candidate_status),
        ]
        .into_iter()
        .map(|(kind, digest)| format!("{kind}={}", digest.hex()))
        .collect::<Vec<_>>()
        .join(",")
    }

    struct FixtureIdentity {
        candidate: String,
        provider_head: String,
        oracle_source: String,
        campaign: Digest,
        workflow: Digest,
        source_manifest: Digest,
    }

    fn fixture_identity(workflow: Digest, source_manifest: Digest) -> FixtureIdentity {
        FixtureIdentity {
            candidate: "c".repeat(40),
            provider_head: "d".repeat(40),
            oracle_source: "e".repeat(40),
            campaign: sha256_bytes(b"fixture campaign"),
            workflow,
            source_manifest,
        }
    }

    fn fixture_record(
        platform: &str,
        case_id: &str,
        operation: &str,
        artifact_id: u64,
        identity: &FixtureIdentity,
        blobs: &FixtureBlobs,
    ) -> String {
        let native = platform != "linux-amd64";
        let oracle_executable = sha256_bytes(format!("oracle {platform}").as_bytes());
        let values = vec![
            platform.to_owned(),
            case_id.to_owned(),
            operation.to_owned(),
            "fixture-path".to_owned(),
            "upstream".to_owned(),
            blobs.source.hex(),
            sha256_bytes(b"arguments").hex(),
            sha256_bytes(b"environment").hex(),
            blobs.stdin.hex(),
            blobs.execution_input.hex(),
            blobs.descriptor.hex(),
            operation.to_owned(),
            "Ord Int".to_owned(),
            sha256_bytes(b"comparator contract").hex(),
            identity.source_manifest.hex(),
            blobs.candidate_typed_semantic.hex(),
            "success".to_owned(),
            if native {
                "native-source-build"
            } else {
                "linux-result-only"
            }
            .to_owned(),
            identity.oracle_source.clone(),
            oracle_executable.hex(),
            if native {
                "-".to_owned()
            } else {
                sha256_bytes(b"linux receipt").hex()
            },
            if native {
                "-".to_owned()
            } else {
                sha256_bytes(b"linux attestation").hex()
            },
            "1327351238".to_owned(),
            "9001".to_owned(),
            "2".to_owned(),
            artifact_id.to_string(),
            "Portfoligno/hell-rs/.github/workflows/collection-authority.yml@refs/heads/main"
                .to_owned(),
            "workflow_dispatch".to_owned(),
            identity.campaign.hex(),
            if native {
                sha256_bytes(format!("build record {platform}").as_bytes()).hex()
            } else {
                "-".to_owned()
            },
            if native {
                "reported-version-no-exact-source"
            } else {
                "unknown-result-only"
            }
            .to_owned(),
            sha256_bytes(format!("bundle {platform} {case_id}").as_bytes()).hex(),
            blobs.oracle_observation.hex(),
            blobs.candidate_observation.hex(),
            blobs.oracle_stdout.hex(),
            blobs.oracle_stderr.hex(),
            blobs.oracle_status.hex(),
            blobs.candidate_stdout.hex(),
            blobs.candidate_stderr.hex(),
            blobs.candidate_status.hex(),
            blobs.candidate_typed_semantic.hex(),
            sha256_bytes(b"comparator contract").hex(),
            "success".to_owned(),
            "success".to_owned(),
            identity.candidate.clone(),
            sha256_bytes(format!("candidate {platform}").as_bytes()).hex(),
            blobs.stdin.hex(),
            blobs.oracle_status.hex(),
            blobs.candidate_status.hex(),
            blobs.candidate_typed.hex(),
            "-".to_owned(),
            blobs.candidate_resource.hex(),
        ];
        let base = values.join("\t");
        format!("{base}\t{}", record_leaf_sha256(&base).hex())
    }

    fn fixture_case_ids() -> Vec<(String, &'static str)> {
        (0..712)
            .map(|index| (format!("map-case-{index:04}"), "Map.fromList"))
            .chain((0..479).map(|index| (format!("set-case-{index:04}"), "Set.fromList")))
            .collect()
    }

    fn write_fixture_records(
        package: &Path,
        identity: &FixtureIdentity,
        blobs: &FixtureBlobs,
    ) -> (String, String) {
        let mapping = fixture_evidence_mapping(blobs);
        let cases = fixture_case_ids();
        let platforms = [
            ("linux-amd64", 101),
            ("macos-arm64", 102),
            ("windows-amd64", 103),
        ];
        let mut records = Vec::with_capacity(EXACT_RECORD_COUNT);
        let mut evidence = Vec::with_capacity(EXACT_RECORD_COUNT);
        for (platform, artifact) in platforms {
            for (case, operation) in &cases {
                records.push(fixture_record(
                    platform, case, operation, artifact, identity, blobs,
                ));
                evidence.push(format!("{platform}\t{case}\t{mapping}"));
            }
        }
        records.sort();
        evidence.sort();
        let records = format!("{RECORD_HEADER}\n{}\n", records.join("\n"));
        let evidence = format!(
            "platform\tcaseId\tretainedEvidenceBlobs\n{}\n",
            evidence.join("\n")
        );
        write_file(&package.join("records.tsv"), records.as_bytes()).unwrap();
        write_file(&package.join("evidence.tsv"), evidence.as_bytes()).unwrap();
        (records, evidence)
    }

    fn fixture_provenance(identity: &FixtureIdentity) -> String {
        let mut document = "platform\trepositoryId\trunId\trunAttempt\tartifactId\tartifactName\tproviderHeadCommit\tcandidateCommit\tworkflowRef\tevent\tobservedAt\tselectionSha256\tartifactApiRootSha256\tjobApiRootSha256\trunApiSha256\tworkflowSha256\toriginalZipSha256\toriginalZipBytes\textractedTreeSha256\tproviderSubjectSha256\toriginalZipRetained\n".to_owned();
        for (platform, artifact) in [
            ("linux-amd64", 101),
            ("macos-arm64", 102),
            ("windows-amd64", 103),
        ] {
            let digest = |role: &str| sha256_bytes(format!("{role} {platform}").as_bytes()).hex();
            writeln!(
                document,
                concat!(
                    "{platform}\t1327351238\t9001\t2\t{artifact}\t",
                    "collection-authority-{platform}-9001-2\t{head}\t{candidate}\t",
                    "Portfoligno/hell-rs/.github/workflows/collection-authority.yml@refs/heads/main\t",
                    "workflow_dispatch\t2026-08-12T00:00:00Z\t{}\t{}\t{}\t{}\t{}\t{}\t100\t{}\t{}\tfalse"
                ),
                digest("selection"),
                digest("artifact api"),
                digest("job api"),
                digest("run api"),
                identity.workflow.hex(),
                digest("zip"),
                digest("tree"),
                digest("provider subject"),
                platform = platform,
                artifact = artifact,
                head = identity.provider_head,
                candidate = identity.candidate,
            )
            .unwrap();
        }
        document
    }

    fn fixture_authority(
        package: &Path,
        source: &hell_testkit::CollectionSourceAuthority,
        identity: &FixtureIdentity,
    ) -> (String, String) {
        let files = write_authority_files(&repository_root(), package, source).unwrap();
        let mut rows = Vec::new();
        for platform in ["macos-arm64", "windows-amd64"] {
            rows.push(format!(
                concat!(
                    "native-build\t{platform}\t{}\t-\t-\t-\t{}\t3.11.1\t{}\t9.8.2\t0.6.8\t{}\t{}\t{}"
                ),
                source.manifest_sha256().hex(),
                identity.oracle_source,
                sha256_bytes(b"resolver lock").hex(),
                sha256_bytes(b"cabal revision").hex(),
                sha256_bytes(format!("oracle {platform}").as_bytes()).hex(),
                sha256_bytes(format!("build record {platform}").as_bytes()).hex(),
                platform = platform,
            ));
        }
        rows.push(format!(
            "source\t-\t{}\t{}\t{}\t{}\t-\t-\t-\t-\t-\t-\t-\t-",
            source.manifest_sha256().hex(),
            source.reviewed_model_sha256().hex(),
            source.map_source_sha256().hex(),
            source.set_source_sha256().hex(),
        ));
        rows.sort();
        let authority = format!(
            concat!(
                "kind\tplatform\tsourceManifestSha256\treviewedModelSha256\tmapSourceSha256\t",
                "setSourceSha256\tsourceCommit\tstackVersion\tresolverLockSha256\tghcVersion\t",
                "containersVersion\tcabalRevisionSha256\toracleExecutableSha256\tbuildRecordSha256\n{}\n"
            ),
            rows.join("\n")
        );
        write_file(&package.join("authority.tsv"), authority.as_bytes()).unwrap();
        (authority, files)
    }

    fn fixture_transformations(records: &str, evidence: &str, provenance: &str) -> String {
        let evidence = evidence
            .lines()
            .skip(1)
            .map(|line| {
                let fields = line.split('\t').collect::<Vec<_>>();
                ((fields[0], fields[1]), fields[2])
            })
            .collect::<BTreeMap<_, _>>();
        let mut lines = records
            .lines()
            .skip(1)
            .map(|line| {
                let fields = line.split('\t').collect::<Vec<_>>();
                let mapping = evidence[&(fields[0], fields[1])];
                format!(
                    "bundle\t{}\t{}\t{}\t{}\t{}\t{}\tomitted-after-attested-transformation",
                    fields[0],
                    fields[1],
                    fields[31],
                    fields[52],
                    evidence_mapping_sha256(mapping).hex(),
                    mapping,
                )
            })
            .collect::<Vec<_>>();
        for row in provenance.lines().skip(1) {
            let fields = row.split('\t').collect::<Vec<_>>();
            lines.push(format!(
                "provider-zip\t{}\t-\t{}\t{}\t-\t-\tomitted-after-attested-transformation",
                fields[0], fields[16], fields[18]
            ));
        }
        lines.sort();
        format!(
            concat!(
                "kind\tplatform\tcaseId\toriginalRootSha256\tretainedRecordOrTreeSha256\t",
                "retainedEvidenceMapSha256\tretainedEvidenceBlobs\tdisposition\n{}\n"
            ),
            lines.join("\n")
        )
    }

    fn fixture_input_roots(
        package: &Path,
        identity: &FixtureIdentity,
        source: &hell_testkit::CollectionSourceAuthority,
    ) -> String {
        let workflow = concat!(
            "name: Collection Authority\n",
            "on:\n",
            "  workflow_dispatch:\n"
        );
        assert_eq!(
            fixture_blob(package, workflow.as_bytes()),
            identity.workflow
        );
        let policy = concat!(
            "repository = \"Portfoligno/hell-rs\"\n",
            "repository_id = \"1327351238\"\n"
        );
        let policy = fixture_blob(package, policy.as_bytes());
        let report = fixture_blob(package, b"successful verifier report\n");
        let verifier = fixture_blob(package, b"trusted verifier executable\n");
        let rows = [
            ("authenticatedProviderTree", sha256_bytes(b"provider tree")),
            ("authenticatedShardTree", sha256_bytes(b"shard tree")),
            ("campaignProviderRoot", identity.campaign),
            ("sourceAuthorityManifest", source.manifest_sha256()),
            ("reviewedModel", source.reviewed_model_sha256()),
            ("successfulVerifierReport", report),
            ("trustedVerifierExecutable", verifier),
            ("historicalProviderWorkflow", identity.workflow),
            ("historicalAcquisitionPolicy", policy),
        ];
        let mut document = "name\tsha256\n".to_owned();
        for (name, digest) in rows {
            writeln!(document, "{name}\t{}", digest.hex()).unwrap();
        }
        write_file(&package.join("input-roots.tsv"), document.as_bytes()).unwrap();
        document
    }

    struct FixtureDocuments<'a> {
        records: &'a str,
        evidence: &'a str,
        provenance: &'a str,
        authority: &'a str,
        authority_files: &'a str,
        transformations: &'a str,
        inputs: &'a str,
    }

    fn finish_fixture_package(
        package: &Path,
        documents: &FixtureDocuments<'_>,
        identity: &FixtureIdentity,
    ) {
        let FixtureDocuments {
            records,
            evidence,
            provenance,
            authority,
            authority_files,
            transformations,
            inputs,
        } = *documents;
        write_file(&package.join("provenance.tsv"), provenance.as_bytes()).unwrap();
        write_file(
            &package.join("transformation.tsv"),
            transformations.as_bytes(),
        )
        .unwrap();
        let blobs = write_blob_inventory(package).unwrap();
        let roots = CustodyComponentRoots {
            records: sha256_bytes(records.as_bytes()),
            evidence: sha256_bytes(evidence.as_bytes()),
            blobs: sha256_bytes(blobs.as_bytes()),
            provenance: sha256_bytes(provenance.as_bytes()),
            authority: authority_component_sha256(authority.as_bytes(), authority_files.as_bytes()),
            transformations: sha256_bytes(transformations.as_bytes()),
            inputs: sha256_bytes(inputs.as_bytes()),
        };
        let payload = roots.payload_merkle_root();
        let custody_identity = CustodyIdentity {
            candidate: &identity.candidate,
            provider_head: &identity.provider_head,
            repository_id: 1_327_351_238,
            run_id: 9_001,
            run_attempt: 2,
        };
        let manifest = render_manifest(&roots, payload, &custody_identity);
        write_file(&package.join("manifest.tsv"), manifest.as_bytes()).unwrap();
        let subject = render_attestation_subject(
            payload,
            sha256_bytes(manifest.as_bytes()),
            &roots,
            &custody_identity,
        );
        write_file(
            &package.join("custody-attestation-subject.json"),
            subject.as_bytes(),
        )
        .unwrap();
        write_file(
            &package.join("custody-attestation-subject.json.sha256"),
            format!(
                "{}  custody-attestation-subject.json\n",
                sha256_bytes(subject.as_bytes()).hex()
            )
            .as_bytes(),
        )
        .unwrap();
    }

    fn core_fixture() -> CoreFixture {
        let root = temporary("core-roundtrip");
        let package = root.join("package");
        fs::create_dir_all(package.join("blobs/sha256")).unwrap();
        let source = hell_testkit::verify_collection_source_authority(&repository_root()).unwrap();
        let workflow = sha256_bytes(
            concat!(
                "name: Collection Authority\n",
                "on:\n",
                "  workflow_dispatch:\n"
            )
            .as_bytes(),
        );
        let identity = fixture_identity(workflow, source.manifest_sha256());
        let blobs = write_fixture_blobs(&package);
        let (records, evidence) = write_fixture_records(&package, &identity, &blobs);
        let provenance = fixture_provenance(&identity);
        let (authority, authority_files) = fixture_authority(&package, &source, &identity);
        let transformations = fixture_transformations(&records, &evidence, &provenance);
        let inputs = fixture_input_roots(&package, &identity, &source);
        finish_fixture_package(
            &package,
            &FixtureDocuments {
                records: &records,
                evidence: &evidence,
                provenance: &provenance,
                authority: &authority,
                authority_files: &authority_files,
                transformations: &transformations,
                inputs: &inputs,
            },
            &identity,
        );
        CoreFixture { root, package }
    }

    fn json_string(value: impl Into<String>) -> crate::assurance::JsonValue {
        crate::assurance::JsonValue::String(value.into())
    }

    fn json_strings(values: &[String]) -> crate::assurance::JsonValue {
        crate::assurance::JsonValue::Array(values.iter().cloned().map(json_string).collect())
    }

    fn fixture_gh_install_manifest() -> Vec<u8> {
        let document = crate::assurance::JsonValue::Object(BTreeMap::from([
            (
                "archiveInventorySha256".to_owned(),
                json_string(sha256_bytes(b"fixture gh archive inventory").hex()),
            ),
            (
                "archiveMemberCount".to_owned(),
                crate::assurance::JsonValue::Number(222),
            ),
            (
                "binaryArchivePath".to_owned(),
                json_string("gh_2.93.0_linux_amd64/bin/gh"),
            ),
            ("binaryMode".to_owned(), json_string("0755")),
            (
                "ghArchiveSha256".to_owned(),
                json_string("02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0"),
            ),
            (
                "ghArchiveUrl".to_owned(),
                json_string(
                    "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_linux_amd64.tar.gz",
                ),
            ),
            (
                "ghBinarySha256".to_owned(),
                json_string("014fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1"),
            ),
            (
                "ghChecksumsEntry".to_owned(),
                json_string(
                    "02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0  gh_2.93.0_linux_amd64.tar.gz",
                ),
            ),
            (
                "ghChecksumsSha256".to_owned(),
                json_string("f62a3bc9dedc88262c9c2b56eb653cb3ded6bde8076bdbb151f4cce9c8729da5"),
            ),
            (
                "ghChecksumsUrl".to_owned(),
                json_string(
                    "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_checksums.txt",
                ),
            ),
            ("ghReleaseVersion".to_owned(), json_string("2.93.0")),
            (
                "schema".to_owned(),
                json_string("hell.collection-custody.gh-install.v1"),
            ),
        ]));
        crate::assurance::canonical_json_bytes(&document).unwrap()
    }

    fn fixture_verify_argv(core: &VerifiedCollectionCustodyCore) -> Vec<String> {
        [
            "gh".to_owned(),
            "attestation".to_owned(),
            "verify".to_owned(),
            "/fixture/custody-attestation-subject.json".to_owned(),
            "--repo".to_owned(),
            "Portfoligno/hell-rs".to_owned(),
            "--bundle".to_owned(),
            "/fixture/attestation-bundle.json".to_owned(),
            "--custom-trusted-root".to_owned(),
            "/fixture/trusted-root.jsonl".to_owned(),
            "--signer-workflow".to_owned(),
            "Portfoligno/hell-rs/.github/workflows/collection-authority.yml".to_owned(),
            "--signer-digest".to_owned(),
            core.provider_head.clone(),
            "--source-digest".to_owned(),
            core.provider_head.clone(),
            "--source-ref".to_owned(),
            "refs/heads/main".to_owned(),
            "--cert-identity".to_owned(),
            "https://github.com/Portfoligno/hell-rs/.github/workflows/collection-authority.yml@refs/heads/main".to_owned(),
            "--cert-oidc-issuer".to_owned(),
            "https://token.actions.githubusercontent.com".to_owned(),
            "--predicate-type".to_owned(),
            "https://slsa.dev/provenance/v1".to_owned(),
            "--deny-self-hosted-runners".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
        ]
        .to_vec()
    }

    struct AttestationFixture {
        bundle: PathBuf,
        root: PathBuf,
        provenance: PathBuf,
        verification: PathBuf,
        manifest: PathBuf,
        output: PathBuf,
    }

    fn write_fixture_attestation_provenance(
        core: &VerifiedCollectionCustodyCore,
        bundle: &Path,
        trusted_root: &Path,
        manifest_bytes: &[u8],
        provenance: &Path,
    ) {
        let gh_binary = "014fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1";
        let mut fields = fixture_gh_provenance_fields(bundle, manifest_bytes, gh_binary);
        fields.extend(BTreeMap::from([
            (
                "ghVersion".to_owned(),
                crate::assurance::JsonValue::Array(vec![json_string("gh version 2.93.0")]),
            ),
            (
                "providerHead".to_owned(),
                json_string(core.provider_head.clone()),
            ),
            ("repository".to_owned(), json_string("Portfoligno/hell-rs")),
            (
                "repositoryId".to_owned(),
                crate::assurance::JsonValue::Number(core.repository_id),
            ),
            (
                "runAttempt".to_owned(),
                crate::assurance::JsonValue::Number(core.run_attempt),
            ),
            (
                "runId".to_owned(),
                crate::assurance::JsonValue::Number(core.run_id),
            ),
            (
                "schema".to_owned(),
                json_string("hell.collection-custody.trusted-root-provenance.v1"),
            ),
            (
                "subjectSha256".to_owned(),
                json_string(core.subject_sha256.hex()),
            ),
            (
                "trustedRootAcquiredAt".to_owned(),
                json_string("2026-08-12T00:30:00Z"),
            ),
            (
                "trustedRootAcquisitionArgv".to_owned(),
                json_strings(&[
                    "gh".to_owned(),
                    "attestation".to_owned(),
                    "trusted-root".to_owned(),
                ]),
            ),
            (
                "trustedRootRecordCount".to_owned(),
                crate::assurance::JsonValue::Number(1),
            ),
            (
                "trustedRootRawSha256".to_owned(),
                json_string(sha256_file(trusted_root).unwrap().hex()),
            ),
            (
                "verificationCredentialsStripped".to_owned(),
                crate::assurance::JsonValue::Bool(true),
            ),
            (
                "verificationNetworkIsolation".to_owned(),
                json_string("credentialless-loopback-proxy-best-effort"),
            ),
            ("verifiedAt".to_owned(), json_string("2026-08-12T01:00:00Z")),
            (
                "verifyArgv".to_owned(),
                json_strings(&fixture_verify_argv(core)),
            ),
        ]));
        let value = crate::assurance::JsonValue::Object(fields);
        write_file(
            provenance,
            &crate::assurance::canonical_json_bytes(&value).unwrap(),
        )
        .unwrap();
    }

    fn fixture_gh_provenance_fields(
        bundle: &Path,
        manifest_bytes: &[u8],
        binary: &str,
    ) -> BTreeMap<String, crate::assurance::JsonValue> {
        BTreeMap::from([
            (
                "bundleSha256".to_owned(),
                json_string(sha256_file(bundle).unwrap().hex()),
            ),
            (
                "domain".to_owned(),
                json_string("hell.collection-custody.attestation.v1"),
            ),
            (
                "ghArchiveSha256".to_owned(),
                json_string("02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0"),
            ),
            (
                "ghArchiveUrl".to_owned(),
                json_string(
                    "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_linux_amd64.tar.gz",
                ),
            ),
            ("ghBinarySha256".to_owned(), json_string(binary)),
            (
                "ghChecksumsSha256".to_owned(),
                json_string("f62a3bc9dedc88262c9c2b56eb653cb3ded6bde8076bdbb151f4cce9c8729da5"),
            ),
            (
                "ghChecksumsUrl".to_owned(),
                json_string(
                    "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_checksums.txt",
                ),
            ),
            ("ghExecutableSha256".to_owned(), json_string(binary)),
            (
                "ghInstallManifestSha256".to_owned(),
                json_string(sha256_bytes(manifest_bytes).hex()),
            ),
            ("ghReleaseVersion".to_owned(), json_string("2.93.0")),
        ])
    }

    fn write_fixture_online_verification(
        core: &VerifiedCollectionCustodyCore,
        bundle: &Path,
        trusted_root: &Path,
        raw: &Path,
        verification: &Path,
    ) {
        let result = crate::assurance::JsonValue::Object(BTreeMap::from([(
            "verified".to_owned(),
            crate::assurance::JsonValue::Bool(true),
        )]));
        let raw_bytes =
            crate::assurance::canonical_json_bytes(&crate::assurance::JsonValue::Array(vec![
                result.clone(),
            ]))
            .unwrap();
        write_file(raw, &raw_bytes).unwrap();
        let value = crate::assurance::JsonValue::Object(BTreeMap::from([
            (
                "bundleSha256".to_owned(),
                json_string(sha256_file(bundle).unwrap().hex()),
            ),
            ("capturedAt".to_owned(), json_string("2026-08-12T01:00:00Z")),
            (
                "domain".to_owned(),
                json_string("hell.collection-custody.attestation.v1"),
            ),
            (
                "ghExecutableSha256".to_owned(),
                json_string("014fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1"),
            ),
            (
                "ghVersion".to_owned(),
                crate::assurance::JsonValue::Array(vec![json_string("gh version 2.93.0")]),
            ),
            (
                "rawVerificationPath".to_owned(),
                json_string("online-verification.raw.json"),
            ),
            (
                "rawVerificationSha256".to_owned(),
                json_string(sha256_bytes(&raw_bytes).hex()),
            ),
            (
                "schema".to_owned(),
                json_string("hell.collection-custody.online-verification.v1"),
            ),
            (
                "subjectSha256".to_owned(),
                json_string(core.subject_sha256.hex()),
            ),
            (
                "trustedRootSha256".to_owned(),
                json_string(sha256_file(trusted_root).unwrap().hex()),
            ),
            ("verificationResult".to_owned(), result),
        ]));
        write_file(
            verification,
            &crate::assurance::canonical_json_bytes(&value).unwrap(),
        )
        .unwrap();
    }

    fn attestation_fixture(fixture: &CoreFixture) -> AttestationFixture {
        let core = verify_core(&repository_root(), &fixture.package).unwrap();
        let directory = fixture.root.join("attestation-input");
        fs::create_dir(&directory).unwrap();
        let bundle = directory.join("attestation-bundle.json");
        let root = directory.join("trusted-root.jsonl");
        let provenance = directory.join("trusted-root-provenance.json");
        let verification = directory.join("online-verification.json");
        let raw = directory.join("online-verification.raw.json");
        let manifest = directory.join("gh-install-manifest.json");
        let output = fixture.root.join("signature");
        write_file(&bundle, b"{\"bundle\":true}\n").unwrap();
        write_file(&root, b"{\"trustedRoot\":true}\n").unwrap();
        let manifest_bytes = fixture_gh_install_manifest();
        write_file(&manifest, &manifest_bytes).unwrap();
        write_fixture_attestation_provenance(&core, &bundle, &root, &manifest_bytes, &provenance);
        write_fixture_online_verification(&core, &bundle, &root, &raw, &verification);
        AttestationFixture {
            bundle,
            root,
            provenance,
            verification,
            manifest,
            output,
        }
    }

    fn rehash_fixture_outer(package: &Path) {
        let original = read_file(&package.join("manifest.tsv")).unwrap();
        let fields = parse_assignments(&original).unwrap();
        let records = read_file(&package.join("records.tsv")).unwrap();
        let evidence = read_file(&package.join("evidence.tsv")).unwrap();
        let blobs = read_file(&package.join("blobs.tsv")).unwrap();
        let provenance = read_file(&package.join("provenance.tsv")).unwrap();
        let authority = read_file(&package.join("authority.tsv")).unwrap();
        let authority_files = read_file(&package.join("authority-files.tsv")).unwrap();
        let transformations = read_file(&package.join("transformation.tsv")).unwrap();
        let inputs = read_file(&package.join("input-roots.tsv")).unwrap();
        let roots = CustodyComponentRoots {
            records: sha256_bytes(&records),
            evidence: sha256_bytes(&evidence),
            blobs: sha256_bytes(&blobs),
            provenance: sha256_bytes(&provenance),
            authority: authority_component_sha256(&authority, &authority_files),
            transformations: sha256_bytes(&transformations),
            inputs: sha256_bytes(&inputs),
        };
        let identity = CustodyIdentity {
            candidate: fields["candidateCommit"],
            provider_head: fields["providerHeadCommit"],
            repository_id: fields["repositoryId"].parse().unwrap(),
            run_id: fields["providerRunId"].parse().unwrap(),
            run_attempt: fields["providerRunAttempt"].parse().unwrap(),
        };
        let payload = roots.payload_merkle_root();
        let manifest = render_manifest(&roots, payload, &identity);
        write_file(&package.join("manifest.tsv"), manifest.as_bytes()).unwrap();
        let subject = render_attestation_subject(
            payload,
            sha256_bytes(manifest.as_bytes()),
            &roots,
            &identity,
        );
        write_file(
            &package.join("custody-attestation-subject.json"),
            subject.as_bytes(),
        )
        .unwrap();
        write_file(
            &package.join("custody-attestation-subject.json.sha256"),
            format!(
                "{}  custody-attestation-subject.json\n",
                sha256_bytes(subject.as_bytes()).hex()
            )
            .as_bytes(),
        )
        .unwrap();
    }

    fn coherent_component_mutation_rejected(
        fixture: &CoreFixture,
        relative: &str,
        from: &str,
        to: &str,
    ) {
        let path = fixture.package.join(relative);
        let baseline = fs::read_to_string(&path).unwrap();
        let changed = baseline.replacen(from, to, 1);
        assert_ne!(
            changed, baseline,
            "fixture mutation did not match {relative}"
        );
        write_file(&path, changed.as_bytes()).unwrap();
        rehash_fixture_outer(&fixture.package);
        assert!(
            verify_core(&repository_root(), &fixture.package).is_err(),
            "coherently rehashed {relative} mutation survived"
        );
        write_file(&path, baseline.as_bytes()).unwrap();
        rehash_fixture_outer(&fixture.package);
    }

    fn replace_retained_digest(fixture: &CoreFixture, old: Digest, replacement: &[u8]) -> Digest {
        let new = sha256_bytes(replacement);
        write_file(
            &fixture.package.join("blobs/sha256").join(new.hex()),
            replacement,
        )
        .unwrap();
        for relative in ["records.tsv", "evidence.tsv"] {
            let path = fixture.package.join(relative);
            let document = fs::read_to_string(&path).unwrap();
            write_file(&path, document.replace(&old.hex(), &new.hex()).as_bytes()).unwrap();
        }
        fs::remove_file(fixture.package.join("blobs/sha256").join(old.hex())).unwrap();
        recompute_record_leaves_and_transformations(fixture);
        write_blob_inventory(&fixture.package).unwrap();
        rehash_fixture_outer(&fixture.package);
        new
    }

    fn recompute_record_leaves_and_transformations(fixture: &CoreFixture) {
        let records_path = fixture.package.join("records.tsv");
        let records = fs::read_to_string(&records_path).unwrap();
        let mut rebuilt = format!("{RECORD_HEADER}\n");
        for line in records.lines().skip(1) {
            let fields = line.split('\t').collect::<Vec<_>>();
            let base = fields[..52].join("\t");
            writeln!(rebuilt, "{base}\t{}", record_leaf_sha256(&base).hex()).unwrap();
        }
        write_file(&records_path, rebuilt.as_bytes()).unwrap();
        let evidence = fs::read_to_string(fixture.package.join("evidence.tsv")).unwrap();
        let provenance = fs::read_to_string(fixture.package.join("provenance.tsv")).unwrap();
        let transformations = fixture_transformations(&rebuilt, &evidence, &provenance);
        write_file(
            &fixture.package.join("transformation.tsv"),
            transformations.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn custody_component_merkle_rejects_every_coherent_root_substitution() {
        let base = CustodyComponentRoots {
            records: sha256_bytes(b"records"),
            evidence: sha256_bytes(b"evidence"),
            blobs: sha256_bytes(b"blobs"),
            provenance: sha256_bytes(b"provenance"),
            authority: sha256_bytes(b"authority"),
            transformations: sha256_bytes(b"transformations"),
            inputs: sha256_bytes(b"inputs"),
        };
        let expected = base.payload_merkle_root();
        for replacement in [
            b"records".as_slice(),
            b"evidence",
            b"blobs",
            b"provenance",
            b"authority",
            b"transformations",
            b"inputs",
        ] {
            let mut mutation = CustodyComponentRoots {
                records: base.records,
                evidence: base.evidence,
                blobs: base.blobs,
                provenance: base.provenance,
                authority: base.authority,
                transformations: base.transformations,
                inputs: base.inputs,
            };
            let changed = sha256_bytes(&[replacement, b"-changed"].concat());
            match replacement {
                b"records" => mutation.records = changed,
                b"evidence" => mutation.evidence = changed,
                b"blobs" => mutation.blobs = changed,
                b"provenance" => mutation.provenance = changed,
                b"authority" => mutation.authority = changed,
                b"transformations" => mutation.transformations = changed,
                _ => mutation.inputs = changed,
            }
            assert_ne!(mutation.payload_merkle_root(), expected);
        }
    }

    #[test]
    fn fixture_only_full_campaign_round_trips_after_current_checkout_drift() {
        let fixture = core_fixture();
        let expected = verify_core(&repository_root(), &fixture.package).unwrap();
        assert_eq!(expected.repository_id, 1_327_351_238);
        assert_eq!(expected.run_id, 9_001);
        assert_eq!(expected.run_attempt, 2);
        assert_eq!(
            verify_core(
                Path::new("/historical-checkout-no-longer-present"),
                &fixture.package
            )
            .unwrap(),
            expected
        );
    }

    #[test]
    fn fixture_only_full_campaign_retains_non_authoritative_attestation_handoff() {
        let fixture = core_fixture();
        let attestation = attestation_fixture(&fixture);
        retain_attestation(
            &repository_root(),
            &RetainAttestationInput {
                package: &fixture.package,
                bundle: &attestation.bundle,
                trusted_root: &attestation.root,
                trusted_root_provenance: &attestation.provenance,
                online_verification: &attestation.verification,
                gh_install_manifest: &attestation.manifest,
                output: &attestation.output,
            },
        )
        .unwrap();
        let handoff = fs::read_to_string(attestation.output.join("custody-handoff.tsv")).unwrap();
        assert!(handoff.contains("state\tprepared/unintegrated/non-authoritative\n"));
        assert_eq!(fs::read_dir(&attestation.output).unwrap().count(), 7);
        assert_eq!(
            verify_retained_attestation(
                &verify_core(&repository_root(), &fixture.package).unwrap(),
                &attestation.output,
            )
            .unwrap(),
            Digest::from_hex(&crate::assurance::record_digest(&attestation.output).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn fixture_only_supplemental_authority_has_exact_isolated_and_combined_deltas() {
        let collection = hell_testkit::reviewed_collection_cases().unwrap();
        verify_supplemental_coverage_delta(&collection).unwrap();
        for prefix in ["runtime-ord-map-", "runtime-ord-set-"] {
            let reduced = collection
                .iter()
                .filter(|case| !case.id.starts_with(prefix))
                .cloned()
                .collect::<Vec<_>>();
            assert!(verify_supplemental_coverage_delta(&reduced).is_err());
        }
    }

    fn fixture_integration_proof(
        _core: &VerifiedCollectionCustodyCore,
        authority: &IntegrationAuthority<'_>,
    ) -> String {
        render_integration_proof(authority)
    }

    fn fixture_admission_authority(current: String) -> (CollectionCustodyReplay, [Digest; 7]) {
        let roots = [
            sha256_bytes(b"fixture-package-root"),
            sha256_bytes(b"fixture-signature-root"),
            sha256_bytes(b"fixture-revocations"),
            sha256_bytes(b"fixture-allowed-signers"),
            sha256_bytes(b"fixture-review-revocations"),
            sha256_bytes(b"fixture-surveillance-policy"),
            sha256_bytes(b"fixture-trust-roots"),
        ];
        (
            CollectionCustodyReplay {
                current_candidate_commit: current,
                candidate_executable_sha256: sha256_bytes(b"fixture-current-candidate"),
                replay_root_sha256: sha256_bytes(b"fixture-current-replay"),
                map_cases: 712,
                set_cases: 479,
            },
            roots,
        )
    }

    fn fixture_review_governance(roots: &[Digest; 7]) -> ReviewGovernance {
        ReviewGovernance {
            allowed_signers: roots[3],
            review_revocations: roots[4],
            surveillance_policy: roots[5],
            trust_roots: roots[6],
        }
    }

    #[test]
    fn fixture_only_integration_proof_rejects_omission_extra_root_and_run_substitution() {
        let fixture = core_fixture();
        let core = verify_core(&repository_root(), &fixture.package).unwrap();
        let current = current_head(&repository_root()).unwrap();
        let (replay, roots) = fixture_admission_authority(current.clone());
        let authority = IntegrationAuthority {
            core: &core,
            package_root: roots[0],
            signature_root: roots[1],
            revocations: roots[2],
            review_governance: fixture_review_governance(&roots),
            replay: &replay,
        };
        let proof = fixture.root.join("integration-proof.tsv");
        let baseline = fixture_integration_proof(&core, &authority);
        write_file(&proof, baseline.as_bytes()).unwrap();
        verify_integration_proof(&repository_root(), &proof, &authority).unwrap();
        for changed in [
            baseline.replace("schemaVersion\t1\n", ""),
            baseline.replace("schemaVersion\t1\n", "schemaVersion\t1\nextra\tfield\n"),
            baseline.replace(&roots[0].hex(), &sha256_bytes(b"wrong-package").hex()),
            baseline.replace(&roots[6].hex(), &sha256_bytes(b"wrong-trust-roots").hex()),
            baseline.replace(
                "state\tcontrolled-custody-overlay-pending-review",
                "state\treviewed-controlled-custody-overlay",
            ),
            baseline.replace(
                "state\tcontrolled-custody-overlay-pending-review",
                "state\tprotected-controlled-integrator",
            ),
            baseline.replace(
                "integratedPathsPolicy\tcustody-payload-signature-proof-review-only-v1\n",
                "integratorRunId\t71\nintegratedPathsPolicy\tcustody-payload-signature-proof-review-only-v1\n",
            ),
            baseline.replace(
                "integratedPathsPolicy\tcustody-payload-signature-proof-review-only-v1",
                "integratedPathsPolicy\tcustody-payload-signature-proof-only-v1",
            ),
            baseline.replace(
                "integratedPathsPolicy\tcustody-payload-signature-proof-review-only-v1",
                "integratedPathsPolicy\tunrestricted",
            ),
            baseline.replace("mapCaseCount\t712", "mapCaseCount\t711"),
            baseline.replace("promotionAuthority\tfalse", "promotionAuthority\ttrue"),
        ] {
            write_file(&proof, changed.as_bytes()).unwrap();
            assert!(verify_integration_proof(&repository_root(), &proof, &authority).is_err());
        }
    }

    #[test]
    fn fixture_only_signed_proof_root_is_independent_of_integrating_commit_identity() {
        let fixture = core_fixture();
        let core = verify_core(&repository_root(), &fixture.package).unwrap();
        let (first_replay, roots) = fixture_admission_authority("a".repeat(40));
        let first = IntegrationAuthority {
            core: &core,
            package_root: roots[0],
            signature_root: roots[1],
            revocations: roots[2],
            review_governance: fixture_review_governance(&roots),
            replay: &first_replay,
        };
        let mut second_replay = first_replay.clone();
        second_replay.current_candidate_commit = "b".repeat(40);
        second_replay.candidate_executable_sha256 = sha256_bytes(b"different-current-binary");
        let second = IntegrationAuthority {
            core: &core,
            package_root: roots[0],
            signature_root: roots[1],
            revocations: roots[2],
            review_governance: fixture_review_governance(&roots),
            replay: &second_replay,
        };
        assert_eq!(
            fixture_integration_proof(&core, &first),
            fixture_integration_proof(&core, &second)
        );
    }

    fn signed_integration_review_fixture(
        root: &Path,
        candidate: &str,
        epoch: &str,
        artifacts: &BTreeSet<String>,
        role: &str,
        label: &str,
    ) -> (PathBuf, String, String, String) {
        let directory = root.join(format!("signed-review-{label}"));
        fs::create_dir_all(&directory).unwrap();
        let key = directory.join("key");
        let generated = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(generated.success());
        let identity = format!("{role}:alice");
        let public = fs::read_to_string(key.with_extension("pub")).unwrap();
        let config = root.join("compat");
        fs::create_dir_all(&config).unwrap();
        fs::write(
            config.join("reviews.allowed_signers"),
            format!("{identity} {}\n", public.trim()),
        )
        .unwrap();
        fs::write(
            config.join("review-revocations.toml"),
            "revoked_review_ids = []\n",
        )
        .unwrap();
        fs::write(
            config.join("surveillance-policy.toml"),
            "mutation_report_maximum_age_days = 14\n",
        )
        .unwrap();
        let issued_at = crate::custody_ops::current_utc_timestamp().unwrap();
        let findings = sha256_bytes(b"[]\n").hex();
        let mut identity_bytes = String::new();
        for field in [
            candidate,
            epoch,
            role,
            identity.as_str(),
            "accept",
            issued_at.as_str(),
            findings.as_str(),
        ] {
            identity_bytes.push_str(field);
            identity_bytes.push('\n');
        }
        for artifact in artifacts {
            identity_bytes.push_str(artifact);
            identity_bytes.push('\n');
        }
        let review_id = sha256_bytes(identity_bytes.as_bytes()).hex();
        let artifacts_json = artifacts
            .iter()
            .map(|artifact| format!("\"{artifact}\""))
            .collect::<Vec<_>>()
            .join(",");
        let payload = format!(
            "{{\"schemaVersion\":1,\"reviewId\":\"{review_id}\",\"role\":\"{role}\",\"reviewer\":\"{identity}\",\"decision\":\"accept\",\"candidateCommit\":\"{candidate}\",\"assuranceEpochSha256\":\"{epoch}\",\"reviewedArtifacts\":[{artifacts_json}],\"distinctSubjects\":1,\"independenceViolations\":[],\"findings\":[],\"issuedAt\":\"{issued_at}\"}}\n"
        );
        let payload_path = directory.join("payload.json");
        fs::write(&payload_path, payload.as_bytes()).unwrap();
        let signed = std::process::Command::new("ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(&key)
            .args(["-n", "hell-rs-promotion-review"])
            .arg(&payload_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(signed.success());
        let signature = fs::read(directory.join("payload.json.sig")).unwrap();
        let review = directory.join("review.dsse.json");
        fs::write(
            &review,
            format!(
                "{{\"payloadType\":\"application/vnd.hell-rs.assurance+json\",\"payload\":\"{}\",\"signatures\":[{{\"scheme\":\"ssh\",\"keyid\":\"{identity}\",\"sig\":\"{}\"}}]}}\n",
                crate::assurance::encode_base64(payload.as_bytes()),
                crate::assurance::encode_base64(&signature),
            ),
        )
        .unwrap();
        (review, review_id, payload, issued_at)
    }

    fn assert_exact_unsigned_review_payload(
        root: &Path,
        core: &VerifiedCollectionCustodyCore,
        artifacts: &BTreeSet<String>,
        payload: &str,
        review_id: &str,
        issued_at: &str,
    ) {
        let policy = root.join("compat/reviews.allowed_signers");
        let render = |reviewer, issued_at| {
            crate::assurance::render_unsigned_custody_review_payload(
                &policy,
                &crate::assurance::UnsignedReviewPayloadInput {
                    reviewer,
                    issued_at,
                    candidate: &core.candidate_commit,
                    epoch: &core.payload_merkle_root.hex(),
                    reviewed_artifacts: artifacts,
                },
            )
        };
        let (rendered, derived_review_id) = render("custody-reviewer:alice", issued_at).unwrap();
        assert_eq!(rendered, payload.as_bytes());
        assert_eq!(derived_review_id, review_id);
        for (reviewer, changed_issued_at) in [
            ("claim-reviewer:alice", issued_at),
            ("custody-reviewer:alice", "1970-01-01T00:00:00Z"),
        ] {
            assert!(render(reviewer, changed_issued_at).is_err());
        }
    }

    fn assert_prepared_review_roundtrip(
        root: &Path,
        authority: &IntegrationAuthority<'_>,
        payload: &str,
        review_id: &str,
        issued_at: &str,
    ) {
        fs::write(
            root.join("compat/trust-roots.toml"),
            "required_signature_types = [\"sigstore\", \"ssh\"]\n",
        )
        .unwrap();
        fixture_git(root, &["init", "--quiet"]);
        fixture_git(
            root,
            &[
                "add",
                "--",
                "compat/reviews.allowed_signers",
                "compat/review-revocations.toml",
                "compat/surveillance-policy.toml",
                "compat/trust-roots.toml",
            ],
        );
        fixture_git(
            root,
            &[
                "-c",
                "user.name=Custody Preparation Fixture",
                "-c",
                "user.email=custody-preparation@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "governance",
            ],
        );
        let directory = root.join("ci-in/collection-custody-review");
        fs::create_dir_all(&directory).unwrap();
        let proof = render_integration_proof(authority);
        let proof_sha256 = sha256_bytes(proof.as_bytes());
        let payload_sha256 = sha256_bytes(payload.as_bytes());
        let request = render_review_request(
            authority,
            "custody-reviewer:alice",
            issued_at,
            proof_sha256,
            payload_sha256,
            review_id,
        );
        let unsigned = format!(
            "{{\"payloadType\":\"application/vnd.hell-rs.assurance+json\",\"payload\":\"{}\",\"signatures\":[]}}\n",
            crate::assurance::encode_base64(payload.as_bytes())
        );
        for (name, bytes) in [
            ("integration-proof.tsv", proof.as_bytes()),
            ("integration-review-payload.json", payload.as_bytes()),
            ("integration-review-request.tsv", request.as_bytes()),
            ("integration-review-unsigned.dsse.json", unsigned.as_bytes()),
        ] {
            fs::write(directory.join(name), bytes).unwrap();
        }
        verify_prepared_custody_review(root, &directory).unwrap();
        for (name, bytes) in [
            (
                "integration-proof.tsv",
                b"promotionAuthority\ttrue\n".as_slice(),
            ),
            ("integration-review-payload.json", b"{}\n".as_slice()),
            (
                "integration-review-request.tsv",
                b"state\tunreviewed\n".as_slice(),
            ),
            ("integration-review-unsigned.dsse.json", b"{}\n".as_slice()),
        ] {
            let path = directory.join(name);
            let original = fs::read(&path).unwrap();
            fs::write(&path, bytes).unwrap();
            assert!(verify_prepared_custody_review(root, &directory).is_err());
            fs::write(path, original).unwrap();
        }
        fs::write(directory.join("extra"), "unreviewed\n").unwrap();
        assert!(verify_prepared_custody_review(root, &directory).is_err());
    }

    #[test]
    fn fixture_only_integration_review_requires_signed_role_candidate_roots_and_revocation() {
        let fixture = core_fixture();
        let core = verify_core(&repository_root(), &fixture.package).unwrap();
        let (replay, roots) = fixture_admission_authority("a".repeat(40));
        let authority = IntegrationAuthority {
            core: &core,
            package_root: roots[0],
            signature_root: roots[1],
            revocations: roots[2],
            review_governance: fixture_review_governance(&roots),
            replay: &replay,
        };
        let proof = fixture.root.join("integration-proof.tsv");
        write_file(
            &proof,
            fixture_integration_proof(&core, &authority).as_bytes(),
        )
        .unwrap();
        let artifacts = integration_review_artifacts(&authority, sha256_file(&proof).unwrap());
        let (review, review_id, payload, issued_at) = signed_integration_review_fixture(
            &fixture.root,
            &core.candidate_commit,
            &core.payload_merkle_root.hex(),
            &artifacts,
            "custody-reviewer",
            "accepted",
        );
        assert_exact_unsigned_review_payload(
            &fixture.root,
            &core,
            &artifacts,
            &payload,
            &review_id,
            &issued_at,
        );
        verify_signed_integration_review(&fixture.root, &proof, &review, &authority).unwrap();

        write_file(&proof, b"state\tunreviewed\n").unwrap();
        assert!(
            verify_signed_integration_review(&fixture.root, &proof, &review, &authority).is_err()
        );
        write_file(
            &proof,
            fixture_integration_proof(&core, &authority).as_bytes(),
        )
        .unwrap();

        fs::write(
            fixture.root.join("compat/review-revocations.toml"),
            format!("revoked_review_ids = [\"{review_id}\"]\n"),
        )
        .unwrap();
        assert!(
            verify_signed_integration_review(&fixture.root, &proof, &review, &authority).is_err()
        );
        fs::write(
            fixture.root.join("compat/review-revocations.toml"),
            "revoked_review_ids = []\n",
        )
        .unwrap();

        for (role, candidate, label) in [
            (
                "claim-reviewer",
                core.candidate_commit.as_str(),
                "wrong-role",
            ),
            (
                "custody-reviewer",
                "dddddddddddddddddddddddddddddddddddddddd",
                "wrong-candidate",
            ),
        ] {
            let (changed, _, _, _) = signed_integration_review_fixture(
                &fixture.root,
                candidate,
                &core.payload_merkle_root.hex(),
                &artifacts,
                role,
                label,
            );
            assert!(
                verify_signed_integration_review(&fixture.root, &proof, &changed, &authority)
                    .is_err()
            );
        }
        let unsigned = fixture.root.join("unsigned-review.json");
        fs::write(&unsigned, "{}\n").unwrap();
        assert!(
            verify_signed_integration_review(&fixture.root, &proof, &unsigned, &authority).is_err()
        );
        assert_prepared_review_roundtrip(
            &fixture.root,
            &authority,
            &payload,
            &review_id,
            &issued_at,
        );
    }

    #[test]
    fn fixture_only_admission_report_path_rejects_authority_escape() {
        let root = repository_root();
        assert!(require_report_outside_authority(&root, Path::new("ci-out/report.json")).is_ok());
        assert!(
            require_report_outside_authority(&root, Path::new("ci-out/nested/report.json")).is_ok()
        );
        for path in [
            "ci-out/../compat/collection-custody/integration-proof.tsv",
            "./ci-out/report.json",
            "compat/collection-custody/report.json",
            "../ci-out/report.json",
        ] {
            assert!(require_report_outside_authority(&root, Path::new(path)).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn fixture_only_admission_report_path_rejects_parent_and_target_symlinks() {
        let root = temporary("admission-report-symlinks");
        fs::create_dir_all(root.join("compat")).unwrap();
        std::os::unix::fs::symlink("compat", root.join("ci-out")).unwrap();
        assert!(require_report_outside_authority(&root, Path::new("ci-out/report.json")).is_err());
        fs::remove_file(root.join("ci-out")).unwrap();

        fs::create_dir_all(root.join("ci-out/real")).unwrap();
        std::os::unix::fs::symlink("../../compat", root.join("ci-out/nested")).unwrap();
        assert!(
            require_report_outside_authority(&root, Path::new("ci-out/nested/report.json"))
                .is_err()
        );
        fs::remove_file(root.join("ci-out/nested")).unwrap();

        std::os::unix::fs::symlink("missing", root.join("ci-out/report.json")).unwrap();
        assert!(require_report_outside_authority(&root, Path::new("ci-out/report.json")).is_err());
        fs::remove_file(root.join("ci-out/report.json")).unwrap();
        std::os::unix::fs::symlink("missing", root.join("ci-out/report.json.sha256")).unwrap();
        assert!(require_report_outside_authority(&root, Path::new("ci-out/report.json")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture_git(root: &Path, arguments: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(["-c", "core.hooksPath=.fixture-no-hooks"])
            .arg("-C")
            .arg(root)
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

    fn commit_fixture(root: &Path, message: &str) -> String {
        fixture_git(root, &["add", "--", "."]);
        fixture_git(
            root,
            &[
                "-c",
                "user.name=Custody Integration Fixture",
                "-c",
                "user.email=custody-integration@example.invalid",
                "commit",
                "--quiet",
                "-m",
                message,
            ],
        );
        fixture_git(root, &["rev-parse", "HEAD"])
    }

    fn tracked_input_fixture() -> (PathBuf, VerifyCustodyInput<'static>) {
        let root = temporary("tracked-admission-inputs");
        fixture_git(&root, &["init", "--quiet"]);
        fs::create_dir_all(root.join("compat/collection-custody/payload")).unwrap();
        fs::create_dir_all(root.join("compat/collection-custody/signature")).unwrap();
        fs::write(
            root.join("compat/collection-custody/payload/manifest.tsv"),
            "fixture\n",
        )
        .unwrap();
        fs::write(
            root.join("compat/collection-custody/signature/custody-handoff.tsv"),
            "fixture\n",
        )
        .unwrap();
        for relative in [
            "compat/collection-custody/integration-proof.tsv",
            "compat/collection-custody/integration-review.dsse.json",
            "compat/collection-authority-revocations.toml",
            "compat/reviews.allowed_signers",
            "compat/review-revocations.toml",
            "compat/surveillance-policy.toml",
            "compat/trust-roots.toml",
        ] {
            fs::write(root.join(relative), "fixture\n").unwrap();
        }
        commit_fixture(&root, "tracked custody fixture");
        let leaked = Box::leak(Box::new([
            root.join("compat/collection-custody/payload"),
            root.join("compat/collection-custody/signature"),
            root.join("candidate"),
            root.join("compat/collection-custody/integration-proof.tsv"),
            root.join("compat/collection-custody/integration-review.dsse.json"),
            root.join("ci-out/report.json"),
        ]));
        let input = VerifyCustodyInput {
            package: &leaked[0],
            signature: &leaked[1],
            candidate_executable: &leaked[2],
            integration_proof: &leaked[3],
            integration_review: &leaked[4],
            worm_custody: None,
            report: &leaked[5],
        };
        (root, input)
    }

    #[test]
    fn fixture_only_tracked_inputs_reject_dirty_untracked_escape_and_symlink() {
        let (root, input) = tracked_input_fixture();
        require_tracked_custody_inputs(&root, &input).unwrap();
        fs::write(input.integration_proof, "dirty\n").unwrap();
        assert!(require_tracked_custody_inputs(&root, &input).is_err());
        fs::write(input.integration_proof, "fixture\n").unwrap();
        for relative in [
            "compat/reviews.allowed_signers",
            "compat/review-revocations.toml",
            "compat/surveillance-policy.toml",
        ] {
            let path = root.join(relative);
            fs::write(&path, "dirty\n").unwrap();
            assert!(require_tracked_custody_inputs(&root, &input).is_err());
            fs::write(path, "fixture\n").unwrap();
        }
        let trust_roots = root.join("compat/trust-roots.toml");
        fs::remove_file(&trust_roots).unwrap();
        assert!(require_tracked_custody_inputs(&root, &input).is_err());
        fs::write(&trust_roots, "dirty\n").unwrap();
        assert!(require_tracked_custody_inputs(&root, &input).is_err());
        fs::write(&trust_roots, "fixture\n").unwrap();
        let untracked = root.join("compat/collection-custody/untracked-review.json");
        fs::write(&untracked, "fixture\n").unwrap();
        let untracked_input = VerifyCustodyInput {
            integration_review: &untracked,
            ..input
        };
        assert!(require_tracked_custody_inputs(&root, &untracked_input).is_err());
        let escape = root.join("compat/collection-custody/../outside-proof.tsv");
        let escaped_input = VerifyCustodyInput {
            integration_proof: &escape,
            ..input
        };
        assert!(require_tracked_custody_inputs(&root, &escaped_input).is_err());
        #[cfg(unix)]
        {
            let trust_target = root.join("trust-roots-symlink-target");
            fs::write(&trust_target, "fixture\n").unwrap();
            fs::remove_file(&trust_roots).unwrap();
            std::os::unix::fs::symlink(&trust_target, &trust_roots).unwrap();
            assert!(require_tracked_custody_inputs(&root, &input).is_err());
            fs::remove_file(&trust_roots).unwrap();
            fs::write(&trust_roots, "fixture\n").unwrap();
            let target = root.join("payload-symlink-target");
            fs::create_dir(&target).unwrap();
            fs::write(target.join("manifest.tsv"), "fixture\n").unwrap();
            fs::remove_dir_all(input.package).unwrap();
            std::os::unix::fs::symlink(&target, input.package).unwrap();
            commit_fixture(&root, "track custody symlink");
            assert!(require_tracked_custody_inputs(&root, &input).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_only_controlled_delta_rejects_unrelated_current_candidate_changes() {
        let root = temporary("controlled-integration-delta");
        fixture_git(&root, &["init", "--quiet"]);
        fs::write(root.join("candidate"), "candidate\n").unwrap();
        let candidate = commit_fixture(&root, "candidate");
        fs::create_dir_all(root.join("compat/collection-custody/payload")).unwrap();
        fs::create_dir_all(root.join("compat/collection-custody/signature")).unwrap();
        for relative in [
            "compat/collection-custody/payload/manifest.tsv",
            "compat/collection-custody/signature/custody-handoff.tsv",
        ] {
            fs::write(root.join(relative), "fixture\n").unwrap();
        }
        commit_fixture(&root, "unsigned custody overlay");
        require_controlled_preparation_delta(&root, &candidate).unwrap();
        for relative in [
            "compat/collection-custody/integration-proof.tsv",
            "compat/collection-custody/integration-review.dsse.json",
        ] {
            fs::write(root.join(relative), "fixture\n").unwrap();
        }
        commit_fixture(&root, "reviewed custody overlay");
        require_controlled_integration_delta(&root, &candidate).unwrap();
        fs::write(root.join("unrelated-source"), "changed\n").unwrap();
        commit_fixture(&root, "unrelated change");
        assert!(require_controlled_integration_delta(&root, &candidate).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_only_historical_blob_read_is_typed_exact_and_substitution_resistant() {
        let root = temporary("historical-blob-read");
        fixture_git(&root, &["init", "--quiet"]);
        fs::create_dir_all(root.join("policy")).unwrap();
        fs::write(root.join("policy/source.toml"), "version = 1\n").unwrap();
        let first = commit_fixture(&root, "first historical blob");
        fs::write(root.join("policy/source.toml"), "version = 2\n").unwrap();
        let second = commit_fixture(&root, "second historical blob");
        assert_eq!(
            git_show_bytes(&root, &first, "policy/source.toml").unwrap(),
            b"version = 1\n"
        );
        assert_eq!(
            git_show_bytes(&root, &second, "policy/source.toml").unwrap(),
            b"version = 2\n"
        );
        for (commit, path) in [
            (first.as_str(), "../policy/source.toml"),
            (first.as_str(), "policy/missing.toml"),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "policy/source.toml",
            ),
            (
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "policy/source.toml",
            ),
        ] {
            assert!(git_show_bytes(&root, commit, path).is_err());
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("source.toml", root.join("policy/link.toml")).unwrap();
            let linked = commit_fixture(&root, "historical symlink");
            assert!(git_show_bytes(&root, &linked, "policy/link.toml").is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_only_current_revocations_fail_closed_for_every_authority_identity() {
        let fixture = core_fixture();
        let core = verify_core(&repository_root(), &fixture.package).unwrap();
        let baseline = concat!(
            "schema_version = 1\n",
            "state = \"active\"\n",
            "revoked_subject_sha256 = []\n",
            "revoked_payload_merkle_roots = []\n",
            "revoked_candidate_commits = []\n",
            "revoked_provider_head_commits = []\n",
            "revoked_provider_run_ids = []\n",
        );
        verify_current_revocations(&core, baseline.as_bytes()).unwrap();
        for (field, value) in [
            ("revoked_subject_sha256", core.subject_sha256.hex()),
            (
                "revoked_payload_merkle_roots",
                core.payload_merkle_root.hex(),
            ),
            ("revoked_candidate_commits", core.candidate_commit.clone()),
            ("revoked_provider_head_commits", core.provider_head.clone()),
            ("revoked_provider_run_ids", core.run_id.to_string()),
        ] {
            let changed = baseline.replace(
                &format!("{field} = []"),
                &format!("{field} = [\"{value}\"]"),
            );
            assert!(
                verify_current_revocations(&core, changed.as_bytes()).is_err(),
                "revocation in {field} survived"
            );
        }
        assert!(verify_current_revocations(&core, b"schema_version = 1\n").is_err());
    }

    #[test]
    fn fixture_only_campaign_rejects_coherently_rehashed_inner_components() {
        let fixture = core_fixture();
        for (relative, from, to) in [
            ("records.tsv", "fixture-path", ""),
            (
                "evidence.tsv",
                "candidate-resource=",
                "unexpected-resource=",
            ),
            (
                "transformation.tsv",
                "omitted-after-attested-transformation",
                "retained",
            ),
            ("provenance.tsv", "2026-08-12T00:00:00Z", "not-a-time"),
            ("authority.tsv", "3.11.1", "3.11.2"),
            ("authority-files.tsv", "map-source", "wrong-map-source"),
            (
                "input-roots.tsv",
                "campaignProviderRoot",
                "wrongCampaignProviderRoot",
            ),
        ] {
            coherent_component_mutation_rejected(&fixture, relative, from, to);
        }
        verify_core(&repository_root(), &fixture.package).unwrap();
        let orphan = fixture_blob(&fixture.package, b"unreferenced custody blob");
        write_blob_inventory(&fixture.package).unwrap();
        rehash_fixture_outer(&fixture.package);
        assert!(verify_core(&repository_root(), &fixture.package).is_err());
        fs::remove_file(fixture.package.join("blobs/sha256").join(orphan.hex())).unwrap();
        write_blob_inventory(&fixture.package).unwrap();
        rehash_fixture_outer(&fixture.package);
        verify_core(&repository_root(), &fixture.package).unwrap();
    }

    #[test]
    fn fixture_only_campaign_rejects_coherent_typed_status_resource_and_manifest_substitution() {
        let fixture = core_fixture();
        let record = fs::read_to_string(fixture.package.join("records.tsv")).unwrap();
        let fields = record
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .collect::<Vec<_>>();
        let changed_status = canonical_process_status_bytes(true, Some(1));
        let mutations = [
            (
                Digest::from_hex(fields[49]).unwrap(),
                b"{\"type\":\"Bool\",\"value\":false}\n".as_slice(),
            ),
            (
                Digest::from_hex(fields[47]).unwrap(),
                changed_status.as_slice(),
            ),
            (
                Digest::from_hex(fields[51]).unwrap(),
                concat!(
                    "{\n",
                    "  \"schemaVersion\": 1,\n",
                    "  \"tasks\": 1,\n",
                    "  \"handles\": 0,\n",
                    "  \"processes\": 0,\n",
                    "  \"httpBodies\": 0,\n",
                    "  \"temporaryResources\": 0,\n",
                    "  \"cleanupFailures\": 0\n",
                    "}\n"
                )
                .as_bytes(),
            ),
        ];
        for (old, replacement) in mutations {
            let original =
                read_file(&fixture.package.join("blobs/sha256").join(old.hex())).unwrap();
            let changed = replace_retained_digest(&fixture, old, replacement);
            assert!(verify_core(&repository_root(), &fixture.package).is_err());
            replace_retained_digest(&fixture, changed, &original);
        }
        verify_core(&repository_root(), &fixture.package).unwrap();
        let evidence = fs::read_to_string(fixture.package.join("evidence.tsv")).unwrap();
        let bundle = evidence
            .lines()
            .nth(1)
            .unwrap()
            .split('\t')
            .nth(2)
            .unwrap()
            .split(',')
            .find_map(|entry| entry.strip_prefix("bundle-manifest="))
            .unwrap();
        let old = Digest::from_hex(bundle).unwrap();
        let mut malformed =
            read_file(&fixture.package.join("blobs/sha256").join(old.hex())).unwrap();
        malformed.extend_from_slice(b"unknown\n");
        let changed = replace_retained_digest(&fixture, old, &malformed);
        assert!(verify_core(&repository_root(), &fixture.package).is_err());
        fs::remove_file(fixture.package.join("blobs/sha256").join(changed.hex())).unwrap();
    }

    #[test]
    fn fixture_only_campaign_rejects_manifest_subject_and_attestation_join_substitutions() {
        let fixture = core_fixture();
        let manifest_path = fixture.package.join("manifest.tsv");
        let manifest = fs::read_to_string(&manifest_path).unwrap();
        write_file(
            &manifest_path,
            manifest
                .replace("repositoryId\t1327351238", "repositoryId\t1")
                .as_bytes(),
        )
        .unwrap();
        assert!(verify_core(&repository_root(), &fixture.package).is_err());
        write_file(&manifest_path, manifest.as_bytes()).unwrap();
        let subject_path = fixture.package.join("custody-attestation-subject.json");
        let subject = fs::read_to_string(&subject_path).unwrap();
        write_file(&subject_path, subject.replace("3573", "3572").as_bytes()).unwrap();
        let mutated = read_file(&subject_path).unwrap();
        write_file(
            &fixture
                .package
                .join("custody-attestation-subject.json.sha256"),
            format!(
                "{}  custody-attestation-subject.json\n",
                sha256_bytes(&mutated).hex()
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(verify_core(&repository_root(), &fixture.package).is_err());

        let fixture = core_fixture();
        let core = verify_core(&repository_root(), &fixture.package).unwrap();
        let attestation = attestation_fixture(&fixture);
        let bundle = sha256_file(&attestation.bundle).unwrap();
        let trusted_root = sha256_file(&attestation.root).unwrap();
        let raw = read_file(
            &attestation
                .verification
                .with_file_name("online-verification.raw.json"),
        )
        .unwrap();
        let provenance = read_file(&attestation.provenance).unwrap();
        let verification = read_file(&attestation.verification).unwrap();
        let install = read_file(&attestation.manifest).unwrap();
        let install_digest = sha256_bytes(&install);
        assert!(
            verify_online_attestation_records(
                &core,
                bundle,
                sha256_bytes(b"wrong trusted root"),
                &raw,
                &provenance,
                &verification,
                install_digest,
            )
            .is_err()
        );
        assert!(
            verify_online_attestation_records(
                &core,
                bundle,
                trusted_root,
                b"[{\"verified\":false}]\n",
                &provenance,
                &verification,
                install_digest,
            )
            .is_err()
        );
        let provenance_text = String::from_utf8(provenance.clone()).unwrap();
        let changed_provenance = provenance_text
            .replace(&core.provider_head, &"a".repeat(40))
            .into_bytes();
        assert!(
            verify_online_attestation_records(
                &core,
                bundle,
                trusted_root,
                &raw,
                &changed_provenance,
                &verification,
                install_digest,
            )
            .is_err()
        );
        assert!(
            verify_gh_install_manifest(
                &String::from_utf8(install)
                    .unwrap()
                    .replace("2.93.0", "2.92.0")
                    .into_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_provenance_is_panic_free_and_fail_closed() {
        for mutation in [
            b"".as_slice(),
            b"header\n",
            b"header\nlinux\n",
            b"header\n\t\n",
        ] {
            let result = catch_unwind(|| provenance_rows(mutation));
            assert!(result.is_ok());
            assert!(result.unwrap().is_err());
        }
    }

    #[test]
    fn attestation_json_scope_rejects_missing_and_extra_fields() {
        let mut object = BTreeMap::from([
            (
                "domain".to_owned(),
                crate::assurance::JsonValue::String("d".to_owned()),
            ),
            (
                "schema".to_owned(),
                crate::assurance::JsonValue::String("s".to_owned()),
            ),
        ]);
        assert!(require_json_keys(&object, &["domain", "schema"]).is_ok());
        object.remove("schema");
        assert!(require_json_keys(&object, &["domain", "schema"]).is_err());
        object.insert(
            "schema".to_owned(),
            crate::assurance::JsonValue::String("s".to_owned()),
        );
        object.insert("extra".to_owned(), crate::assurance::JsonValue::Null);
        assert!(require_json_keys(&object, &["domain", "schema"]).is_err());
        let reordered = b"{\"schema\":\"s\",\"domain\":\"d\"}\n";
        let parsed = crate::assurance::parse_json(std::str::from_utf8(reordered).unwrap()).unwrap();
        assert_ne!(
            crate::assurance::canonical_json_bytes(&parsed).unwrap(),
            reordered
        );
    }

    #[test]
    fn custody_blob_inventory_rejects_nonregular_entries() {
        let root = temporary("blob-kind");
        fs::create_dir_all(root.join("blobs/sha256")).unwrap();
        let bytes = b"retained";
        let digest = sha256_bytes(bytes).hex();
        fs::create_dir(root.join("blobs/sha256").join(&digest)).unwrap();
        let inventory = format!("sha256\tbytes\n{digest}\t{}\n", bytes.len());
        assert!(verify_blobs(&root, inventory.as_bytes()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn collection_worm_subject_inventory_is_exact_and_symlink_free() {
        let root = temporary("worm-subject-inventory");
        let subject = root.join("subject");
        fs::create_dir_all(subject.join("payload")).unwrap();
        fs::create_dir(subject.join("signature")).unwrap();
        fs::write(subject.join("integration-proof.tsv"), b"proof\n").unwrap();
        fs::write(subject.join("integration-review.dsse.json"), b"review\n").unwrap();
        assert!(require_exact_collection_worm_subject_inventory(&subject).is_ok());

        fs::write(subject.join("extra"), b"unbound\n").unwrap();
        assert!(require_exact_collection_worm_subject_inventory(&subject).is_err());
        fs::remove_file(subject.join("extra")).unwrap();

        fs::remove_file(subject.join("integration-proof.tsv")).unwrap();
        fs::create_dir(subject.join("integration-proof.tsv")).unwrap();
        assert!(require_exact_collection_worm_subject_inventory(&subject).is_err());
        fs::remove_dir(subject.join("integration-proof.tsv")).unwrap();

        #[cfg(unix)]
        {
            let alias = root.join("subject-alias");
            std::os::unix::fs::symlink(&subject, &alias).unwrap();
            assert!(require_exact_collection_worm_subject_inventory(&alias).is_err());
            let target = root.join("proof-target");
            fs::write(&target, b"proof\n").unwrap();
            std::os::unix::fs::symlink(target, subject.join("integration-proof.tsv")).unwrap();
            assert!(require_exact_collection_worm_subject_inventory(&subject).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn collection_worm_envelope_uses_current_overlay_identity() {
        let root = repository_root();
        let (candidate, envelope_epoch) = collection_worm_envelope_identity(&root).unwrap();
        let (_, current_epoch) = crate::assurance::epoch(&root).unwrap();
        assert_eq!(candidate, current_head(&root).unwrap());
        assert_eq!(envelope_epoch, current_epoch);
    }

    #[test]
    fn collection_worm_artifact_digest_and_path_are_exact() {
        let root = temporary("worm-artifact-digest");
        let artifact = root.join("ci-in/collection-worm-custody");
        fs::create_dir_all(artifact.join("subject/payload")).unwrap();
        fs::create_dir(artifact.join("subject/signature")).unwrap();
        fs::write(artifact.join("subject/integration-proof.tsv"), b"proof\n").unwrap();
        fs::write(
            artifact.join("subject/integration-review.dsse.json"),
            b"review\n",
        )
        .unwrap();
        fs::write(artifact.join("custody-receipt.json"), b"receipt\n").unwrap();
        let digest = crate::custody_ops::directory_digest(&artifact).unwrap();
        assert!(verify_worm_artifact(&root, &artifact, &digest).is_ok());
        assert!(verify_worm_artifact(&root, &artifact, &"a".repeat(64)).is_err());
        assert!(
            verify_worm_artifact(
                &root,
                &root.join("ci-in/substituted-collection-worm"),
                &digest,
            )
            .is_err()
        );
        fs::write(artifact.join("subject/extra"), b"extra\n").unwrap();
        let mutated = crate::custody_ops::directory_digest(&artifact).unwrap();
        assert!(verify_worm_artifact(&root, &artifact, &mutated).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn collection_worm_preparation_uses_an_existing_safe_staging_parent() {
        let root = temporary("worm-staging-parent");
        let output = root.join("ci-out");
        fs::create_dir_all(output.join("source/evidence")).unwrap();
        let subject = output.join("subject");
        assert!(prepare_worm_output_parent(&output, &subject).is_ok());

        fs::write(&subject, b"occupied\n").unwrap();
        assert!(prepare_worm_output_parent(&output, &subject).is_err());
        fs::remove_file(&subject).unwrap();

        fs::create_dir(output.join("custody-package")).unwrap();
        assert!(prepare_worm_output_parent(&output, &subject).is_err());
        fs::remove_dir(output.join("custody-package")).unwrap();

        #[cfg(unix)]
        {
            let target = root.join("output-target");
            fs::create_dir(&target).unwrap();
            let alias = root.join("ci-out-alias");
            std::os::unix::fs::symlink(target, &alias).unwrap();
            assert!(prepare_worm_output_parent(&alias, &alias.join("subject")).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn activation_preparation_token_binds_exact_non_authoritative_admission() {
        let digest = sha256_bytes(b"activation token fixture");
        let candidate = "c".repeat(40);
        let verified = VerifiedAdmissionAuthority {
            core: VerifiedCollectionCustodyCore {
                payload_merkle_root: digest,
                subject_sha256: digest,
                candidate_commit: candidate.clone(),
                provider_head: candidate.clone(),
                repository_id: 1,
                run_id: 2,
                run_attempt: 3,
            },
            package_root: digest,
            signature_root: digest,
            revocations: digest,
            review_governance: ReviewGovernance {
                allowed_signers: digest,
                review_revocations: digest,
                surveillance_policy: digest,
                trust_roots: digest,
            },
            replay: CollectionCustodyReplay {
                current_candidate_commit: candidate,
                candidate_executable_sha256: digest,
                replay_root_sha256: digest,
                map_cases: 712,
                set_cases: 479,
            },
            integration: VerifiedIntegrationReview {
                proof_sha256: digest,
                review_sha256: digest,
                subject: "custody-reviewer:fixture".to_owned(),
                signer_fingerprint: digest.hex(),
            },
            custody_policy: digest,
        };
        let report = render_admission_report(&verified, Some(digest)).unwrap();
        let token = render_activation_preparation_token(&verified, digest, &report).unwrap();
        let root = temporary("activation-token");
        let report_path = root.join("collection-custody-admission.json");
        let token_path = root.join("collection-custody-activation-token.json");
        fs::write(&report_path, &report).unwrap();
        fs::write(&token_path, &token).unwrap();
        write_test_digest_sibling(&report_path);
        write_test_digest_sibling(&token_path);
        let accepted = verify_activation_preparation_token(&report_path, &token_path).unwrap();
        assert_eq!(accepted.payload_merkle_root, digest.hex());
        assert_eq!(accepted.worm_custody_identity_sha256, digest.hex());
        mutate_activation_token_inventory(&root, &report_path, &token_path);
        mutate_activation_token_semantics(&report_path, &token_path, &report, &token);

        #[cfg(unix)]
        {
            let retained = root.join("retained-token");
            fs::rename(&token_path, &retained).unwrap();
            std::os::unix::fs::symlink(&retained, &token_path).unwrap();
            assert!(verify_activation_preparation_token(&report_path, &token_path).is_err());
            fs::remove_file(&token_path).unwrap();
            fs::rename(retained, &token_path).unwrap();
        }

        let token_text = String::from_utf8(token).unwrap();
        fs::write(
            &token_path,
            token_text.replace(&digest.hex(), &"d".repeat(64)),
        )
        .unwrap();
        write_test_digest_sibling(&token_path);
        assert!(verify_activation_preparation_token(&report_path, &token_path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn mutate_activation_token_inventory(root: &Path, report_path: &Path, token_path: &Path) {
        fs::write(root.join("extra"), b"extra\n").unwrap();
        assert!(verify_activation_preparation_token(report_path, token_path).is_err());
        fs::remove_file(root.join("extra")).unwrap();
        fs::remove_file(token_path.with_extension("json.sha256")).unwrap();
        assert!(verify_activation_preparation_token(report_path, token_path).is_err());
        write_test_digest_sibling(token_path);
        fs::write(
            token_path.with_extension("json.sha256"),
            format!(
                "{}  collection-custody-activation-token.json\n",
                "0".repeat(64)
            ),
        )
        .unwrap();
        assert!(verify_activation_preparation_token(report_path, token_path).is_err());
        write_test_digest_sibling(token_path);
    }

    fn mutate_activation_token_semantics(
        report_path: &Path,
        token_path: &Path,
        report: &str,
        token: &[u8],
    ) {
        fs::write(
            report_path,
            report.replace(
                "\"promotionAuthority\":false",
                "\"promotionAuthority\":true",
            ),
        )
        .unwrap();
        write_test_digest_sibling(report_path);
        assert!(verify_activation_preparation_token(report_path, token_path).is_err());
        fs::write(report_path, report).unwrap();
        write_test_digest_sibling(report_path);

        let report_mutant = report
            .replace(
                "\"mapOnlyIncompleteCells\":127",
                "\"mapOnlyIncompleteCells\":126",
            )
            .into_bytes();
        fs::write(report_path, &report_mutant).unwrap();
        write_test_digest_sibling(report_path);
        let token_mutant = std::str::from_utf8(token)
            .unwrap()
            .replace(
                "\"mapOnlyIncompleteCells\":127",
                "\"mapOnlyIncompleteCells\":126",
            )
            .replace(
                &sha256_bytes(report.as_bytes()).hex(),
                &sha256_bytes(&report_mutant).hex(),
            );
        fs::write(token_path, token_mutant).unwrap();
        write_test_digest_sibling(token_path);
        assert!(verify_activation_preparation_token(report_path, token_path).is_err());
        fs::write(report_path, report).unwrap();
        fs::write(token_path, token).unwrap();
        write_test_digest_sibling(report_path);
        write_test_digest_sibling(token_path);
    }

    fn write_test_digest_sibling(path: &Path) {
        let bytes = fs::read(path).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        fs::write(
            path.with_extension("json.sha256"),
            format!("{}  {name}\n", sha256_bytes(&bytes).hex()),
        )
        .unwrap();
    }
}
