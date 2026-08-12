//! Split source/model and black-box execution authority for constrained
//! collection claims.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

use crate::{ClaimPlatform, ExecutionProfile};
use crate::{Digest, sha256_bytes, sha256_file};

const SOURCE_MANIFEST_RELATIVE: &str = "compat/oracle-sources/collection-source-authority.tsv";
const SOURCE_MANIFEST: &str =
    include_str!("../../../compat/oracle-sources/collection-source-authority.tsv");
const NATIVE_SOURCE_COMMIT: &str = "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff";
const LINUX_RELEASE_COMMIT: &str = "d4d028609ed46a560c62caea8c70e7e91d1afd29";
const LINUX_RELEASE_ASSET_SHA256: &str =
    "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9";
const MAP_SOURCE_SHA256: &str = "541dd92c62307a6543edbc0269af44d95973b4de647149a75c5660697e5c2e56";
const SET_SOURCE_SHA256: &str = "68c58fab8023b84b32fb496219edc148e5efef98fbf7cbba7435a950fa2a57bb";
const LICENSE_SHA256: &str = "7904b49880da042ab0e3125ef4da8ba2322b7b5e13de13bc6a322e5e2670bc5c";
const CABAL_REVISION_SHA256: &str =
    "bb2bec1bbc6b39a7c97cd95e056a5698ec45beb5d8feb6caae12af64e4bd823c";
const ARCHIVE_SHA256: &str = "2247af69fab1c9c48d3b7e184f18b63d12d273572a7f55319c0d6fae896de1e1";

/// Exact number of reviewed Map and Set cases required by collection
/// black-box authority: Map 712 plus Set 479.
pub const COLLECTION_CASE_AUTHORITY_COUNT: usize = 1_191;

/// Returns the exact dormant Map712 and Set479 campaign without registering
/// either tranche as committed compatibility evidence.
///
/// # Errors
///
/// Returns an error if either reviewed generator no longer has its exact
/// audited inventory.
pub fn reviewed_collection_cases() -> Result<Vec<crate::DifferentialCase>, String> {
    let map = crate::corpus::runtime_ord_map_cases();
    let set = crate::corpus::runtime_ord_set_cases();
    if map.len() != 712 || set.len() != 479 {
        return Err("reviewed collection corpus is not the exact Map712/Set479 split".into());
    }
    Ok(map.into_iter().chain(set).collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionSourceAuthority {
    pub(crate) manifest: Digest,
    pub(crate) reviewed_model: Digest,
    pub(crate) map_source: Digest,
    pub(crate) set_source: Digest,
}

impl CollectionSourceAuthority {
    /// Digest of the verified collection source-authority manifest bytes.
    #[must_use]
    pub const fn manifest_sha256(&self) -> Digest {
        self.manifest
    }

    /// Digest of the independently reviewed collection model source.
    #[must_use]
    pub const fn reviewed_model_sha256(&self) -> Digest {
        self.reviewed_model
    }

    /// Digest of the retained `Data.Map.Internal` source bytes.
    #[must_use]
    pub const fn map_source_sha256(&self) -> Digest {
        self.map_source
    }

    /// Digest of the retained `Data.Set.Internal` source bytes.
    #[must_use]
    pub const fn set_source_sha256(&self) -> Digest {
        self.set_source
    }
}

/// Verifies the complete retained containers source/model authority package.
///
/// This authority identifies the reviewed version source and model. It does
/// not claim that a GHC boot package was built from these exact retained bytes.
///
/// # Errors
///
/// Returns an error for a missing, extra, substituted, or malformed manifest,
/// source, license, package revision, resolver input, archive, model, or source
/// anchor.
pub fn verify_collection_source_authority(
    repository_root: &Path,
) -> std::io::Result<CollectionSourceAuthority> {
    let manifest_path = repository_root.join(SOURCE_MANIFEST_RELATIVE);
    let manifest = fs::read_to_string(&manifest_path)?;
    if manifest != SOURCE_MANIFEST {
        return Err(std::io::Error::other(
            "collection source authority manifest is noncanonical",
        ));
    }
    let fields = parse_manifest(&manifest)?;
    validate_manifest_constants(&fields)?;
    verify_manifest_file(repository_root, &fields, "stackYamlPath", "stackYamlSha256")?;
    verify_manifest_file(repository_root, &fields, "stackLockPath", "stackLockSha256")?;
    verify_manifest_file(
        repository_root,
        &fields,
        "cabalRevisionPath",
        "cabalRevisionSha256",
    )?;
    verify_manifest_file(repository_root, &fields, "licensePath", "licenseSha256")?;
    let map_source_sha256 =
        verify_manifest_file(repository_root, &fields, "mapSourcePath", "mapSourceSha256")?;
    let set_source_sha256 =
        verify_manifest_file(repository_root, &fields, "setSourcePath", "setSourceSha256")?;
    let reviewed_model_sha256 = verify_manifest_file(
        repository_root,
        &fields,
        "reviewedModelPath",
        "reviewedModelSha256",
    )?;
    verify_archive(repository_root, &fields)?;
    verify_cabal_revision_size(repository_root, &fields)?;
    verify_source_anchors(repository_root, &fields, "mapSourcePath", MAP_ANCHORS)?;
    verify_source_anchors(repository_root, &fields, "setSourcePath", SET_ANCHORS)?;
    Ok(CollectionSourceAuthority {
        manifest: sha256_bytes(manifest.as_bytes()),
        reviewed_model: reviewed_model_sha256,
        map_source: map_source_sha256,
        set_source: set_source_sha256,
    })
}

fn parse_manifest(document: &str) -> std::io::Result<BTreeMap<&str, &str>> {
    let mut fields = BTreeMap::new();
    for line in document.lines() {
        let (name, value) = line
            .split_once('\t')
            .ok_or_else(|| std::io::Error::other("collection source manifest line is malformed"))?;
        if name.is_empty() || value.is_empty() || fields.insert(name, value).is_some() {
            return Err(std::io::Error::other(
                "collection source manifest field is empty or duplicated",
            ));
        }
    }
    Ok(fields)
}

fn validate_manifest_constants(fields: &BTreeMap<&str, &str>) -> std::io::Result<()> {
    let expected = [
        ("schemaVersion", "1"),
        (
            "domain",
            "hell-collection-reviewed-version-source-model-authority-v1",
        ),
        ("authorityClass", "reviewed-version-source-and-model"),
        ("builtFromExactSourceBytes", "false"),
        (
            "dependencyJoin",
            "external-authenticated-native-build-record-required",
        ),
        ("hellSourceCommit", NATIVE_SOURCE_COMMIT),
        ("stackResolver", "nightly-2024-10-21"),
        ("stackVersion", "3.11.1"),
        ("ghcVersion", "9.8.2"),
        ("packageName", "containers"),
        ("packageVersion", "0.6.8"),
        ("sourceArchiveEncoding", "base64"),
        ("sourceArchiveSha256", ARCHIVE_SHA256),
        ("cabalRevisionBytes", "2670"),
        ("cabalRevisionSha256", CABAL_REVISION_SHA256),
        ("licenseSpdx", "BSD-3-Clause"),
        ("licenseSha256", LICENSE_SHA256),
        ("mapSourceSha256", MAP_SOURCE_SHA256),
        ("setSourceSha256", SET_SOURCE_SHA256),
        (
            "reviewedModelDomain",
            "hell-runtime-collection-comparator-trace-v1",
        ),
    ];
    if expected
        .iter()
        .any(|(name, value)| fields.get(name).copied() != Some(*value))
    {
        return Err(std::io::Error::other(
            "collection source authority identity is invalid",
        ));
    }
    Ok(())
}

fn verify_manifest_file(
    repository_root: &Path,
    fields: &BTreeMap<&str, &str>,
    path_field: &str,
    digest_field: &str,
) -> std::io::Result<Digest> {
    let path = manifest_path(repository_root, fields, path_field)?;
    let expected = manifest_digest(fields, digest_field)?;
    let actual = sha256_file(&path)?;
    if actual != expected {
        return Err(std::io::Error::other(format!(
            "collection source authority file differs for {path_field}"
        )));
    }
    Ok(actual)
}

fn manifest_path(
    repository_root: &Path,
    fields: &BTreeMap<&str, &str>,
    field: &str,
) -> std::io::Result<std::path::PathBuf> {
    let relative = fields
        .get(field)
        .ok_or_else(|| std::io::Error::other(format!("missing collection manifest {field}")))?;
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(std::io::Error::other(
            "collection source authority path is nonportable",
        ));
    }
    Ok(repository_root.join(path))
}

fn manifest_digest(fields: &BTreeMap<&str, &str>, field: &str) -> std::io::Result<Digest> {
    fields
        .get(field)
        .ok_or_else(|| std::io::Error::other(format!("missing collection manifest {field}")))
        .and_then(|value| Digest::from_hex(value).map_err(std::io::Error::other))
}

fn verify_archive(repository_root: &Path, fields: &BTreeMap<&str, &str>) -> std::io::Result<()> {
    let encoded = fs::read(manifest_path(repository_root, fields, "sourceArchivePath")?)?;
    let decoded = decode_base64(&encoded)?;
    if sha256_bytes(&decoded) != manifest_digest(fields, "sourceArchiveSha256")? {
        return Err(std::io::Error::other(
            "retained containers source archive digest differs",
        ));
    }
    verify_archive_members(repository_root, &decoded)?;
    Ok(())
}

fn verify_archive_members(repository_root: &Path, gzip: &[u8]) -> std::io::Result<()> {
    let expected = [
        (
            "containers-0.6.8/LICENSE",
            "compat/oracle-sources/containers-0.6.8/LICENSE",
        ),
        (
            "containers-0.6.8/containers.cabal",
            "compat/oracle-sources/containers-0.6.8/containers.cabal",
        ),
        (
            "containers-0.6.8/src/Data/Map/Internal.hs",
            "compat/oracle-sources/containers-0.6.8/src/Data/Map/Internal.hs",
        ),
        (
            "containers-0.6.8/src/Data/Set/Internal.hs",
            "compat/oracle-sources/containers-0.6.8/src/Data/Set/Internal.hs",
        ),
    ];
    let mut members = BTreeMap::<String, Vec<u8>>::new();
    let decoder = flate2::read::GzDecoder::new(gzip);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry
            .path()?
            .to_str()
            .ok_or_else(|| std::io::Error::other("containers archive path is not UTF-8"))?
            .to_owned();
        if members.contains_key(&path) {
            return Err(std::io::Error::other(
                "containers archive repeats a member path",
            ));
        }
        if expected.iter().any(|(required, _)| *required == path) {
            if !entry.header().entry_type().is_file() {
                return Err(std::io::Error::other(
                    "required containers archive member is not a file",
                ));
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            members.insert(path, bytes);
        } else {
            members.insert(path, Vec::new());
        }
    }
    for (archive_path, retained_path) in expected {
        let observed = members
            .get(archive_path)
            .ok_or_else(|| std::io::Error::other("containers archive omits a required member"))?;
        if observed != &fs::read(repository_root.join(retained_path))? {
            return Err(std::io::Error::other(
                "containers archive member differs from retained source bytes",
            ));
        }
    }
    Ok(())
}

fn decode_base64(encoded: &[u8]) -> std::io::Result<Vec<u8>> {
    let sextets = encoded
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(base64_sextet)
        .collect::<std::io::Result<Vec<_>>>()?;
    if sextets.len() % 4 != 0 {
        return Err(std::io::Error::other(
            "retained source archive base64 is truncated",
        ));
    }
    let mut output = Vec::with_capacity(sextets.len() / 4 * 3);
    for chunk in sextets.chunks_exact(4) {
        let padding = usize::from(chunk[3] == 64) + usize::from(chunk[2] == 64);
        if chunk[..2].contains(&64)
            || (chunk[2] == 64 && chunk[3] != 64)
            || chunk[..4 - padding].contains(&64)
        {
            return Err(std::io::Error::other(
                "retained source archive base64 is invalid",
            ));
        }
        let bits = (u32::from(chunk[0]) << 18)
            | (u32::from(chunk[1]) << 12)
            | (u32::from(chunk[2] & 63) << 6)
            | u32::from(chunk[3] & 63);
        let bytes = bits.to_be_bytes();
        output.push(bytes[1]);
        if padding < 2 {
            output.push(bytes[2]);
        }
        if padding == 0 {
            output.push(bytes[3]);
        }
    }
    Ok(output)
}

/// Decodes the retained collection source archive and returns its exact
/// content digest. The decoder is the same strict implementation used by the
/// production collection source-authority verifier.
///
/// # Errors
///
/// Returns an error if the retained archive is not canonical base64.
pub fn decoded_collection_source_archive_sha256(encoded: &[u8]) -> std::io::Result<Digest> {
    Ok(sha256_bytes(&decode_base64(encoded)?))
}

fn base64_sextet(byte: u8) -> std::io::Result<u8> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        b'=' => Ok(64),
        _ => Err(std::io::Error::other(
            "retained source archive base64 is invalid",
        )),
    }
}

fn verify_cabal_revision_size(
    repository_root: &Path,
    fields: &BTreeMap<&str, &str>,
) -> std::io::Result<()> {
    let expected = fields
        .get("cabalRevisionBytes")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| std::io::Error::other("cabal revision byte count is malformed"))?;
    let actual = fs::metadata(manifest_path(repository_root, fields, "cabalRevisionPath")?)?.len();
    if actual != expected {
        return Err(std::io::Error::other("cabal revision byte count differs"));
    }
    Ok(())
}

fn verify_source_anchors(
    repository_root: &Path,
    fields: &BTreeMap<&str, &str>,
    source_field: &str,
    anchors: &[(&str, usize, &str)],
) -> std::io::Result<()> {
    let source = fs::read_to_string(manifest_path(repository_root, fields, source_field)?)?;
    let lines = source.lines().collect::<Vec<_>>();
    for (symbol, line, expected) in anchors {
        if lines.get(line - 1).copied() != Some(*expected) {
            return Err(std::io::Error::other(format!(
                "collection source anchor {symbol}@{line} differs"
            )));
        }
    }
    Ok(())
}

const MAP_ANCHORS: &[(&str, usize, &str)] = &[
    ("lookup", 572, "lookup :: Ord k => k -> Map k a -> Maybe a"),
    (
        "insert",
        778,
        "insert :: Ord k => k -> a -> Map k a -> Map k a",
    ),
    (
        "insertR",
        827,
        "insertR :: Ord k => k -> a -> Map k a -> Map k a",
    ),
    (
        "insertWith",
        859,
        "insertWith :: Ord k => (a -> a -> a) -> k -> a -> Map k a -> Map k a",
    ),
    ("delete", 1008, "delete :: Ord k => k -> Map k a -> Map k a"),
    (
        "adjust",
        1036,
        "adjust :: Ord k => (a -> a) -> k -> Map k a -> Map k a",
    ),
    (
        "unionWith",
        1855,
        "unionWith :: Ord k => (a -> a -> a) -> Map k a -> Map k a -> Map k a",
    ),
    ("fromList", 3443, "fromList :: Ord k => [(k,a)] -> Map k a"),
    ("go", 3456, "    go !_ t [] = t"),
    ("create", 3468, "    create !_ [] = (Tip, [], [])"),
    (
        "splitLookup",
        3898,
        "splitLookup :: Ord k => k -> Map k a -> (Map k a,Maybe a,Map k a)",
    ),
    (
        "link",
        3969,
        "link :: k -> a -> Map k a -> Map k a -> Map k a",
    ),
    (
        "insertMax",
        3979,
        "insertMax,insertMin :: k -> a -> Map k a -> Map k a",
    ),
    ("link2", 3995, "link2 :: Map k a -> Map k a -> Map k a"),
    ("glue", 4007, "glue :: Map k a -> Map k a -> Map k a"),
    (
        "balanceL",
        4162,
        "balanceL :: k -> a -> Map k a -> Map k a -> Map k a",
    ),
    (
        "balanceR",
        4187,
        "balanceR :: k -> a -> Map k a -> Map k a -> Map k a",
    ),
];

const SET_ANCHORS: &[(&str, usize, &str)] = &[
    ("member", 388, "member :: Ord a => a -> Set a -> Bool"),
    ("insert", 519, "insert :: Ord a => a -> Set a -> Set a"),
    ("insertR", 549, "insertR :: Ord a => a -> Set a -> Set a"),
    ("delete", 571, "delete :: Ord a => a -> Set a -> Set a"),
    ("union", 820, "union :: Ord a => Set a -> Set a -> Set a"),
    (
        "difference",
        843,
        "difference :: Ord a => Set a -> Set a -> Set a",
    ),
    (
        "intersection",
        870,
        "intersection :: Ord a => Set a -> Set a -> Set a",
    ),
    ("fromList", 1092, "fromList :: Ord a => [a] -> Set a"),
    ("go", 1105, "    go !_ t [] = t"),
    ("create", 1117, "    create !_ [] = (Tip, [], [])"),
    (
        "splitMember",
        1320,
        "splitMember :: Ord a => a -> Set a -> (Set a,Bool,Set a)",
    ),
    ("link", 1579, "link :: a -> Set a -> Set a -> Set a"),
    (
        "insertMax",
        1589,
        "insertMax,insertMin :: a -> Set a -> Set a",
    ),
    ("merge", 1605, "merge :: Set a -> Set a -> Set a"),
    ("glue", 1617, "glue :: Set a -> Set a -> Set a"),
    ("balanceL", 1745, "balanceL :: a -> Set a -> Set a -> Set a"),
    ("balanceR", 1770, "balanceR :: a -> Set a -> Set a -> Set a"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionOracleSubject {
    NativeSourceBuild,
    LinuxSignedReleaseResultOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionDependencyAuthority {
    UnknownResultOnly,
    ReportedVersionNoExactSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectionCompletion {
    Success,
    Failure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionCaseAuthority {
    pub case_id: Arc<str>,
    pub operation: Arc<str>,
    pub path: Arc<str>,
    pub profile: ExecutionProfile,
    pub source_sha256: Digest,
    pub arguments_sha256: Digest,
    pub environment_sha256: Digest,
    pub stdin_sha256: Digest,
    pub execution_input_sha256: Digest,
    pub descriptor_sha256: Digest,
    pub target_builtin: Arc<str>,
    pub instance_target: Arc<str>,
    pub comparator_contract_sha256: Digest,
    pub source_authority_manifest_sha256: Digest,
    pub expected_candidate_typed_result_sha256: Option<Digest>,
    pub expected_completion: CollectionCompletion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionNativeBuildAuthority {
    pub platform: ClaimPlatform,
    pub source_commit: Arc<str>,
    pub stack_version: Arc<str>,
    pub resolver_lock_sha256: Digest,
    pub ghc_version: Arc<str>,
    pub containers_version: Arc<str>,
    pub cabal_revision_sha256: Digest,
    pub oracle_executable_sha256: Digest,
    pub build_record_sha256: Digest,
    pub source_authority_manifest_sha256: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionBlackBoxShard {
    pub platform: ClaimPlatform,
    pub case: CollectionCaseAuthority,
    pub oracle_subject: CollectionOracleSubject,
    pub oracle_source_commit: Arc<str>,
    pub oracle_executable_sha256: Digest,
    pub oracle_acquisition_receipt_sha256: Option<Digest>,
    pub oracle_provider_attestation_sha256: Option<Digest>,
    pub provider_repository_id: u64,
    pub provider_run_id: u64,
    pub provider_run_attempt: u64,
    pub provider_artifact_id: u64,
    pub provider_workflow_ref: Arc<str>,
    pub provider_event: Arc<str>,
    pub provider_candidate_subject_sha256: Digest,
    pub oracle_build_record_sha256: Option<Digest>,
    pub dependency_authority: CollectionDependencyAuthority,
    pub bundle_sha256: Digest,
    pub oracle_observation_sha256: Digest,
    pub candidate_observation_sha256: Digest,
    pub oracle_stdout_sha256: Digest,
    pub oracle_stderr_sha256: Digest,
    pub oracle_status_sha256: Digest,
    pub candidate_stdout_sha256: Digest,
    pub candidate_stderr_sha256: Digest,
    pub candidate_status_sha256: Digest,
    pub candidate_typed_result_sha256: Option<Digest>,
    pub candidate_comparator_trace_sha256: Digest,
    pub oracle_completion: CollectionCompletion,
    pub candidate_completion: CollectionCompletion,
    pub candidate_source_commit: Arc<str>,
    pub candidate_executable_sha256: Digest,
}

/// Bundle facts rederived from one exact reviewed collection observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionBundleFacts {
    pub case: CollectionCaseAuthority,
    pub bundle_sha256: Digest,
    pub oracle_observation_sha256: Digest,
    pub candidate_observation_sha256: Digest,
    pub oracle_stdout_sha256: Digest,
    pub oracle_stderr_sha256: Digest,
    pub oracle_status_sha256: Digest,
    pub candidate_stdout_sha256: Digest,
    pub candidate_stderr_sha256: Digest,
    pub candidate_status_sha256: Digest,
    pub candidate_typed_result_sha256: Option<Digest>,
    pub candidate_comparator_trace_sha256: Digest,
    pub oracle_completion: CollectionCompletion,
    pub candidate_completion: CollectionCompletion,
    pub oracle_executable_sha256: Digest,
    pub oracle_acquisition_receipt_sha256: Option<Digest>,
    pub oracle_acquisition_attestation_sha256: Option<Digest>,
    pub candidate_executable_sha256: Digest,
}

/// Provider/authentication facts that must be rederived by the external
/// artifact-selection verifier before a retained observation bundle is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionVerifiedProviderRoot {
    pub(crate) platform: ClaimPlatform,
    pub(crate) oracle_subject: CollectionOracleSubject,
    pub(crate) oracle_source_commit: Arc<str>,
    pub(crate) oracle_executable_sha256: Digest,
    pub(crate) oracle_acquisition_receipt_sha256: Digest,
    pub(crate) oracle_provider_attestation_sha256: Digest,
    pub(crate) provider_repository_id: u64,
    pub(crate) provider_run_id: u64,
    pub(crate) provider_run_attempt: u64,
    pub(crate) provider_artifact_id: u64,
    pub(crate) provider_workflow_ref: Arc<str>,
    pub(crate) provider_event: Arc<str>,
    pub(crate) provider_candidate_subject_sha256: Digest,
    pub(crate) candidate_source_commit: Arc<str>,
    pub(crate) candidate_executable_sha256: Digest,
    pub(crate) oracle_build_record_sha256: Option<Digest>,
    pub(crate) dependency_authority: CollectionDependencyAuthority,
}

/// Validates the exact shape and joins of a three-platform Map/Set black-box
/// set against the separate reviewed source/model authority.
///
/// This structural validator deliberately does not authenticate or rehash the
/// provider artifacts named by its inputs. Claim admission must first derive
/// these records from retained, provider-authenticated bytes. Calling this
/// function on hand-authored records is never promotion authority.
///
/// # Errors
///
/// Returns an error for any missing, extra, duplicated, local/unattested,
/// cross-platform-drifting, source/model-substituted, asset-substituted, or
/// observation-substituted case.
pub fn validate_collection_black_box_structure(
    source: &CollectionSourceAuthority,
    native_builds: &[CollectionNativeBuildAuthority],
    shards: &[CollectionBlackBoxShard],
) -> Result<(), String> {
    let expected_cases = reviewed_collection_case_authorities(source)?;
    validate_expected_cases(source, &expected_cases)?;
    let builds = validate_native_builds(source, native_builds)?;
    if shards.len() != expected_cases.len() * 3 {
        return Err("collection black-box authority must contain exactly 1191x3 shards".into());
    }
    let expected = expected_cases
        .iter()
        .map(|case| (case.case_id.as_ref(), case))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut executable_platforms = BTreeMap::<String, ClaimPlatform>::new();
    let mut candidate_executable_platforms = BTreeMap::<String, ClaimPlatform>::new();
    let mut candidate_source_commit = None::<Arc<str>>;
    let mut campaign_root = None::<CollectionCampaignRoot>;
    let mut platform_roots = BTreeMap::<&str, CollectionPlatformRoot>::new();
    let mut case_outputs = BTreeMap::<&str, CollectionCaseOutput>::new();
    for shard in shards {
        let key = (
            shard.case.case_id.to_string(),
            platform_name(shard.platform),
        );
        if !seen.insert(key) {
            return Err("collection black-box authority repeats a case/platform".into());
        }
        let reviewed = expected
            .get(shard.case.case_id.as_ref())
            .ok_or_else(|| "collection black-box authority contains an extra case".to_owned())?;
        if shard.case != **reviewed {
            return Err(
                "collection black-box case/source/input/descriptor/model join differs".into(),
            );
        }
        validate_shard_observations(shard)?;
        validate_shard_subject(source, shard, &builds)?;
        validate_platform_root(shard, &mut platform_roots)?;
        validate_campaign_root(shard, &mut campaign_root)?;
        validate_case_output(shard, &mut case_outputs)?;
        if candidate_source_commit
            .as_ref()
            .is_some_and(|expected| expected != &shard.candidate_source_commit)
        {
            return Err("collection candidate source commit drifts across platforms".into());
        }
        candidate_source_commit.get_or_insert_with(|| Arc::clone(&shard.candidate_source_commit));
        if executable_platforms
            .insert(shard.oracle_executable_sha256.hex(), shard.platform)
            .is_some_and(|prior| prior != shard.platform)
        {
            return Err("collection platforms reuse an oracle executable identity".into());
        }
        if candidate_executable_platforms
            .insert(shard.candidate_executable_sha256.hex(), shard.platform)
            .is_some_and(|prior| prior != shard.platform)
        {
            return Err("collection platforms reuse a candidate executable identity".into());
        }
    }
    if expected_cases.iter().any(|case| {
        required_platforms()
            .iter()
            .any(|platform| !seen.contains(&(case.case_id.to_string(), platform_name(*platform))))
    }) {
        return Err("collection black-box authority omits a required case/platform".into());
    }
    Ok(())
}

/// Derives the exact canonical Map712/Set479 case-authority inventory from the
/// reviewed source/model authority.
///
/// # Errors
///
/// Returns an error if any reviewed case, descriptor, instance, comparator,
/// input, or expected result is missing or noncanonical.
pub fn reviewed_collection_case_authorities(
    source: &CollectionSourceAuthority,
) -> Result<Vec<CollectionCaseAuthority>, String> {
    reviewed_collection_cases()?
        .into_iter()
        .map(|case| reviewed_collection_case(source, &case))
        .collect()
}

pub(crate) fn reviewed_collection_case(
    source: &CollectionSourceAuthority,
    case: &crate::DifferentialCase,
) -> Result<CollectionCaseAuthority, String> {
    let descriptor = case
        .claim_evidence
        .as_ref()
        .ok_or_else(|| "reviewed collection case lacks a descriptor".to_owned())?;
    let targets = descriptor
        .semantic_targets
        .iter()
        .filter(|target| target.expected_comparator_trace_sha256.is_some())
        .collect::<Vec<_>>();
    let [target] = targets.as_slice() else {
        return Err("reviewed collection case lacks one exact comparator target".into());
    };
    let execution_input = crate::artifact::execution_input_json(case)
        .map_err(|error| format!("reviewed collection execution input is invalid: {error}"))?;
    Ok(CollectionCaseAuthority {
        case_id: Arc::clone(&case.id),
        operation: Arc::clone(&target.builtin),
        path: Arc::clone(&case.id),
        profile: descriptor.profile,
        source_sha256: sha256_bytes(case.source.as_bytes()),
        arguments_sha256: argument_sha256(&case.arguments)?,
        environment_sha256: environment_sha256(&case.environment)?,
        stdin_sha256: sha256_bytes(&case.stdin),
        execution_input_sha256: sha256_bytes(execution_input.as_bytes()),
        descriptor_sha256: sha256_bytes(crate::artifact::case_descriptor(case).as_bytes()),
        target_builtin: Arc::clone(&target.builtin),
        instance_target: Arc::clone(
            target
                .expected_instance_target
                .as_ref()
                .ok_or_else(|| "reviewed collection target lacks its instance".to_owned())?,
        ),
        comparator_contract_sha256: target
            .expected_comparator_trace_sha256
            .ok_or_else(|| "reviewed collection comparator contract disappeared".to_owned())?,
        source_authority_manifest_sha256: source.manifest,
        expected_candidate_typed_result_sha256: target.expected_typed_result_sha256,
        expected_completion: if case.expected_runtime_completion {
            CollectionCompletion::Success
        } else {
            CollectionCompletion::Failure
        },
    })
}

fn argument_sha256(arguments: &[std::ffi::OsString]) -> Result<Digest, String> {
    let mut canonical = b"hell-collection-arguments-v1\0".to_vec();
    canonical.extend_from_slice(&(arguments.len() as u64).to_be_bytes());
    for argument in arguments {
        push_os_field(&mut canonical, argument)?;
    }
    Ok(sha256_bytes(&canonical))
}

fn environment_sha256(
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Digest, String> {
    let mut canonical = b"hell-collection-environment-v1\0".to_vec();
    canonical.extend_from_slice(&(environment.len() as u64).to_be_bytes());
    for (name, value) in environment {
        push_os_field(&mut canonical, name)?;
        push_os_field(&mut canonical, value)?;
    }
    Ok(sha256_bytes(&canonical))
}

fn push_os_field(canonical: &mut Vec<u8>, value: &std::ffi::OsStr) -> Result<(), String> {
    let value = value
        .to_str()
        .ok_or_else(|| "reviewed collection input is not canonical UTF-8".to_owned())?;
    canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
    canonical.extend_from_slice(value.as_bytes());
    Ok(())
}

fn validate_expected_cases(
    source: &CollectionSourceAuthority,
    cases: &[CollectionCaseAuthority],
) -> Result<(), String> {
    let mut ids = BTreeSet::new();
    for case in cases {
        if !ids.insert(case.case_id.as_ref())
            || case.case_id.is_empty()
            || case.operation.is_empty()
            || case.path.is_empty()
            || case.target_builtin.is_empty()
            || case.instance_target.is_empty()
            || case.source_authority_manifest_sha256 != source.manifest
            || case.profile != ExecutionProfile::Upstream
            || case_digests(case).contains(&Digest::default())
            || !matches!(case.target_builtin.as_ref(), name if name.starts_with("Map.") || name.starts_with("Set."))
        {
            return Err("collection expected case inventory is malformed or duplicated".into());
        }
    }
    Ok(())
}

fn case_digests(case: &CollectionCaseAuthority) -> [Digest; 8] {
    [
        case.source_sha256,
        case.arguments_sha256,
        case.environment_sha256,
        case.stdin_sha256,
        case.execution_input_sha256,
        case.descriptor_sha256,
        case.comparator_contract_sha256,
        case.source_authority_manifest_sha256,
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CollectionPlatformRoot {
    oracle_subject: CollectionOracleSubject,
    oracle_source_commit: Arc<str>,
    oracle_executable_sha256: Digest,
    oracle_acquisition_receipt_sha256: Option<Digest>,
    oracle_provider_attestation_sha256: Option<Digest>,
    provider_repository_id: u64,
    provider_run_id: u64,
    provider_run_attempt: u64,
    provider_artifact_id: u64,
    oracle_build_record_sha256: Option<Digest>,
    candidate_source_commit: Arc<str>,
    candidate_executable_sha256: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CollectionCampaignRoot {
    provider_repository_id: u64,
    provider_run_id: u64,
    provider_run_attempt: u64,
    provider_workflow_ref: Arc<str>,
    provider_event: Arc<str>,
    provider_candidate_subject_sha256: Digest,
    candidate_source_commit: Arc<str>,
}

impl From<&CollectionBlackBoxShard> for CollectionPlatformRoot {
    fn from(shard: &CollectionBlackBoxShard) -> Self {
        Self {
            oracle_subject: shard.oracle_subject,
            oracle_source_commit: Arc::clone(&shard.oracle_source_commit),
            oracle_executable_sha256: shard.oracle_executable_sha256,
            oracle_acquisition_receipt_sha256: shard.oracle_acquisition_receipt_sha256,
            oracle_provider_attestation_sha256: shard.oracle_provider_attestation_sha256,
            provider_repository_id: shard.provider_repository_id,
            provider_run_id: shard.provider_run_id,
            provider_run_attempt: shard.provider_run_attempt,
            provider_artifact_id: shard.provider_artifact_id,
            oracle_build_record_sha256: shard.oracle_build_record_sha256,
            candidate_source_commit: Arc::clone(&shard.candidate_source_commit),
            candidate_executable_sha256: shard.candidate_executable_sha256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CollectionCaseOutput {
    stdout_sha256: Digest,
    stderr_sha256: Digest,
    status_sha256: Digest,
    completion: CollectionCompletion,
}

fn validate_platform_root(
    shard: &CollectionBlackBoxShard,
    roots: &mut BTreeMap<&'static str, CollectionPlatformRoot>,
) -> Result<(), String> {
    if shard.candidate_source_commit.len() != 40
        || !shard
            .candidate_source_commit
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || shard.candidate_executable_sha256 == Digest::default()
    {
        return Err("collection candidate source/binary identity is malformed".into());
    }
    let platform = platform_name(shard.platform);
    let observed = CollectionPlatformRoot::from(shard);
    if roots
        .get(platform)
        .is_some_and(|expected| expected != &observed)
    {
        return Err("collection platform provider/run/build/subject root drifts by case".into());
    }
    roots.entry(platform).or_insert(observed);
    Ok(())
}

fn validate_campaign_root(
    shard: &CollectionBlackBoxShard,
    root: &mut Option<CollectionCampaignRoot>,
) -> Result<(), String> {
    let observed = CollectionCampaignRoot {
        provider_repository_id: shard.provider_repository_id,
        provider_run_id: shard.provider_run_id,
        provider_run_attempt: shard.provider_run_attempt,
        provider_workflow_ref: Arc::clone(&shard.provider_workflow_ref),
        provider_event: Arc::clone(&shard.provider_event),
        provider_candidate_subject_sha256: shard.provider_candidate_subject_sha256,
        candidate_source_commit: Arc::clone(&shard.candidate_source_commit),
    };
    if root.as_ref().is_some_and(|expected| expected != &observed) {
        return Err("collection three-platform campaign root drifts".into());
    }
    root.get_or_insert(observed);
    Ok(())
}

fn validate_case_output<'a>(
    shard: &'a CollectionBlackBoxShard,
    outputs: &mut BTreeMap<&'a str, CollectionCaseOutput>,
) -> Result<(), String> {
    let observed = CollectionCaseOutput {
        stdout_sha256: shard.oracle_stdout_sha256,
        stderr_sha256: shard.oracle_stderr_sha256,
        status_sha256: shard.oracle_status_sha256,
        completion: shard.oracle_completion,
    };
    if outputs
        .get(shard.case.case_id.as_ref())
        .is_some_and(|expected| expected != &observed)
    {
        return Err("collection black-box raw/status output drifts across platforms".into());
    }
    outputs
        .entry(shard.case.case_id.as_ref())
        .or_insert(observed);
    Ok(())
}

fn validate_native_builds<'a>(
    source: &CollectionSourceAuthority,
    builds: &'a [CollectionNativeBuildAuthority],
) -> Result<BTreeMap<&'static str, &'a CollectionNativeBuildAuthority>, String> {
    if builds.len() != 2 {
        return Err("collection authority requires exact macOS and Windows native builds".into());
    }
    let mut by_platform = BTreeMap::new();
    for build in builds {
        if !matches!(
            build.platform,
            ClaimPlatform::MacOs | ClaimPlatform::Windows
        ) || by_platform
            .insert(platform_name(build.platform), build)
            .is_some()
            || build.source_commit.as_ref() != NATIVE_SOURCE_COMMIT
            || build.stack_version.as_ref() != "3.11.1"
            || build.resolver_lock_sha256
                != digest("119cff36de1117edfb6098fd9688f9dad843c716d874d02dce49ecdc0dcfb61a")
            || build.ghc_version.as_ref() != "9.8.2"
            || build.containers_version.as_ref() != "0.6.8"
            || build.cabal_revision_sha256 != digest(CABAL_REVISION_SHA256)
            || build.source_authority_manifest_sha256 != source.manifest
            || [
                build.oracle_executable_sha256,
                build.build_record_sha256,
                build.source_authority_manifest_sha256,
            ]
            .contains(&Digest::default())
        {
            return Err("collection native build authority is invalid".into());
        }
    }
    Ok(by_platform)
}

fn validate_shard_observations(shard: &CollectionBlackBoxShard) -> Result<(), String> {
    let case = &shard.case;
    if shard.provider_repository_id == 0
        || shard.provider_run_id == 0
        || shard.provider_run_attempt == 0
        || shard.provider_artifact_id == 0
        || shard.provider_workflow_ref.is_empty()
        || shard.provider_event.is_empty()
        || [
            shard.oracle_executable_sha256,
            shard.provider_candidate_subject_sha256,
            shard.bundle_sha256,
            shard.oracle_observation_sha256,
            shard.candidate_observation_sha256,
            shard.oracle_stdout_sha256,
            shard.oracle_stderr_sha256,
            shard.oracle_status_sha256,
            shard.candidate_stdout_sha256,
            shard.candidate_stderr_sha256,
            shard.candidate_status_sha256,
            shard.candidate_comparator_trace_sha256,
        ]
        .contains(&Digest::default())
        || shard.oracle_observation_sha256 == shard.candidate_observation_sha256
        || shard.oracle_stdout_sha256 != shard.candidate_stdout_sha256
        || shard.oracle_stderr_sha256 != shard.candidate_stderr_sha256
        || shard.oracle_status_sha256 != shard.candidate_status_sha256
        || shard.oracle_completion != case.expected_completion
        || shard.candidate_completion != case.expected_completion
        || shard.candidate_typed_result_sha256 != case.expected_candidate_typed_result_sha256
        || shard.candidate_comparator_trace_sha256 != case.comparator_contract_sha256
    {
        return Err("collection black-box observation/raw/status/model join differs".into());
    }
    Ok(())
}

fn validate_shard_subject(
    source: &CollectionSourceAuthority,
    shard: &CollectionBlackBoxShard,
    builds: &BTreeMap<&str, &CollectionNativeBuildAuthority>,
) -> Result<(), String> {
    match shard.platform {
        ClaimPlatform::Linux => {
            if shard.oracle_subject != CollectionOracleSubject::LinuxSignedReleaseResultOnly
                || shard.oracle_source_commit.as_ref() != LINUX_RELEASE_COMMIT
                || shard.oracle_executable_sha256 != digest(LINUX_RELEASE_ASSET_SHA256)
                || shard.oracle_build_record_sha256.is_some()
                || shard.dependency_authority != CollectionDependencyAuthority::UnknownResultOnly
                || shard
                    .oracle_acquisition_receipt_sha256
                    .is_none_or(|digest| digest == Digest::default())
                || shard
                    .oracle_provider_attestation_sha256
                    .is_none_or(|digest| digest == Digest::default())
            {
                return Err("Linux collection shard exceeds result-only release authority".into());
            }
        }
        ClaimPlatform::MacOs | ClaimPlatform::Windows => {
            let build = builds
                .get(platform_name(shard.platform))
                .ok_or_else(|| "collection native build authority disappeared".to_owned())?;
            if shard.oracle_subject != CollectionOracleSubject::NativeSourceBuild
                || shard.oracle_source_commit.as_ref() != NATIVE_SOURCE_COMMIT
                || shard.oracle_executable_sha256 != build.oracle_executable_sha256
                || shard.oracle_build_record_sha256 != Some(build.build_record_sha256)
                || shard.dependency_authority
                    != CollectionDependencyAuthority::ReportedVersionNoExactSource
                || shard.oracle_acquisition_receipt_sha256.is_some()
                || shard.oracle_provider_attestation_sha256.is_some()
                || shard.case.source_authority_manifest_sha256 != source.manifest
            {
                return Err("native collection shard build/source authority join differs".into());
            }
        }
        ClaimPlatform::All => {
            return Err("collection black-box shard cannot use aggregate platform All".into());
        }
    }
    Ok(())
}

fn required_platforms() -> [ClaimPlatform; 3] {
    [
        ClaimPlatform::Linux,
        ClaimPlatform::MacOs,
        ClaimPlatform::Windows,
    ]
}

fn platform_name(platform: ClaimPlatform) -> &'static str {
    match platform {
        ClaimPlatform::Linux => "linux",
        ClaimPlatform::MacOs => "macos",
        ClaimPlatform::Windows => "windows",
        ClaimPlatform::All => "all",
    }
}

fn digest(value: &str) -> Digest {
    Digest::from_hex(value).expect("collection authority digest constant is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap()
            .to_path_buf()
    }

    #[test]
    fn retained_collection_source_authority_verifies_exact_bytes_and_anchors() {
        let authority = verify_collection_source_authority(&repository_root()).unwrap();
        assert_eq!(authority.map_source, digest(MAP_SOURCE_SHA256));
        assert_eq!(authority.set_source, digest(SET_SOURCE_SHA256));
        assert_ne!(authority.manifest, Digest::default());
        assert_ne!(authority.reviewed_model, Digest::default());
    }

    #[test]
    fn collection_source_authority_rejects_manifest_and_byte_substitution() {
        let root = repository_root();
        let original = fs::read_to_string(root.join(SOURCE_MANIFEST_RELATIVE)).unwrap();
        let sandbox =
            std::env::temp_dir().join(format!("hell-collection-authority-{}", std::process::id()));
        if sandbox.exists() {
            fs::remove_dir_all(&sandbox).unwrap();
        }
        copy_authority_tree(&root, &sandbox);
        fs::write(
            sandbox.join(SOURCE_MANIFEST_RELATIVE),
            original.replacen("packageVersion\t0.6.8", "packageVersion\t0.6.7", 1),
        )
        .unwrap();
        assert!(verify_collection_source_authority(&sandbox).is_err());
        copy_authority_tree(&root, &sandbox);
        let map = sandbox.join("compat/oracle-sources/containers-0.6.8/src/Data/Map/Internal.hs");
        let mut bytes = fs::read(&map).unwrap();
        bytes[0] ^= 1;
        fs::write(map, bytes).unwrap();
        assert!(verify_collection_source_authority(&sandbox).is_err());
        fs::remove_dir_all(sandbox).unwrap();
    }

    #[test]
    fn collection_archive_members_reject_omit_duplicate_path_and_byte_substitution() {
        let root = repository_root();
        let entries = retained_archive_entries(&root);
        let valid = gzip_archive(&entries);
        verify_archive_members(&root, &valid).unwrap();

        assert!(verify_archive_members(&root, &valid[..valid.len() / 2]).is_err());
        assert!(verify_archive_members(&root, &gzip_archive(&entries[..3])).is_err());

        let mut renamed = entries.clone();
        renamed[2].0.push_str(".substituted");
        assert!(verify_archive_members(&root, &gzip_archive(&renamed)).is_err());

        let mut substituted = entries.clone();
        substituted[2].1[0] ^= 1;
        assert!(verify_archive_members(&root, &gzip_archive(&substituted)).is_err());

        let mut duplicated = entries.clone();
        duplicated.push(entries[2].clone());
        assert!(verify_archive_members(&root, &gzip_archive(&duplicated)).is_err());
    }

    #[test]
    fn collection_black_box_structure_requires_exact_1191_by_three_joins() {
        let source = verify_collection_source_authority(&repository_root()).unwrap();
        let builds = fixture_native_builds(&source);
        let mut shards = fixture_black_box_shards(&source);
        validate_collection_black_box_structure(&source, &builds, &shards).unwrap();

        let removed = shards.pop().unwrap();
        assert!(validate_collection_black_box_structure(&source, &builds, &shards).is_err());
        shards.push(removed.clone());
        shards.push(removed);
        assert!(validate_collection_black_box_structure(&source, &builds, &shards).is_err());
        shards.pop();

        assert_structural_mutant_rejected(&source, &builds, &shards, |shard| {
            shard.case.comparator_contract_sha256 = fixture_digest("wrong comparator");
        });
        assert_structural_mutant_rejected(&source, &builds, &shards, |shard| {
            shard.candidate_stdout_sha256 = fixture_digest("wrong candidate stdout");
        });
        assert_structural_mutant_rejected(&source, &builds, &shards, |shard| {
            shard.provider_run_attempt += 1;
        });
        assert_structural_mutant_rejected(&source, &builds, &shards, |shard| {
            shard.provider_repository_id += 1;
        });
        assert_structural_mutant_rejected(&source, &builds, &shards, |shard| {
            shard.provider_workflow_ref =
                Arc::from("owner/repository/.github/workflows/other.yml@refs/heads/main");
        });
        assert_structural_mutant_rejected(&source, &builds, &shards, |shard| {
            shard.provider_event = Arc::from("push");
        });
        assert_structural_mutant_rejected(&source, &builds, &shards, |shard| {
            shard.provider_candidate_subject_sha256 = fixture_digest("wrong candidate subject");
        });
        let mut wrong_stack = builds.clone();
        wrong_stack[0].stack_version = Arc::from("3.11.0");
        assert!(validate_collection_black_box_structure(&source, &wrong_stack, &shards).is_err());
        let linux = shards
            .iter()
            .position(|shard| shard.platform == ClaimPlatform::Linux)
            .unwrap();
        let mut mutant = shards.clone();
        mutant[linux].oracle_subject = CollectionOracleSubject::NativeSourceBuild;
        assert!(validate_collection_black_box_structure(&source, &builds, &mutant).is_err());
    }

    fn assert_structural_mutant_rejected(
        source: &CollectionSourceAuthority,
        builds: &[CollectionNativeBuildAuthority],
        shards: &[CollectionBlackBoxShard],
        mutate: impl FnOnce(&mut CollectionBlackBoxShard),
    ) {
        let mut mutant = shards.to_vec();
        mutate(&mut mutant[0]);
        assert!(validate_collection_black_box_structure(source, builds, &mutant).is_err());
    }

    fn fixture_native_builds(
        source: &CollectionSourceAuthority,
    ) -> Vec<CollectionNativeBuildAuthority> {
        [ClaimPlatform::MacOs, ClaimPlatform::Windows]
            .into_iter()
            .map(|platform| CollectionNativeBuildAuthority {
                platform,
                source_commit: Arc::from(NATIVE_SOURCE_COMMIT),
                stack_version: Arc::from("3.11.1"),
                resolver_lock_sha256: digest(
                    "119cff36de1117edfb6098fd9688f9dad843c716d874d02dce49ecdc0dcfb61a",
                ),
                ghc_version: Arc::from("9.8.2"),
                containers_version: Arc::from("0.6.8"),
                cabal_revision_sha256: digest(CABAL_REVISION_SHA256),
                oracle_executable_sha256: platform_digest(platform, "oracle executable"),
                build_record_sha256: platform_digest(platform, "build record"),
                source_authority_manifest_sha256: source.manifest,
            })
            .collect()
    }

    fn fixture_black_box_shards(
        source: &CollectionSourceAuthority,
    ) -> Vec<CollectionBlackBoxShard> {
        reviewed_collection_case_authorities(source)
            .unwrap()
            .into_iter()
            .flat_map(|case| {
                required_platforms()
                    .into_iter()
                    .map(move |platform| fixture_black_box_shard(case.clone(), platform))
            })
            .collect()
    }

    fn fixture_black_box_shard(
        case: CollectionCaseAuthority,
        platform: ClaimPlatform,
    ) -> CollectionBlackBoxShard {
        let linux = platform == ClaimPlatform::Linux;
        let stdout = fixture_digest(&format!("{} stdout", case.case_id));
        let stderr = fixture_digest(&format!("{} stderr", case.case_id));
        let status = fixture_digest(&format!("{} status", case.case_id));
        CollectionBlackBoxShard {
            platform,
            oracle_subject: if linux {
                CollectionOracleSubject::LinuxSignedReleaseResultOnly
            } else {
                CollectionOracleSubject::NativeSourceBuild
            },
            oracle_source_commit: Arc::from(if linux {
                LINUX_RELEASE_COMMIT
            } else {
                NATIVE_SOURCE_COMMIT
            }),
            oracle_executable_sha256: if linux {
                digest(LINUX_RELEASE_ASSET_SHA256)
            } else {
                platform_digest(platform, "oracle executable")
            },
            oracle_acquisition_receipt_sha256: linux
                .then(|| platform_digest(platform, "acquisition")),
            oracle_provider_attestation_sha256: linux
                .then(|| platform_digest(platform, "attestation")),
            provider_repository_id: 42,
            provider_run_id: 77,
            provider_run_attempt: 1,
            provider_artifact_id: platform_id(platform) + 100,
            provider_workflow_ref: Arc::from(
                "owner/repository/.github/workflows/nightly.yml@refs/heads/main",
            ),
            provider_event: Arc::from("workflow_dispatch"),
            provider_candidate_subject_sha256: fixture_digest("candidate subject"),
            oracle_build_record_sha256: (!linux).then(|| platform_digest(platform, "build record")),
            dependency_authority: if linux {
                CollectionDependencyAuthority::UnknownResultOnly
            } else {
                CollectionDependencyAuthority::ReportedVersionNoExactSource
            },
            bundle_sha256: case_platform_digest(&case, platform, "bundle"),
            oracle_observation_sha256: case_platform_digest(&case, platform, "oracle observation"),
            candidate_observation_sha256: case_platform_digest(
                &case,
                platform,
                "candidate observation",
            ),
            oracle_stdout_sha256: stdout,
            oracle_stderr_sha256: stderr,
            oracle_status_sha256: status,
            candidate_stdout_sha256: stdout,
            candidate_stderr_sha256: stderr,
            candidate_status_sha256: status,
            candidate_typed_result_sha256: case.expected_candidate_typed_result_sha256,
            candidate_comparator_trace_sha256: case.comparator_contract_sha256,
            oracle_completion: case.expected_completion,
            candidate_completion: case.expected_completion,
            candidate_source_commit: Arc::from("0123456789abcdef0123456789abcdef01234567"),
            candidate_executable_sha256: platform_digest(platform, "candidate executable"),
            case,
        }
    }

    fn platform_id(platform: ClaimPlatform) -> u64 {
        match platform {
            ClaimPlatform::Linux => 1,
            ClaimPlatform::MacOs => 2,
            ClaimPlatform::Windows => 3,
            ClaimPlatform::All => unreachable!(),
        }
    }

    fn platform_digest(platform: ClaimPlatform, field: &str) -> Digest {
        fixture_digest(&format!("{} {field}", platform_name(platform)))
    }

    fn case_platform_digest(
        case: &CollectionCaseAuthority,
        platform: ClaimPlatform,
        field: &str,
    ) -> Digest {
        fixture_digest(&format!(
            "{} {} {field}",
            case.case_id,
            platform_name(platform)
        ))
    }

    fn fixture_digest(label: &str) -> Digest {
        sha256_bytes(label.as_bytes())
    }

    fn retained_archive_entries(root: &Path) -> Vec<(String, Vec<u8>)> {
        [
            (
                "containers-0.6.8/LICENSE",
                "compat/oracle-sources/containers-0.6.8/LICENSE",
            ),
            (
                "containers-0.6.8/containers.cabal",
                "compat/oracle-sources/containers-0.6.8/containers.cabal",
            ),
            (
                "containers-0.6.8/src/Data/Map/Internal.hs",
                "compat/oracle-sources/containers-0.6.8/src/Data/Map/Internal.hs",
            ),
            (
                "containers-0.6.8/src/Data/Set/Internal.hs",
                "compat/oracle-sources/containers-0.6.8/src/Data/Set/Internal.hs",
            ),
        ]
        .into_iter()
        .map(|(archive, retained)| (archive.to_owned(), fs::read(root.join(retained)).unwrap()))
        .collect()
    }

    fn gzip_archive(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(u64::try_from(bytes.len()).unwrap());
            header.set_cksum();
            archive
                .append_data(&mut header, path, bytes.as_slice())
                .unwrap();
        }
        let encoder = archive.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    fn copy_authority_tree(source: &Path, target: &Path) {
        for relative in [
            SOURCE_MANIFEST_RELATIVE,
            "compat/oracle-sources/hell-8e952cf9/stack.yaml",
            "compat/oracle-sources/hell-8e952cf9/stack.yaml.lock",
            "compat/oracle-sources/containers-0.6.8/containers-0.6.8.tar.gz.base64",
            "compat/oracle-sources/containers-0.6.8/containers.cabal",
            "compat/oracle-sources/containers-0.6.8/LICENSE",
            "compat/oracle-sources/containers-0.6.8/src/Data/Map/Internal.hs",
            "compat/oracle-sources/containers-0.6.8/src/Data/Set/Internal.hs",
            "crates/hell-testkit/src/reviewed_set.rs",
        ] {
            let destination = target.join(relative);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(source.join(relative), destination).unwrap();
        }
    }
}
