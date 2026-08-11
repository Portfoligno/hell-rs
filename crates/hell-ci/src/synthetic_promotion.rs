//! Domain-separated synthetic promotion authority used only for integration testing.
//!
//! These records exercise shard/provider completeness without being admissible as
//! production evidence. Production promotion readers do not recognize this domain.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use hell_testkit::sha256_bytes;

const DOMAIN: &str = "hell-rs-synthetic-promotion-authority-v1";
const TEST_KEYSET_ID: &str = "hell-rs-synthetic-test-keyset-v1";
const FIXTURE_ID: &str = "int-plus-pure-runtime-three-platform-v1";
const PLATFORMS: [&str; 3] = ["linux-amd64", "macos-arm64", "windows-amd64"];
const CASE_SCOPE: &str = "int-plus-boundary-positive-value:Int.plus:pure-runtime";
const REVIEWER: &str = "synthetic-reviewer:fixture-reviewer";
const FIRST_SCHEME: &str = "local-hmac-sha256-a-v1";
const SECOND_SCHEME: &str = "local-hmac-sha256-b-v1";
const FIRST_KEY: [u8; 32] = *b"synthetic-review-first-key-v1!!!";
const SECOND_KEY: [u8; 32] = *b"synthetic-review-second-key-v1!!";

mod sealed {
    pub trait AuthorityDomain {}
}

trait AuthorityDomain: sealed::AuthorityDomain {
    fn fixture_id(&self) -> &str;
    fn root_digest(&self) -> &str;
}

pub(crate) struct SyntheticAuthority {
    fixture_id: String,
    root_digest: String,
}

impl sealed::AuthorityDomain for SyntheticAuthority {}

impl AuthorityDomain for SyntheticAuthority {
    fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    fn root_digest(&self) -> &str {
        &self.root_digest
    }
}

impl SyntheticAuthority {
    pub(crate) fn derive(candidate: &str, epoch: &str, catalog: &str) -> Self {
        let policy = authority_policy_digest();
        let identity = format!("{DOMAIN}\0{FIXTURE_ID}\0{policy}\0{candidate}\0{epoch}\0{catalog}");
        Self {
            fixture_id: FIXTURE_ID.to_owned(),
            root_digest: sha256_bytes(identity.as_bytes()).hex(),
        }
    }

    pub(crate) const fn domain() -> &'static str {
        DOMAIN
    }

    pub(crate) fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    pub(crate) fn root_digest(&self) -> &str {
        &self.root_digest
    }
}

fn authority_policy_digest() -> String {
    let platforms = PLATFORMS.join(",");
    let first_key = sha256_bytes(&FIRST_KEY).hex();
    let second_key = sha256_bytes(&SECOND_KEY).hex();
    sha256_bytes(
        format!(
            "{DOMAIN}\0{FIXTURE_ID}\0{platforms}\0{CASE_SCOPE}\0case-count=1\0{REVIEWER}\0{FIRST_SCHEME}:{first_key}\0{SECOND_SCHEME}:{second_key}"
        )
        .as_bytes(),
    )
    .hex()
}

fn build_fixture(root: &Path, candidate: &str, epoch: &str, catalog: &str) -> Result<(), String> {
    validate_authority_identity(candidate, epoch, catalog)?;
    let authority = SyntheticAuthority::derive(candidate, epoch, catalog);
    if root.exists() {
        return Err("synthetic fixture output already exists".to_owned());
    }
    let shards = root.join("shards");
    fs::create_dir_all(&shards)
        .map_err(|error| format!("cannot create synthetic fixture shards: {error}"))?;
    let mut digests = Vec::new();
    for (index, platform) in PLATFORMS.into_iter().enumerate() {
        let document = shard_document(
            &authority,
            platform,
            index as u64 + 1,
            candidate,
            epoch,
            catalog,
        );
        let path = shards.join(format!("{platform}.toml"));
        write_new(&path, document.as_bytes())?;
        digests.push((platform, sha256_bytes(document.as_bytes()).hex()));
    }
    let finalized_path = crate::assurance::build_synthetic_finalized_claim_authority(
        root, candidate, epoch, &digests,
    )?;
    let finalized_sha256 = sha256_bytes(&read_regular(&finalized_path)?).hex();
    let published_path = crate::custody_ops::build_synthetic_published_state_authority(
        root,
        &authority,
        candidate,
        epoch,
        &finalized_sha256,
    )?;
    let published_sha256 = sha256_bytes(&read_regular(&published_path)?).hex();
    let review_payload_sha256 =
        synthetic_review_payload_digest(&digests, &finalized_sha256, &published_sha256);
    let review =
        synthetic_authentication_document(&authority, "authority-review", &review_payload_sha256)?;
    write_new(&root.join("review.toml"), review.as_bytes())?;
    let review_sha256 = sha256_bytes(review.as_bytes()).hex();
    let asymmetric_reviews_sha256 =
        write_synthetic_asymmetric_reviews(root, candidate, epoch, &review_payload_sha256)?;
    let manifest = manifest_document(
        &authority,
        &ManifestFacts {
            candidate,
            epoch,
            catalog,
            digests: &digests,
            review_payload_sha256: &review_payload_sha256,
            review_sha256: &review_sha256,
            asymmetric_reviews_sha256: &asymmetric_reviews_sha256,
            finalized_sha256: &finalized_sha256,
            published_sha256: &published_sha256,
        },
    );
    write_new(&root.join("manifest.toml"), manifest.as_bytes())?;
    verify_fixture(root, candidate, epoch, catalog)
}

fn shard_document(
    authority: &impl AuthorityDomain,
    platform: &str,
    provider_object_version: u64,
    candidate: &str,
    epoch: &str,
    catalog: &str,
) -> String {
    let source_tree = sha256_bytes(
        format!(
            "{DOMAIN}\0{}\0{}\0source\0{candidate}",
            authority.fixture_id(),
            authority.root_digest()
        )
        .as_bytes(),
    )
    .hex();
    let provider_archive = sha256_bytes(
        format!(
            "{DOMAIN}\0{}\0{}\0provider\0{platform}\0{candidate}\0{epoch}",
            authority.fixture_id(),
            authority.root_digest()
        )
        .as_bytes(),
    )
    .hex();
    let statement = shard_statement(
        authority,
        &ShardFacts {
            platform,
            candidate,
            epoch,
            catalog,
            provider_object_version,
            source_tree: &source_tree,
            provider_archive: &provider_archive,
        },
    );
    format!(
        "{statement}statement_sha256 = \"{}\"\n",
        sha256_bytes(statement.as_bytes()).hex()
    )
}

struct ShardFacts<'a> {
    platform: &'a str,
    candidate: &'a str,
    epoch: &'a str,
    catalog: &'a str,
    provider_object_version: u64,
    source_tree: &'a str,
    provider_archive: &'a str,
}

fn shard_statement(authority: &impl AuthorityDomain, facts: &ShardFacts<'_>) -> String {
    let ShardFacts {
        platform,
        candidate,
        epoch,
        catalog,
        provider_object_version,
        source_tree,
        provider_archive,
    } = facts;
    format!(
        "schema_version = 1\ndomain = \"{DOMAIN}\"\nfixture_id = \"{}\"\nroot_digest = \"{}\"\nauthority_policy_sha256 = \"{}\"\ntest_keyset_id = \"{TEST_KEYSET_ID}\"\ncandidate_source_commit = \"{candidate}\"\nassurance_epoch_sha256 = \"{epoch}\"\ncatalog_sha256 = \"{catalog}\"\ncase_scope = \"{CASE_SCOPE}\"\nplatform = \"{platform}\"\nsource_tree_sha256 = \"{source_tree}\"\nprovider = \"synthetic-fake-provider-{platform}\"\nprovider_object_version = {provider_object_version}\nprovider_archive_sha256 = \"{provider_archive}\"\nprovider_available = true\ncase_count = 1\n",
        authority.fixture_id(),
        authority.root_digest(),
        authority_policy_digest(),
    )
}

struct ManifestFacts<'a> {
    candidate: &'a str,
    epoch: &'a str,
    catalog: &'a str,
    digests: &'a [(&'a str, String)],
    review_payload_sha256: &'a str,
    review_sha256: &'a str,
    asymmetric_reviews_sha256: &'a str,
    finalized_sha256: &'a str,
    published_sha256: &'a str,
}

fn manifest_document(authority: &impl AuthorityDomain, facts: &ManifestFacts<'_>) -> String {
    let shard_set = facts
        .digests
        .iter()
        .map(|(platform, digest)| format!("{platform}:{digest}"))
        .collect::<Vec<_>>()
        .join("\n");
    let set_digest = sha256_bytes(shard_set.as_bytes()).hex();
    let entries = facts
        .digests
        .iter()
        .map(|(platform, digest)| format!("\"{platform}:{digest}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "schema_version = 1\ndomain = \"{DOMAIN}\"\nfixture_id = \"{}\"\nroot_digest = \"{}\"\nauthority_policy_sha256 = \"{}\"\ntest_keyset_id = \"{TEST_KEYSET_ID}\"\ncandidate_source_commit = \"{candidate}\"\nassurance_epoch_sha256 = \"{epoch}\"\ncatalog_sha256 = \"{catalog}\"\ncase_scope = \"{CASE_SCOPE}\"\nshard_count = 3\nshards = [{entries}]\nshard_set_sha256 = \"{set_digest}\"\nreview_payload_sha256 = \"{review_payload_sha256}\"\nreview_sha256 = \"{review_sha256}\"\nasymmetric_reviews_path = \"asymmetric-reviews.toml\"\nasymmetric_reviews_sha256 = \"{asymmetric_reviews_sha256}\"\nfinalized_claim_path = \"synthetic-finalized-claim/finalized.json\"\nfinalized_claim_sha256 = \"{finalized_sha256}\"\npublished_state_path = \"synthetic-published-state/synthetic-public-authority.toml\"\npublished_state_sha256 = \"{published_sha256}\"\nstate = \"synthetic-complete-never-production-admissible\"\n",
        authority.fixture_id(),
        authority.root_digest(),
        authority_policy_digest(),
        candidate = facts.candidate,
        epoch = facts.epoch,
        catalog = facts.catalog,
        review_payload_sha256 = facts.review_payload_sha256,
        review_sha256 = facts.review_sha256,
        asymmetric_reviews_sha256 = facts.asymmetric_reviews_sha256,
        finalized_sha256 = facts.finalized_sha256,
        published_sha256 = facts.published_sha256,
    )
}

fn verify_fixture(root: &Path, candidate: &str, epoch: &str, catalog: &str) -> Result<(), String> {
    validate_authority_identity(candidate, epoch, catalog)?;
    let authority = SyntheticAuthority::derive(candidate, epoch, catalog);
    let manifest = read_assignments(&root.join("manifest.toml"))?;
    require_exact_keys(
        &manifest,
        &[
            "assurance_epoch_sha256",
            "asymmetric_reviews_path",
            "asymmetric_reviews_sha256",
            "authority_policy_sha256",
            "candidate_source_commit",
            "case_scope",
            "catalog_sha256",
            "domain",
            "finalized_claim_path",
            "finalized_claim_sha256",
            "fixture_id",
            "published_state_path",
            "published_state_sha256",
            "root_digest",
            "review_payload_sha256",
            "review_sha256",
            "schema_version",
            "shard_count",
            "shard_set_sha256",
            "shards",
            "state",
            "test_keyset_id",
        ],
    )?;
    verify_common_identity(&manifest, &authority, candidate, epoch, catalog)?;
    if integer(&manifest, "shard_count")? != 3
        || quoted(&manifest, "state")? != "synthetic-complete-never-production-admissible"
    {
        return Err("synthetic manifest is incomplete or production-admissible".to_owned());
    }
    let mut observed = Vec::new();
    let mut platforms = BTreeSet::new();
    for platform in PLATFORMS {
        let path = root.join("shards").join(format!("{platform}.toml"));
        let bytes = read_regular(&path)?;
        let shard = crate::strict_toml::assignments(
            std::str::from_utf8(&bytes).map_err(|_| "synthetic shard is not UTF-8".to_owned())?,
        )?;
        verify_shard(&shard, &authority, platform, candidate, epoch, catalog)?;
        platforms.insert(quoted(&shard, "platform")?.to_owned());
        observed.push((platform, sha256_bytes(&bytes).hex()));
    }
    verify_manifest_shard_set(&manifest, &observed)?;
    verify_synthetic_authority_components(
        root, &manifest, &authority, candidate, epoch, &observed,
    )?;
    if platforms != PLATFORMS.into_iter().map(str::to_owned).collect() {
        return Err("synthetic fixture platform set is incomplete".to_owned());
    }
    reject_extra_shards(&root.join("shards"))
}

fn verify_synthetic_authority_components(
    root: &Path,
    manifest: &BTreeMap<String, String>,
    authority: &SyntheticAuthority,
    candidate: &str,
    epoch: &str,
    observed: &[(&str, String)],
) -> Result<(), String> {
    if quoted(manifest, "finalized_claim_path")? != "synthetic-finalized-claim/finalized.json"
        || quoted(manifest, "published_state_path")?
            != "synthetic-published-state/synthetic-public-authority.toml"
    {
        return Err("synthetic authority component path changed".to_owned());
    }
    let finalized_path = root.join(quoted(manifest, "finalized_claim_path")?);
    let finalized_sha256 = sha256_bytes(&read_regular(&finalized_path)?).hex();
    if quoted(manifest, "finalized_claim_sha256")? != finalized_sha256 {
        return Err("synthetic finalized claim digest changed".to_owned());
    }
    crate::assurance::verify_synthetic_finalized_claim_authority(
        &finalized_path,
        candidate,
        epoch,
        observed,
    )?;
    if crate::assurance::verify_with_production_claim_coverage_parser(
        &finalized_path,
        candidate,
        epoch,
    )
    .is_ok()
    {
        return Err("synthetic claim authority entered the production parser".to_owned());
    }
    let published_path = root.join(quoted(manifest, "published_state_path")?);
    let published_sha256 = sha256_bytes(&read_regular(&published_path)?).hex();
    if quoted(manifest, "published_state_sha256")? != published_sha256 {
        return Err("synthetic published state digest changed".to_owned());
    }
    crate::custody_ops::verify_synthetic_published_state_authority(
        &published_path,
        authority,
        candidate,
        epoch,
        &finalized_sha256,
    )?;
    let review_payload_sha256 =
        synthetic_review_payload_digest(observed, &finalized_sha256, &published_sha256);
    if quoted(manifest, "review_payload_sha256")? != review_payload_sha256 {
        return Err("synthetic review payload does not bind all authority components".to_owned());
    }
    let review_bytes = read_regular(&root.join("review.toml"))?;
    if quoted(manifest, "review_sha256")? != sha256_bytes(&review_bytes).hex() {
        return Err("synthetic review digest changed".to_owned());
    }
    let review_text = std::str::from_utf8(&review_bytes)
        .map_err(|_| "synthetic review is not UTF-8".to_owned())?;
    let review = crate::strict_toml::assignments(review_text)?;
    verify_synthetic_authentication(
        authority,
        "authority-review",
        &review,
        &review_payload_sha256,
    )?;
    verify_synthetic_asymmetric_reviews(root, candidate, epoch, &review_payload_sha256, manifest)?;
    Ok(())
}

fn write_synthetic_asymmetric_reviews(
    root: &Path,
    candidate: &str,
    epoch: &str,
    payload_sha256: &str,
) -> Result<String, String> {
    let mut records = Vec::new();
    for subject in ["synthetic-reviewer-a", "synthetic-reviewer-b"] {
        let directory = root.join(format!("asymmetric-{subject}"));
        let (review, allowed) =
            crate::assurance::tests::signed_synthetic_asymmetric_review_fixture(
                &directory,
                candidate,
                epoch,
                payload_sha256,
                subject,
            )?;
        crate::assurance::tests::verify_synthetic_asymmetric_review_fixture(
            &review,
            &allowed,
            candidate,
            epoch,
            payload_sha256,
        )?;
        records.push((subject, sha256_bytes(&read_regular(&review)?).hex()));
    }
    let document = format!(
        "schema_version = 1\ndomain = \"{DOMAIN}\"\npayload_sha256 = \"{payload_sha256}\"\nfirst_reviewer = \"{}\"\nfirst_review_sha256 = \"{}\"\nsecond_reviewer = \"{}\"\nsecond_review_sha256 = \"{}\"\ndistinct_subjects = 2\nstate = \"synthetic-two-independent-asymmetric-reviews\"\n",
        records[0].0, records[0].1, records[1].0, records[1].1,
    );
    let path = root.join("asymmetric-reviews.toml");
    write_new(&path, document.as_bytes())?;
    Ok(sha256_bytes(document.as_bytes()).hex())
}

fn verify_synthetic_asymmetric_reviews(
    root: &Path,
    candidate: &str,
    epoch: &str,
    payload_sha256: &str,
    manifest: &BTreeMap<String, String>,
) -> Result<(), String> {
    if quoted(manifest, "asymmetric_reviews_path")? != "asymmetric-reviews.toml" {
        return Err("synthetic asymmetric review path changed".to_owned());
    }
    let path = root.join("asymmetric-reviews.toml");
    let document = read_assignments(&path)?;
    require_exact_keys(
        &document,
        &[
            "distinct_subjects",
            "domain",
            "first_review_sha256",
            "first_reviewer",
            "payload_sha256",
            "schema_version",
            "second_review_sha256",
            "second_reviewer",
            "state",
        ],
    )?;
    if quoted(manifest, "asymmetric_reviews_sha256")? != sha256_bytes(&read_regular(&path)?).hex()
        || integer(&document, "schema_version")? != 1
        || quoted(&document, "domain")? != DOMAIN
        || quoted(&document, "payload_sha256")? != payload_sha256
        || integer(&document, "distinct_subjects")? != 2
        || quoted(&document, "first_reviewer")? != "synthetic-reviewer-a"
        || quoted(&document, "second_reviewer")? != "synthetic-reviewer-b"
        || quoted(&document, "state")? != "synthetic-two-independent-asymmetric-reviews"
    {
        return Err("synthetic asymmetric review authority changed".to_owned());
    }
    for (prefix, subject) in [
        ("first", "synthetic-reviewer-a"),
        ("second", "synthetic-reviewer-b"),
    ] {
        let directory = root.join(format!("asymmetric-{subject}"));
        let review = directory.join("review.dsse.json");
        let allowed = directory.join("reviewer.allowed_signers");
        if quoted(&document, &format!("{prefix}_review_sha256"))?
            != sha256_bytes(&read_regular(&review)?).hex()
        {
            return Err("synthetic asymmetric review digest changed".to_owned());
        }
        crate::assurance::tests::verify_synthetic_asymmetric_review_fixture(
            &review,
            &allowed,
            candidate,
            epoch,
            payload_sha256,
        )?;
        let trust_roots = directory.join("trust-roots.toml");
        fs::write(
            &trust_roots,
            include_bytes!("../../../compat/trust-roots.toml"),
        )
        .map_err(|error| format!("cannot stage production trust roots: {error}"))?;
        let production_result = crate::assurance::tests::verify_synthetic_asymmetric_review_fixture(
            &review,
            &allowed,
            candidate,
            epoch,
            payload_sha256,
        );
        fs::remove_file(&trust_roots)
            .map_err(|error| format!("cannot remove production trust roots: {error}"))?;
        if production_result.is_ok() {
            return Err("synthetic SSH review entered production dual-signature trust".to_owned());
        }
    }
    Ok(())
}

fn verify_shard(
    shard: &BTreeMap<String, String>,
    authority: &impl AuthorityDomain,
    platform: &str,
    candidate: &str,
    epoch: &str,
    catalog: &str,
) -> Result<(), String> {
    require_exact_keys(
        shard,
        &[
            "assurance_epoch_sha256",
            "authority_policy_sha256",
            "candidate_source_commit",
            "case_count",
            "case_scope",
            "catalog_sha256",
            "domain",
            "fixture_id",
            "platform",
            "provider",
            "provider_archive_sha256",
            "provider_available",
            "provider_object_version",
            "root_digest",
            "schema_version",
            "source_tree_sha256",
            "statement_sha256",
            "test_keyset_id",
        ],
    )?;
    verify_common_identity(shard, authority, candidate, epoch, catalog)?;
    if quoted(shard, "platform")? != platform
        || quoted(shard, "provider")? != format!("synthetic-fake-provider-{platform}")
        || integer(shard, "provider_object_version")? == 0
        || quoted(shard, "case_scope")? != CASE_SCOPE
        || integer(shard, "case_count")? != 1
        || shard.get("provider_available").map(String::as_str) != Some("true")
    {
        return Err("synthetic shard provider or completeness facts changed".to_owned());
    }
    require_digest(quoted(shard, "source_tree_sha256")?)?;
    require_digest(quoted(shard, "provider_archive_sha256")?)?;
    let statement = shard_statement(
        authority,
        &ShardFacts {
            platform,
            candidate,
            epoch,
            catalog,
            provider_object_version: integer(shard, "provider_object_version")?,
            source_tree: quoted(shard, "source_tree_sha256")?,
            provider_archive: quoted(shard, "provider_archive_sha256")?,
        },
    );
    if quoted(shard, "statement_sha256")? != sha256_bytes(statement.as_bytes()).hex() {
        return Err("synthetic shard statement digest changed".to_owned());
    }
    Ok(())
}

fn verify_common_identity(
    document: &BTreeMap<String, String>,
    authority: &impl AuthorityDomain,
    candidate: &str,
    epoch: &str,
    catalog: &str,
) -> Result<(), String> {
    if integer(document, "schema_version")? != 1
        || quoted(document, "domain")? != DOMAIN
        || quoted(document, "fixture_id")? != authority.fixture_id()
        || quoted(document, "root_digest")? != authority.root_digest()
        || quoted(document, "authority_policy_sha256")? != authority_policy_digest()
        || quoted(document, "test_keyset_id")? != TEST_KEYSET_ID
        || quoted(document, "case_scope")? != CASE_SCOPE
        || quoted(document, "candidate_source_commit")? != candidate
        || quoted(document, "assurance_epoch_sha256")? != epoch
        || quoted(document, "catalog_sha256")? != catalog
    {
        return Err("synthetic authority identity changed".to_owned());
    }
    Ok(())
}

struct SyntheticReviewBackend {
    first_key: [u8; 32],
    second_key: [u8; 32],
}

pub(crate) fn synthetic_authentication_document(
    authority: &SyntheticAuthority,
    purpose: &str,
    payload_sha256: &str,
) -> Result<String, String> {
    SyntheticReviewBackend::fixture().authenticate(authority, purpose, payload_sha256)
}

pub(crate) fn verify_synthetic_authentication_text(
    authority: &SyntheticAuthority,
    purpose: &str,
    document: &str,
    payload_sha256: &str,
) -> Result<(), String> {
    let parsed = crate::strict_toml::assignments(document)?;
    verify_synthetic_authentication(authority, purpose, &parsed, payload_sha256)
}

fn verify_synthetic_authentication(
    authority: &SyntheticAuthority,
    purpose: &str,
    document: &BTreeMap<String, String>,
    payload_sha256: &str,
) -> Result<(), String> {
    SyntheticReviewBackend::fixture().verify(authority, purpose, document, payload_sha256)
}

impl SyntheticReviewBackend {
    fn fixture() -> Self {
        Self {
            first_key: FIRST_KEY,
            second_key: SECOND_KEY,
        }
    }

    fn authenticate(
        &self,
        authority: &impl AuthorityDomain,
        purpose: &str,
        payload_sha256: &str,
    ) -> Result<String, String> {
        require_digest(payload_sha256)?;
        let first = synthetic_review_signature(
            &self.first_key,
            FIRST_SCHEME,
            authority,
            purpose,
            payload_sha256,
        );
        let second = synthetic_review_signature(
            &self.second_key,
            SECOND_SCHEME,
            authority,
            purpose,
            payload_sha256,
        );
        Ok(format!(
            "schema_version = 1\ndomain = \"{DOMAIN}\"\nfixture_id = \"{}\"\nroot_digest = \"{}\"\nauthority_policy_sha256 = \"{}\"\npurpose = \"{purpose}\"\npayload_sha256 = \"{payload_sha256}\"\nfirst_scheme = \"{FIRST_SCHEME}\"\nfirst_reviewer = \"{REVIEWER}\"\nfirst_signature = \"{first}\"\nsecond_scheme = \"{SECOND_SCHEME}\"\nsecond_reviewer = \"{REVIEWER}\"\nsecond_signature = \"{second}\"\ndistinct_subjects = 1\nstate = \"synthetic-dual-authentication-never-production-admissible\"\n",
            authority.fixture_id(),
            authority.root_digest(),
            authority_policy_digest(),
        ))
    }

    fn verify(
        &self,
        authority: &impl AuthorityDomain,
        purpose: &str,
        document: &BTreeMap<String, String>,
        payload_sha256: &str,
    ) -> Result<(), String> {
        require_exact_keys(
            document,
            &[
                "distinct_subjects",
                "domain",
                "authority_policy_sha256",
                "first_reviewer",
                "first_scheme",
                "first_signature",
                "fixture_id",
                "payload_sha256",
                "purpose",
                "root_digest",
                "schema_version",
                "second_reviewer",
                "second_scheme",
                "second_signature",
                "state",
            ],
        )?;
        verify_common_review_identity(document, authority, purpose, payload_sha256)?;
        let schemes = [
            ("first", &self.first_key, FIRST_SCHEME, REVIEWER),
            ("second", &self.second_key, SECOND_SCHEME, REVIEWER),
        ];
        for (prefix, key, scheme, reviewer) in schemes {
            if quoted(document, &format!("{prefix}_scheme"))? != scheme
                || quoted(document, &format!("{prefix}_reviewer"))? != reviewer
                || quoted(document, &format!("{prefix}_signature"))?
                    != synthetic_review_signature(key, scheme, authority, purpose, payload_sha256)
            {
                return Err("synthetic dual review signature changed".to_owned());
            }
        }
        Ok(())
    }
}

fn verify_common_review_identity(
    document: &BTreeMap<String, String>,
    authority: &impl AuthorityDomain,
    purpose: &str,
    payload_sha256: &str,
) -> Result<(), String> {
    if integer(document, "schema_version")? != 1
        || quoted(document, "domain")? != DOMAIN
        || quoted(document, "fixture_id")? != authority.fixture_id()
        || quoted(document, "root_digest")? != authority.root_digest()
        || quoted(document, "authority_policy_sha256")? != authority_policy_digest()
        || quoted(document, "payload_sha256")? != payload_sha256
        || quoted(document, "purpose")? != purpose
        || integer(document, "distinct_subjects")? != 1
        || quoted(document, "state")? != "synthetic-dual-authentication-never-production-admissible"
    {
        return Err("synthetic dual review identity changed".to_owned());
    }
    Ok(())
}

fn synthetic_review_signature(
    key: &[u8; 32],
    scheme: &str,
    authority: &impl AuthorityDomain,
    purpose: &str,
    payload_sha256: &str,
) -> String {
    let message = format!(
        "{DOMAIN}\0{}\0{}\0{purpose}\0{scheme}\0{payload_sha256}",
        authority.fixture_id(),
        authority.root_digest()
    );
    hmac_sha256(key, message.as_bytes())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(inner_pad.len() + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(message);
    let inner_digest = sha256_bytes(&inner);
    let mut outer = Vec::with_capacity(outer_pad.len() + 32);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(&inner_digest.0);
    sha256_bytes(&outer).hex()
}

fn verify_manifest_shard_set(
    manifest: &BTreeMap<String, String>,
    observed: &[(&str, String)],
) -> Result<(), String> {
    let expected_entries = observed
        .iter()
        .map(|(platform, digest)| format!("{platform}:{digest}"))
        .collect::<Vec<_>>();
    if quoted_array(manifest, "shards")? != expected_entries {
        return Err("synthetic manifest shard sequence changed".to_owned());
    }
    let joined = expected_entries.join("\n");
    if quoted(manifest, "shard_set_sha256")? != sha256_bytes(joined.as_bytes()).hex() {
        return Err("synthetic manifest shard-set digest changed".to_owned());
    }
    Ok(())
}

fn shard_set_digest(observed: &[(&str, String)]) -> String {
    let joined = observed
        .iter()
        .map(|(platform, digest)| format!("{platform}:{digest}"))
        .collect::<Vec<_>>()
        .join("\n");
    sha256_bytes(joined.as_bytes()).hex()
}

fn synthetic_review_payload_digest(
    observed: &[(&str, String)],
    finalized_sha256: &str,
    published_sha256: &str,
) -> String {
    sha256_bytes(
        format!(
            "{DOMAIN}\0reviewed-authority\0{}\0{finalized_sha256}\0{published_sha256}",
            shard_set_digest(observed)
        )
        .as_bytes(),
    )
    .hex()
}

fn reject_extra_shards(root: &Path) -> Result<(), String> {
    let expected = PLATFORMS
        .into_iter()
        .map(|platform| format!("{platform}.toml"))
        .collect::<BTreeSet<_>>();
    let observed = fs::read_dir(root)
        .map_err(|error| format!("cannot read synthetic shards: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot enumerate synthetic shards: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "synthetic shard filename is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed != expected {
        return Err("synthetic shard directory is not the exact three-platform set".to_owned());
    }
    Ok(())
}

fn validate_authority_identity(candidate: &str, epoch: &str, catalog: &str) -> Result<(), String> {
    if candidate.len() != 40
        || !candidate
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("synthetic candidate is not a Git SHA".to_owned());
    }
    require_digest(epoch)?;
    require_digest(catalog)
}

fn require_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("synthetic authority digest is invalid".to_owned());
    }
    Ok(())
}

fn read_assignments(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let bytes = read_regular(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "synthetic authority record is not UTF-8".to_owned())?;
    crate::strict_toml::assignments(text)
}

fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect synthetic authority record: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("synthetic authority record is not a regular file".to_owned());
    }
    fs::read(path).map_err(|error| format!("cannot read synthetic authority record: {error}"))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    let mut file = options
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create synthetic authority record: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot retain synthetic authority record: {error}"))
}

fn require_exact_keys(
    document: &BTreeMap<String, String>,
    expected: &[&str],
) -> Result<(), String> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let observed = document.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed != expected {
        return Err("synthetic authority record keys changed".to_owned());
    }
    Ok(())
}

fn quoted<'a>(document: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    document
        .get(key)
        .and_then(|value| value.strip_prefix('"')?.strip_suffix('"'))
        .ok_or_else(|| format!("synthetic authority field {key} is not a quoted string"))
}

fn integer(document: &BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    document
        .get(key)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("synthetic authority field {key} is not an integer"))
}

fn quoted_array(document: &BTreeMap<String, String>, key: &str) -> Result<Vec<String>, String> {
    let value = document
        .get(key)
        .and_then(|value| value.strip_prefix('[')?.strip_suffix(']'))
        .ok_or_else(|| format!("synthetic authority field {key} is not an array"))?;
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|item| {
            item.trim()
                .strip_prefix('"')
                .and_then(|item| item.strip_suffix('"'))
                .map(str::to_owned)
                .ok_or_else(|| "synthetic authority shard entry is not quoted".to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quoted_json_field(document: &str, field: &str) -> String {
        for separator in [": \"", ":\""] {
            let marker = format!("\"{field}\"{separator}");
            if let Some((_, remainder)) = document.split_once(&marker) {
                return remainder.split_once('"').unwrap().0.to_owned();
            }
        }
        panic!("missing JSON field {field}")
    }

    fn json_number_field(document: &str, field: &str) -> u64 {
        for separator in [": ", ":"] {
            let marker = format!("\"{field}\"{separator}");
            if let Some((_, remainder)) = document.split_once(&marker) {
                let end = remainder.find([',', '\n', '}']).unwrap();
                return remainder[..end].parse().unwrap();
            }
        }
        panic!("missing numeric JSON field {field}")
    }

    fn rebind_selection_receipt(root: &Path) {
        let selection = root.join("synthetic-provider-selection/selection.json");
        let receipt = root.join("synthetic-published-state/public-report-publication.json");
        let wrapper = root.join("synthetic-published-state/synthetic-public-authority.toml");
        let selection_sha256 = sha256_bytes(&fs::read(&selection).unwrap()).hex();
        let mut receipt_text = fs::read_to_string(&receipt).unwrap();
        let old_selection = quoted_json_field(&receipt_text, "sourceSelectionSha256");
        receipt_text = receipt_text.replace(&old_selection, &selection_sha256);
        fs::write(&receipt, receipt_text).unwrap();
        let receipt_sha256 = sha256_bytes(&fs::read(&receipt).unwrap()).hex();
        let mut wrapper_text = fs::read_to_string(&wrapper).unwrap();
        let old_receipt = quoted(
            &crate::strict_toml::assignments(&wrapper_text).unwrap(),
            "receipt_sha256",
        )
        .unwrap()
        .to_owned();
        wrapper_text = wrapper_text
            .replace(&old_selection, &selection_sha256)
            .replace(&old_receipt, &receipt_sha256);
        fs::write(wrapper, wrapper_text).unwrap();
    }

    fn rebind_receipt_wrapper(root: &Path) {
        let receipt = root.join("synthetic-published-state/public-report-publication.json");
        let wrapper = root.join("synthetic-published-state/synthetic-public-authority.toml");
        let mut wrapper_text = fs::read_to_string(&wrapper).unwrap();
        wrapper_text = replace_toml_string_field(
            &wrapper_text,
            "receipt_sha256",
            &sha256_bytes(&fs::read(receipt).unwrap()).hex(),
        );
        fs::write(wrapper, wrapper_text).unwrap();
    }

    fn replace_json_string_field(document: &str, field: &str, value: &str) -> String {
        let old = quoted_json_field(document, field);
        document.replacen(
            &format!("\"{field}\": \"{old}\""),
            &format!("\"{field}\": \"{value}\""),
            1,
        )
    }

    fn replace_json_number_field(document: &str, field: &str, value: u64) -> String {
        for separator in [": ", ":"] {
            let marker = format!("\"{field}\"{separator}");
            if let Some((prefix, remainder)) = document.split_once(&marker) {
                let end = remainder.find([',', '\n', '}']).unwrap();
                return format!("{prefix}{marker}{value}{}", &remainder[end..]);
            }
        }
        panic!("missing numeric JSON field {field}")
    }

    fn replace_toml_string_field(document: &str, field: &str, value: &str) -> String {
        let fields = crate::strict_toml::assignments(document).unwrap();
        let old = quoted(&fields, field).unwrap();
        document.replacen(
            &format!("{field} = \"{old}\""),
            &format!("{field} = \"{value}\""),
            1,
        )
    }

    fn rebind_public_packet_receipt(
        root: &Path,
        authority: &SyntheticAuthority,
        observed_at: &str,
    ) {
        let publication = root.join("synthetic-published-state");
        let wrapper = publication.join("synthetic-public-authority.toml");
        let wrapper_text = fs::read_to_string(&wrapper).unwrap();
        let wrapper_fields = crate::strict_toml::assignments(&wrapper_text).unwrap();
        let finalized = quoted(&wrapper_fields, "finalized_claim_sha256").unwrap();
        let file_digest =
            |name: &str| sha256_bytes(&fs::read(publication.join(name)).unwrap()).hex();
        let packet = format!(
            "schema_version = 1\ndomain = \"{DOMAIN}\"\nfixture_id = \"{}\"\nroot_digest = \"{}\"\nfinalized_claim_sha256 = \"{finalized}\"\nrecord_sha256 = \"{}\"\nreport_sha256 = \"{}\"\ndivergences_sha256 = \"{}\"\nrelease_sha256 = \"{}\"\n",
            authority.fixture_id(),
            authority.root_digest(),
            file_digest("promotion-transition.json"),
            file_digest("compatibility-report.md"),
            file_digest("accepted-divergences.json"),
            file_digest("public-release-statement.json"),
        );
        let packet_path = publication.join("promotion-transition-packet.json");
        fs::write(&packet_path, packet).unwrap();
        let packet_sha256 = file_digest("promotion-transition-packet.json");
        fs::write(
            publication.join("promotion-transition.dsse.json"),
            synthetic_authentication_document(authority, "public-transition", &packet_sha256)
                .unwrap(),
        )
        .unwrap();
        let receipt = publication.join("public-report-publication.json");
        let mut receipt_text = fs::read_to_string(&receipt).unwrap();
        let record_text =
            fs::read_to_string(publication.join("promotion-transition.json")).unwrap();
        for (field, value) in [
            ("observedAt", observed_at.to_owned()),
            (
                "candidateCommit",
                quoted_json_field(&record_text, "candidateCommit"),
            ),
            (
                "assuranceEpochSha256",
                quoted_json_field(&record_text, "assuranceEpochSha256"),
            ),
            ("recordSha256", file_digest("promotion-transition.json")),
            ("packetSha256", packet_sha256),
            ("dsseSha256", file_digest("promotion-transition.dsse.json")),
            (
                "compatibilityReportSha256",
                file_digest("compatibility-report.md"),
            ),
            (
                "acceptedDivergencesSha256",
                file_digest("accepted-divergences.json"),
            ),
            (
                "releaseStatementSha256",
                file_digest("public-release-statement.json"),
            ),
        ] {
            receipt_text = replace_json_string_field(&receipt_text, field, &value);
        }
        fs::write(&receipt, receipt_text).unwrap();
        let mut wrapper_text = wrapper_text;
        for (field, value) in [
            (
                "receipt_sha256",
                sha256_bytes(&fs::read(&receipt).unwrap()).hex(),
            ),
            (
                "packet_sha256",
                file_digest("promotion-transition-packet.json"),
            ),
            (
                "authentication_sha256",
                file_digest("promotion-transition.dsse.json"),
            ),
        ] {
            wrapper_text = replace_toml_string_field(&wrapper_text, field, &value);
        }
        fs::write(wrapper, wrapper_text).unwrap();
    }

    fn rebind_provider_archive_receipt(root: &Path) {
        let selection_root = root.join("synthetic-provider-selection");
        let archive = selection_root.join("provider-archive.zip");
        let artifact = selection_root.join("provider-selected-artifact.json");
        let selection = selection_root.join("selection.json");
        let receipt = root.join("synthetic-published-state/public-report-publication.json");
        let archive_bytes = fs::read(&archive).unwrap();
        let archive_sha256 = sha256_bytes(&archive_bytes).hex();
        let archive_size = archive_bytes.len() as u64;
        let mut artifact_text = fs::read_to_string(&artifact).unwrap();
        artifact_text = replace_json_string_field(
            &artifact_text,
            "digest",
            &format!("sha256:{archive_sha256}"),
        );
        artifact_text = replace_json_number_field(&artifact_text, "size_in_bytes", archive_size);
        fs::write(&artifact, artifact_text).unwrap();
        let artifact_sha256 = sha256_bytes(&fs::read(&artifact).unwrap()).hex();
        let mut selection_text = fs::read_to_string(&selection).unwrap();
        selection_text =
            replace_json_string_field(&selection_text, "providerArchiveSha256", &archive_sha256);
        selection_text =
            replace_json_number_field(&selection_text, "providerArchiveSize", archive_size);
        selection_text = replace_json_string_field(
            &selection_text,
            "providerArtifactApiSha256",
            &artifact_sha256,
        );
        fs::write(&selection, selection_text).unwrap();
        let mut receipt_text = fs::read_to_string(&receipt).unwrap();
        receipt_text = replace_json_string_field(
            &receipt_text,
            "sourceProviderArchiveSha256",
            &archive_sha256,
        );
        receipt_text =
            replace_json_number_field(&receipt_text, "sourceProviderArchiveSize", archive_size);
        receipt_text =
            replace_json_string_field(&receipt_text, "sourceArtifactApiSha256", &artifact_sha256);
        fs::write(receipt, receipt_text).unwrap();
        rebind_selection_receipt(root);
    }

    fn rebind_all_provider_receipt_facts(root: &Path) {
        let selection = root.join("synthetic-provider-selection/selection.json");
        let selection_text = fs::read_to_string(&selection).unwrap();
        let receipt = root.join("synthetic-published-state/public-report-publication.json");
        let mut receipt_text = fs::read_to_string(&receipt).unwrap();
        for (receipt_field, selection_field) in [
            ("sourceProviderArchiveSha256", "providerArchiveSha256"),
            ("sourceExtractedSha256", "directorySha256"),
            ("sourceArtifactApiSha256", "providerArtifactApiSha256"),
            ("sourceRunApiSha256", "providerRunApiSha256"),
            ("sourceWorkflowSha256", "workflowBlobSha256"),
        ] {
            receipt_text = replace_json_string_field(
                &receipt_text,
                receipt_field,
                &quoted_json_field(&selection_text, selection_field),
            );
        }
        receipt_text = replace_json_number_field(
            &receipt_text,
            "sourceProviderArchiveSize",
            json_number_field(&selection_text, "providerArchiveSize"),
        );
        fs::write(receipt, receipt_text).unwrap();
        rebind_selection_receipt(root);
    }

    fn restore_files(files: &[(PathBuf, Vec<u8>)]) {
        for (path, bytes) in files {
            fs::write(path, bytes).unwrap();
        }
    }

    fn authority_digest_tree(root: &Path) -> BTreeMap<String, String> {
        let mut pending = vec![root.to_path_buf()];
        let mut files = BTreeMap::new();
        while let Some(directory) = pending.pop() {
            let mut entries = fs::read_dir(&directory)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            entries.sort_by_key(fs::DirEntry::file_name);
            for entry in entries {
                let relative = entry.path().strip_prefix(root).unwrap().to_path_buf();
                if relative
                    .components()
                    .any(|component| component.as_os_str() == ".git")
                {
                    continue;
                }
                if entry.file_type().unwrap().is_dir() {
                    pending.push(entry.path());
                } else {
                    files.insert(
                        relative.to_string_lossy().replace('\\', "/"),
                        sha256_bytes(&fs::read(entry.path()).unwrap()).hex(),
                    );
                }
            }
        }
        files
    }

    fn authority_tree_sha256(root: &Path) -> String {
        let mut statement = String::new();
        for (path, digest) in authority_digest_tree(root) {
            statement.push_str(&path);
            statement.push('\0');
            statement.push_str(&digest);
            statement.push('\n');
        }
        sha256_bytes(statement.as_bytes()).hex()
    }

    fn copy_complete_authority_tree(source: &Path, destination: &Path) {
        copy_authority_tree_with_git(source, destination, false);
    }

    fn copy_authority_tree_with_git(source: &Path, destination: &Path, include_git: bool) {
        fs::create_dir_all(destination).unwrap();
        let mut entries = fs::read_dir(source)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            if !include_git && entry.file_name() == ".git" {
                continue;
            }
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_authority_tree_with_git(&entry.path(), &target, include_git);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn git_fixture_command(repository: &Path, arguments: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(arguments)
            .current_dir(repository)
            .env("GIT_AUTHOR_DATE", "2026-08-11T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-08-11T00:00:00Z")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write_synthetic_promotion(package: &Path, output: &Path, authority: &SyntheticAuthority) {
        let retained = output.join("package");
        copy_complete_authority_tree(package, &retained);
        let manifest = retained.join("manifest.toml");
        let manifest_fields =
            crate::strict_toml::assignments(&fs::read_to_string(&manifest).unwrap()).unwrap();
        let record = format!(
            "schema_version = 1\ndomain = \"{DOMAIN}\"\nfixture_id = \"{}\"\nroot_digest = \"{}\"\npackage_path = \"package\"\npackage_tree_sha256 = \"{}\"\nmanifest_sha256 = \"{}\"\nreview_payload_sha256 = \"{}\"\nasymmetric_reviews_sha256 = \"{}\"\npublished_state_sha256 = \"{}\"\nstate = \"synthetic-reviewed-awaiting-controlled-integration\"\n",
            authority.fixture_id(),
            authority.root_digest(),
            authority_tree_sha256(&retained),
            sha256_bytes(&fs::read(manifest).unwrap()).hex(),
            quoted(&manifest_fields, "review_payload_sha256").unwrap(),
            quoted(&manifest_fields, "asymmetric_reviews_sha256").unwrap(),
            quoted(&manifest_fields, "published_state_sha256").unwrap(),
        );
        fs::write(output.join("promoted-synthetic-authority.toml"), record).unwrap();
    }

    fn verify_synthetic_promotion(
        promotion: &Path,
        candidate: &str,
        epoch: &str,
        catalog: &str,
        authority: &SyntheticAuthority,
    ) -> Result<(), String> {
        let record = read_assignments(&promotion.join("promoted-synthetic-authority.toml"))?;
        require_exact_keys(
            &record,
            &[
                "asymmetric_reviews_sha256",
                "domain",
                "fixture_id",
                "manifest_sha256",
                "package_path",
                "package_tree_sha256",
                "published_state_sha256",
                "review_payload_sha256",
                "root_digest",
                "schema_version",
                "state",
            ],
        )?;
        let package = promotion.join("package");
        let manifest_path = package.join("manifest.toml");
        let manifest = read_assignments(&manifest_path)?;
        if integer(&record, "schema_version")? != 1
            || quoted(&record, "domain")? != DOMAIN
            || quoted(&record, "fixture_id")? != authority.fixture_id()
            || quoted(&record, "root_digest")? != authority.root_digest()
            || quoted(&record, "package_path")? != "package"
            || quoted(&record, "package_tree_sha256")? != authority_tree_sha256(&package)
            || quoted(&record, "manifest_sha256")?
                != sha256_bytes(&read_regular(&manifest_path)?).hex()
            || quoted(&record, "review_payload_sha256")?
                != quoted(&manifest, "review_payload_sha256")?
            || quoted(&record, "asymmetric_reviews_sha256")?
                != quoted(&manifest, "asymmetric_reviews_sha256")?
            || quoted(&record, "published_state_sha256")?
                != quoted(&manifest, "published_state_sha256")?
            || quoted(&record, "state")? != "synthetic-reviewed-awaiting-controlled-integration"
        {
            return Err("synthetic promotion record differs from reviewed authority".to_owned());
        }
        verify_fixture(&package, candidate, epoch, catalog)
    }

    fn fixture_identity() -> (String, String, String) {
        (
            "a".repeat(40),
            sha256_bytes(b"synthetic epoch").hex(),
            sha256_bytes(b"synthetic catalog").hex(),
        )
    }

    #[test]
    fn exact_three_shard_fixture_is_complete_and_never_production_admissible() {
        let root =
            std::env::temp_dir().join(format!("hell-synthetic-promotion-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        verify_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        let finalized = root.join("synthetic-finalized-claim/finalized.json");
        assert!(
            crate::assurance::verify_with_production_claim_coverage_parser(
                &finalized, &candidate, &epoch,
            )
            .is_err()
        );

        let shard = root.join("shards/linux-amd64.toml");
        let original = fs::read_to_string(&shard).unwrap();
        fs::write(&shard, original.replace(&candidate, &"b".repeat(40))).unwrap();
        assert!(verify_fixture(&root, &candidate, &epoch, &catalog).is_err());
        fs::write(&shard, &original).unwrap();
        fs::write(root.join("shards/extra.toml"), b"extra\n").unwrap();
        assert!(verify_fixture(&root, &candidate, &epoch, &catalog).is_err());
        assert!(
            build_fixture(
                &root.with_extension("uppercase"),
                &candidate.to_ascii_uppercase(),
                &epoch,
                &catalog,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_authority_and_dual_review_reject_domain_mixing() {
        let (candidate, epoch, catalog) = fixture_identity();
        let authority = SyntheticAuthority::derive(&candidate, &epoch, &catalog);
        let backend = SyntheticReviewBackend::fixture();
        let payload = sha256_bytes(b"synthetic reviewed package").hex();
        let review = backend
            .authenticate(&authority, "authority-review", &payload)
            .unwrap();
        let parsed = crate::strict_toml::assignments(&review).unwrap();
        backend
            .verify(&authority, "authority-review", &parsed, &payload)
            .unwrap();

        let other = SyntheticAuthority::derive(&"b".repeat(40), &epoch, &catalog);
        assert!(
            backend
                .verify(&other, "authority-review", &parsed, &payload)
                .is_err()
        );
        let changed_payload = sha256_bytes(b"changed synthetic reviewed package").hex();
        assert!(
            backend
                .verify(&authority, "authority-review", &parsed, &changed_payload)
                .is_err()
        );

        let missing_marker = review.replace(&format!("domain = \"{DOMAIN}\"\n"), "");
        let missing_marker = crate::strict_toml::assignments(&missing_marker).unwrap();
        assert!(
            backend
                .verify(&authority, "authority-review", &missing_marker, &payload)
                .is_err()
        );

        let mut changed_signature = parsed;
        changed_signature.insert(
            "first_signature".to_owned(),
            format!("\"{}\"", sha256_bytes(b"forged signature").hex()),
        );
        assert!(
            backend
                .verify(&authority, "authority-review", &changed_signature, &payload,)
                .is_err()
        );
    }

    #[test]
    fn synthetic_asymmetric_reviews_reject_rehashed_reviewer_key_substitution() {
        let root = std::env::temp_dir().join(format!(
            "hell-synthetic-asymmetric-substitution-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        let first = root.join("asymmetric-synthetic-reviewer-a/review.dsse.json");
        let second = root.join("asymmetric-synthetic-reviewer-b/review.dsse.json");
        fs::copy(&second, &first).unwrap();
        let aggregate = root.join("asymmetric-reviews.toml");
        let mut aggregate_text = fs::read_to_string(&aggregate).unwrap();
        aggregate_text = replace_toml_string_field(
            &aggregate_text,
            "first_review_sha256",
            &sha256_bytes(&fs::read(&first).unwrap()).hex(),
        );
        fs::write(&aggregate, aggregate_text).unwrap();
        let manifest = root.join("manifest.toml");
        let mut manifest_text = fs::read_to_string(&manifest).unwrap();
        manifest_text = replace_toml_string_field(
            &manifest_text,
            "asymmetric_reviews_sha256",
            &sha256_bytes(&fs::read(&aggregate).unwrap()).hex(),
        );
        fs::write(manifest, manifest_text).unwrap();
        assert!(verify_fixture(&root, &candidate, &epoch, &catalog).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_public_authority_rejects_rehashed_head_and_subject_substitution() {
        let root = std::env::temp_dir().join(format!(
            "hell-synthetic-public-substitution-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        let authority = SyntheticAuthority::derive(&candidate, &epoch, &catalog);
        let wrapper = root.join("synthetic-published-state/synthetic-public-authority.toml");
        let finalized =
            sha256_bytes(&fs::read(root.join("synthetic-finalized-claim/finalized.json")).unwrap())
                .hex();
        let selection = root.join("synthetic-provider-selection/selection.json");
        let run = root.join("synthetic-provider-selection/provider-selected-run.json");
        let receipt = root.join("synthetic-published-state/public-report-publication.json");
        let originals = [
            (selection.clone(), fs::read(&selection).unwrap()),
            (run.clone(), fs::read(&run).unwrap()),
            (receipt.clone(), fs::read(&receipt).unwrap()),
            (wrapper.clone(), fs::read(&wrapper).unwrap()),
        ];

        let receipt_text = fs::read_to_string(&receipt).unwrap();
        let provider_head = quoted_json_field(&receipt_text, "publisherSourceCommit");
        let selection_text = fs::read_to_string(&selection).unwrap();
        fs::write(
            &selection,
            selection_text.replace(
                &format!("\"candidateCommit\":\"{candidate}\""),
                &format!("\"candidateCommit\":\"{provider_head}\""),
            ),
        )
        .unwrap();
        rebind_selection_receipt(&root);
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        restore_files(&originals);

        let run_text = fs::read_to_string(&run).unwrap();
        fs::write(
            &run,
            run_text.replace(
                &format!("\"head_sha\":\"{provider_head}\""),
                &format!("\"head_sha\":\"{candidate}\""),
            ),
        )
        .unwrap();
        let mut selection_text = fs::read_to_string(&selection).unwrap();
        let old_run = quoted_json_field(&selection_text, "providerRunApiSha256");
        let new_run = sha256_bytes(&fs::read(&run).unwrap()).hex();
        selection_text = selection_text.replace(&old_run, &new_run);
        fs::write(&selection, selection_text).unwrap();
        rebind_selection_receipt(&root);
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        restore_files(&originals);

        fs::write(
            root.join("synthetic-public-provider-subject/compatibility-report.md"),
            b"# Coherently selected alternate public report\n",
        )
        .unwrap();
        fs::remove_dir_all(root.join("synthetic-provider-selection")).unwrap();
        fs::remove_dir_all(root.join("synthetic-provider-repository")).unwrap();
        crate::assurance::tests::exact_synthetic_provider_selection(
            &root,
            &root.join("synthetic-public-provider-subject"),
            ".github/workflows/promotion-surveillance.yml",
            "promotion-public-current-state-19-2",
            &candidate,
        )
        .unwrap();
        rebind_all_provider_receipt_facts(&root);
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_public_authority_rejects_reauthenticated_semantic_substitutions() {
        let root = std::env::temp_dir().join(format!(
            "hell-synthetic-public-semantics-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        let authority = SyntheticAuthority::derive(&candidate, &epoch, &catalog);
        let publication = root.join("synthetic-published-state");
        let wrapper = publication.join("synthetic-public-authority.toml");
        let finalized =
            sha256_bytes(&fs::read(root.join("synthetic-finalized-claim/finalized.json")).unwrap())
                .hex();
        let record = publication.join("promotion-transition.json");
        let record_text = fs::read_to_string(&record).unwrap();
        let changed_time = "2026-08-11T00:00:01Z";
        fs::write(
            &record,
            replace_json_string_field(&record_text, "observedAt", changed_time),
        )
        .unwrap();
        rebind_public_packet_receipt(&root, &authority, changed_time);
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_public_authority_rejects_rehashed_workflow_and_provider_identity() {
        let root = std::env::temp_dir().join(format!(
            "hell-synthetic-public-provider-mutants-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        let authority = SyntheticAuthority::derive(&candidate, &epoch, &catalog);
        let wrapper = root.join("synthetic-published-state/synthetic-public-authority.toml");
        let finalized =
            sha256_bytes(&fs::read(root.join("synthetic-finalized-claim/finalized.json")).unwrap())
                .hex();
        let selection = root.join("synthetic-provider-selection/selection.json");
        let workflow = root.join("synthetic-provider-selection/provider-workflow.yml");
        let receipt = root.join("synthetic-published-state/public-report-publication.json");
        let provider_subject = root.join("synthetic-public-provider-subject");
        let originals = [
            (selection.clone(), fs::read(&selection).unwrap()),
            (workflow.clone(), fs::read(&workflow).unwrap()),
            (receipt.clone(), fs::read(&receipt).unwrap()),
            (wrapper.clone(), fs::read(&wrapper).unwrap()),
            (
                provider_subject.join("compatibility-report.md"),
                fs::read(provider_subject.join("compatibility-report.md")).unwrap(),
            ),
        ];

        fs::write(&workflow, b"name: substituted synthetic workflow\n").unwrap();
        let mut selection_text = fs::read_to_string(&selection).unwrap();
        let old_workflow = quoted_json_field(&selection_text, "workflowBlobSha256");
        let new_workflow = sha256_bytes(&fs::read(&workflow).unwrap()).hex();
        selection_text = selection_text.replace(&old_workflow, &new_workflow);
        fs::write(&selection, selection_text).unwrap();
        rebind_selection_receipt(&root);
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        restore_files(&originals);

        fs::write(
            provider_subject.join("compatibility-report.md"),
            b"equal-side provider subject substitution\n",
        )
        .unwrap();
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        restore_files(&originals);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_public_authority_rejects_rehashed_archive_receipt_and_report_substitutions() {
        let root = std::env::temp_dir().join(format!(
            "hell-synthetic-public-chain-mutants-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        let authority = SyntheticAuthority::derive(&candidate, &epoch, &catalog);
        let publication = root.join("synthetic-published-state");
        let wrapper = publication.join("synthetic-public-authority.toml");
        let finalized =
            sha256_bytes(&fs::read(root.join("synthetic-finalized-claim/finalized.json")).unwrap())
                .hex();
        let archive = root.join("synthetic-provider-selection/provider-archive.zip");
        let artifact = root.join("synthetic-provider-selection/provider-selected-artifact.json");
        let selection = root.join("synthetic-provider-selection/selection.json");
        let receipt = publication.join("public-report-publication.json");
        let report = publication.join("compatibility-report.md");
        let provider_subject = root.join("synthetic-public-provider-subject");
        let packet = publication.join("promotion-transition-packet.json");
        let authentication = publication.join("promotion-transition.dsse.json");
        let originals = [
            (archive.clone(), fs::read(&archive).unwrap()),
            (artifact.clone(), fs::read(&artifact).unwrap()),
            (selection.clone(), fs::read(&selection).unwrap()),
            (receipt.clone(), fs::read(&receipt).unwrap()),
            (report.clone(), fs::read(&report).unwrap()),
            (packet.clone(), fs::read(&packet).unwrap()),
            (authentication.clone(), fs::read(&authentication).unwrap()),
            (wrapper.clone(), fs::read(&wrapper).unwrap()),
        ];

        let mut archive_bytes = fs::read(&archive).unwrap();
        let index = archive_bytes
            .windows(b"Synthetic compatibility report".len())
            .position(|window| window == b"Synthetic compatibility report")
            .unwrap();
        archive_bytes[index] = b'X';
        fs::write(&archive, archive_bytes).unwrap();
        rebind_provider_archive_receipt(&root);
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        restore_files(&originals);

        let receipt_text = fs::read_to_string(&receipt).unwrap();
        fs::write(
            &receipt,
            replace_json_string_field(
                &receipt_text,
                "publisherStableId",
                "substituted-provider-stable-id",
            ),
        )
        .unwrap();
        rebind_receipt_wrapper(&root);
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        restore_files(&originals);

        fs::write(&report, b"# Reauthenticated but false public report\n").unwrap();
        rebind_public_packet_receipt(&root, &authority, "2026-08-11T00:00:00Z");
        for name in [
            "promotion-transition.json",
            "promotion-transition-packet.json",
            "promotion-transition.dsse.json",
            "compatibility-report.md",
            "accepted-divergences.json",
            "public-release-statement.json",
        ] {
            fs::copy(publication.join(name), provider_subject.join(name)).unwrap();
        }
        fs::remove_dir_all(root.join("synthetic-provider-selection")).unwrap();
        fs::remove_dir_all(root.join("synthetic-provider-repository")).unwrap();
        crate::assurance::tests::exact_synthetic_provider_selection(
            &root,
            &provider_subject,
            ".github/workflows/promotion-surveillance.yml",
            "promotion-public-current-state-19-2",
            &candidate,
        )
        .unwrap();
        rebind_all_provider_receipt_facts(&root);
        assert!(
            crate::custody_ops::verify_synthetic_published_state_authority(
                &wrapper, &authority, &candidate, &epoch, &finalized,
            )
            .is_err()
        );
        restore_files(&originals);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_authority_is_byte_deterministic_across_roots() {
        let temporary = std::env::temp_dir();
        let first = temporary.join(format!(
            "hell-synthetic-determinism-a-{}",
            std::process::id()
        ));
        let second = temporary.join(format!(
            "hell-synthetic-determinism-b-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&first);
        let _ = fs::remove_dir_all(&second);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&first, &candidate, &epoch, &catalog).unwrap();
        build_fixture(&second, &candidate, &epoch, &catalog).unwrap();
        assert_eq!(
            authority_digest_tree(&first),
            authority_digest_tree(&second)
        );
        fs::remove_dir_all(first).unwrap();
        fs::remove_dir_all(second).unwrap();
    }

    fn integrate_synthetic_promotion(
        repository: &Path,
        promotion: &Path,
        custody: &Path,
        authority: &SyntheticAuthority,
        candidate: &str,
        epoch: &str,
    ) -> (PathBuf, String, String, String) {
        fs::create_dir_all(repository.join("compat/synthetic-promotions")).unwrap();
        fs::write(
            repository.join("compat/synthetic-promotion-corpus.tsv"),
            "schema_version\t1\ncolumns\troot_digest\tcandidate_commit\tassurance_epoch_sha256\tpromotion_path\tpromotion_sha256\tprovider_selection_path\tprovider_selection_sha256\n",
        )
        .unwrap();
        git_fixture_command(repository, &["init", "--quiet", "--initial-branch=main"]);
        git_fixture_command(repository, &["add", "--all"]);
        commit_synthetic_integration(repository, "synthetic integration baseline");
        let prior_head = git_fixture_command(repository, &["rev-parse", "HEAD"]);
        let case_root = repository
            .join("compat/synthetic-promotions")
            .join(authority.root_digest());
        let integrated = case_root.join("promotion");
        copy_complete_authority_tree(promotion, &integrated);
        let retained_selection = case_root.join("synthetic-provider-selection");
        copy_complete_authority_tree(
            &custody.join("synthetic-provider-selection"),
            &retained_selection,
        );
        let promotion_sha256 = authority_tree_sha256(&integrated);
        let selection_sha256 = authority_tree_sha256(&retained_selection);
        let promotion_path = format!(
            "compat/synthetic-promotions/{}/promotion",
            authority.root_digest()
        );
        let selection_path = format!(
            "compat/synthetic-promotions/{}/synthetic-provider-selection",
            authority.root_digest()
        );
        fs::write(
            repository.join("compat/synthetic-promotion-corpus.tsv"),
            format!(
                "schema_version\t1\ncolumns\troot_digest\tcandidate_commit\tassurance_epoch_sha256\tpromotion_path\tpromotion_sha256\tprovider_selection_path\tprovider_selection_sha256\n{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                authority.root_digest(),
                candidate,
                epoch,
                promotion_path,
                promotion_sha256,
                selection_path,
                selection_sha256,
            ),
        )
        .unwrap();
        git_fixture_command(repository, &["add", "--all"]);
        commit_synthetic_integration(repository, "integrate synthetic reviewed authority");
        let integrated_head = git_fixture_command(repository, &["rev-parse", "HEAD"]);
        (integrated, prior_head, integrated_head, promotion_sha256)
    }

    fn verify_synthetic_integration_record(
        repository: &Path,
        authority: &SyntheticAuthority,
        candidate: &str,
        epoch: &str,
    ) -> Result<(PathBuf, PathBuf), String> {
        let catalog = fs::read_to_string(repository.join("compat/synthetic-promotion-corpus.tsv"))
            .map_err(|error| format!("cannot read synthetic integration catalog: {error}"))?;
        let lines = catalog.lines().collect::<Vec<_>>();
        if lines.len() != 3
            || lines[0] != "schema_version\t1"
            || lines[1]
                != "columns\troot_digest\tcandidate_commit\tassurance_epoch_sha256\tpromotion_path\tpromotion_sha256\tprovider_selection_path\tprovider_selection_sha256"
        {
            return Err("synthetic integration catalog is not canonical".to_owned());
        }
        let fields = lines[2].split('\t').collect::<Vec<_>>();
        if fields.len() != 7
            || fields[0] != authority.root_digest()
            || fields[1] != candidate
            || fields[2] != epoch
        {
            return Err("synthetic integration row identity differs".to_owned());
        }
        let expected_promotion = format!(
            "compat/synthetic-promotions/{}/promotion",
            authority.root_digest()
        );
        let expected_selection = format!(
            "compat/synthetic-promotions/{}/synthetic-provider-selection",
            authority.root_digest()
        );
        if fields[3] != expected_promotion || fields[5] != expected_selection {
            return Err("synthetic integration row paths are not canonical".to_owned());
        }
        let promotion = repository.join(fields[3]);
        let selection = repository.join(fields[5]);
        if fields[4] != authority_tree_sha256(&promotion)
            || fields[6] != authority_tree_sha256(&selection)
        {
            return Err("synthetic integration row digest differs".to_owned());
        }
        Ok((promotion, selection))
    }

    fn commit_synthetic_integration(repository: &Path, message: &str) {
        git_fixture_command(
            repository,
            &[
                "-c",
                "user.name=Synthetic Integration",
                "-c",
                "user.email=synthetic-integration@example.invalid",
                "commit",
                "--quiet",
                "--no-gpg-sign",
                "-m",
                message,
            ],
        );
    }

    struct FreshIntegrationReplay<'a> {
        root: &'a Path,
        repository: &'a Path,
        custody: &'a Path,
        authority: &'a SyntheticAuthority,
        candidate: &'a str,
        epoch: &'a str,
        catalog: &'a str,
    }

    fn assert_fresh_integration_replay(inputs: &FreshIntegrationReplay<'_>) {
        let index = git_fixture_command(inputs.repository, &["ls-files", "--stage"]);
        assert!(
            index.lines().all(|line| !line.starts_with("160000 ")),
            "synthetic integration must not retain nested Git repositories"
        );
        let fresh = inputs.root.join("fresh-checkout");
        git_fixture_command(
            inputs.root,
            &[
                "clone",
                "--quiet",
                inputs.repository.to_str().unwrap(),
                fresh.to_str().unwrap(),
            ],
        );
        let (promotion, selection) = verify_synthetic_integration_record(
            &fresh,
            inputs.authority,
            inputs.candidate,
            inputs.epoch,
        )
        .unwrap();
        verify_synthetic_promotion(
            &promotion,
            inputs.candidate,
            inputs.epoch,
            inputs.catalog,
            inputs.authority,
        )
        .unwrap();
        let case_root = selection.parent().unwrap();
        crate::assurance::tests::reverify_retained_synthetic_provider_selection(
            case_root,
            &promotion,
            ".github/workflows/regression-corpus.yml",
            inputs.candidate,
        )
        .unwrap();
        assert_fresh_integration_substitutions(inputs, &fresh, &promotion, &selection);
    }

    fn assert_fresh_integration_substitutions(
        inputs: &FreshIntegrationReplay<'_>,
        fresh: &Path,
        promotion: &Path,
        selection: &Path,
    ) {
        let fresh_catalog = fresh.join("compat/synthetic-promotion-corpus.tsv");
        let catalog_bytes = fs::read(&fresh_catalog).unwrap();
        let canonical_selection_path = format!(
            "compat/synthetic-promotions/{}/synthetic-provider-selection",
            inputs.authority.root_digest()
        );
        for outside_selection in [
            "../../outside/synthetic-provider-selection".to_owned(),
            "compat/synthetic-promotions/other/synthetic-provider-selection".to_owned(),
            inputs
                .custody
                .join("synthetic-provider-selection")
                .to_string_lossy()
                .into_owned(),
        ] {
            fs::write(
                &fresh_catalog,
                std::str::from_utf8(&catalog_bytes)
                    .unwrap()
                    .replace(&canonical_selection_path, &outside_selection),
            )
            .unwrap();
            assert!(
                verify_synthetic_integration_record(
                    fresh,
                    inputs.authority,
                    inputs.candidate,
                    inputs.epoch,
                )
                .is_err()
            );
        }
        fs::write(&fresh_catalog, catalog_bytes).unwrap();
        let selected_run = selection.join("provider-selected-run.json");
        let selected_run_bytes = fs::read(&selected_run).unwrap();
        fs::write(&selected_run, b"{}\n").unwrap();
        assert!(
            verify_synthetic_integration_record(
                fresh,
                inputs.authority,
                inputs.candidate,
                inputs.epoch,
            )
            .is_err()
        );
        assert!(
            crate::assurance::tests::reverify_retained_synthetic_provider_selection(
                selection.parent().unwrap(),
                promotion,
                ".github/workflows/regression-corpus.yml",
                inputs.candidate,
            )
            .is_err()
        );
        fs::write(&selected_run, selected_run_bytes).unwrap();
    }

    #[test]
    fn synthetic_review_promotion_custody_and_post_commit_history_compose() {
        let root = std::env::temp_dir().join(format!(
            "hell-synthetic-compositional-e2e-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let package = root.join("authority-package");
        let promotion = root.join("promotion");
        let custody = root.join("custody");
        let repository = root.join("repository");
        let (candidate, epoch, catalog) = fixture_identity();
        let authority = SyntheticAuthority::derive(&candidate, &epoch, &catalog);
        build_fixture(&package, &candidate, &epoch, &catalog).unwrap();
        write_synthetic_promotion(&package, &promotion, &authority);
        verify_synthetic_promotion(&promotion, &candidate, &epoch, &catalog, &authority).unwrap();
        fs::create_dir(&custody).unwrap();
        crate::assurance::tests::exact_synthetic_provider_selection(
            &custody,
            &promotion,
            ".github/workflows/regression-corpus.yml",
            "reviewed-regression-synthetic-19-2",
            &candidate,
        )
        .unwrap();
        crate::assurance::tests::reverify_exact_synthetic_provider_selection(
            &custody,
            &promotion,
            ".github/workflows/regression-corpus.yml",
            &candidate,
        )
        .unwrap();

        let (integrated, prior_head, integrated_head, promotion_sha256) =
            integrate_synthetic_promotion(
                &repository,
                &promotion,
                &custody,
                &authority,
                &candidate,
                &epoch,
            );
        assert_ne!(prior_head, integrated_head);
        let (recorded_promotion, _) =
            verify_synthetic_integration_record(&repository, &authority, &candidate, &epoch)
                .unwrap();
        assert_eq!(recorded_promotion, integrated);
        verify_synthetic_promotion(&integrated, &candidate, &epoch, &catalog, &authority).unwrap();
        crate::assurance::tests::reverify_exact_synthetic_provider_selection(
            &custody,
            &integrated,
            ".github/workflows/regression-corpus.yml",
            &candidate,
        )
        .unwrap();
        assert_eq!(promotion_sha256, authority_tree_sha256(&integrated));
        assert_fresh_integration_replay(&FreshIntegrationReplay {
            root: &root,
            repository: &repository,
            custody: &custody,
            authority: &authority,
            candidate: &candidate,
            epoch: &epoch,
            catalog: &catalog,
        });

        fs::write(
            integrated.join("package/review.toml"),
            b"substituted post-integration review\n",
        )
        .unwrap();
        assert!(
            verify_synthetic_promotion(&integrated, &candidate, &epoch, &catalog, &authority)
                .is_err()
        );
        assert!(
            crate::assurance::tests::reverify_exact_synthetic_provider_selection(
                &custody,
                &integrated,
                ".github/workflows/regression-corpus.yml",
                &candidate,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_authority_property_matrix_rejects_every_shard_permutation_and_domain_mix() {
        let root = std::env::temp_dir().join(format!(
            "hell-synthetic-authority-properties-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        let manifest = root.join("manifest.toml");
        let original = fs::read_to_string(&manifest).unwrap();
        let fields = crate::strict_toml::assignments(&original).unwrap();
        let shards = quoted_array(&fields, "shards").unwrap();
        for order in [[0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let changed = format!(
                "[\"{}\", \"{}\", \"{}\"]",
                shards[order[0]], shards[order[1]], shards[order[2]],
            );
            fs::write(
                &manifest,
                original.replacen(fields.get("shards").unwrap(), &changed, 1),
            )
            .unwrap();
            assert!(verify_fixture(&root, &candidate, &epoch, &catalog).is_err());
        }
        fs::write(
            &manifest,
            original.replace(DOMAIN, "hell-rs-synthetic-promotion-authority-v2"),
        )
        .unwrap();
        assert!(verify_fixture(&root, &candidate, &epoch, &catalog).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn synthetic_authority_parser_fuzz_matrix_never_accepts_malformed_records() {
        for seed in 0_u8..=u8::MAX {
            let mut bytes = vec![0_u8; usize::from(seed % 31) + 1];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = seed
                    .wrapping_mul(37)
                    .wrapping_add(u8::try_from(index).expect("fuzz input length is bounded"))
                    .wrapping_add(0x80);
            }
            let invalid_index = usize::from(seed) % bytes.len();
            bytes[invalid_index] = 0;
            let parsed = std::panic::catch_unwind(|| {
                std::str::from_utf8(&bytes)
                    .map_err(|_| "not UTF-8".to_owned())
                    .and_then(crate::strict_toml::assignments)
                    .and_then(|document| {
                        require_exact_keys(
                            &document,
                            &["domain", "fixture_id", "root_digest", "schema_version"],
                        )?;
                        if quoted(&document, "domain")? != DOMAIN
                            || integer(&document, "schema_version")? != 1
                        {
                            return Err("fuzzed authority identity changed".to_owned());
                        }
                        Ok(document)
                    })
            });
            assert!(parsed.is_ok());
            assert!(parsed.unwrap().is_err());
        }
    }

    #[test]
    fn synthetic_provider_service_failure_matrix_fails_closed() {
        let root = std::env::temp_dir().join(format!(
            "hell-synthetic-provider-failures-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (candidate, epoch, catalog) = fixture_identity();
        build_fixture(&root, &candidate, &epoch, &catalog).unwrap();
        let subject = root.join("synthetic-public-provider-subject");
        let selection_root = root.join("synthetic-provider-selection");
        let selection = selection_root.join("selection.json");
        let artifact = selection_root.join("provider-selected-artifact.json");
        let run = selection_root.join("provider-selected-run.json");
        let archive = selection_root.join("provider-archive.zip");
        let originals = [
            (selection.clone(), fs::read(&selection).unwrap()),
            (artifact.clone(), fs::read(&artifact).unwrap()),
            (run.clone(), fs::read(&run).unwrap()),
            (archive.clone(), fs::read(&archive).unwrap()),
        ];
        for (path, changed) in [
            (
                artifact.clone(),
                fs::read_to_string(&artifact)
                    .unwrap()
                    .replace("\"expired\":false", "\"expired\":true")
                    .into_bytes(),
            ),
            (
                run.clone(),
                fs::read_to_string(&run)
                    .unwrap()
                    .replace("\"run_attempt\":2", "\"run_attempt\":0")
                    .into_bytes(),
            ),
            (archive.clone(), b"truncated provider archive".to_vec()),
        ] {
            fs::write(&path, changed).unwrap();
            if path == artifact {
                let mut selection_text = fs::read_to_string(&selection).unwrap();
                selection_text = replace_json_string_field(
                    &selection_text,
                    "providerArtifactApiSha256",
                    &sha256_bytes(&fs::read(&artifact).unwrap()).hex(),
                );
                fs::write(&selection, selection_text).unwrap();
            } else if path == run {
                let mut selection_text = fs::read_to_string(&selection).unwrap();
                selection_text = replace_json_string_field(
                    &selection_text,
                    "providerRunApiSha256",
                    &sha256_bytes(&fs::read(&run).unwrap()).hex(),
                );
                fs::write(&selection, selection_text).unwrap();
            } else {
                rebind_provider_archive_receipt(&root);
            }
            assert!(
                crate::assurance::tests::reverify_exact_synthetic_provider_selection(
                    &root,
                    &subject,
                    ".github/workflows/promotion-surveillance.yml",
                    &candidate,
                )
                .is_err()
            );
            restore_files(&originals);
        }
        fs::remove_file(&archive).unwrap();
        assert!(
            crate::assurance::tests::reverify_exact_synthetic_provider_selection(
                &root,
                &subject,
                ".github/workflows/promotion-surveillance.yml",
                &candidate,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
