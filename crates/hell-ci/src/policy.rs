use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::Arc;
use std::time::Duration;

use crate::command::CommandSpec;
#[cfg(any(target_os = "linux", windows))]
use crate::json::json_member;
use crate::json::{JsonValue, canonical_json_bytes};

const REPOSITORY_INVENTORY_ENTRY_LIMIT: usize = 100_000;
const REPOSITORY_INVENTORY_PATH_BYTE_LIMIT: usize = 8 * 1024 * 1024;
const REPOSITORY_INVENTORY_DETAIL_LIMIT: usize = 2 * 1024;

thread_local! {
    static REPOSITORY_INVENTORY_EVIDENCE: RefCell<Option<JsonValue>> = const { RefCell::new(None) };
}

pub(crate) fn take_repository_inventory_evidence() -> Option<JsonValue> {
    REPOSITORY_INVENTORY_EVIDENCE.with(|slot| slot.borrow_mut().take())
}

#[derive(Clone, Debug)]
struct RepositoryRootIdentity {
    requested: PathBuf,
    canonical: PathBuf,
    #[cfg(windows)]
    object_identity: Arc<same_file::Handle>,
}

#[derive(Clone, Debug)]
struct RepositoryInventoryCommon {
    root: RepositoryRootIdentity,
    paths: Vec<PathBuf>,
    status: Option<i32>,
    timed_out: bool,
    capture: RepositoryInventoryCapture,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_sha256: hell_testkit::Digest,
    stderr_sha256: hell_testkit::Digest,
    termination: RepositoryInventoryTermination,
}

#[derive(Clone, Copy, Debug)]
struct RepositoryInventoryCapture {
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[derive(Clone, Copy, Debug)]
struct RepositoryInventoryTermination {
    cleanup_id: Option<u64>,
    forced: bool,
    reaped: bool,
    candidate_quiescence_complete: bool,
}

trait RepositoryInventoryAuthority: Clone + std::fmt::Debug {
    const SCOPE: &'static str;

    fn run(
        command: &CommandSpec,
    ) -> Result<crate::command::CommandResult, crate::command::CommandRunError>;

    fn bind(
        common: &RepositoryInventoryCommon,
        result: &crate::command::CommandResult,
    ) -> Result<Self, String>
    where
        Self: Sized;

    fn validate(&self, common: &RepositoryInventoryCommon) -> Result<(), String>;

    #[cfg(windows)]
    fn launch_control(&self) -> Option<&hell_testkit::WindowsLaunchControlReceipt>;
}

#[derive(Clone, Debug)]
struct BaseRepositoryInventoryAuthority;

#[derive(Clone, Debug)]
struct RepositoryInventoryReceipt<A: RepositoryInventoryAuthority> {
    common: RepositoryInventoryCommon,
    authority: A,
    receipt_sha256: hell_testkit::Digest,
}

type BaseRepositoryInventoryReceipt = RepositoryInventoryReceipt<BaseRepositoryInventoryAuthority>;

#[cfg(windows)]
#[derive(Clone, Debug)]
struct ValidatedWindowsRepositoryLaunchControl(hell_testkit::WindowsLaunchControlReceipt);

#[cfg(windows)]
#[derive(Clone, Debug)]
struct RestrictedWindowsRepositoryInventoryAuthority {
    launch_control: ValidatedWindowsRepositoryLaunchControl,
}

#[cfg(windows)]
type RestrictedWindowsRepositoryInventoryReceipt =
    RepositoryInventoryReceipt<RestrictedWindowsRepositoryInventoryAuthority>;

pub fn check_repository(root: &Path) -> Result<(), String> {
    let inventory = tracked_files_base(root)?;
    inventory.validate()?;
    let common = inventory.common;
    let mut failures = tracked_file_failures(&common.root.canonical, &common.paths);
    failures.extend(crate::protocol::repository_failures(&common.root.canonical));
    check_dormant_collection_activation(&common.root.canonical, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

pub(crate) fn check_text_files(root: &Path) -> Result<(), String> {
    let inventory = tracked_files_base(root)?;
    inventory.validate()?;
    let failures = tracked_file_failures(&inventory.common.root.canonical, &inventory.common.paths);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn tracked_file_failures(root: &Path, tracked: &[PathBuf]) -> Vec<String> {
    let mut failures = Vec::new();
    for path in tracked {
        check_tracked_file(root, path, &mut failures);
    }
    failures
}

impl RepositoryRootIdentity {
    fn capture(requested: &Path) -> Result<Self, String> {
        if !requested.is_absolute() {
            return Err("repository inventory root is not absolute".to_owned());
        }
        let canonical = fs::canonicalize(requested)
            .map_err(|error| format!("cannot canonicalize repository inventory root: {error}"))?;
        #[cfg(windows)]
        let object_identity = Arc::new(
            same_file::Handle::from_path(&canonical)
                .map_err(|error| format!("cannot bind repository inventory root: {error}"))?,
        );
        let identity = Self {
            requested: requested.to_owned(),
            canonical,
            #[cfg(windows)]
            object_identity,
        };
        identity.revalidate()?;
        Ok(identity)
    }

    fn revalidate(&self) -> Result<(), String> {
        let requested = fs::canonicalize(&self.requested)
            .map_err(|error| format!("cannot revalidate requested repository root: {error}"))?;
        let canonical = fs::canonicalize(&self.canonical)
            .map_err(|error| format!("cannot revalidate canonical repository root: {error}"))?;
        let metadata = fs::symlink_metadata(&self.canonical)
            .map_err(|error| format!("cannot inspect canonical repository root: {error}"))?;
        #[cfg(windows)]
        let requested_object = same_file::Handle::from_path(&self.requested)
            .map_err(|error| format!("cannot rebind requested repository root: {error}"))?;
        #[cfg(windows)]
        let canonical_object = same_file::Handle::from_path(&self.canonical)
            .map_err(|error| format!("cannot rebind canonical repository root: {error}"))?;
        #[cfg(windows)]
        if requested_object != *self.object_identity || canonical_object != *self.object_identity {
            return Err("repository inventory root object identity changed".to_owned());
        }
        if requested != self.canonical
            || canonical != self.canonical
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
        {
            return Err("repository inventory root identity changed".to_owned());
        }
        Ok(())
    }
}

impl RepositoryInventoryCommon {
    fn validate(&self) -> Result<(), String> {
        if self.status != Some(0)
            || self.timed_out
            || self.capture.stdout_truncated
            || self.capture.stderr_truncated
            || self.stderr_bytes != 0
            || self.stdout_bytes < u64::try_from(self.paths.len()).unwrap_or(u64::MAX)
            || self.stdout_sha256 == hell_testkit::Digest::default()
            || self.stderr_sha256 != hell_testkit::sha256_bytes(&[])
            || self.termination.cleanup_id.is_none()
            || !self.termination.forced
            || !self.termination.reaped
        {
            return Err("repository inventory terminal receipt is inconsistent".to_owned());
        }
        self.root.revalidate()
    }
}

impl RepositoryInventoryAuthority for BaseRepositoryInventoryAuthority {
    const SCOPE: &'static str = "base";

    fn run(
        command: &CommandSpec,
    ) -> Result<crate::command::CommandResult, crate::command::CommandRunError> {
        command.run_trusted_host_captured()
    }

    fn bind(
        common: &RepositoryInventoryCommon,
        result: &crate::command::CommandResult,
    ) -> Result<Self, String> {
        Self::validate_observation(
            common,
            result.termination.candidate_quiescence_complete,
            #[cfg(windows)]
            result.windows_launch_control.as_ref(),
        )?;
        Ok(Self)
    }

    fn validate(&self, common: &RepositoryInventoryCommon) -> Result<(), String> {
        if common.termination.candidate_quiescence_complete {
            return Err("base repository inventory retained candidate quiescence".to_owned());
        }
        Ok(())
    }

    #[cfg(windows)]
    fn launch_control(&self) -> Option<&hell_testkit::WindowsLaunchControlReceipt> {
        None
    }
}

impl BaseRepositoryInventoryAuthority {
    #[cfg(not(windows))]
    fn validate_observation(
        _common: &RepositoryInventoryCommon,
        candidate_quiescence_complete: bool,
    ) -> Result<(), String> {
        if candidate_quiescence_complete {
            Err("base repository inventory used candidate launch authority".to_owned())
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn validate_observation(
        _common: &RepositoryInventoryCommon,
        candidate_quiescence_complete: bool,
        launch_control: Option<&hell_testkit::WindowsLaunchControlReceipt>,
    ) -> Result<(), String> {
        if candidate_quiescence_complete || launch_control.is_some() {
            Err("base repository inventory used Windows restricted launch authority".to_owned())
        } else {
            Ok(())
        }
    }
}

impl<A: RepositoryInventoryAuthority> RepositoryInventoryReceipt<A> {
    fn bind(
        root: RepositoryRootIdentity,
        result: &crate::command::CommandResult,
    ) -> Result<Self, String> {
        let common = bind_repository_inventory_common(root, result)?;
        let authority = A::bind(&common, result)?;
        let receipt_sha256 = repository_inventory_receipt_digest(&common, &authority)?;
        let receipt = Self {
            common,
            authority,
            receipt_sha256,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), String> {
        self.common.validate()?;
        self.authority.validate(&self.common)?;
        if repository_inventory_receipt_digest(&self.common, &self.authority)?
            != self.receipt_sha256
        {
            return Err("repository inventory receipt digest differs".to_owned());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl ValidatedWindowsRepositoryLaunchControl {
    fn bind(
        common: &RepositoryInventoryCommon,
        observed: Option<&hell_testkit::WindowsLaunchControlReceipt>,
    ) -> Result<Self, String> {
        let control = observed
            .ok_or_else(|| "Windows restricted repository launch receipt is absent".to_owned())?;
        control
            .validate()
            .map_err(|error| format!("Windows repository launch receipt differs: {error}"))?;
        let program_is_git = control
            .program
            .as_deref()
            .and_then(Path::file_name)
            .is_some_and(|name| {
                name.eq_ignore_ascii_case(std::ffi::OsStr::new("git.exe"))
                    || name.eq_ignore_ascii_case(std::ffi::OsStr::new("git"))
            });
        if !common.termination.candidate_quiescence_complete
            || control.schema_version != 1
            || control.state != "completed"
            || control.phases.len() != 12
            || control.bytes == 0
            || control.sha256 == hell_testkit::Digest::default()
            || control.request_sha256 == hell_testkit::Digest::default()
            || control.status_code != common.status
            || control.timed_out != common.timed_out
            || !control.termination.forced
            || !control.termination.reaped
            || !control.candidate_quiescence_complete
            || control.termination.forced != common.termination.forced
            || control.termination.reaped != common.termination.reaped
            || control.candidate_quiescence_complete
                != common.termination.candidate_quiescence_complete
            || control.program_bytes.is_none_or(|bytes| bytes == 0)
            || control
                .program_sha256
                .is_none_or(|digest| digest == hell_testkit::Digest::default())
            || !program_is_git
            || control.current_directory != common.root.canonical
        {
            return Err("Windows restricted repository launch receipt is incomplete".to_owned());
        }
        Ok(Self(control.clone()))
    }

    fn validate(&self, common: &RepositoryInventoryCommon) -> Result<(), String> {
        Self::bind(common, Some(&self.0)).map(|_| ())
    }
}

#[cfg(windows)]
impl RepositoryInventoryAuthority for RestrictedWindowsRepositoryInventoryAuthority {
    const SCOPE: &'static str = "restricted-windows";

    fn run(
        command: &CommandSpec,
    ) -> Result<crate::command::CommandResult, crate::command::CommandRunError> {
        command.run()
    }

    fn bind(
        common: &RepositoryInventoryCommon,
        result: &crate::command::CommandResult,
    ) -> Result<Self, String> {
        Ok(Self {
            launch_control: ValidatedWindowsRepositoryLaunchControl::bind(
                common,
                result.windows_launch_control.as_ref(),
            )?,
        })
    }

    fn validate(&self, common: &RepositoryInventoryCommon) -> Result<(), String> {
        self.launch_control.validate(common)
    }

    fn launch_control(&self) -> Option<&hell_testkit::WindowsLaunchControlReceipt> {
        Some(&self.launch_control.0)
    }
}

fn repository_inventory_receipt_digest<A: RepositoryInventoryAuthority>(
    common: &RepositoryInventoryCommon,
    authority: &A,
) -> Result<hell_testkit::Digest, String> {
    let authority = repository_inventory_authority_evidence(authority);
    let binding = JsonValue::Object(BTreeMap::from([
        ("authority".to_owned(), authority),
        (
            "candidateQuiescenceComplete".to_owned(),
            JsonValue::Bool(common.termination.candidate_quiescence_complete),
        ),
        (
            "cleanupId".to_owned(),
            common
                .termination
                .cleanup_id
                .map_or(JsonValue::Null, JsonValue::Number),
        ),
        (
            "pathCount".to_owned(),
            JsonValue::Number(u64::try_from(common.paths.len()).unwrap_or(u64::MAX)),
        ),
        (
            "repositoryRootCanonical".to_owned(),
            JsonValue::String(common.root.canonical.display().to_string()),
        ),
        (
            "repositoryRootRequested".to_owned(),
            JsonValue::String(common.root.requested.display().to_string()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        (
            "statusCode".to_owned(),
            common
                .status
                .and_then(|status| u64::try_from(status).ok())
                .map_or(JsonValue::Null, JsonValue::Number),
        ),
        (
            "stderrBytes".to_owned(),
            JsonValue::Number(common.stderr_bytes),
        ),
        (
            "stderrSha256".to_owned(),
            JsonValue::String(common.stderr_sha256.hex()),
        ),
        (
            "stderrTruncated".to_owned(),
            JsonValue::Bool(common.capture.stderr_truncated),
        ),
        (
            "stdoutBytes".to_owned(),
            JsonValue::Number(common.stdout_bytes),
        ),
        (
            "stdoutSha256".to_owned(),
            JsonValue::String(common.stdout_sha256.hex()),
        ),
        (
            "stdoutTruncated".to_owned(),
            JsonValue::Bool(common.capture.stdout_truncated),
        ),
        (
            "terminationForced".to_owned(),
            JsonValue::Bool(common.termination.forced),
        ),
        (
            "terminationReaped".to_owned(),
            JsonValue::Bool(common.termination.reaped),
        ),
        ("timedOut".to_owned(), JsonValue::Bool(common.timed_out)),
    ]));
    Ok(hell_testkit::sha256_bytes(&canonical_json_bytes(&binding)?))
}

#[cfg(not(windows))]
fn repository_inventory_authority_evidence<A: RepositoryInventoryAuthority>(
    _authority: &A,
) -> JsonValue {
    JsonValue::Object(BTreeMap::from([(
        "kind".to_owned(),
        JsonValue::String(A::SCOPE.to_owned()),
    )]))
}

#[cfg(windows)]
fn repository_inventory_authority_evidence<A: RepositoryInventoryAuthority>(
    authority: &A,
) -> JsonValue {
    let mut evidence =
        BTreeMap::from([("kind".to_owned(), JsonValue::String(A::SCOPE.to_owned()))]);
    evidence.insert(
        "launchControl".to_owned(),
        authority
            .launch_control()
            .map_or(JsonValue::Null, repository_inventory_launch_control),
    );
    JsonValue::Object(evidence)
}

#[cfg(windows)]
pub(crate) fn verify_repository_inventory_for_integration(root: &Path) -> Result<(), String> {
    let inventory = tracked_files_windows_restricted(root)?;
    inventory.validate()?;
    let control = &inventory.authority.launch_control.0;
    if inventory.common.paths.is_empty()
        || control.current_directory != inventory.common.root.canonical
    {
        return Err("Windows repository inventory launch receipt differs".to_owned());
    }
    if ValidatedWindowsRepositoryLaunchControl::bind(&inventory.common, None).is_ok() {
        return Err("absent Windows restricted launch receipt was accepted".to_owned());
    }
    if BaseRepositoryInventoryAuthority::validate_observation(
        &inventory.common,
        inventory.common.termination.candidate_quiescence_complete,
        Some(control),
    )
    .is_ok()
    {
        return Err("restricted Windows inventory was accepted as base authority".to_owned());
    }
    let mut corrupted = inventory.clone();
    corrupted.authority.launch_control.0.request_sha256 = hell_testkit::Digest::default();
    if corrupted.validate().is_ok() {
        return Err("corrupted Windows repository launch receipt was accepted".to_owned());
    }
    let mut substituted = inventory.clone();
    substituted.receipt_sha256 = hell_testkit::Digest::default();
    if substituted.validate().is_ok() {
        return Err("substituted repository inventory receipt digest was accepted".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_base_repository_inventory_inside_candidate_scope_for_integration(
    root: &Path,
) -> Result<(), String> {
    verify_base_repository_inventory_inside_candidate_scope_with_paths_for_integration(root, None)
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_base_repository_inventory_inside_candidate_scope_with_paths_for_integration(
    root: &Path,
    expected_paths: Option<&[PathBuf]>,
) -> Result<(), String> {
    if !hell_testkit::candidate_launch_policy_is_installed_for_integration() {
        return Err(
            "base repository inventory verifier lacks ambient candidate authority".to_owned(),
        );
    }
    let inventory = tracked_files_base(root)?;
    inventory.validate()?;
    if !hell_testkit::candidate_launch_policy_is_installed_for_integration() {
        return Err(
            "base repository inventory did not restore ambient candidate authority".to_owned(),
        );
    }
    if inventory.common.paths.is_empty()
        || inventory.common.termination.candidate_quiescence_complete
    {
        return Err("base repository inventory retained candidate launch authority".to_owned());
    }
    if expected_paths.is_some_and(|expected| inventory.common.paths != expected) {
        return Err("base repository inventory tracked-path receipt differs".to_owned());
    }
    let evidence = take_repository_inventory_evidence()
        .ok_or_else(|| "base repository inventory evidence is absent".to_owned())?;
    let fields = evidence.object()?;
    let roots = json_member(fields, "repositoryRoot")?.object()?;
    if json_member(fields, "schemaVersion")?.number()? != 3
        || json_member(fields, "inventoryScope")?.string()? != "base"
        || json_member(fields, "candidateQuiescenceComplete")?.boolean()?
        || json_member(fields, "receiptSha256")?.string()? != inventory.receipt_sha256.hex()
        || json_member(roots, "requested")?.string()?
            != inventory.common.root.requested.display().to_string()
        || json_member(roots, "canonical")?.string()?
            != inventory.common.root.canonical.display().to_string()
    {
        return Err("base repository inventory schema-v3 evidence differs".to_owned());
    }
    if BaseRepositoryInventoryAuthority::validate_observation(&inventory.common, true).is_ok() {
        return Err("candidate-authorized result was accepted as base authority".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_base_repository_inventory_failure_evidence_for_integration(
    root: &Path,
) -> Result<(), String> {
    let failure = tracked_files_base(root)
        .expect_err("a directory without a Git repository must reject base inventory");
    if !failure.contains("git ls-files failed while inventorying repository policy")
        || !failure.contains("status=Some(")
        || !failure.contains("stdoutBytes=")
        || !failure.contains("stderrBytes=")
        || !failure.contains("stdoutSha256=")
        || !failure.contains("stderrSha256=")
    {
        return Err(format!(
            "base repository inventory failure evidence is incomplete: {failure}"
        ));
    }
    let evidence = take_repository_inventory_evidence()
        .ok_or_else(|| "base repository inventory failure evidence is absent".to_owned())?;
    let fields = evidence.object()?;
    if json_member(fields, "schemaVersion")?.number()? != 3
        || json_member(fields, "inventoryScope")?.string()? != "base"
        || json_member(fields, "state")?.string()? != "failed"
        || json_member(fields, "stderrBytes")?.number()? == 0
        || json_member(fields, "stdoutSha256")?.string()?.is_empty()
        || json_member(fields, "stderrSha256")?.string()?.is_empty()
    {
        return Err("base repository inventory failure receipt differs".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_candidate_authorized_repository_result_rejected_for_integration(
    root: &Path,
    result: &crate::command::CommandResult,
) -> Result<(), String> {
    let root = RepositoryRootIdentity::capture(root)?;
    let common = bind_repository_inventory_common(root, result)?;
    match BaseRepositoryInventoryAuthority::bind(&common, result) {
        Err(error) if error == "base repository inventory used candidate launch authority" => {
            Ok(())
        }
        Err(error) => Err(format!(
            "candidate-authorized repository result had the wrong rejection: {error}"
        )),
        Ok(_) => Err("candidate-authorized result was accepted as base authority".to_owned()),
    }
}

#[cfg(windows)]
pub(crate) fn verify_base_repository_inventory_for_integration(root: &Path) -> Result<(), String> {
    let inventory = tracked_files_base(root)?;
    inventory.validate()?;
    if inventory.common.paths.is_empty()
        || inventory.common.termination.candidate_quiescence_complete
    {
        return Err("base repository inventory receipt differs".to_owned());
    }
    let evidence = take_repository_inventory_evidence()
        .ok_or_else(|| "base repository inventory evidence is absent".to_owned())?;
    let fields = evidence.object()?;
    let roots = json_member(fields, "repositoryRoot")?.object()?;
    if json_member(fields, "schemaVersion")?.number()? != 3
        || json_member(fields, "inventoryScope")?.string()? != "base"
        || !matches!(json_member(fields, "launchControl")?, JsonValue::Null)
        || json_member(fields, "receiptSha256")?.string()? != inventory.receipt_sha256.hex()
        || json_member(roots, "requested")?.string()?
            != inventory.common.root.requested.display().to_string()
        || json_member(roots, "canonical")?.string()?
            != inventory.common.root.canonical.display().to_string()
    {
        return Err("base repository inventory schema-v3 evidence differs".to_owned());
    }
    if BaseRepositoryInventoryAuthority::validate_observation(&inventory.common, true, None).is_ok()
    {
        return Err("candidate quiescence was accepted as base authority".to_owned());
    }
    let mut corrupted = inventory.clone();
    corrupted.receipt_sha256 = hell_testkit::Digest::default();
    if corrupted.validate().is_ok() {
        return Err("corrupted base repository receipt digest was accepted".to_owned());
    }
    let mut redirected = inventory.clone();
    redirected.common.root.canonical = redirected
        .common
        .root
        .canonical
        .parent()
        .ok_or_else(|| "base repository root has no parent authority".to_owned())?
        .to_path_buf();
    if redirected.validate().is_ok() {
        return Err("redirected base repository root was accepted".to_owned());
    }
    Ok(())
}

pub(crate) fn normalized_relative_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!("path is not a normalized relative path: {value:?}"));
    }
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!("path is not a normalized relative path: {value:?}"));
    }
    Ok(path)
}

fn tracked_files_base(root: &Path) -> Result<BaseRepositoryInventoryReceipt, String> {
    tracked_files_with_authority(root)
}

#[cfg(windows)]
fn tracked_files_windows_restricted(
    root: &Path,
) -> Result<RestrictedWindowsRepositoryInventoryReceipt, String> {
    tracked_files_with_authority(root)
}

fn tracked_files_with_authority<A: RepositoryInventoryAuthority>(
    requested_root: &Path,
) -> Result<RepositoryInventoryReceipt<A>, String> {
    REPOSITORY_INVENTORY_EVIDENCE.with(|slot| slot.replace(None));
    let root = RepositoryRootIdentity::capture(requested_root)?;
    let command = CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(&root.canonical)
        .arguments(["ls-files", "-z"])
        .current_directory(&root.canonical);
    let result = match A::run(&command) {
        Ok(result) => result,
        Err(error) => {
            REPOSITORY_INVENTORY_EVIDENCE.with(|slot| {
                slot.replace(Some(JsonValue::Object(BTreeMap::from([
                    (
                        "inventoryScope".to_owned(),
                        JsonValue::String(A::SCOPE.to_owned()),
                    ),
                    ("detail".to_owned(), JsonValue::String(error.to_string())),
                    (
                        "phase".to_owned(),
                        JsonValue::String(error.phase().as_str().to_owned()),
                    ),
                    (
                        "repositoryRoot".to_owned(),
                        repository_inventory_root_evidence(&root),
                    ),
                    ("schemaVersion".to_owned(), JsonValue::Number(3)),
                    (
                        "state".to_owned(),
                        JsonValue::String("unavailable".to_owned()),
                    ),
                ]))))
            });
            return Err(format!("cannot inventory tracked files: {error}"));
        }
    };
    let receipt = match RepositoryInventoryReceipt::<A>::bind(root.clone(), &result) {
        Ok(receipt) => receipt,
        Err(error) => {
            REPOSITORY_INVENTORY_EVIDENCE.with(|slot| {
                slot.replace(Some(repository_inventory_observation_evidence::<A>(
                    &root, &result, &error,
                )))
            });
            return Err(error);
        }
    };
    let evidence = repository_inventory_evidence(&receipt, &result)?;
    REPOSITORY_INVENTORY_EVIDENCE.with(|slot| slot.replace(Some(evidence)));
    Ok(receipt)
}

fn bind_repository_inventory_common(
    root: RepositoryRootIdentity,
    result: &crate::command::CommandResult,
) -> Result<RepositoryInventoryCommon, String> {
    require_repository_inventory_terminal(result)?;
    if !result.stdout.is_empty() && !result.stdout.ends_with(&[0]) {
        return Err("git ls-files returned an unterminated repository inventory".to_owned());
    }
    if result.stdout.len() > REPOSITORY_INVENTORY_PATH_BYTE_LIMIT {
        return Err("git ls-files repository inventory exceeds its byte bound".to_owned());
    }
    let mut paths = result
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| {
            std::str::from_utf8(bytes)
                .map(PathBuf::from)
                .map_err(|_| "tracked path is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if paths.len() > REPOSITORY_INVENTORY_ENTRY_LIMIT {
        return Err("git ls-files repository inventory exceeds its entry bound".to_owned());
    }
    let mut unique = std::collections::BTreeSet::new();
    for path in &paths {
        let text = path
            .to_str()
            .ok_or_else(|| "tracked path is not UTF-8".to_owned())?;
        normalized_relative_path(text)?;
        if !unique.insert(path.clone()) {
            return Err("git ls-files repository inventory contains a duplicate path".to_owned());
        }
    }
    paths.retain(|path| root.canonical.join(path).exists());
    let release_workflow = PathBuf::from(".github/workflows/release.yml");
    if root.canonical.join(&release_workflow).is_file() && !paths.contains(&release_workflow) {
        paths.push(release_workflow);
    }
    paths.sort();
    let common = RepositoryInventoryCommon {
        root,
        paths,
        status: result.status.code(),
        timed_out: result.timed_out,
        capture: RepositoryInventoryCapture {
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
        },
        stdout_bytes: result.stdout_bytes,
        stderr_bytes: result.stderr_bytes,
        stdout_sha256: result.stdout_sha256,
        stderr_sha256: result.stderr_sha256,
        termination: RepositoryInventoryTermination {
            cleanup_id: result.termination.cleanup_id,
            forced: result.termination.forced,
            reaped: result.termination.reaped,
            candidate_quiescence_complete: result.termination.candidate_quiescence_complete,
        },
    };
    common.validate()?;
    Ok(common)
}

fn repository_inventory_evidence<A: RepositoryInventoryAuthority>(
    receipt: &RepositoryInventoryReceipt<A>,
    result: &crate::command::CommandResult,
) -> Result<JsonValue, String> {
    receipt.validate()?;
    let mut evidence = repository_inventory_base_evidence(result);
    evidence.insert(
        "inventoryScope".to_owned(),
        JsonValue::String(A::SCOPE.to_owned()),
    );
    evidence.insert(
        "receiptSha256".to_owned(),
        JsonValue::String(receipt.receipt_sha256.hex()),
    );
    evidence.insert(
        "repositoryRoot".to_owned(),
        repository_inventory_root_evidence(&receipt.common.root),
    );
    #[cfg(windows)]
    evidence.insert(
        "launchControl".to_owned(),
        receipt
            .authority
            .launch_control()
            .map_or(JsonValue::Null, repository_inventory_launch_control),
    );
    Ok(JsonValue::Object(evidence))
}

fn repository_inventory_observation_evidence<A: RepositoryInventoryAuthority>(
    root: &RepositoryRootIdentity,
    result: &crate::command::CommandResult,
    error: &str,
) -> JsonValue {
    let mut evidence = repository_inventory_base_evidence(result);
    evidence.insert(
        "inventoryScope".to_owned(),
        JsonValue::String(A::SCOPE.to_owned()),
    );
    evidence.insert(
        "receiptError".to_owned(),
        JsonValue::String(error.to_owned()),
    );
    evidence.insert("receiptSha256".to_owned(), JsonValue::Null);
    evidence.insert(
        "repositoryRoot".to_owned(),
        repository_inventory_root_evidence(root),
    );
    #[cfg(windows)]
    evidence.insert(
        "launchControl".to_owned(),
        result
            .windows_launch_control
            .as_ref()
            .map_or(JsonValue::Null, repository_inventory_launch_control),
    );
    JsonValue::Object(evidence)
}

fn repository_inventory_root_evidence(root: &RepositoryRootIdentity) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "canonical".to_owned(),
            JsonValue::String(root.canonical.display().to_string()),
        ),
        (
            "requested".to_owned(),
            JsonValue::String(root.requested.display().to_string()),
        ),
    ]))
}

fn bounded_repository_inventory_detail(bytes: &[u8]) -> JsonValue {
    let rendered = String::from_utf8_lossy(bytes);
    let boundary = (0..=rendered.len().min(REPOSITORY_INVENTORY_DETAIL_LIMIT))
        .rev()
        .find(|boundary| rendered.is_char_boundary(*boundary))
        .unwrap_or_default();
    JsonValue::String(rendered[..boundary].to_owned())
}

fn repository_inventory_base_evidence(
    result: &crate::command::CommandResult,
) -> BTreeMap<String, JsonValue> {
    BTreeMap::from([
        ("schemaVersion".to_owned(), JsonValue::Number(3)),
        (
            "durationMillis".to_owned(),
            JsonValue::Number(u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX)),
        ),
        (
            "state".to_owned(),
            JsonValue::String(
                if result.status.success()
                    && !result.timed_out
                    && !result.stdout_truncated
                    && !result.stderr_truncated
                    && result.stderr.is_empty()
                {
                    "completed"
                } else {
                    "failed"
                }
                .to_owned(),
            ),
        ),
        (
            "statusCode".to_owned(),
            result
                .status
                .code()
                .and_then(|code| u64::try_from(code).ok())
                .map_or(JsonValue::Null, JsonValue::Number),
        ),
        ("timedOut".to_owned(), JsonValue::Bool(result.timed_out)),
        (
            "cleanupId".to_owned(),
            result
                .termination
                .cleanup_id
                .map_or(JsonValue::Null, JsonValue::Number),
        ),
        (
            "terminationForced".to_owned(),
            JsonValue::Bool(result.termination.forced),
        ),
        (
            "terminationReaped".to_owned(),
            JsonValue::Bool(result.termination.reaped),
        ),
        (
            "candidateQuiescenceComplete".to_owned(),
            JsonValue::Bool(result.termination.candidate_quiescence_complete),
        ),
        (
            "stdoutBytes".to_owned(),
            JsonValue::Number(result.stdout_bytes),
        ),
        (
            "stderrBytes".to_owned(),
            JsonValue::Number(result.stderr_bytes),
        ),
        (
            "stdoutSha256".to_owned(),
            JsonValue::String(result.stdout_sha256.hex()),
        ),
        (
            "stderrSha256".to_owned(),
            JsonValue::String(result.stderr_sha256.hex()),
        ),
        (
            "stdoutTruncated".to_owned(),
            JsonValue::Bool(result.stdout_truncated),
        ),
        (
            "stderrTruncated".to_owned(),
            JsonValue::Bool(result.stderr_truncated),
        ),
        (
            "stdoutDetail".to_owned(),
            bounded_repository_inventory_detail(&result.stdout),
        ),
        (
            "stderrDetail".to_owned(),
            bounded_repository_inventory_detail(&result.stderr),
        ),
    ])
}

#[cfg(windows)]
fn repository_inventory_launch_control(
    control: &hell_testkit::WindowsLaunchControlReceipt,
) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("bytes".to_owned(), JsonValue::Number(control.bytes)),
        (
            "candidateQuiescenceComplete".to_owned(),
            JsonValue::Bool(control.candidate_quiescence_complete),
        ),
        (
            "currentDirectory".to_owned(),
            JsonValue::String(control.current_directory.display().to_string()),
        ),
        (
            "program".to_owned(),
            control.program.as_ref().map_or(JsonValue::Null, |path| {
                JsonValue::String(path.display().to_string())
            }),
        ),
        (
            "programBytes".to_owned(),
            control
                .program_bytes
                .map_or(JsonValue::Null, JsonValue::Number),
        ),
        (
            "programSha256".to_owned(),
            control
                .program_sha256
                .map_or(JsonValue::Null, |digest| JsonValue::String(digest.hex())),
        ),
        (
            "phases".to_owned(),
            JsonValue::Array(
                control
                    .phases
                    .iter()
                    .map(|phase| JsonValue::String((*phase).to_owned()))
                    .collect(),
            ),
        ),
        (
            "requestSha256".to_owned(),
            JsonValue::String(control.request_sha256.hex()),
        ),
        (
            "schemaVersion".to_owned(),
            JsonValue::Number(control.schema_version),
        ),
        ("sha256".to_owned(), JsonValue::String(control.sha256.hex())),
        (
            "state".to_owned(),
            JsonValue::String(control.state.to_owned()),
        ),
        (
            "statusCode".to_owned(),
            control
                .status_code
                .and_then(|code| u64::try_from(code).ok())
                .map_or(JsonValue::Null, JsonValue::Number),
        ),
        ("timedOut".to_owned(), JsonValue::Bool(control.timed_out)),
        (
            "terminationForced".to_owned(),
            JsonValue::Bool(control.termination.forced),
        ),
        (
            "terminationReaped".to_owned(),
            JsonValue::Bool(control.termination.reaped),
        ),
    ]))
}

fn require_repository_inventory_terminal(
    result: &crate::command::CommandResult,
) -> Result<(), String> {
    if !result.status.success()
        || result.timed_out
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.stderr.is_empty()
    {
        Err(repository_inventory_failure_detail(result))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn verify_repository_inventory_target_stderr_for_integration(
    result: &crate::command::CommandResult,
) -> Result<(), String> {
    let control = result
        .windows_launch_control
        .as_ref()
        .ok_or_else(|| "Windows target-stderr launch receipt is absent".to_owned())?;
    control
        .validate()
        .map_err(|error| format!("Windows target-stderr launch receipt differs: {error}"))?;
    if control.state != "completed" || result.stderr.is_empty() {
        return Err("Windows target-stderr fixture did not reach its intended boundary".to_owned());
    }
    let failure = require_repository_inventory_terminal(result)
        .expect_err("target stderr must reject repository inventory");
    if !failure.contains("stderrBytes=")
        || !failure.contains("stderrSha256=")
        || !failure.contains("inventory-target-stderr")
    {
        return Err("Windows target-stderr failure evidence is incomplete".to_owned());
    }
    Ok(())
}

fn repository_inventory_failure_detail(result: &crate::command::CommandResult) -> String {
    let bounded = |bytes: &[u8]| {
        let rendered = String::from_utf8_lossy(bytes);
        let boundary = (0..=rendered.len().min(REPOSITORY_INVENTORY_DETAIL_LIMIT))
            .rev()
            .find(|boundary| rendered.is_char_boundary(*boundary))
            .unwrap_or_default();
        let mut detail = rendered[..boundary].to_owned();
        if boundary < rendered.len() {
            detail.push_str("<TRUNCATED>");
        }
        detail
    };
    #[cfg(windows)]
    let control = result.windows_launch_control.as_ref().map_or_else(
        || "unavailable".to_owned(),
        |receipt| {
            format!(
                "{}:{}:{}:{}",
                receipt.schema_version,
                receipt.state,
                receipt.request_sha256.hex(),
                receipt.sha256.hex()
            )
        },
    );
    #[cfg(not(windows))]
    let control = "not-applicable".to_owned();
    format!(
        "git ls-files failed while inventorying repository policy: status={:?}, timedOut={}, stdoutBytes={}, stderrBytes={}, stdoutSha256={}, stderrSha256={}, stdoutTruncated={}, stderrTruncated={}, launchControl={control:?}, stdout={:?}, stderr={:?}",
        result.status.code(),
        result.timed_out,
        result.stdout_bytes,
        result.stderr_bytes,
        result.stdout_sha256.hex(),
        result.stderr_sha256.hex(),
        result.stdout_truncated,
        result.stderr_truncated,
        bounded(&result.stdout),
        bounded(&result.stderr),
    )
}

fn check_tracked_file(root: &Path, relative: &Path, failures: &mut Vec<String>) {
    let path = root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            failures.push(format!("cannot inspect {}: {error}", relative.display()));
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        failures.push(format!(
            "tracked path must be a regular file: {}",
            relative.display()
        ));
        return;
    }
    if matches!(
        relative.extension().and_then(|value| value.to_str()),
        Some("sh" | "bash")
    ) {
        failures.push(format!("shell script is forbidden: {}", relative.display()));
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", relative.display()));
            return;
        }
    };
    if !bytes.is_empty() && textual(relative, &bytes) && !bytes.ends_with(b"\n") {
        failures.push(format!(
            "tracked text file lacks a trailing newline: {}",
            relative.display()
        ));
    }
}

fn textual(path: &Path, bytes: &[u8]) -> bool {
    let extension = path.extension().and_then(|value| value.to_str());
    matches!(
        extension,
        Some(
            "md" | "rs"
                | "toml"
                | "yml"
                | "yaml"
                | "json"
                | "txt"
                | "hell"
                | "hs"
                | "cabal"
                | "lock"
                | "tsv"
                | "csv"
        )
    ) || std::str::from_utf8(bytes)
        .is_ok_and(|text| text.starts_with("#!") || text.lines().all(|line| !line.contains('\0')))
}

fn check_dormant_collection_activation(root: &Path, failures: &mut Vec<String>) {
    let manifest = root.join("compat/collection-activation.toml");
    let provenance = root.join("compat/collection-activation-provenance.json");
    let claims = root.join("compat/collection-activation-claims.json");
    let result = (|| {
        let manifest_bytes = fs::read(&manifest)
            .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
        let provenance_bytes = fs::read(&provenance)
            .map_err(|error| format!("cannot read {}: {error}", provenance.display()))?;
        let claims_bytes = fs::read(&claims)
            .map_err(|error| format!("cannot read {}: {error}", claims.display()))?;
        let active = hell_testkit::verify_collection_activation_state(
            &manifest_bytes,
            &provenance_bytes,
            &claims_bytes,
        )?;
        if active {
            return Err(
                "collection activation is active but its retired authority implementation is unavailable"
                    .to_owned(),
            );
        }
        Ok(())
    })();
    if let Err(error) = result {
        failures.push(error);
    }
}
