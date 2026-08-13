use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::{CommandResult, CommandSpec, with_release_candidate_environment};
use crate::json::{JsonValue, canonical_json_bytes, json_member, parse_json};
use crate::report::Report;

use super::archive::{ArchiveInput, create, extract_binary};
use super::manifest::{read_json, read_regular, write_atomic, write_json};
use super::plan::source_inventory;
use super::schema::{ReleasePlan, ReleasePlatform, expected_gates, number, object, string};

pub(crate) fn run(
    platform: ReleasePlatform,
    required_gates: String,
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    root: PathBuf,
    oracle_source: PathBuf,
    output: PathBuf,
) -> Result<String, String> {
    if required_gates.split(',').collect::<Vec<_>>() != expected_gates(platform) {
        return Err("release platform required gate inventory differs from policy".to_owned());
    }
    let plan = ReleasePlan::parse(&read_json(&plan_path)?)?;
    let conformance_plan = validate_conformance_plan(&plan, &conformance_plan_path)?;
    let root = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize candidate root: {error}"))?;
    let oracle_source = fs::canonicalize(oracle_source)
        .map_err(|error| format!("cannot canonicalize oracle root: {error}"))?;
    validate_checkout(&root, &plan)?;
    validate_runner(platform)?;
    validate_oracle(&oracle_source)?;
    let oracle_inventory_before = source_inventory(&oracle_source)?;
    let oracle_inventory_digest =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&oracle_inventory_before)?).hex();
    if output.exists() {
        return Err("platform output already exists".to_owned());
    }
    fs::create_dir_all(output.join("archive"))
        .map_err(|error| format!("cannot create platform output: {error}"))?;
    fs::create_dir(output.join("conformance-evidence"))
        .map_err(|error| format!("cannot create conformance evidence output: {error}"))?;
    fs::create_dir(output.join("conformance-observations"))
        .map_err(|error| format!("cannot create conformance observation output: {error}"))?;
    let output = fs::canonicalize(output)
        .map_err(|error| format!("cannot canonicalize platform output: {error}"))?;
    let target = root
        .parent()
        .ok_or_else(|| "candidate root has no parent".to_owned())?
        .join("candidate-target");
    if !target.is_absolute() {
        return Err("candidate target directory is not absolute".to_owned());
    }
    require_candidate_target(&root, &target)?;
    let confinement =
        establish_candidate_process_confinement(platform, &root, &oracle_source, &target, &output)?;
    let launch_policy = &confinement.policy;

    // Candidate-readable package inputs are retained before the first
    // candidate-controlled child. Later packaging never rereads source files.
    let license = read_regular(&root.join("LICENSES/BSD-3-Clause-Hell.txt"))?;
    let notice = read_regular(&root.join("NOTICE"))?;
    let readme = read_regular(&root.join("README.md"))?;
    let inventory = source_inventory(&root)?;
    let inventory_bytes = canonical_json_bytes(&inventory)?;
    if hell_testkit::sha256_bytes(&inventory_bytes).hex() != plan.source_inventory_sha256 {
        return Err("candidate source inventory differs from release plan".to_owned());
    }
    if read_regular(&root.join("deny.toml"))? != include_bytes!("../../../../deny.toml") {
        return Err("candidate dependency policy differs from trusted automation".to_owned());
    }
    write_atomic(&output.join("source-inventory.json"), &inventory_bytes)?;
    let (tools, prepared_oracle) =
        hell_testkit::with_candidate_launch_policy(launch_policy, || -> Result<_, String> {
            Ok((
                tool_identities(platform, &oracle_source, &target)?,
                prepare_oracle(platform, &oracle_source, &root, &target)?,
            ))
        })?;

    let mut gates = BTreeMap::from([
        ("runner-identity", true),
        ("candidate-checkout", true),
        ("oracle-checkout", true),
    ]);
    let mut evidence = BTreeMap::new();
    evidence.insert(
        "runner-identity".to_owned(),
        object([
            ("arch", string(&env::var("RUNNER_ARCH").unwrap_or_default())),
            ("os", string(&env::var("RUNNER_OS").unwrap_or_default())),
            ("schemaVersion", number(1)),
            ("state", string("passed")),
        ]),
    );
    evidence.insert(
        "candidate-checkout".to_owned(),
        object([
            ("schemaVersion", number(1)),
            ("sha", string(&plan.resolution.candidate_sha)),
            ("state", string("passed")),
        ]),
    );
    evidence.insert(
        "oracle-checkout".to_owned(),
        object([
            ("schemaVersion", number(1)),
            ("sha", string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff")),
            ("sourceInventorySha256", string(&oracle_inventory_digest)),
            ("state", string("passed")),
        ]),
    );
    gates.insert("conformance-plan-binding", true);
    evidence.insert(
        "conformance-plan-binding".to_owned(),
        object([
            (
                "conformancePlanSha256",
                string(&conformance_plan.plan_sha256),
            ),
            ("platform", string(platform.id())),
            ("schemaVersion", number(1)),
            ("state", string("passed")),
            (
                "trustedInputsSha256",
                string(&conformance_plan.trusted_inputs_sha256),
            ),
        ]),
    );
    let mut retained_outputs =
        BTreeMap::from([("source-inventory.json".to_owned(), inventory_bytes)]);
    with_release_candidate_environment(&target, plan.source_date_epoch, launch_policy, || {
        run_platform_gates(
            platform,
            &plan,
            &conformance_plan,
            &root,
            &oracle_source,
            &output,
            &mut gates,
            &mut evidence,
            &mut retained_outputs,
            prepared_oracle,
            &oracle_inventory_digest,
        )
    })?;
    require_source_inventory(&root, &plan.source_inventory_sha256)?;
    validate_oracle(&oracle_source)?;
    let oracle_inventory_after = source_inventory(&oracle_source)?;
    if hell_testkit::sha256_bytes(&canonical_json_bytes(&oracle_inventory_after)?).hex()
        != oracle_inventory_digest
    {
        return Err("oracle source changed during candidate execution".to_owned());
    }
    require_candidate_target(&root, &target)?;
    // The digest sibling is an internal hand-off used by the differential
    // verifier.  It is deliberately not part of the exact platform artifact.
    fs::remove_file(output.join("dependency-policy.sha256"))
        .map_err(|error| format!("cannot remove transient dependency digest: {error}"))?;

    let binary = target.join("release").join(platform.executable());
    require_real_binary_path(&target, &binary)?;
    let archive_name = format!("hell-v{}-{}.tar.gz", plan.version, platform.id());
    let archive_path = output.join("archive").join(&archive_name);
    let archive_sha256 = create(&ArchiveInput {
        platform,
        version: &plan.version,
        source_date_epoch: plan.source_date_epoch,
        executable: &binary,
        license: &license,
        notice: &notice,
        readme: &readme,
        output: &archive_path,
    })?;
    // Snapshot every candidate-adjacent output before the final executable
    // smoke test. The candidate runs as the same workspace user, so the trusted
    // parent rewrites these retained bytes after process-tree quiescence.
    let retained_archive = read_regular(&archive_path)?;
    let unpacked_root = transient_path(&root, &format!("unpacked-{}", platform.id()));
    let unpacked = extract_binary(
        &archive_path,
        platform,
        &plan.version,
        plan.source_date_epoch,
        &unpacked_root,
    )?;
    let smoke =
        with_release_candidate_environment(&target, plan.source_date_epoch, launch_policy, || {
            CommandSpec::new(unpacked.as_os_str(), Duration::from_secs(30))
                .argument("--help")
                .run()
        })
        .map_err(|error| format!("cannot smoke-test packaged executable: {error}"))?;
    if !smoke.status.success() || smoke.timed_out {
        return Err("packaged executable smoke test failed".to_owned());
    }
    require_real_output_directories(&output)?;
    write_atomic(&archive_path, &retained_archive)?;
    for (name, bytes) in retained_outputs {
        write_atomic(&output.join(name), &bytes)?;
    }
    gates.insert("archive-verification", true);
    gates.insert("package-smoke", true);
    evidence.insert(
        "archive-verification".to_owned(),
        object([
            ("archiveSha256", string(&archive_sha256)),
            ("schemaVersion", number(1)),
            ("state", string("passed")),
        ]),
    );
    evidence.insert(
        "package-smoke".to_owned(),
        object([
            ("executable", string(platform.executable())),
            ("schemaVersion", number(1)),
            ("state", string("passed")),
        ]),
    );
    fs::remove_dir_all(&unpacked_root)
        .map_err(|error| format!("cannot remove unpacked smoke-test directory: {error}"))?;
    let expected = expected_gates(platform);
    if gates
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        != expected.iter().copied().collect()
        || gates.values().any(|passed| !passed)
        || evidence
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != expected.iter().copied().collect()
    {
        return Err("release platform gate implementation is incomplete".to_owned());
    }
    let ordered_gates = expected
        .iter()
        .map(|name| {
            object([
                ("name", string(name)),
                ("passed", JsonValue::Bool(gates[name])),
            ])
        })
        .collect();
    let conformance_gate = evidence
        .get("conformance-evidence")
        .ok_or_else(|| "conformance evidence gate is absent".to_owned())?
        .object()?
        .clone();
    let report = object([
        (
            "assignedObligationCount",
            json_member(&conformance_gate, "assignedObligations")?.clone(),
        ),
        ("archiveName", string(&archive_name)),
        ("archiveSha256", string(&archive_sha256)),
        ("buildInputsSha256", string(&plan.build_inputs_sha256)),
        ("candidateSha", string(&plan.resolution.candidate_sha)),
        (
            "conformancePlanSha256",
            string(&plan.conformance_plan_sha256),
        ),
        ("conformanceStandard", string(&plan.conformance_standard)),
        ("evidence", JsonValue::Object(evidence)),
        (
            "evidenceManifestSha256",
            json_member(&conformance_gate, "manifestSha256")?.clone(),
        ),
        (
            "exploratoryObservationCount",
            json_member(&conformance_gate, "exploratoryRecords")?.clone(),
        ),
        ("gates", JsonValue::Array(ordered_gates)),
        ("imageOS", string(&env::var("ImageOS").unwrap_or_default())),
        (
            "imageVersion",
            string(&env::var("ImageVersion").unwrap_or_default()),
        ),
        ("planSha256", string(&plan.plan_sha256)),
        ("platform", string(platform.id())),
        (
            "producedEvidenceRecordCount",
            json_member(&conformance_gate, "producedRecords")?.clone(),
        ),
        ("runAttempt", number(plan.resolution.run_attempt)),
        ("runId", number(plan.resolution.run_id)),
        ("schemaVersion", number(2)),
        ("state", string("passed")),
        ("tag", string(&plan.tag)),
        ("toolIdentities", JsonValue::Object(tools)),
        (
            "trustedConformanceInputsSha256",
            string(&plan.trusted_conformance_inputs_sha256),
        ),
        (
            "unclassifiedMismatchCount",
            json_member(&conformance_gate, "unclassifiedMismatches")?.clone(),
        ),
        ("version", string(&plan.version)),
        ("workflowSha", string(&plan.resolution.workflow_sha)),
    ]);
    write_json(&output.join("platform-report.json"), &report)?;
    write_json(
        &output.join("package-report.json"),
        &object([
            ("archiveSha256", string(&archive_sha256)),
            ("schemaVersion", number(1)),
            ("state", string("verified")),
        ]),
    )?;
    write_json(
        &output.join("archive-manifest.json"),
        &object([
            ("archiveName", string(&archive_name)),
            ("archiveSha256", string(&archive_sha256)),
            ("schemaVersion", number(1)),
        ]),
    )?;
    verify_final_platform_inventory(&output, platform, &archive_name)?;
    Ok(format!("completed {} release gate", platform.id()))
}

#[cfg(unix)]
fn establish_candidate_process_confinement(
    platform: ReleasePlatform,
    candidate_root: &Path,
    oracle_root: &Path,
    target: &Path,
    output: &Path,
) -> Result<CandidateConfinement, String> {
    let sudo = parent_executable("sudo")?;
    let principal = format!("hellrel{}", std::process::id());
    let group = format!("hellrel{}", std::process::id());
    let uid = match platform {
        ReleasePlatform::LinuxX86_64 => 61_000_u32
            .checked_add(std::process::id() % 1_000)
            .ok_or_else(|| "candidate UID overflow".to_owned())?,
        ReleasePlatform::MacosAarch64 => 550_u32
            .checked_add(std::process::id() % 40)
            .ok_or_else(|| "candidate UID overflow".to_owned())?,
        ReleasePlatform::WindowsX86_64 => {
            return Err("Windows platform selected the POSIX confinement path".to_owned());
        }
    };
    let uid_text = uid.to_string();
    match platform {
        ReleasePlatform::LinuxX86_64 => {
            trusted_status(
                &sudo,
                ["-n", "--", "/usr/sbin/groupadd", "--gid", &uid_text, &group],
            )?;
            trusted_status(
                &sudo,
                [
                    "-n",
                    "--",
                    "/usr/sbin/useradd",
                    "--uid",
                    &uid_text,
                    "--gid",
                    &group,
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    &principal,
                ],
            )?;
        }
        ReleasePlatform::MacosAarch64 => {
            trusted_status(
                &sudo,
                [
                    "-n",
                    "--",
                    "/usr/sbin/dseditgroup",
                    "-o",
                    "create",
                    "-i",
                    &uid_text,
                    &group,
                ],
            )?;
            for (property, value) in [
                ("UniqueID", uid_text.as_str()),
                ("PrimaryGroupID", uid_text.as_str()),
                ("UserShell", "/usr/bin/false"),
                ("NFSHomeDirectory", "/var/empty"),
            ] {
                let record = Path::new("/Users").join(&principal);
                trusted_status(
                    &sudo,
                    [
                        "-n",
                        "--",
                        "/usr/bin/dscl",
                        ".",
                        "-create",
                        record
                            .to_str()
                            .ok_or_else(|| "candidate account path is not UTF-8".to_owned())?,
                        property,
                        value,
                    ],
                )?;
            }
        }
        ReleasePlatform::WindowsX86_64 => unreachable!(),
    }
    let isolated = target.join("release-child-environment");
    for directory in [
        target.to_path_buf(),
        isolated.join("home"),
        isolated.join("cargo"),
        isolated.join("sccache"),
        isolated.join("tmp"),
    ] {
        fs::create_dir_all(&directory)
            .map_err(|error| format!("cannot create candidate writable root: {error}"))?;
        trusted_status(
            &sudo,
            [
                "-n",
                "--",
                "/usr/bin/chgrp",
                "-R",
                &group,
                directory
                    .to_str()
                    .ok_or_else(|| "candidate writable path is not UTF-8".to_owned())?,
            ],
        )?;
        normalize_candidate_cache_tree(&directory)?;
    }
    for protected in [candidate_root, oracle_root] {
        if platform == ReleasePlatform::MacosAarch64 {
            trusted_status(
                &sudo,
                [
                    "-n",
                    "--",
                    "/bin/chmod",
                    "-RN",
                    protected
                        .to_str()
                        .ok_or_else(|| "protected path is not UTF-8".to_owned())?,
                ],
            )?;
        }
        trusted_status(
            &sudo,
            [
                "-n",
                "--",
                "/usr/bin/chmod",
                "-R",
                "a-w",
                protected
                    .to_str()
                    .ok_or_else(|| "protected path is not UTF-8".to_owned())?,
            ],
        )?;
    }
    set_posix_mode(output, 0o700)?;
    let policy = hell_testkit::CandidateLaunchPolicy::posix(
        sudo.clone(),
        std::env::current_exe()
            .map_err(|error| format!("cannot resolve trusted POSIX adapter: {error}"))?,
        principal.clone(),
        uid,
        group.clone(),
        vec![target.to_path_buf()],
    )
    .map_err(|error| format!("cannot establish candidate launch policy: {error}"))?;
    Ok(CandidateConfinement {
        policy,
        _cleanup: PosixPrincipalCleanup {
            platform,
            sudo,
            principal,
            group,
            uid,
        },
    })
}

#[cfg(windows)]
fn establish_candidate_process_confinement(
    _platform: ReleasePlatform,
    candidate_root: &Path,
    oracle_root: &Path,
    target: &Path,
    output: &Path,
) -> Result<CandidateConfinement, String> {
    windows_confinement::protect_tree(candidate_root, false)?;
    windows_confinement::protect_tree(oracle_root, false)?;
    windows_confinement::protect_tree(output, false)?;
    windows_confinement::protect_tree(target, true)?;
    let policy = hell_testkit::CandidateLaunchPolicy::windows(
        std::env::current_exe()
            .map_err(|error| format!("cannot resolve trusted driver: {error}"))?,
        vec![target.to_path_buf()],
    )
    .map_err(|error| format!("cannot establish Windows candidate launch policy: {error}"))?;
    Ok(CandidateConfinement { policy })
}

#[cfg(windows)]
mod windows_confinement {
    use super::*;
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GENERIC_ALL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
        PROTECTED_DACL_SECURITY_INFORMATION, SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        WinAuthenticatedUserSid, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        WinRestrictedCodeSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};

    pub(super) fn protect_tree(root: &Path, writable: bool) -> Result<(), String> {
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| format!("cannot inspect Windows confinement root: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Windows confinement root is not a real directory".to_owned());
        }
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            set_dacl(&path, writable)?;
            if fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect Windows confinement entry: {error}"))?
                .is_dir()
            {
                for entry in fs::read_dir(&path).map_err(|error| {
                    format!("cannot enumerate Windows confinement tree: {error}")
                })? {
                    let entry = entry.map_err(|error| {
                        format!("cannot inspect Windows confinement entry: {error}")
                    })?;
                    let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                        format!("cannot inspect Windows confinement entry: {error}")
                    })?;
                    if metadata.file_type().is_symlink()
                        || !(metadata.is_file() || metadata.is_dir())
                    {
                        return Err(
                            "Windows confinement tree contains a redirected or special entry"
                                .to_owned(),
                        );
                    }
                    pending.push(entry.path());
                }
            }
        }
        Ok(())
    }

    fn sid(kind: i32) -> Result<Vec<u8>, String> {
        let mut size = 68_u32;
        let mut value = vec![0_u8; usize::try_from(size).unwrap_or(68)];
        unsafe {
            if CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                value.as_mut_ptr().cast(),
                &mut size,
            ) == 0
            {
                return Err(format!(
                    "cannot create Windows confinement SID: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(value)
    }

    fn set_dacl(path: &Path, writable: bool) -> Result<(), String> {
        let mut administrators = sid(WinBuiltinAdministratorsSid)?;
        let mut system = sid(WinLocalSystemSid)?;
        let mut authenticated = sid(WinAuthenticatedUserSid)?;
        let mut restricted = sid(WinRestrictedCodeSid)?;
        let candidate_rights = if writable {
            GENERIC_ALL
        } else {
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
        };
        let inheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT | OBJECT_INHERIT_ACE;
        let mut entries = [
            entry(administrators.as_mut_ptr().cast(), GENERIC_ALL, inheritance),
            entry(system.as_mut_ptr().cast(), GENERIC_ALL, inheritance),
            entry(
                authenticated.as_mut_ptr().cast(),
                candidate_rights,
                inheritance,
            ),
            entry(
                restricted.as_mut_ptr().cast(),
                candidate_rights,
                inheritance,
            ),
        ];
        let mut acl = std::ptr::null_mut();
        unsafe {
            if SetEntriesInAclW(
                u32::try_from(entries.len()).unwrap_or(u32::MAX),
                entries.as_ptr(),
                std::ptr::null(),
                &mut acl,
            ) != ERROR_SUCCESS
            {
                return Err("cannot construct Windows confinement DACL".to_owned());
            }
            let mut wide = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let status = SetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl,
                std::ptr::null(),
            );
            LocalFree(acl.cast());
            if status != ERROR_SUCCESS {
                return Err(format!("cannot apply Windows confinement DACL: {status}"));
            }
        }
        Ok(())
    }

    fn entry(
        sid: windows_sys::Win32::Security::PSID,
        permissions: u32,
        inheritance: u32,
    ) -> EXPLICIT_ACCESS_W {
        let mut value = EXPLICIT_ACCESS_W {
            grfAccessPermissions: permissions,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inheritance,
            ..Default::default()
        };
        unsafe { BuildTrusteeWithSidW(&mut value.Trustee, sid) };
        value
    }
}

struct CandidateConfinement {
    policy: hell_testkit::CandidateLaunchPolicy,
    #[cfg(unix)]
    _cleanup: PosixPrincipalCleanup,
}

#[cfg(unix)]
struct PosixPrincipalCleanup {
    platform: ReleasePlatform,
    sudo: PathBuf,
    principal: String,
    group: String,
    uid: u32,
}

#[cfg(unix)]
impl Drop for PosixPrincipalCleanup {
    fn drop(&mut self) {
        let uid = self.uid.to_string();
        let _ = std::process::Command::new(&self.sudo)
            .args(["-n", "--", "/usr/bin/pkill", "-KILL", "-U"])
            .arg(uid)
            .status();
        match self.platform {
            ReleasePlatform::LinuxX86_64 => {
                let _ = std::process::Command::new(&self.sudo)
                    .args(["-n", "--", "/usr/sbin/userdel"])
                    .arg(&self.principal)
                    .status();
                let _ = std::process::Command::new(&self.sudo)
                    .args(["-n", "--", "/usr/sbin/groupdel"])
                    .arg(&self.group)
                    .status();
            }
            ReleasePlatform::MacosAarch64 => {
                let _ = std::process::Command::new(&self.sudo)
                    .args(["-n", "--", "/usr/bin/dscl", ".", "-delete"])
                    .arg(Path::new("/Users").join(&self.principal))
                    .status();
                let _ = std::process::Command::new(&self.sudo)
                    .args(["-n", "--", "/usr/bin/dscl", ".", "-delete"])
                    .arg(Path::new("/Groups").join(&self.group))
                    .status();
            }
            ReleasePlatform::WindowsX86_64 => {}
        }
    }
}

#[cfg(unix)]
fn parent_executable(name: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").ok_or_else(|| "PATH is unavailable".to_owned())?;
    std::env::split_paths(&path)
        .map(|root| root.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| fs::canonicalize(candidate).ok())
        .ok_or_else(|| format!("trusted parent cannot resolve {name}"))
}

#[cfg(unix)]
fn trusted_status<const N: usize>(program: &Path, arguments: [&str; N]) -> Result<(), String> {
    let result = CommandSpec::new(program.as_os_str(), Duration::from_secs(30))
        .arguments(arguments)
        .run()
        .map_err(|error| format!("trusted confinement command failed: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("trusted confinement command did not succeed".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn set_posix_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot set candidate writable mode: {error}"))
}

#[cfg(unix)]
fn normalize_candidate_cache_tree(root: &Path) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};

    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect restored candidate cache: {error}"))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink()
            || file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
        {
            return Err("restored candidate cache contains a link or special file".to_owned());
        }
        if file_type.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate restored candidate cache: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read restored cache entry: {error}"))?
                        .path(),
                );
            }
            set_posix_mode(&path, 0o2770)?;
        } else if file_type.is_file() {
            let executable = metadata.permissions().mode() & 0o111 != 0;
            set_posix_mode(&path, if executable { 0o770 } else { 0o660 })?;
        } else {
            return Err("restored candidate cache entry is not regular".to_owned());
        }
    }
    Ok(())
}

fn validate_conformance_plan(
    plan: &ReleasePlan,
    path: &Path,
) -> Result<crate::conformance::ConformancePlan, String> {
    let conformance = crate::conformance::ConformancePlan::parse(&read_json(path)?)?;
    if !accept_conformance_plan_binding(
        conformance.plan_sha256 == plan.conformance_plan_sha256
            && conformance.candidate_sha == plan.resolution.candidate_sha
            && conformance.workflow_sha == plan.resolution.workflow_sha
            && conformance.release_evaluation_instant == plan.release_evaluation_instant
            && conformance.trusted_inputs_sha256 == plan.trusted_conformance_inputs_sha256
            && conformance.source_inventory_sha256 == plan.source_inventory_sha256
            && conformance.standard == plan.conformance_standard,
    ) {
        return Err("conformance plan binding differs from release plan".to_owned());
    }
    Ok(conformance)
}

fn accept_conformance_plan_binding(matches: bool) -> bool {
    let substitution = cfg!(feature = "mutation-testing")
        && std::env::var("HELL_ASSURANCE_MUTANT_ID").as_deref()
            == Ok("candidate-conformance-plan-substitution");
    substitution || matches
}

fn require_real_binary_path(target: &Path, binary: &Path) -> Result<(), String> {
    let release = target.join("release");
    let release_metadata = fs::symlink_metadata(&release)
        .map_err(|error| format!("cannot inspect release target directory: {error}"))?;
    if release_metadata.file_type().is_symlink() || !release_metadata.is_dir() {
        return Err("candidate release target is not a real directory".to_owned());
    }
    if fs::canonicalize(&release)
        .map_err(|error| format!("cannot canonicalize release target: {error}"))?
        != release
    {
        return Err("candidate release target is redirected".to_owned());
    }
    let binary_metadata = fs::symlink_metadata(binary)
        .map_err(|error| format!("cannot inspect release binary: {error}"))?;
    if binary_metadata.file_type().is_symlink() || !binary_metadata.is_file() {
        return Err("candidate release binary is not a real file".to_owned());
    }
    Ok(())
}

fn verify_final_platform_inventory(
    output: &Path,
    platform: ReleasePlatform,
    archive_name: &str,
) -> Result<(), String> {
    let mut expected = std::collections::BTreeSet::from([
        "archive",
        "archive-manifest.json",
        "conformance-evidence",
        "conformance-evidence-manifest.json",
        "conformance-observations",
        "oracle-report.json",
        "package-report.json",
        "platform-report.json",
        "source-inventory.json",
    ]);
    if platform == ReleasePlatform::LinuxX86_64 {
        expected.insert("dependency-policy.json");
        expected.insert("mutation-report.json");
    }
    let observed = fs::read_dir(output)
        .map_err(|error| format!("cannot enumerate final platform output: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot inspect final platform output: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "final platform output name is not UTF-8".to_owned())
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if observed != expected.into_iter().map(str::to_owned).collect() {
        return Err(format!(
            "final platform output exact set differs: {observed:?}"
        ));
    }
    let archives = fs::read_dir(output.join("archive"))
        .map_err(|error| format!("cannot enumerate final archive output: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect final archive output: {error}"))?;
    if archives.len() != 1
        || archives[0].file_name().to_str() != Some(archive_name)
        || !archives[0]
            .file_type()
            .map_err(|error| format!("cannot inspect final archive type: {error}"))?
            .is_file()
    {
        return Err("final platform archive exact set differs".to_owned());
    }
    let manifest = crate::conformance::EvidenceManifest::parse(&read_json(
        &output.join("conformance-evidence-manifest.json"),
    )?)?;
    let expected_members = manifest
        .records
        .iter()
        .chain(&manifest.exploratory_records)
        .chain(&manifest.observations)
        .map(|member| (member.path.as_str(), member.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    for directory in ["conformance-evidence", "conformance-observations"] {
        let path = output.join(directory);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {directory}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!("{directory} is not a real directory"));
        }
        let observed = fs::read_dir(&path)
            .map_err(|error| format!("cannot enumerate {directory}: {error}"))?
            .map(|entry| {
                let entry =
                    entry.map_err(|error| format!("cannot inspect {directory}: {error}"))?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| format!("{directory} member is not UTF-8"))?;
                let relative = format!("{directory}/{name}");
                let expected = expected_members
                    .get(relative.as_str())
                    .ok_or_else(|| format!("unlisted {directory} member {name:?}"))?;
                let metadata = entry
                    .metadata()
                    .map_err(|error| format!("cannot inspect {directory} member: {error}"))?;
                if entry
                    .file_type()
                    .map_err(|error| format!("cannot inspect {directory} member type: {error}"))?
                    .is_symlink()
                    || !metadata.is_file()
                    || hell_testkit::sha256_file(&entry.path())
                        .map_err(|error| format!("cannot hash {directory} member: {error}"))?
                        .hex()
                        != *expected
                {
                    return Err(format!("{directory} member identity differs"));
                }
                Ok(relative)
            })
            .collect::<Result<BTreeSet<_>, String>>()?;
        let expected = expected_members
            .keys()
            .filter(|name| name.starts_with(directory))
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<_>>();
        if observed != expected {
            return Err(format!("{directory} exact set differs"));
        }
    }
    Ok(())
}

fn require_candidate_target(root: &Path, target: &Path) -> Result<(), String> {
    let expected_parent = root
        .parent()
        .ok_or_else(|| "candidate root has no parent".to_owned())?;
    if target.parent() != Some(expected_parent) {
        return Err("candidate target is outside the isolated runner workspace".to_owned());
    }
    if target.exists() {
        let metadata = fs::symlink_metadata(target)
            .map_err(|error| format!("cannot inspect candidate target: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("candidate target is not a real directory".to_owned());
        }
        let canonical = fs::canonicalize(target)
            .map_err(|error| format!("cannot canonicalize candidate target: {error}"))?;
        if canonical != target {
            return Err("candidate target changed identity".to_owned());
        }
        reject_link_descendants(target)?;
    } else {
        fs::create_dir(target)
            .map_err(|error| format!("cannot create candidate target: {error}"))?;
    }
    Ok(())
}

fn reject_link_descendants(root: &Path) -> Result<(), String> {
    for entry in
        fs::read_dir(root).map_err(|error| format!("cannot enumerate candidate target: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect candidate target: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect candidate target entry: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("candidate target contains a symbolic link".to_owned());
        }
        if metadata.is_dir() {
            let canonical = fs::canonicalize(entry.path())
                .map_err(|error| format!("cannot canonicalize candidate target entry: {error}"))?;
            if canonical != entry.path() {
                return Err("candidate target contains a redirected directory".to_owned());
            }
            reject_link_descendants(&entry.path())?;
        } else if !metadata.is_file() {
            return Err("candidate target contains a special entry".to_owned());
        }
    }
    Ok(())
}

fn require_real_output_directories(output: &Path) -> Result<(), String> {
    for path in [
        output.to_path_buf(),
        output.join("archive"),
        output.join("conformance-evidence"),
        output.join("conformance-observations"),
    ] {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("cannot inspect trusted output {}: {error}", path.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "trusted output is not a real directory: {}",
                path.display()
            ));
        }
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("cannot canonicalize trusted output: {error}"))?;
        if canonical != path {
            return Err(format!(
                "trusted output path changed identity: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn run_platform_gates(
    platform: ReleasePlatform,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    root: &Path,
    _oracle_source: &Path,
    output: &Path,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
    retained: &mut BTreeMap<String, Vec<u8>>,
    prepared_oracle: hell_testkit::ExecutableIdentity,
    oracle_source_sha256: &str,
) -> Result<(), String> {
    let oracle_identity = prepared_oracle.clone();
    require_executable_digest(
        &oracle_identity.path,
        oracle_identity.sha256,
        "retained oracle",
    )?;
    if platform == ReleasePlatform::LinuxX86_64 {
        command_gate(
            "dependency-policy",
            CommandSpec::new("cargo-deny", Duration::from_mins(10))
                .arguments(["--all-features", "check", "all"])
                .current_directory(root),
            gates,
            evidence,
        )?;
        crate::release_suite::release_dependency_attestation(
            root,
            &output.join("dependency-policy.json"),
            &plan.resolution.candidate_sha,
        )?;
        retained.insert(
            "dependency-policy.json".to_owned(),
            read_regular(&output.join("dependency-policy.json"))?,
        );
        in_process_gate(
            "conformance-policy",
            crate::compatibility::release_conformance_policy(root),
            gates,
            evidence,
        )?;
        for (name, arguments) in [
            ("case-catalog", &["case-catalog", "verify"][..]),
            ("normalizer-catalog", &["normalizer-audit", "verify"][..]),
            ("divergence-catalog", &["divergence-verify", "verify"][..]),
        ] {
            in_process_gate(
                name,
                crate::compatibility::release_gate(root, arguments),
                gates,
                evidence,
            )?;
        }
        suite_gate(
            "verify",
            root,
            output,
            crate::release_suite::release_verify,
            gates,
            evidence,
        )?;
        for (name, command) in linux_rust_commands(root) {
            if name == "release-build" {
                require_source_inventory(root, &plan.source_inventory_sha256)?;
            }
            command_gate(name, command, gates, evidence)?;
        }
        suite_examples(root, output, gates, evidence)?;
        in_process_gate(
            "release-mutation-catalog",
            crate::mutation::release_mutation_catalog(
                root,
                &output.join("mutation-report.json"),
                &plan.resolution.candidate_sha,
            ),
            gates,
            evidence,
        )?;
        retained.insert(
            "mutation-report.json".to_owned(),
            read_regular(&output.join("mutation-report.json"))?,
        );
        fs::remove_dir_all(output.join("mutation-results"))
            .map_err(|error| format!("cannot remove transient mutation details: {error}"))?;
        gates.insert("linux-release-oracle-digest", true);
        evidence.insert(
            "linux-release-oracle-digest".to_owned(),
            object([
                ("sha256", string(&prepared_oracle.sha256.hex())),
                ("schemaVersion", number(1)),
                ("state", string("passed")),
            ]),
        );
        write_json(
            &output.join("oracle-report.json"),
            &object([
                ("commit", string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff")),
                ("executableSha256", string(&oracle_identity.sha256.hex())),
                ("repository", string("chrisdone/hell")),
                ("schemaVersion", number(2)),
                ("sourceSha256", string(oracle_source_sha256)),
                ("state", string("verified")),
            ]),
        )?;
        retained.insert(
            "oracle-report.json".to_owned(),
            read_regular(&output.join("oracle-report.json"))?,
        );
        in_process_gate(
            "divergence-prototypes",
            crate::compatibility::release_divergence_prototype_catalog(root),
            gates,
            evidence,
        )?;
    } else {
        crate::release_suite::release_dependency_attestation(
            root,
            &output.join("dependency-policy.json"),
            &plan.resolution.candidate_sha,
        )?;
        suite_gate(
            "portability",
            root,
            output,
            crate::release_suite::release_portability,
            gates,
            evidence,
        )?;
        require_source_inventory(root, &plan.source_inventory_sha256)?;
        command_gate(
            "workspace-tests",
            cargo(
                root,
                Duration::from_hours(1),
                [
                    "test",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                ],
            ),
            gates,
            evidence,
        )?;
        command_gate(
            "release-build",
            cargo(
                root,
                Duration::from_mins(30),
                [
                    "build",
                    "--release",
                    "--locked",
                    "--package",
                    "hell-cli",
                    "--bin",
                    "hell",
                ],
            ),
            gates,
            evidence,
        )?;
        write_json(
            &output.join("oracle-report.json"),
            &object([
                ("commit", string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff")),
                ("executableSha256", string(&oracle_identity.sha256.hex())),
                ("repository", string("chrisdone/hell")),
                ("schemaVersion", number(2)),
                ("sourceSha256", string(oracle_source_sha256)),
                ("state", string("verified")),
            ]),
        )?;
        retained.insert(
            "oracle-report.json".to_owned(),
            read_regular(&output.join("oracle-report.json"))?,
        );
        in_process_gate(
            "native-oracle-build",
            Ok("built and retained a pinned-source native oracle identity".to_owned()),
            gates,
            evidence,
        )?;
        fs::remove_file(output.join("dependency-policy.json")).map_err(|error| {
            format!("cannot remove transient native dependency evidence: {error}")
        })?;
        in_process_gate(
            "divergence-prototypes",
            crate::compatibility::release_divergence_prototype_catalog(root),
            gates,
            evidence,
        )?;
    }
    require_executable_digest(
        &oracle_identity.path,
        oracle_identity.sha256,
        "retained oracle",
    )?;
    collect_conformance_evidence(
        platform,
        plan,
        conformance_plan,
        root,
        output,
        gates,
        evidence,
        retained,
        &oracle_identity,
        oracle_source_sha256,
    )?;
    Ok(())
}

fn require_executable_digest(
    path: &Path,
    expected: hell_testkit::Digest,
    label: &str,
) -> Result<(), String> {
    let observed =
        hell_testkit::sha256_file(path).map_err(|error| format!("cannot hash {label}: {error}"))?;
    if observed != expected {
        return Err(format!("{label} changed after trusted acquisition"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_conformance_evidence(
    platform: ReleasePlatform,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    root: &Path,
    output: &Path,
    gates: &mut BTreeMap<&'static str, bool>,
    gate_evidence: &mut BTreeMap<String, JsonValue>,
    retained: &mut BTreeMap<String, Vec<u8>>,
    oracle: &hell_testkit::ExecutableIdentity,
    oracle_source_sha256: &str,
) -> Result<(), String> {
    let conformance_platform = crate::conformance::ConformancePlatform::parse(platform.id())?;
    let assigned = conformance_plan
        .cells
        .iter()
        .flat_map(|cell| {
            cell.obligations
                .iter()
                .map(move |obligation| (cell, obligation))
        })
        .filter(|(cell, obligation)| {
            matches!(
                cell.scope,
                crate::conformance::ScopeDisposition::Required { .. }
            ) && obligation_is_assigned(cell, obligation, conformance_platform)
        })
        .collect::<Vec<_>>();
    let assigned_obligations =
        crate::conformance::assigned_obligation_count(conformance_plan, conformance_platform)?;
    if assigned_obligations
        != u64::try_from(assigned.len()).map_err(|_| "assigned obligation count overflow")?
    {
        return Err("platform obligation assignment differs from trusted engine".to_owned());
    }
    let target = root
        .parent()
        .ok_or_else(|| "candidate root has no parent".to_owned())?
        .join("candidate-target");
    let candidate_path = target.join("release").join(platform.executable());
    require_real_binary_path(&target, &candidate_path)?;
    let candidate = hell_testkit::verify_executable(
        &candidate_path,
        hell_testkit::ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot bind conformance candidate executable: {error}"))?;
    let oracle_binding = crate::conformance::OracleBinding {
        repository: "chrisdone/hell".to_owned(),
        commit: "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff".to_owned(),
        executable_sha256: oracle.sha256.hex(),
        source_sha256: oracle_source_sha256.to_owned(),
    };
    let mut committed_case_list = hell_testkit::committed_differential_cases();
    bind_process_helper(&mut committed_case_list)?;
    let committed_cases = committed_case_list
        .into_iter()
        .map(|case| (case.id.to_string(), case))
        .collect::<BTreeMap<_, _>>();
    let requested_case_ids = assigned
        .iter()
        .flat_map(|(_, obligation)| obligation.case_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut observations = BTreeMap::<String, Vec<u8>>::new();
    let mut committed_observations = BTreeMap::<String, (String, String)>::new();
    for case_id in requested_case_ids {
        let case = committed_cases
            .get(&case_id)
            .ok_or_else(|| format!("planned committed case {case_id:?} is unavailable"))?;
        let report = collect_one_differential(oracle, &candidate, case)?;
        let oracle_digest = retain_observation(&report.oracle, &mut observations)?;
        let candidate_digest = retain_observation(&report.candidate, &mut observations)?;
        committed_observations.insert(case_id, (candidate_digest, oracle_digest));
    }
    let mut record_files = BTreeMap::<String, Vec<u8>>::new();
    let mut record_members = Vec::new();
    for (cell, obligation) in &assigned {
        for case_id in &obligation.case_ids {
            let case = committed_cases
                .get(case_id)
                .ok_or_else(|| format!("planned committed case {case_id:?} is unavailable"))?;
            let (candidate_observation_sha256, oracle_observation_sha256) = committed_observations
                .get(case_id)
                .ok_or_else(|| "committed observation was not collected".to_owned())?;
            let mut record = crate::conformance::EvidenceRecord {
                record_id: String::new(),
                release_plan_sha256: plan.plan_sha256.clone(),
                conformance_plan_sha256: conformance_plan.plan_sha256.clone(),
                candidate_sha: plan.resolution.candidate_sha.clone(),
                candidate_executable_sha256: candidate.sha256.hex(),
                source_inventory_sha256: plan.source_inventory_sha256.clone(),
                oracle: oracle_binding.clone(),
                platform: conformance_platform,
                profile: cell.key.profile,
                target: crate::conformance::EvidenceTarget {
                    cell: cell.key.clone(),
                    obligation_id: obligation.id.clone(),
                    case_id: case_id.clone(),
                },
                descriptor_sha256: hell_testkit::case_descriptor_sha256(case).hex(),
                case_source: crate::conformance::CaseSource::Committed,
                candidate_observation_sha256: candidate_observation_sha256.clone(),
                oracle_observation_sha256: oracle_observation_sha256.clone(),
                requested_normalizers: obligation.allowed_normalizers.clone(),
            };
            record.record_id = record.canonical_id()?;
            let bytes = canonical_json_bytes(&record.json())?;
            let path = format!("conformance-evidence/{}.json", record.record_id);
            record_members.push(crate::conformance::EvidenceMember {
                id: Some(record.record_id.clone()),
                path: path.clone(),
                sha256: hell_testkit::sha256_bytes(&bytes).hex(),
            });
            if record_files.insert(path, bytes).is_some() {
                return Err("conformance evidence record identity is duplicated".to_owned());
            }
        }
    }
    let mut exploratory_members = Vec::new();
    let mut unclassified_mismatches = 0_u64;
    for generated in hell_testkit::generated_typed_cases(
        crate::conformance::EXPLORATORY_GENERATOR_SEED,
        crate::conformance::EXPLORATORY_GENERATOR_COUNT,
    ) {
        let case = hell_testkit::DifferentialCase {
            id: generated.id.clone(),
            source: generated.source.clone(),
            ..hell_testkit::DifferentialCase::default()
        };
        let report = collect_one_differential(oracle, &candidate, &case)?;
        let oracle_observation_sha256 = retain_observation(&report.oracle, &mut observations)?;
        let candidate_observation_sha256 =
            retain_observation(&report.candidate, &mut observations)?;
        if candidate_observation_sha256 != oracle_observation_sha256 {
            unclassified_mismatches = unclassified_mismatches
                .checked_add(1)
                .ok_or_else(|| "unclassified mismatch count overflow".to_owned())?;
        }
        let record = crate::conformance::ExploratoryRecord {
            generated_case_id: generated.id.to_string(),
            platform: conformance_platform,
            generator_version: crate::conformance::EXPLORATORY_GENERATOR_VERSION.to_owned(),
            seed: generated.seed,
            source_sha256: hell_testkit::sha256_bytes(generated.source.as_bytes()).hex(),
            ast_sha256: generated.ast_sha256.hex(),
            release_plan_sha256: plan.plan_sha256.clone(),
            conformance_plan_sha256: conformance_plan.plan_sha256.clone(),
            candidate_sha: plan.resolution.candidate_sha.clone(),
            candidate_executable_sha256: candidate.sha256.hex(),
            source_inventory_sha256: plan.source_inventory_sha256.clone(),
            oracle: oracle_binding.clone(),
            candidate_observation_sha256,
            oracle_observation_sha256,
        };
        let id = record.canonical_id()?;
        let bytes = canonical_json_bytes(&record.json()?)?;
        let path = format!("conformance-evidence/{id}.json");
        exploratory_members.push(crate::conformance::EvidenceMember {
            id: Some(id),
            path: path.clone(),
            sha256: hell_testkit::sha256_bytes(&bytes).hex(),
        });
        if record_files.insert(path, bytes).is_some() {
            return Err("exploratory evidence record identity is duplicated".to_owned());
        }
    }
    require_executable_digest(&oracle.path, oracle.sha256, "retained oracle")?;
    require_executable_digest(&candidate.path, candidate.sha256, "candidate executable")?;
    let mut observation_members = observations
        .iter()
        .map(|(digest, bytes)| crate::conformance::EvidenceMember {
            id: None,
            path: format!("conformance-observations/{digest}.json"),
            sha256: hell_testkit::sha256_bytes(bytes).hex(),
        })
        .collect::<Vec<_>>();
    record_members.sort_by(|left, right| left.path.cmp(&right.path));
    exploratory_members.sort_by(|left, right| left.path.cmp(&right.path));
    observation_members.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = crate::conformance::EvidenceManifest::new(
        conformance_platform,
        plan.resolution.candidate_sha.clone(),
        candidate.sha256.hex(),
        plan.plan_sha256.clone(),
        conformance_plan.plan_sha256.clone(),
        oracle_binding,
        record_members,
        exploratory_members,
        observation_members,
        assigned_obligations,
    )?;
    for (path, bytes) in record_files {
        write_atomic(&output.join(&path), &bytes)?;
        retained.insert(path, bytes);
    }
    for (digest, bytes) in observations {
        let path = format!("conformance-observations/{digest}.json");
        write_atomic(&output.join(&path), &bytes)?;
        retained.insert(path, bytes);
    }
    let manifest_bytes = canonical_json_bytes(&manifest.json())?;
    write_atomic(
        &output.join("conformance-evidence-manifest.json"),
        &manifest_bytes,
    )?;
    retained.insert(
        "conformance-evidence-manifest.json".to_owned(),
        manifest_bytes,
    );
    gates.insert("conformance-evidence", true);
    gate_evidence.insert(
        "conformance-evidence".to_owned(),
        object([
            ("assignedObligations", number(assigned_obligations)),
            ("candidateExecutableSha256", string(&candidate.sha256.hex())),
            (
                "exploratoryRecords",
                number(
                    u64::try_from(manifest.exploratory_records.len())
                        .map_err(|_| "exploratory record count overflow")?,
                ),
            ),
            ("manifestSha256", string(&manifest.manifest_sha256)),
            (
                "oracleCommit",
                string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff"),
            ),
            ("oracleExecutableSha256", string(&oracle.sha256.hex())),
            ("oracleRepository", string("chrisdone/hell")),
            ("oracleSourceSha256", string(oracle_source_sha256)),
            ("producedRecords", number(manifest.produced_records)),
            ("schemaVersion", number(1)),
            ("state", string("collected")),
            ("unclassifiedMismatches", number(unclassified_mismatches)),
        ]),
    );
    Ok(())
}

fn obligation_is_assigned(
    cell: &crate::conformance::PlannedCell,
    obligation: &crate::conformance::PlannedObligation,
    platform: crate::conformance::ConformancePlatform,
) -> bool {
    match obligation.strategy {
        crate::conformance::EvidenceStrategy::NativeOracle
        | crate::conformance::EvidenceStrategy::CommittedDifferentialCorpus => {
            cell.key.platform == platform
        }
        crate::conformance::EvidenceStrategy::PortableStatic
        | crate::conformance::EvidenceStrategy::StructuralInvariant => {
            platform == crate::conformance::ConformancePlatform::LinuxX86_64
        }
        crate::conformance::EvidenceStrategy::CrossPlatformRelation => false,
    }
}

fn collect_one_differential(
    oracle: &hell_testkit::ExecutableIdentity,
    candidate: &hell_testkit::ExecutableIdentity,
    case: &hell_testkit::DifferentialCase,
) -> Result<hell_testkit::DifferentialReport, String> {
    require_executable_digest(&oracle.path, oracle.sha256, "retained oracle")?;
    require_executable_digest(&candidate.path, candidate.sha256, "candidate executable")?;
    let result = hell_testkit::differential_with_identities(oracle, candidate, case);
    require_executable_digest(&oracle.path, oracle.sha256, "retained oracle")?;
    require_executable_digest(&candidate.path, candidate.sha256, "candidate executable")?;
    result.map_err(|error| format!("cannot collect differential case {:?}: {error}", case.id))
}

fn bind_process_helper(cases: &mut [hell_testkit::DifferentialCase]) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate trusted release driver: {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "trusted release driver has no directory".to_owned())?;
    let profile = if directory.file_name().is_some_and(|name| name == "deps") {
        directory.parent().unwrap_or(directory)
    } else {
        directory
    };
    hell_testkit::bind_process_helper_directory(cases, profile)
        .map(|_| ())
        .map_err(|error| format!("cannot bind trusted differential helper: {error}"))
}

fn require_source_inventory(root: &Path, expected: &str) -> Result<(), String> {
    let observed = source_inventory(root)?;
    let digest = hell_testkit::sha256_bytes(&canonical_json_bytes(&observed)?).hex();
    if digest != expected {
        return Err("candidate source inventory changed during candidate execution".to_owned());
    }
    Ok(())
}

fn retain_observation(
    observation: &hell_testkit::Observation,
    observations: &mut BTreeMap<String, Vec<u8>>,
) -> Result<String, String> {
    let bytes = hell_testkit::canonical_conformance_observation_json(observation)
        .map_err(|error| format!("cannot encode bounded conformance observation: {error}"))?;
    let parsed = crate::conformance::Observation::parse_canonical(bytes.clone())?;
    match observations.entry(parsed.sha256.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(bytes);
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &bytes => {}
        std::collections::btree_map::Entry::Occupied(_) => {
            return Err("observation digest collision has contradictory bytes".to_owned());
        }
    }
    Ok(parsed.sha256)
}

fn acquire_linux_oracle(output: &Path) -> Result<PathBuf, String> {
    const URL: &str =
        "https://github.com/chrisdone/hell/releases/download/2026-05-29/hell-linux-amd64";
    const SHA256: &str = "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9";
    const MAX_ORACLE_BYTES: u64 = 64 * 1024 * 1024;
    fs::create_dir_all(output)
        .map_err(|error| format!("cannot create Linux oracle directory: {error}"))?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_mins(5)))
        .build();
    let agent: ureq::Agent = config.into();
    let mut response = agent
        .get(URL)
        .header("Accept", "application/octet-stream")
        .header("User-Agent", "hell-ci-release-oracle")
        .call()
        .map_err(|_| "pinned Linux oracle download failed".to_owned())?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "pinned Linux oracle returned HTTP {}",
            response.status().as_u16()
        ));
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_ORACLE_BYTES)
        .read_to_vec()
        .map_err(|error| format!("cannot read bounded Linux oracle response: {error}"))?;
    if bytes.is_empty() || hell_testkit::sha256_bytes(&bytes).hex() != SHA256 {
        return Err("pinned Linux oracle digest differs".to_owned());
    }
    let path = output.join("hell-linux-amd64");
    write_atomic(&path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot set Linux oracle executable mode: {error}"))?;
    }
    Ok(path)
}

fn prepare_oracle(
    platform: ReleasePlatform,
    oracle_source: &Path,
    candidate_root: &Path,
    candidate_target: &Path,
) -> Result<hell_testkit::ExecutableIdentity, String> {
    if platform == ReleasePlatform::LinuxX86_64 {
        let oracle = acquire_linux_oracle(&transient_path(candidate_root, "oracle-acquisition"))?;
        let identity = hell_testkit::verify_executable(
            &oracle,
            hell_testkit::ExecutableRole::Oracle,
            Some(
                hell_testkit::Digest::from_hex(
                    "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9",
                )
                .map_err(str::to_owned)?,
            ),
            hell_builtins::LANGUAGE_VERSION,
        )
        .map_err(|error| format!("cannot prepare pinned Linux oracle: {error}"))?;
        return retain_oracle_copy(candidate_root, identity);
    }
    let build = CommandSpec::new("stack", Duration::from_hours(2))
        .arguments([
            "build",
            "--stack-yaml",
            "stack.yaml",
            "--locked",
            "--work-dir",
        ])
        .argument(candidate_target.join("oracle-stack-work").as_os_str())
        .current_directory(oracle_source);
    let result = build
        .run()
        .map_err(|error| format!("cannot build native oracle: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("native oracle build failed before candidate execution".to_owned());
    }
    let path = CommandSpec::new("stack", Duration::from_mins(5))
        .arguments([
            "path",
            "--stack-yaml",
            "stack.yaml",
            "--local-install-root",
            "--work-dir",
        ])
        .argument(candidate_target.join("oracle-stack-work").as_os_str())
        .current_directory(oracle_source);
    let result = path
        .run()
        .map_err(|error| format!("cannot resolve native oracle: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("native oracle path lookup failed".to_owned());
    }
    let install_root = std::str::from_utf8(&result.stdout)
        .map_err(|_| "native oracle path is not UTF-8".to_owned())?
        .trim();
    let executable = PathBuf::from(install_root)
        .join("bin")
        .join(format!("hell{}", std::env::consts::EXE_SUFFIX));
    let identity = hell_testkit::verify_executable(
        &executable,
        hell_testkit::ExecutableRole::Oracle,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot prepare native oracle: {error}"))?;
    retain_oracle_copy(candidate_root, identity)
}

fn retain_oracle_copy(
    candidate_root: &Path,
    identity: hell_testkit::ExecutableIdentity,
) -> Result<hell_testkit::ExecutableIdentity, String> {
    let retained_root = transient_path(candidate_root, "retained-oracle");
    if retained_root.exists() {
        return Err("retained oracle directory already exists".to_owned());
    }
    fs::create_dir_all(&retained_root)
        .map_err(|error| format!("cannot create retained oracle directory: {error}"))?;
    let bytes = read_regular(&identity.path)?;
    let retained = retained_root.join(format!("hell{}", std::env::consts::EXE_SUFFIX));
    write_atomic(&retained, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&retained, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot set retained oracle mode: {error}"))?;
    }
    hell_testkit::verify_executable(
        &retained,
        hell_testkit::ExecutableRole::Oracle,
        Some(identity.sha256),
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot verify retained oracle copy: {error}"))
}

fn linux_rust_commands(root: &Path) -> Vec<(&'static str, CommandSpec)> {
    vec![
        (
            "format",
            cargo(root, Duration::from_mins(5), ["fmt", "--all", "--check"]),
        ),
        (
            "clippy",
            cargo(
                root,
                Duration::from_mins(30),
                [
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
        ),
        (
            "workspace-tests",
            cargo(
                root,
                Duration::from_hours(1),
                [
                    "test",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                ],
            ),
        ),
        (
            "documentation",
            cargo(
                root,
                Duration::from_mins(30),
                [
                    "doc",
                    "--workspace",
                    "--all-features",
                    "--no-deps",
                    "--locked",
                ],
            )
            .environment("RUSTDOCFLAGS", "-D warnings"),
        ),
        (
            "release-build",
            cargo(
                root,
                Duration::from_mins(30),
                [
                    "build",
                    "--release",
                    "--locked",
                    "--package",
                    "hell-cli",
                    "--bin",
                    "hell",
                ],
            ),
        ),
    ]
}

fn suite_examples(
    root: &Path,
    _output: &Path,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let mut report = Report::new("release-examples");
    crate::release_suite::examples(
        root,
        &mut report,
        &transient_path(root, "examples"),
        "release",
    )
    .map_err(|kind| format!("release examples failed: {kind:?}"))?;
    gates.insert("release-examples", true);
    evidence.insert("release-examples".to_owned(), suite_evidence(&report)?);
    Ok(())
}

fn suite_gate(
    name: &'static str,
    root: &Path,
    _output: &Path,
    run: fn(&Path, &mut Report, &Path) -> Result<(), crate::release_suite::FailureKind>,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let mut report = Report::new(name);
    run(root, &mut report, &transient_path(root, name))
        .map_err(|kind| format!("release gate {name} failed: {kind:?}"))?;
    gates.insert(name, true);
    evidence.insert(name.to_owned(), suite_evidence(&report)?);
    Ok(())
}

fn suite_evidence(report: &Report) -> Result<JsonValue, String> {
    Ok(object([
        ("report", parse_json(&report.to_json())?),
        ("schemaVersion", number(1)),
        ("state", string("passed")),
    ]))
}

fn transient_path(root: &Path, name: &str) -> PathBuf {
    root.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("release-gate-transient")
        .join(name)
}

fn command_gate(
    name: &'static str,
    command: CommandSpec,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let program = command.display_program();
    let arguments = command.display_arguments();
    let result = command
        .run()
        .map_err(|error| format!("release gate {name} could not run: {error}"))?;
    let passed = result.status.success() && !result.timed_out;
    evidence.insert(
        name.to_owned(),
        command_evidence(&program, &arguments, &result),
    );
    gates.insert(name, passed);
    passed
        .then_some(())
        .ok_or_else(|| format!("release gate {name} failed"))
}

fn command_evidence(program: &str, arguments: &[String], result: &CommandResult) -> JsonValue {
    object([
        (
            "arguments",
            JsonValue::Array(arguments.iter().map(|value| string(value)).collect()),
        ),
        ("program", string(program)),
        ("schemaVersion", number(1)),
        (
            "state",
            string(if result.status.success() && !result.timed_out {
                "passed"
            } else {
                "failed"
            }),
        ),
        ("stderrSha256", string(&result.stderr_sha256.hex())),
        ("stdoutSha256", string(&result.stdout_sha256.hex())),
    ])
}

fn in_process_gate(
    name: &'static str,
    result: Result<String, String>,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let detail = result?;
    gates.insert(name, true);
    evidence.insert(
        name.to_owned(),
        object([
            ("detail", string(&detail)),
            ("schemaVersion", number(1)),
            ("state", string("passed")),
        ]),
    );
    Ok(())
}

fn cargo<const N: usize>(root: &Path, timeout: Duration, arguments: [&str; N]) -> CommandSpec {
    CommandSpec::new("cargo", timeout)
        .arguments(arguments)
        .current_directory(root)
}

fn tool_identities(
    platform: ReleasePlatform,
    oracle_source: &Path,
    candidate_target: &Path,
) -> Result<BTreeMap<String, JsonValue>, String> {
    let mut identities = BTreeMap::new();
    for (name, command) in [
        (
            "cargo",
            CommandSpec::new("cargo", Duration::from_secs(30)).argument("--version"),
        ),
        (
            "rustc",
            CommandSpec::new("rustc", Duration::from_secs(30))
                .arguments(["--version", "--verbose"]),
        ),
        (
            "stack",
            CommandSpec::new("stack", Duration::from_secs(30)).argument("--numeric-version"),
        ),
    ] {
        identities.insert(name.to_owned(), string(&tool_output(command, name)?));
    }
    if identities
        .get("stack")
        .ok_or_else(|| "Stack identity is missing".to_owned())?
        .string()?
        != "3.11.1"
    {
        return Err("Stack version differs from release policy".to_owned());
    }
    if platform != ReleasePlatform::LinuxX86_64 {
        identities.insert(
            "ghc".to_owned(),
            string(&tool_output(
                CommandSpec::new("stack", Duration::from_mins(5))
                    .argument("--stack-yaml")
                    .argument(oracle_source.join("stack.yaml").as_os_str())
                    .argument("--work-dir")
                    .argument(candidate_target.join("oracle-stack-work").as_os_str())
                    .arguments(["exec", "--", "ghc", "--numeric-version"]),
                "ghc",
            )?),
        );
    }
    Ok(identities)
}

fn tool_output(command: CommandSpec, label: &str) -> Result<String, String> {
    let result = command
        .run()
        .map_err(|error| format!("cannot identify {label}: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err(format!("{label} identity command failed"));
    }
    let value = std::str::from_utf8(&result.stdout)
        .map_err(|_| format!("{label} identity is not UTF-8"))?
        .trim()
        .to_owned();
    if value.is_empty() {
        return Err(format!("{label} identity is empty"));
    }
    Ok(value)
}

fn validate_checkout(root: &Path, plan: &ReleasePlan) -> Result<(), String> {
    let observed = git_head(root)?;
    if observed != plan.resolution.candidate_sha {
        return Err("platform candidate checkout differs from plan".to_owned());
    }
    Ok(())
}

fn validate_runner(platform: ReleasePlatform) -> Result<(), String> {
    let expected = platform.runner();
    if env::var("RUNNER_OS").as_deref() != Ok(expected.0)
        || env::var("RUNNER_ARCH").as_deref() != Ok(expected.1)
    {
        return Err(format!("runner identity does not match {}", platform.id()));
    }
    Ok(())
}

fn validate_oracle(root: &Path) -> Result<(), String> {
    if git_head(root)? != "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff" {
        return Err("oracle source checkout differs from pinned commit".to_owned());
    }
    Ok(())
}

fn git_head(root: &Path) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(["rev-parse", "HEAD"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot verify checkout: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("git checkout identity command failed".to_owned());
    }
    Ok(std::str::from_utf8(&result.stdout)
        .map_err(|_| "checkout HEAD is not UTF-8".to_owned())?
        .trim()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::accept_conformance_plan_binding;

    #[cfg(unix)]
    use super::normalize_candidate_cache_tree;

    #[test]
    fn candidate_conformance_plan_substitution_is_rejected() {
        assert!(accept_conformance_plan_binding(true));
        assert!(!accept_conformance_plan_binding(false));
    }

    #[cfg(unix)]
    #[test]
    fn nested_restored_cache_is_made_writable_without_following_links() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = std::env::temp_dir().join(format!(
            "hell-restored-cache-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let nested = root.join("debug/deps");
        std::fs::create_dir_all(&nested).unwrap();
        let artifact = nested.join("artifact");
        std::fs::write(&artifact, b"cache\n").unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o644)).unwrap();
        normalize_candidate_cache_tree(&root).unwrap();
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o7777,
            0o2770
        );
        assert_eq!(
            std::fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
            0o660
        );
        let outside = root.with_extension("outside");
        std::fs::write(&outside, b"outside\n").unwrap();
        symlink(&outside, root.join("redirect")).unwrap();
        assert!(normalize_candidate_cache_tree(&root).is_err());
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_file(&outside).unwrap();
    }
}
