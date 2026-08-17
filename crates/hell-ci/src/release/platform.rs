use std::collections::{BTreeMap, BTreeSet};
use std::env;
#[cfg(unix)]
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(any(unix, windows))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::command::{CommandResult, CommandSpec, with_release_candidate_environment};
use crate::json::{JsonValue, canonical_json_bytes, json_member, parse_json};
use crate::report::Report;

use super::archive::{ArchiveInput, create, extract_binary};
use super::manifest::{read_json, read_regular, write_atomic, write_json};
use super::plan::{pinned_oracle_source_inventory, source_inventory};
use super::schema::{ReleasePlan, ReleasePlatform, expected_gates, number, object, string};

#[cfg(unix)]
static POSIX_ADAPTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
static POSIX_CARGO_SEED_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
static POSIX_CARGO_METADATA_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
static POSIX_STACK_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
const POSIX_RUSTUP_STAGE_ENTRY_LIMIT: usize = 100_000;

#[cfg(unix)]
const POSIX_RUSTUP_STAGE_BYTE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;

#[cfg(windows)]
static WINDOWS_TOOLCHAIN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
const WINDOWS_TOOLCHAIN_STAGE_ENTRY_LIMIT: usize = 100_000;

#[cfg(windows)]
const WINDOWS_TOOLCHAIN_STAGE_BYTE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;

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
    let runner_identity = validate_runner(platform)?;
    let oracle_inventory_before = pinned_oracle_source_inventory(&oracle_source)?;
    let oracle_inventory_digest =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&oracle_inventory_before)?).hex();
    // Retain and bind every trusted package input before establishing the
    // candidate principal. The POSIX confinement path copies this exact clean
    // checkout into a root-owned, read-only authority that the candidate can
    // traverse without gaining access to hosted-runner workspace ancestors.
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
    let mut confinement = establish_candidate_process_confinement(
        platform,
        &root,
        &oracle_source,
        &inventory,
        &oracle_inventory_before,
        &plan.resolution.candidate_sha,
        &target,
        &output,
    )?;
    let candidate_execution_root = confinement.candidate_root().to_path_buf();
    let oracle_execution_root = confinement.oracle_root().to_path_buf();
    write_atomic(&output.join("source-inventory.json"), &inventory_bytes)?;
    let (tools, unretained_oracle) = {
        let archive_adapter = crate::command::NativeArchiveAdapter::for_macos(
            platform == ReleasePlatform::MacosAarch64,
            confinement.archive_adapter_base(&target),
            &oracle_execution_root,
            confinement.archive_launcher(),
        )?;
        #[cfg(unix)]
        let archive_adapter_seal = (platform == ReleasePlatform::MacosAarch64)
            .then(|| {
                confinement.seal_archive_adapter_authority(
                    archive_adapter
                        .directory_path()
                        .ok_or_else(|| "macOS archive adapter directory is absent".to_owned())?,
                )
            })
            .transpose()?;
        #[cfg(unix)]
        let launch_policy = if platform == ReleasePlatform::MacosAarch64 {
            confinement
                .policy
                .clone()
                .with_posix_stack_work_authority(
                    &oracle_execution_root,
                    confinement.stack_work_authority()?,
                )
                .map_err(|error| format!("cannot bind native Stack work authority: {error}"))?
        } else {
            confinement.policy.clone()
        };
        #[cfg(not(unix))]
        let launch_policy = confinement.policy.clone();
        let result =
            hell_testkit::with_candidate_launch_policy(&launch_policy, || -> Result<_, String> {
                Ok((
                    tool_identities(
                        platform,
                        &candidate_execution_root,
                        &oracle_execution_root,
                        &archive_adapter,
                    )?,
                    prepare_oracle(platform, &oracle_execution_root, &output, &archive_adapter)?,
                ))
            });
        #[cfg(unix)]
        let restore = archive_adapter_seal
            .map(PosixArchiveAdapterSeal::restore)
            .transpose();
        drop(archive_adapter);
        #[cfg(unix)]
        restore?;
        result?
    };
    let prepared_oracle = confinement.retain_oracle(&unretained_oracle)?;
    unretained_oracle.cleanup()?;
    require_candidate_target(&root, &target)?;

    let mut gates = BTreeMap::from([
        ("runner-identity", true),
        ("candidate-checkout", true),
        ("oracle-checkout", true),
    ]);
    let mut evidence = BTreeMap::new();
    evidence.insert(
        "runner-identity".to_owned(),
        object([
            ("arch", string(&runner_identity.1)),
            ("os", string(&runner_identity.0)),
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
    let platform_gate_result = with_release_candidate_environment(
        &target,
        plan.source_date_epoch,
        &confinement.policy,
        || {
            run_platform_gates(
                platform,
                &plan,
                &conformance_plan,
                &candidate_execution_root,
                &oracle_execution_root,
                &output,
                &mut gates,
                &mut evidence,
                &mut retained_outputs,
                prepared_oracle,
                &oracle_inventory_digest,
            )
        },
    );
    confinement.cleanup_dependency_policy_cache()?;
    platform_gate_result?;
    confinement.require_bound_sources()?;
    require_source_inventory(&root, &plan.source_inventory_sha256)?;
    let oracle_inventory_after = pinned_oracle_source_inventory(&oracle_source)?;
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
    let smoke = with_release_candidate_environment(
        &target,
        plan.source_date_epoch,
        &confinement.policy,
        || {
            CommandSpec::new(unpacked.as_os_str(), Duration::from_secs(30))
                .argument("--help")
                .run()
        },
    )
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
    candidate_inventory: &JsonValue,
    oracle_inventory: &JsonValue,
    candidate_sha: &str,
    target: &Path,
    output: &Path,
) -> Result<CandidateConfinement, String> {
    let sudo = crate::command::resolve_absolute_standard_executable(Path::new("/usr/bin/sudo"))
        .map_err(|error| format!("cannot bind trusted sudo authority: {error}"))?
        .invocation_path()
        .to_path_buf();
    let chmod_path = posix_adapter_tool_paths(platform)?.chmod;
    let chmod = crate::command::resolve_absolute_standard_executable(Path::new(chmod_path))
        .map_err(|error| format!("cannot bind trusted chmod authority: {error}"))?;
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
    let id = crate::command::resolve_absolute_standard_executable(Path::new("/usr/bin/id"))
        .map_err(|error| format!("cannot bind trusted candidate identity authority: {error}"))?;
    for (option, label) in [("-u", "UID"), ("-g", "primary GID")] {
        require_exact_posix_candidate_identity(&id, option, &principal, uid, label)?;
    }
    let group_output =
        exact_posix_candidate_identity_output(&id, "-G", &principal, "complete group inventory")?;
    let candidate_group_ids =
        posix_candidate_group_inventory(&group_output, uid).ok_or_else(|| {
            "candidate complete group inventory is not canonical or omits the primary GID"
                .to_owned()
        })?;
    use std::os::unix::fs::MetadataExt as _;

    let trusted_checkout_metadata = fs::symlink_metadata(candidate_root)
        .map_err(|error| format!("cannot inspect trusted candidate checkout owner: {error}"))?;
    let trusted_owner = trusted_checkout_metadata.uid();
    let trusted_group = trusted_checkout_metadata.gid();
    if candidate_group_ids.contains(&trusted_group) {
        return Err(
            "candidate account unexpectedly belongs to the trusted runner group".to_owned(),
        );
    }
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("cannot resolve trusted POSIX adapter: {error}"))?;
    let adapter_protection = stage_posix_executable(platform, &sudo, &current_exe, "hell-ci")?;
    normalize_candidate_cache_with_adapter(&sudo, &adapter_protection, target, trusted_owner, uid)?;
    let cargo = crate::command::resolve_cargo_executable()?;
    let isolated = target.join("release-child-environment");
    for directory in [
        isolated.join("home"),
        isolated.join("cargo"),
        isolated.join("sccache"),
        isolated.join("tmp"),
    ] {
        fs::create_dir_all(&directory)
            .map_err(|error| format!("cannot create candidate writable root: {error}"))?;
    }
    normalize_candidate_cache_with_adapter(&sudo, &adapter_protection, target, trusted_owner, uid)?;
    let stack_root_protection = (platform == ReleasePlatform::MacosAarch64)
        .then(|| stage_posix_stack_root(platform, &sudo, &adapter_protection, uid, trusted_group))
        .transpose()?;
    for protected in [candidate_root, oracle_root] {
        if platform == ReleasePlatform::MacosAarch64 {
            trusted_tool_status(
                &sudo,
                &chmod,
                [
                    "-RN",
                    protected
                        .to_str()
                        .ok_or_else(|| "protected path is not UTF-8".to_owned())?,
                ],
            )?;
        }
        trusted_tool_status(
            &sudo,
            &chmod,
            [
                "-R",
                "a-w",
                protected
                    .to_str()
                    .ok_or_else(|| "protected path is not UTF-8".to_owned())?,
            ],
        )?;
    }
    set_posix_mode(output, 0o700)?;
    let cargo_authority = crate::command::resolve_posix_cargo_authority(&cargo, candidate_root)?;
    let rustup_authority = match &cargo_authority {
        crate::command::ResolvedPosixCargoAuthority::Native { .. } => None,
        crate::command::ResolvedPosixCargoAuthority::Rustup(authority) => Some(authority),
    };
    let rustup_protection = rustup_authority
        .map(|authority| stage_posix_rustup_authority(platform, &sudo, authority))
        .transpose()?;
    let source_protection = stage_posix_sources(
        platform,
        &sudo,
        candidate_root,
        oracle_root,
        candidate_inventory,
        oracle_inventory,
        candidate_sha,
        target,
        &group,
        trusted_owner,
        uid,
        trusted_group,
    )?;
    // The whole-target normalizer and protected source staging establish the
    // final candidate authorities. Materialize cargo-deny's cache and metadata
    // against that exact execution checkout so no hosted-workspace path leaks
    // into the candidate invocation.
    let cargo_deny_home_protection = (platform == ReleasePlatform::LinuxX86_64)
        .then(|| {
            stage_posix_cargo_deny_home(
                platform,
                &sudo,
                &adapter_protection,
                target,
                &source_protection.candidate,
                &cargo,
                uid,
                trusted_owner,
                trusted_group,
            )
        })
        .transpose()?;
    let cargo_protection =
        stage_posix_executable(platform, &sudo, cargo.canonical_identity(), "cargo")?;
    let stack = (platform == ReleasePlatform::MacosAarch64)
        .then(|| crate::command::resolve_standard_path_executable(std::ffi::OsStr::new("stack")))
        .transpose()
        .map_err(|error| format!("cannot bind required Stack authority: {error}"))?;
    let stack_protection = stack
        .as_ref()
        .map(|resolved| {
            stage_posix_executable(platform, &sudo, resolved.canonical_identity(), "stack")
        })
        .transpose()?;
    let cargo_deny = (platform == ReleasePlatform::LinuxX86_64)
        .then(|| {
            crate::command::resolve_standard_path_executable(std::ffi::OsStr::new("cargo-deny"))
        })
        .transpose()
        .map_err(|error| format!("cannot bind pinned cargo-deny authority: {error}"))?;
    let cargo_deny_protection = cargo_deny
        .as_ref()
        .map(|resolved| {
            stage_posix_executable(platform, &sudo, resolved.canonical_identity(), "cargo-deny")
        })
        .transpose()?;
    let candidate_identity = hell_testkit::PosixCandidateIdentity::new(
        principal.clone(),
        uid,
        uid,
        candidate_group_ids,
        group.clone(),
    )
    .map_err(|error| format!("cannot bind candidate account identity: {error}"))?;
    let mut launch_authorities = hell_testkit::PosixLaunchAuthorities::new(
        adapter_protection.adapter.clone(),
        adapter_protection.sha256,
        cargo.canonical_identity().to_path_buf(),
        cargo_protection.adapter.clone(),
        cargo_protection.sha256,
        posix_cargo_source_authority(&cargo_authority, rustup_protection.as_ref())?,
    );
    if let (Some(resolved), Some(protection)) = (&cargo_deny, &cargo_deny_protection) {
        let home_protection = cargo_deny_home_protection
            .as_ref()
            .ok_or_else(|| "Linux cargo-deny home authority is absent".to_owned())?;
        let metadata = fs::metadata(resolved.canonical_identity())
            .map_err(|error| format!("cannot inspect pinned cargo-deny authority: {error}"))?;
        let source_sha256 = hell_testkit::sha256_file(resolved.canonical_identity())
            .map_err(|error| format!("cannot hash pinned cargo-deny authority: {error}"))?;
        launch_authorities =
            launch_authorities.cargo_deny(hell_testkit::PosixCargoDenyAuthority::new(
                hell_testkit::PosixStandardExecutableIdentity::new(
                    resolved.invocation_path().to_path_buf(),
                    resolved.canonical_identity().to_path_buf(),
                    metadata.dev(),
                    metadata.ino(),
                ),
                source_sha256,
                protection.adapter.clone(),
                protection.sha256,
                home_protection.home.clone(),
                hell_testkit::PosixCargoDenyMetadataAuthority::new(
                    home_protection.metadata.directory.clone(),
                    home_protection.metadata.path.clone(),
                    home_protection.metadata.size,
                    home_protection.metadata.sha256,
                    home_protection.metadata.trusted_owner,
                ),
                hell_testkit::PosixCargoDenyCacheOwnership::new(trusted_owner, trusted_group),
            ));
    }
    if let (Some(resolved), Some(protection)) = (&stack, &stack_protection) {
        let metadata = fs::metadata(resolved.canonical_identity())
            .map_err(|error| format!("cannot inspect required Stack authority: {error}"))?;
        let source_sha256 = hell_testkit::sha256_file(resolved.canonical_identity())
            .map_err(|error| format!("cannot hash required Stack authority: {error}"))?;
        launch_authorities = launch_authorities.stack(hell_testkit::PosixStackAuthority::new(
            hell_testkit::PosixStandardExecutableIdentity::new(
                resolved.invocation_path().to_path_buf(),
                resolved.canonical_identity().to_path_buf(),
                metadata.dev(),
                metadata.ino(),
            ),
            source_sha256,
            protection.adapter.clone(),
            protection.sha256,
            stack_root_protection
                .as_ref()
                .ok_or_else(|| "macOS Stack-root authority is absent".to_owned())?
                .root
                .clone(),
            trusted_group,
        ));
    }
    let mut writable_roots = vec![target.to_path_buf(), source_protection.transient.clone()];
    if let Some(protection) = &stack_root_protection {
        writable_roots.push(protection.root.clone());
    }
    let policy = hell_testkit::CandidateLaunchPolicy::posix(
        sudo.clone(),
        launch_authorities,
        candidate_identity,
        writable_roots,
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
        _adapter_protection: adapter_protection,
        _cargo_protection: cargo_protection,
        _cargo_deny_protection: cargo_deny_protection,
        cargo_deny_home_protection,
        _stack_protection: stack_protection,
        stack_root_protection,
        _rustup_protection: rustup_protection,
        source_protection,
    })
}

#[cfg(unix)]
fn posix_cargo_source_authority(
    resolved: &crate::command::ResolvedPosixCargoAuthority,
    staged: Option<&PosixRustupProtection>,
) -> Result<hell_testkit::PosixCargoSourceAuthority, String> {
    match (resolved, staged) {
        (
            crate::command::ResolvedPosixCargoAuthority::Native {
                cargo,
                standard_rustup,
            },
            None,
        ) => Ok(hell_testkit::PosixCargoSourceAuthority::Native {
            cargo: hell_testkit::PosixCanonicalExecutableIdentity::new(
                cargo.canonical().to_path_buf(),
                cargo.device(),
                cargo.inode(),
            ),
            standard_rustup: hell_testkit::PosixStandardExecutableIdentity::new(
                standard_rustup.invocation().to_path_buf(),
                standard_rustup.canonical().to_path_buf(),
                standard_rustup.device(),
                standard_rustup.inode(),
            ),
        }),
        (crate::command::ResolvedPosixCargoAuthority::Rustup(_), Some(protection)) => {
            let proxy = &protection.proxy_identity;
            let rustc_standard = protection.rustc_authority.standard();
            let rustc_identity = hell_testkit::PosixStandardExecutableIdentity::new(
                rustc_standard.invocation().to_path_buf(),
                rustc_standard.canonical().to_path_buf(),
                rustc_standard.device(),
                rustc_standard.inode(),
            );
            let rustc_authority = match &protection.rustc_authority {
                crate::command::ResolvedPosixRustcAuthority::RustupProxy { .. } => {
                    hell_testkit::PosixRustcAuthority::RustupProxy(rustc_identity)
                }
                crate::command::ResolvedPosixRustcAuthority::SelectedToolchain { .. } => {
                    hell_testkit::PosixRustcAuthority::SelectedToolchain(rustc_identity)
                }
            };
            let source_rustc = protection
                .source_home
                .join("toolchains")
                .join(&protection.toolchain)
                .join("bin")
                .join("rustc");
            let staged_rustc = protection
                .home
                .join("toolchains")
                .join(&protection.toolchain)
                .join("bin")
                .join("rustc");
            let source_sha256 = hell_testkit::sha256_file(&source_rustc)
                .map_err(|error| format!("cannot hash source Rust compiler: {error}"))?;
            let staged_sha256 = hell_testkit::sha256_file(&staged_rustc)
                .map_err(|error| format!("cannot hash staged Rust compiler: {error}"))?;
            Ok(hell_testkit::PosixCargoSourceAuthority::Rustup(Box::new(
                hell_testkit::PosixRustupAuthority::new(
                    hell_testkit::PosixRustupProxyIdentity::new(
                        proxy.cargo_invocation().to_path_buf(),
                        proxy.cargo().to_path_buf(),
                        proxy.rustup_invocation().to_path_buf(),
                        proxy.rustup().to_path_buf(),
                        proxy.device(),
                        proxy.inode(),
                    ),
                    rustc_authority,
                    protection.source_home.clone(),
                    protection.home.clone(),
                    protection.toolchain.clone(),
                    hell_testkit::PosixRustupCompilerMapping::new(
                        source_rustc,
                        source_sha256,
                        staged_rustc,
                        staged_sha256,
                    ),
                ),
            )))
        }
        _ => Err("resolved and staged Rustup authorities disagree".to_owned()),
    }
}

#[cfg(unix)]
struct PosixAdapterProtection {
    platform: ReleasePlatform,
    installation_root: PathBuf,
    installation_root_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    adapter: PathBuf,
    adapter_identity: PosixObjectIdentity,
    sha256: hell_testkit::Digest,
    staged_name: &'static str,
    sudo: PathBuf,
    tools: PosixAdapterTools,
}

#[cfg(unix)]
struct PosixSourceProtection {
    platform: ReleasePlatform,
    installation_root: PathBuf,
    installation_root_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    candidate: PathBuf,
    oracle: PathBuf,
    stack_work: Option<PathBuf>,
    stack_work_identity: Option<PosixObjectIdentity>,
    stack_work_owner: u32,
    stack_work_group: u32,
    transient: PathBuf,
    archive_adapter: PathBuf,
    archive_adapter_identity: PosixObjectIdentity,
    archive_adapter_owner: u32,
    archive_adapter_group: u32,
    retained_oracle: PathBuf,
    retained_oracle_directory_identity: PosixObjectIdentity,
    retained_oracle_file: Option<PosixRetainedOracleFile>,
    candidate_inventory: JsonValue,
    oracle_inventory: JsonValue,
    candidate_sha: String,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    active: bool,
}

#[cfg(unix)]
struct PosixArchiveAdapterSeal<'a> {
    platform: ReleasePlatform,
    parent: PathBuf,
    parent_identity: PosixObjectIdentity,
    parent_owner: u32,
    parent_group: u32,
    adapter: PathBuf,
    adapter_identity: PosixObjectIdentity,
    work_directory: PathBuf,
    work_directory_identity: PosixObjectIdentity,
    source_parent: PathBuf,
    source_parent_identity: PosixObjectIdentity,
    source: PathBuf,
    source_identity: PosixObjectIdentity,
    stack_work: PathBuf,
    stack_work_identity: PosixObjectIdentity,
    stack_work_owner: u32,
    stack_work_group: u32,
    normalizer: &'a PosixAdapterProtection,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    active: bool,
}

#[cfg(unix)]
impl PosixArchiveAdapterSeal<'_> {
    fn restore(mut self) -> Result<(), String> {
        self.restore_inner()?;
        self.active = false;
        Ok(())
    }

    fn restore_inner(&self) -> Result<(), String> {
        let adapter_initial = require_posix_archive_adapter_transition_state(
            &self.parent,
            &self.parent_identity,
            self.parent_owner,
            self.parent_group,
            0o2550,
            &self.adapter,
            &self.adapter_identity,
            &self.work_directory,
            &self.work_directory_identity,
        );
        let stack_audit = (|| {
            if posix_object_identity(&self.source_parent)? != self.source_parent_identity
                || posix_object_identity(&self.source)? != self.source_identity
                || self.stack_work != self.source.join(".stack-work")
                || posix_object_identity(&self.stack_work)? != self.stack_work_identity
            {
                return Err("candidate Stack work authority changed before cleanup".to_owned());
            }
            self.normalize_stack_work()?;
            validate_posix_stack_root_post_state(
                &self.stack_work,
                self.stack_work_owner,
                self.stack_work_group,
            )
        })();
        let stack_cleanup = (|| {
            trusted_tool_status(
                &self.sudo,
                &self.tools.remove_file,
                [
                    "-rf",
                    "--",
                    path_text(&self.stack_work, "candidate Stack work cleanup")?,
                ],
            )?;
            match fs::symlink_metadata(&self.stack_work) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err("candidate Stack work cleanup was not exact".to_owned()),
            }
            require_clean_checkout(
                &self.source,
                crate::command::PINNED_ORACLE_SOURCE_COMMIT,
                "staged oracle",
            )?;
            require_posix_read_only_tree(&self.source, "staged oracle")
        })();
        let adapter_restore = (|| {
            trusted_tool_status(
                &self.sudo,
                &self.tools.chmod,
                posix_chmod_arguments(
                    self.platform,
                    "2770",
                    path_text(&self.parent, "native archive adapter authority")?,
                )?,
            )?;
            require_posix_archive_adapter_transition_state(
                &self.parent,
                &self.parent_identity,
                self.parent_owner,
                self.parent_group,
                0o2770,
                &self.adapter,
                &self.adapter_identity,
                &self.work_directory,
                &self.work_directory_identity,
            )
        })();
        adapter_initial?;
        stack_audit?;
        stack_cleanup?;
        adapter_restore
    }

    fn normalize_stack_work(&self) -> Result<(), String> {
        require_posix_adapter_unchanged(self.normalizer)?;
        if posix_object_identity(&self.source_parent)? != self.source_parent_identity
            || posix_object_identity(&self.source)? != self.source_identity
            || posix_object_identity(&self.stack_work)? != self.stack_work_identity
        {
            return Err("candidate Stack work authority changed before normalization".to_owned());
        }
        let values = [
            self.source_parent_identity.device.to_string(),
            self.source_parent_identity.inode.to_string(),
            self.source_identity.device.to_string(),
            self.source_identity.inode.to_string(),
            self.stack_work_identity.device.to_string(),
            self.stack_work_identity.inode.to_string(),
            self.stack_work_owner.to_string(),
            self.stack_work_group.to_string(),
        ];
        trusted_status(
            &self.sudo,
            [
                "-n",
                "--",
                path_text(&self.normalizer.adapter, "trusted Stack-work normalizer")?,
                "__release-normalize-stack-work",
                path_text(&self.source_parent, "candidate Stack-work parent authority")?,
                &values[0],
                &values[1],
                path_text(&self.source, "candidate Stack-work source authority")?,
                &values[2],
                &values[3],
                path_text(&self.stack_work, "candidate Stack-work authority")?,
                &values[4],
                &values[5],
                &values[6],
                &values[7],
            ],
        )?;
        require_posix_adapter_unchanged(self.normalizer)
    }
}

#[cfg(unix)]
impl Drop for PosixArchiveAdapterSeal<'_> {
    fn drop(&mut self) {
        if self.active && self.restore_inner().is_ok() {
            self.active = false;
        }
    }
}

#[cfg(unix)]
struct PosixRetainedOracleFile {
    path: PathBuf,
    identity: PosixObjectIdentity,
    sha256: hell_testkit::Digest,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixRustupInventoryEntry {
    relative: PathBuf,
    directory: bool,
    size: u64,
    sha256: Option<hell_testkit::Digest>,
    executable: bool,
}

#[cfg(unix)]
struct PosixRustupProtection {
    platform: ReleasePlatform,
    installation_root: PathBuf,
    installation_root_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    home: PathBuf,
    source_home: PathBuf,
    toolchain: OsString,
    proxy_identity: crate::command::ResolvedPosixRustupProxyIdentity,
    rustc_authority: crate::command::ResolvedPosixRustcAuthority,
    inventory: Vec<PosixRustupInventoryEntry>,
    sudo: PathBuf,
    tools: PosixAdapterTools,
}

#[cfg(unix)]
struct PosixCargoDenyHomeProtection {
    target: PathBuf,
    target_identity: PosixObjectIdentity,
    home: PathBuf,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
    advisory_lock: fs::File,
    metadata: PosixCargoDenyMetadataProtection,
    active: bool,
}

#[cfg(unix)]
struct PosixCargoDenyMetadataProtection {
    parent: PathBuf,
    parent_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    path: PathBuf,
    file_identity: PosixObjectIdentity,
    size: u64,
    sha256: hell_testkit::Digest,
    trusted_owner: u32,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    active: bool,
}

#[cfg(unix)]
struct PosixStackRootProtection {
    parent: PathBuf,
    parent_identity: PosixObjectIdentity,
    root: PathBuf,
    root_identity: PosixObjectIdentity,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    candidate_uid: u32,
    trusted_group_id: u32,
    active: bool,
}

#[cfg(unix)]
impl PosixStackRootProtection {
    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        if posix_object_identity(&self.parent)? != self.parent_identity
            || posix_object_identity(&self.root)? != self.root_identity
            || !posix_stack_root_is_exact(&self.root)
        {
            return Err("candidate Stack-root cleanup authority changed".to_owned());
        }
        let post_state = validate_posix_stack_root_post_state(
            &self.root,
            self.candidate_uid,
            self.trusted_group_id,
        );
        let cleanup = trusted_tool_status(
            &self.sudo,
            &self.tools.remove_file,
            [
                "-rf",
                "--",
                path_text(&self.root, "candidate Stack-root cleanup")?,
            ],
        );
        if cleanup.is_ok() {
            self.active = false;
        }
        cleanup?;
        post_state
    }
}

#[cfg(unix)]
impl Drop for PosixStackRootProtection {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(unix)]
impl PosixCargoDenyHomeProtection {
    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let home_cleanup = self.cleanup_home();
        let metadata_cleanup = self.metadata.cleanup();
        if home_cleanup.is_ok() && metadata_cleanup.is_ok() {
            self.active = false;
        }
        home_cleanup.and(metadata_cleanup)
    }

    fn cleanup_home(&self) -> Result<(), String> {
        if posix_object_identity(&self.target)? != self.target_identity
            || !posix_cargo_deny_home_is_exact(&self.target, &self.home)
        {
            Err("candidate cargo-deny home cleanup authority changed".to_owned())
        } else {
            let post_state = validate_posix_cargo_deny_home_post_state(
                &self.home,
                self.candidate_uid,
                self.trusted_owner,
                self.trusted_group_id,
                &self.advisory_lock,
            );
            trusted_tool_status(
                &self.sudo,
                &self.tools.remove_file,
                [
                    "-rf",
                    "--",
                    path_text(&self.home, "candidate cargo-deny home cleanup")?,
                ],
            )
            .and(post_state)
        }
    }
}

#[cfg(unix)]
impl PosixCargoDenyMetadataProtection {
    fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let file = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot inspect cargo-deny metadata authority: {error}"))?;
        if !self.active
            || validate_posix_adapter_installation_root(ReleasePlatform::LinuxX86_64, &self.parent)?
                != self.parent
            || posix_object_identity(&self.parent)? != self.parent_identity
            || !posix_cargo_deny_metadata_is_exact(&self.parent, &self.directory, &self.path)
            || posix_object_identity(&self.directory)? != self.directory_identity
            || posix_object_identity(&self.path)? != self.file_identity
            || self.directory_identity.owner != self.trusted_owner
            || self.directory_identity.mode != 0o555
            || file.file_type().is_symlink()
            || !file.is_file()
            || file.nlink() != 1
            || file.uid() != self.trusted_owner
            || file.permissions().mode() & 0o7777 != 0o444
            || file.len() != self.size
            || hell_testkit::sha256_file(&self.path)
                .map_err(|error| format!("cannot rehash cargo-deny metadata: {error}"))?
                != self.sha256
        {
            return Err("cargo-deny metadata authority changed".to_owned());
        }
        require_exact_directory_members(
            &self.directory,
            &[std::ffi::OsString::from("metadata.json")],
            "cargo-deny metadata authority",
        )?;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.validate()?;
        trusted_tool_status(
            &self.sudo,
            &self.tools.remove_file,
            [
                "-rf",
                "--",
                path_text(&self.directory, "cargo-deny metadata cleanup")?,
            ],
        )?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PosixCargoDenyMetadataProtection {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(unix)]
impl Drop for PosixCargoDenyHomeProtection {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(unix)]
fn stage_posix_cargo_deny_home(
    platform: ReleasePlatform,
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    target: &Path,
    candidate_root: &Path,
    cargo: &crate::command::ResolvedCargoExecutable,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
) -> Result<PosixCargoDenyHomeProtection, String> {
    let target_identity = posix_object_identity(target)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let environment_root = target.join("release-child-environment");
    fs::create_dir_all(&environment_root)
        .map_err(|error| format!("cannot reserve candidate environment root: {error}"))?;
    let home = environment_root.join("cargo-deny-cargo-home");
    if home.exists() {
        fs::remove_dir_all(&home)
            .map_err(|error| format!("cannot clear prior candidate cargo-deny home: {error}"))?;
    }
    fs::create_dir(&home)
        .map_err(|error| format!("cannot reserve candidate cargo-deny home: {error}"))?;
    let copy_result = (|| {
        let mut seed = TrustedCargoCacheSeed::create(platform)?;
        seed.fetch(cargo, candidate_root)?;
        let mut entries = 1_usize;
        let mut bytes = 0_u64;
        copy_posix_cargo_cache_tree(seed.root(), &home, &mut entries, &mut bytes)?;
        let metadata = seed.prove_staged_home_offline(cargo, candidate_root, &home)?;
        let advisory_lock = reserve_posix_cargo_deny_advisory_lock(&home)?;
        let metadata =
            stage_posix_cargo_deny_metadata(platform, sudo, &tools, &metadata, trusted_owner)?;
        normalize_posix_cargo_deny_home_with_adapter(
            sudo,
            adapter,
            &home,
            candidate_uid,
            trusted_owner,
            trusted_group_id,
        )?;
        seed.prove_staged_home_frozen_fetch(cargo, candidate_root, &home)?;
        validate_posix_cargo_deny_home_post_state(
            &home,
            candidate_uid,
            trusted_owner,
            trusted_group_id,
            &advisory_lock,
        )?;
        seed.cleanup()?;
        Ok((metadata, advisory_lock))
    })();
    let (metadata, advisory_lock) = match copy_result {
        Ok(authority) => authority,
        Err(error) => {
            if let Ok(home_text) = path_text(&home, "partial candidate cargo-deny home cleanup") {
                let _ = trusted_tool_status(sudo, &tools.remove_file, ["-rf", "--", home_text]);
            }
            return Err(error);
        }
    };
    Ok(PosixCargoDenyHomeProtection {
        target: target.to_path_buf(),
        target_identity,
        home,
        sudo: sudo.to_path_buf(),
        tools,
        candidate_uid,
        trusted_owner,
        trusted_group_id,
        advisory_lock,
        metadata,
        active: true,
    })
}

#[cfg(unix)]
fn reserve_posix_cargo_deny_advisory_lock(home: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::MetadataExt as _;

    let advisory_root = home.join("advisory-dbs");
    fs::create_dir_all(&advisory_root)
        .map_err(|error| format!("cannot reserve cargo-deny advisory root: {error}"))?;
    let lock = advisory_root.join("db.lock");
    if fs::symlink_metadata(&lock).is_ok() {
        fs::remove_file(&lock)
            .map_err(|error| format!("cannot replace staged cargo-deny advisory lock: {error}"))?;
    }
    let reserved_lock = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
        .map_err(|error| format!("cannot reserve cargo-deny advisory lock: {error}"))?;
    drop(reserved_lock);
    let lock_authority = fs::OpenOptions::new()
        .read(true)
        .open(&lock)
        .map_err(|error| format!("cannot bind cargo-deny advisory lock metadata: {error}"))?;
    let metadata = fs::symlink_metadata(&lock)
        .map_err(|error| format!("cannot inspect cargo-deny advisory lock: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err("cargo-deny advisory lock is not an exact regular file".to_owned());
    }
    Ok(lock_authority)
}

#[cfg(unix)]
fn stage_posix_cargo_deny_metadata(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    document: &[u8],
    trusted_owner: u32,
) -> Result<PosixCargoDenyMetadataProtection, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if platform != ReleasePlatform::LinuxX86_64 {
        return Err("cargo-deny metadata authority is only supported on Linux".to_owned());
    }
    let parent = posix_adapter_installation_root(platform)?;
    let parent_identity = posix_object_identity(&parent)?;
    let sequence = POSIX_CARGO_METADATA_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = parent.join(format!(
        "hell-cargo-deny-metadata-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot reserve cargo-deny metadata authority: {error}"))?;
    let path = directory.join("metadata.json");
    let prepare = (|| {
        fs::write(&path, document)
            .map_err(|error| format!("cannot write cargo-deny metadata authority: {error}"))?;
        let owner = trusted_owner.to_string();
        for entry in [&directory, &path] {
            trusted_tool_status(
                sudo,
                &tools.change_owner,
                [
                    owner.as_str(),
                    path_text(entry, "cargo-deny metadata owner")?,
                ],
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(
                platform,
                "0444",
                path_text(&path, "cargo-deny metadata document")?,
            )?,
        )?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(
                platform,
                "0555",
                path_text(&directory, "cargo-deny metadata directory")?,
            )?,
        )?;
        let directory_metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("cannot inspect cargo-deny metadata directory: {error}"))?;
        let file_metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect cargo-deny metadata document: {error}"))?;
        let size = u64::try_from(document.len())
            .map_err(|_| "cargo-deny metadata size exceeds u64".to_owned())?;
        let sha256 = hell_testkit::sha256_bytes(document);
        if posix_object_identity(&parent)? != parent_identity
            || !posix_cargo_deny_metadata_is_exact(&parent, &directory, &path)
            || directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.uid() != trusted_owner
            || directory_metadata.permissions().mode() & 0o7777 != 0o555
            || file_metadata.file_type().is_symlink()
            || !file_metadata.is_file()
            || file_metadata.nlink() != 1
            || file_metadata.uid() != trusted_owner
            || file_metadata.permissions().mode() & 0o7777 != 0o444
            || file_metadata.len() != size
            || hell_testkit::sha256_file(&path)
                .map_err(|error| format!("cannot hash cargo-deny metadata document: {error}"))?
                != sha256
        {
            return Err("cargo-deny metadata authority differs after staging".to_owned());
        }
        require_exact_directory_members(
            &directory,
            &[std::ffi::OsString::from("metadata.json")],
            "cargo-deny metadata authority",
        )?;
        Ok(PosixCargoDenyMetadataProtection {
            parent,
            parent_identity,
            directory: directory.clone(),
            directory_identity: posix_object_identity(&directory)?,
            path: path.clone(),
            file_identity: posix_object_identity(&path)?,
            size,
            sha256,
            trusted_owner,
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
            active: true,
        })
    })();
    if prepare.is_err() {
        if let Ok(directory_text) = path_text(&directory, "partial cargo-deny metadata cleanup") {
            let _ = trusted_tool_status(sudo, &tools.remove_file, ["-rf", "--", directory_text]);
        }
    }
    prepare
}

#[cfg(unix)]
fn stage_posix_stack_root(
    platform: ReleasePlatform,
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    candidate_uid: u32,
    trusted_group_id: u32,
) -> Result<PosixStackRootProtection, String> {
    if platform != ReleasePlatform::MacosAarch64 {
        return Err("candidate Stack root is only supported on macOS".to_owned());
    }
    require_posix_adapter_unchanged(adapter)?;
    let parent = posix_adapter_installation_root(platform)?;
    let parent_identity = posix_object_identity(&parent)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let sequence = POSIX_STACK_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = parent.join(format!("hell-stack-root-{}-{sequence}", std::process::id()));
    fs::create_dir(&root)
        .map_err(|error| format!("cannot reserve empty candidate Stack root: {error}"))?;
    let prepare_result = (|| {
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                platform,
                false,
                path_text(&root, "candidate Stack root ACL")?,
            )?,
        )?;
        normalize_posix_stack_root_with_adapter(
            sudo,
            adapter,
            &root,
            candidate_uid,
            trusted_group_id,
        )?;
        require_posix_adapter_unchanged(adapter)?;
        if posix_object_identity(&parent)? != parent_identity {
            return Err("candidate Stack-root parent authority changed".to_owned());
        }
        posix_object_identity(&root)
    })();
    let root_identity = match prepare_result {
        Ok(identity) => identity,
        Err(error) => {
            if let Ok(root_text) = path_text(&root, "partial candidate Stack-root cleanup") {
                let _ = trusted_tool_status(sudo, &tools.remove_file, ["-rf", "--", root_text]);
            }
            return Err(error);
        }
    };
    Ok(PosixStackRootProtection {
        parent,
        parent_identity,
        root,
        root_identity,
        sudo: sudo.to_path_buf(),
        tools,
        candidate_uid,
        trusted_group_id,
        active: true,
    })
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustedCargoSeedInputFile {
    identity: PosixObjectIdentity,
    size: u64,
    sha256: hell_testkit::Digest,
}

#[cfg(unix)]
impl TrustedCargoSeedInputFile {
    fn bind(root: &Path, name: &str) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect trusted Cargo seed {name}: {error}"))?;
        if fs::canonicalize(root).ok().as_deref() != Some(root)
            || path.parent() != Some(root)
            || fs::canonicalize(&path).ok().as_deref() != Some(path.as_path())
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
        {
            return Err(format!("trusted Cargo seed {name} is redirected or linked"));
        }
        Ok(Self {
            identity: posix_object_identity(&path)?,
            size: metadata.len(),
            sha256: hell_testkit::sha256_file(&path)
                .map_err(|error| format!("cannot hash trusted Cargo seed {name}: {error}"))?,
        })
    }
}

#[cfg(unix)]
struct TrustedCargoCacheSeed {
    root: PathBuf,
    identity: PosixObjectIdentity,
    active: bool,
}

#[cfg(unix)]
impl TrustedCargoCacheSeed {
    fn create(platform: ReleasePlatform) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = posix_adapter_installation_root(platform)?;
        let sequence = POSIX_CARGO_SEED_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!("hell-cargo-seed-{}-{sequence}", std::process::id()));
        fs::create_dir(&root)
            .map_err(|error| format!("cannot reserve trusted Cargo cache seed: {error}"))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot protect trusted Cargo cache seed: {error}"))?;
        let metadata = fs::symlink_metadata(&root)
            .map_err(|error| format!("cannot inspect trusted Cargo cache seed: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || fs::canonicalize(&root).ok().as_deref() != Some(root.as_path())
        {
            let _ = fs::remove_dir(&root);
            return Err("trusted Cargo cache seed differs from its private authority".to_owned());
        }
        let identity = match posix_object_identity(&root) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = fs::remove_dir(&root);
                return Err(error);
            }
        };
        Ok(Self {
            identity,
            root,
            active: true,
        })
    }

    fn vendor_root(&self) -> PathBuf {
        self.root.join("vendor")
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = self
            .root
            .parent()
            .ok_or_else(|| "trusted Cargo cache seed has no parent".to_owned())?;
        let name = self
            .root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();
        let metadata = fs::symlink_metadata(&self.root)
            .map_err(|error| format!("cannot revalidate trusted Cargo cache seed: {error}"))?;
        if !self.active
            || (parent != Path::new("/var/tmp") && parent != Path::new("/private/var/tmp"))
            || !name.starts_with("hell-cargo-seed-")
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || fs::canonicalize(&self.root).ok().as_deref() != Some(self.root.as_path())
            || posix_object_identity(&self.root)? != self.identity
        {
            return Err("trusted Cargo cache seed authority changed".to_owned());
        }
        Ok(())
    }

    fn fetch(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
    ) -> Result<(), String> {
        let manifest = candidate_root.join("Cargo.toml");
        let manifest_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.toml")?;
        let lock_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")?;
        let program_identity = hell_testkit::BoundProgramInvocation::new(
            cargo.invocation_path().to_path_buf(),
            cargo.canonical_identity().to_path_buf(),
        )
        .map_err(|error| format!("cannot bind trusted Cargo seed executable: {error}"))?;
        self.validate()?;
        self.run_cargo(
            cargo,
            candidate_root,
            trusted_cargo_cache_seed_arguments(candidate_root, &manifest)?,
            "fetch",
        )?;
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "fetch",
        )?;
        let metadata = self.run_cargo_with_home(
            cargo,
            candidate_root,
            trusted_cargo_cache_metadata_arguments(candidate_root, &manifest)?,
            "metadata materialization",
            &self.root,
        )?;
        if metadata.stdout_truncated
            || u64::try_from(metadata.stdout.len()).ok() != Some(metadata.stdout_bytes)
        {
            return Err("trusted Cargo metadata exceeds its capture authority".to_owned());
        }
        let metadata_path = self.root.join("hell-cargo-deny-metadata.json");
        if fs::symlink_metadata(&metadata_path).is_ok() {
            return Err("trusted cargo-deny metadata seed already exists".to_owned());
        }
        fs::write(&metadata_path, &metadata.stdout)
            .map_err(|error| format!("cannot write trusted cargo-deny metadata seed: {error}"))?;
        self.run_cargo_deny_advisories(cargo, candidate_root, &metadata_path)?;
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "advisory database materialization",
        )?;
        let vendor = self.vendor_root();
        if fs::symlink_metadata(&vendor).is_ok() {
            return Err("trusted Cargo vendor destination already exists".to_owned());
        }
        self.run_cargo(
            cargo,
            candidate_root,
            trusted_cargo_vendor_arguments(candidate_root, &manifest, &self.root, &vendor)?,
            "vendor materialization",
        )?;
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "vendor materialization",
        )?;
        validate_trusted_cargo_cache_tree(&vendor)?;
        let lock_document = fs::read(candidate_root.join("Cargo.lock"))
            .map_err(|error| format!("cannot read trusted Cargo lock: {error}"))?;
        if u64::try_from(lock_document.len()).ok() != Some(lock_identity.size)
            || TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")? != lock_identity
        {
            return Err("trusted Cargo lock changed during vendor materialization".to_owned());
        }
        validate_staged_vendor_covers_frozen_lock(&lock_document, &vendor)
    }

    fn run_cargo_deny_advisories(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        metadata: &Path,
    ) -> Result<(), String> {
        self.validate()?;
        let result = crate::command::CommandSpec::cargo_deny(Duration::from_mins(10))
            .arguments(trusted_cargo_deny_advisory_arguments(&self.root, metadata)?)
            .current_directory(candidate_root)
            .environment("CARGO", cargo.invocation_path().as_os_str().to_owned())
            .environment("CARGO_HOME", self.root.as_os_str())
            .environment("CARGO_TARGET_DIR", self.root.join("target"))
            .run()
            .map_err(|error| format!("cannot run trusted cargo-deny advisory seed: {error}"))?;
        if result.timed_out || !result.status.success() {
            return Err(format!(
                "trusted cargo-deny advisory seed failed with status {}",
                result.status.code().unwrap_or(1)
            ));
        }
        self.validate()
    }

    fn run_cargo(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        arguments: Vec<OsString>,
        operation: &str,
    ) -> Result<(), String> {
        self.run_cargo_with_home(cargo, candidate_root, arguments, operation, &self.root)
            .map(|_| ())
    }

    fn run_cargo_with_home(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        arguments: Vec<OsString>,
        operation: &str,
        cargo_home: &Path,
    ) -> Result<CommandResult, String> {
        self.validate()?;
        let result = crate::command::CommandSpec::trusted_cargo(Duration::from_secs(300), cargo)
            .arguments(arguments)
            .current_directory(candidate_root)
            .environment("CARGO_HOME", cargo_home.as_os_str())
            .environment("CARGO_TARGET_DIR", cargo_home.join("target"))
            .run()
            .map_err(|error| format!("cannot run trusted Cargo cache {operation}: {error}"))?;
        if result.timed_out || !result.status.success() {
            return Err(format!(
                "trusted Cargo cache {operation} failed with status {}",
                result.status.code().unwrap_or(1)
            ));
        }
        Ok(result)
    }

    fn prove_staged_home_offline(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        staged_home: &Path,
    ) -> Result<Vec<u8>, String> {
        let manifest = candidate_root.join("Cargo.toml");
        let manifest_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.toml")?;
        let lock_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")?;
        let program_identity = hell_testkit::BoundProgramInvocation::new(
            cargo.invocation_path().to_path_buf(),
            cargo.canonical_identity().to_path_buf(),
        )
        .map_err(|error| format!("cannot bind staged Cargo proof executable: {error}"))?;
        let staged_identity = posix_object_identity(staged_home)?;
        configure_staged_cargo_home_directory_source(staged_home)?;
        let result = self.run_cargo_with_home(
            cargo,
            candidate_root,
            trusted_cargo_cache_offline_metadata_arguments(candidate_root, &manifest)?,
            "staged offline metadata proof",
            staged_home,
        )?;
        if result.stdout_truncated
            || u64::try_from(result.stdout.len()).ok() != Some(result.stdout_bytes)
        {
            return Err("staged offline Cargo metadata exceeds its capture authority".to_owned());
        }
        if posix_object_identity(staged_home)? != staged_identity {
            return Err("staged Cargo home identity changed during offline proof".to_owned());
        }
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "staged offline metadata proof",
        )?;
        validate_trusted_cargo_cache_tree(staged_home)?;
        validate_staged_cargo_metadata(&result.stdout, candidate_root, staged_home)?;
        Ok(result.stdout)
    }

    fn prove_staged_home_frozen_fetch(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        staged_home: &Path,
    ) -> Result<(), String> {
        let manifest = candidate_root.join("Cargo.toml");
        let manifest_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.toml")?;
        let lock_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")?;
        let program_identity = hell_testkit::BoundProgramInvocation::new(
            cargo.invocation_path().to_path_buf(),
            cargo.canonical_identity().to_path_buf(),
        )
        .map_err(|error| format!("cannot bind staged frozen fetch executable: {error}"))?;
        let staged_identity = posix_object_identity(staged_home)?;
        self.run_cargo_with_home(
            cargo,
            candidate_root,
            trusted_cargo_cache_fetch_arguments(candidate_root, &manifest)?,
            "staged frozen fetch proof",
            staged_home,
        )?;
        if posix_object_identity(staged_home)? != staged_identity {
            return Err("staged Cargo home identity changed during frozen fetch proof".to_owned());
        }
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "staged frozen fetch proof",
        )?;
        validate_trusted_cargo_cache_tree(&staged_home.join("vendor"))
    }

    fn revalidate_inputs(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        manifest_identity: &TrustedCargoSeedInputFile,
        lock_identity: &TrustedCargoSeedInputFile,
        program_identity: &hell_testkit::BoundProgramInvocation,
        operation: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.toml")? != *manifest_identity
            || TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")? != *lock_identity
            || hell_testkit::BoundProgramInvocation::new(
                cargo.invocation_path().to_path_buf(),
                cargo.canonical_identity().to_path_buf(),
            )
            .map_err(|error| format!("cannot rebind trusted Cargo seed executable: {error}"))?
                != *program_identity
        {
            return Err(format!(
                "trusted Cargo cache seed authority changed during {operation}"
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        self.validate()?;
        fs::remove_dir_all(&self.root)
            .map_err(|error| format!("cannot remove trusted Cargo cache seed: {error}"))?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for TrustedCargoCacheSeed {
    fn drop(&mut self) {
        if self.active {
            let _ = self.cleanup();
        }
    }
}

#[cfg(unix)]
fn trusted_cargo_cache_seed_arguments(
    candidate_root: &Path,
    manifest: &Path,
) -> Result<Vec<OsString>, String> {
    if !candidate_root.is_absolute()
        || candidate_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || manifest != candidate_root.join("Cargo.toml")
    {
        return Err("trusted Cargo cache seed manifest is not exact".to_owned());
    }
    Ok(vec![
        OsString::from("fetch"),
        OsString::from("--locked"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
    ])
}

#[cfg(unix)]
fn trusted_cargo_cache_metadata_arguments(
    candidate_root: &Path,
    manifest: &Path,
) -> Result<Vec<OsString>, String> {
    if !candidate_root.is_absolute()
        || candidate_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || manifest != candidate_root.join("Cargo.toml")
    {
        return Err("trusted Cargo cache metadata manifest is not exact".to_owned());
    }
    Ok(vec![
        OsString::from("metadata"),
        OsString::from("--locked"),
        OsString::from("--all-features"),
        OsString::from("--format-version"),
        OsString::from("1"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
    ])
}

#[cfg(unix)]
fn trusted_cargo_cache_offline_metadata_arguments(
    candidate_root: &Path,
    manifest: &Path,
) -> Result<Vec<OsString>, String> {
    let mut arguments = trusted_cargo_cache_metadata_arguments(candidate_root, manifest)?;
    arguments.insert(2, OsString::from("--offline"));
    Ok(arguments)
}

#[cfg(unix)]
fn trusted_cargo_cache_fetch_arguments(
    candidate_root: &Path,
    manifest: &Path,
) -> Result<Vec<OsString>, String> {
    if !candidate_root.is_absolute()
        || candidate_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || manifest != candidate_root.join("Cargo.toml")
    {
        return Err("trusted Cargo cache fetch manifest is not exact".to_owned());
    }
    // cargo-deny 0.20.2 always shells out to exactly this frozen fetch shape
    // while checking, even when `--metadata-path` supplies a pre-captured
    // document. Keep the redundant explicit flags in their observed order so
    // the proof exercises the hosted child's argv rather than an equivalent
    // command that happens to share `--frozen`.
    Ok(vec![
        OsString::from("fetch"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
        OsString::from("--frozen"),
        OsString::from("--locked"),
        OsString::from("--offline"),
    ])
}

#[cfg(unix)]
const TRUSTED_CARGO_LOCK_PACKAGE_LIMIT: usize = 10_000;

#[cfg(unix)]
fn frozen_lock_registry_package(
    name: Option<String>,
    version: Option<String>,
    registry: bool,
) -> Result<Option<String>, String> {
    if !registry {
        return Ok(None);
    }
    let Some(name) = name else {
        return Err("frozen Cargo lock registry package has no name".to_owned());
    };
    let Some(version) = version else {
        return Err("frozen Cargo lock registry package has no version".to_owned());
    };
    if name.is_empty()
        || version.is_empty()
        || !name
            .bytes()
            .chain(version.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_+.".contains(&byte))
    {
        return Err("frozen Cargo lock package identity is not exact".to_owned());
    }
    Ok(Some(format!("{name}-{version}")))
}

#[cfg(unix)]
fn validate_staged_vendor_covers_frozen_lock(
    document: &[u8],
    vendor_root: &Path,
) -> Result<(), String> {
    const MAX_LOCK_BYTES: usize = 16 * 1024 * 1024;

    if document.is_empty() || document.len() > MAX_LOCK_BYTES {
        return Err("frozen Cargo lock exceeds its byte authority".to_owned());
    }
    let text =
        std::str::from_utf8(document).map_err(|_| "frozen Cargo lock is not UTF-8".to_owned())?;
    let mut registry_packages = BTreeSet::new();
    let mut packages = 0_usize;
    let mut name = None;
    let mut version = None;
    let mut registry = false;
    let mut in_package = false;
    for line in text.lines() {
        if line.starts_with("[[package]]") {
            in_package = true;
            packages += 1;
            if packages > TRUSTED_CARGO_LOCK_PACKAGE_LIMIT {
                return Err("frozen Cargo lock exceeds its package bound".to_owned());
            }
            if let Some(identity) = frozen_lock_registry_package(
                name.take(),
                version.take(),
                std::mem::take(&mut registry),
            )? {
                registry_packages.insert(identity);
            }
            continue;
        }
        if line.starts_with('[') {
            in_package = false;
            if let Some(identity) = frozen_lock_registry_package(
                name.take(),
                version.take(),
                std::mem::take(&mut registry),
            )? {
                registry_packages.insert(identity);
            }
            continue;
        }
        if !in_package || line.starts_with('#') {
            continue;
        }
        if let Some(value) = line.strip_prefix("name = \"") {
            name = Some(value.trim_end_matches('"').to_owned());
        } else if let Some(value) = line.strip_prefix("version = \"") {
            version = Some(value.trim_end_matches('"').to_owned());
        } else if let Some(value) = line.strip_prefix("source = \"") {
            registry = value.trim_end_matches('"').starts_with("registry+");
        }
    }
    if let Some(identity) =
        frozen_lock_registry_package(name.take(), version.take(), std::mem::take(&mut registry))?
    {
        registry_packages.insert(identity);
    }
    if packages == 0 || registry_packages.is_empty() {
        return Err("frozen Cargo lock registry inventory is empty".to_owned());
    }
    for identity in &registry_packages {
        let package = vendor_root.join(identity);
        if !package.is_dir() || !package.join(".cargo-checksum.json").is_file() {
            return Err(format!(
                "staged Cargo vendor closure omits frozen registry package {identity}"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_cargo_deny_advisory_arguments(
    cargo_home: &Path,
    metadata: &Path,
) -> Result<Vec<OsString>, String> {
    let expected = cargo_home.join("hell-cargo-deny-metadata.json");
    if !cargo_home.is_absolute()
        || cargo_home.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || metadata != expected
    {
        return Err("trusted cargo-deny advisory metadata seed is not exact".to_owned());
    }
    Ok(vec![
        OsString::from("--metadata-path"),
        metadata.as_os_str().to_owned(),
        OsString::from("--all-features"),
        OsString::from("check"),
        OsString::from("advisories"),
    ])
}

#[cfg(unix)]
fn validate_staged_cargo_metadata(
    document: &[u8],
    candidate_root: &Path,
    staged_home: &Path,
) -> Result<(), String> {
    const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;

    if document.is_empty() || document.len() > MAX_METADATA_BYTES {
        return Err("staged Cargo metadata document exceeds its byte authority".to_owned());
    }
    let text = std::str::from_utf8(document)
        .map_err(|_| "staged Cargo metadata document is not UTF-8".to_owned())?;
    let root = parse_json(text)?;
    let root = root.object()?;
    if json_member(root, "version")?.number()? != 1
        || Path::new(json_member(root, "workspace_root")?.string()?) != candidate_root
        || Path::new(json_member(root, "target_directory")?.string()?) != staged_home.join("target")
    {
        return Err("staged Cargo metadata root or schema differs from policy".to_owned());
    }
    let packages = validate_staged_cargo_metadata_packages(
        json_member(root, "packages")?.array()?,
        candidate_root,
        &staged_home.join("vendor"),
    )?;
    validate_staged_cargo_metadata_members(
        json_member(root, "workspace_members")?.array()?,
        &packages,
        "workspace members",
    )?;
    validate_staged_cargo_metadata_members(
        json_member(root, "workspace_default_members")?.array()?,
        &packages,
        "default workspace members",
    )
}

#[cfg(unix)]
fn validate_staged_cargo_metadata_packages(
    packages: &[JsonValue],
    candidate_root: &Path,
    vendor_root: &Path,
) -> Result<BTreeMap<String, bool>, String> {
    if packages.is_empty() {
        return Err("staged Cargo metadata package inventory is empty".to_owned());
    }
    let mut identities = BTreeMap::new();
    for package in packages {
        let package = package.object()?;
        let id = json_member(package, "id")?.string()?.to_owned();
        let manifest = Path::new(json_member(package, "manifest_path")?.string()?);
        let workspace = matches!(json_member(package, "source")?, JsonValue::Null);
        let authority = if workspace {
            candidate_root
        } else {
            vendor_root
        };
        if id.is_empty()
            || !manifest.is_absolute()
            || manifest.file_name() != Some(std::ffi::OsStr::new("Cargo.toml"))
            || manifest.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || !manifest.starts_with(authority)
            || fs::canonicalize(manifest).ok().as_deref() != Some(manifest)
            || identities.insert(id, workspace).is_some()
        {
            return Err("staged Cargo metadata package path or identity is not exact".to_owned());
        }
    }
    Ok(identities)
}

#[cfg(unix)]
fn validate_staged_cargo_metadata_members(
    members: &[JsonValue],
    packages: &BTreeMap<String, bool>,
    label: &str,
) -> Result<(), String> {
    let mut observed = BTreeSet::new();
    for member in members {
        let member = member.string()?;
        if !packages.get(member).copied().unwrap_or(false) || !observed.insert(member) {
            return Err(format!(
                "staged Cargo metadata {label} differ from package authority"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_cargo_vendor_arguments(
    candidate_root: &Path,
    manifest: &Path,
    seed_root: &Path,
    vendor: &Path,
) -> Result<Vec<OsString>, String> {
    if !candidate_root.is_absolute()
        || !seed_root.is_absolute()
        || candidate_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || seed_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || manifest != candidate_root.join("Cargo.toml")
        || vendor != seed_root.join("vendor")
    {
        return Err("trusted Cargo vendor authority is not exact".to_owned());
    }
    Ok(vec![
        OsString::from("vendor"),
        OsString::from("--locked"),
        OsString::from("--versioned-dirs"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
        vendor.as_os_str().to_owned(),
    ])
}

#[cfg(unix)]
fn configure_staged_cargo_home_directory_source(home: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let source = home.join("vendor");
    let metadata = fs::symlink_metadata(&source)
        .map_err(|error| format!("cannot inspect staged Cargo vendor root: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || source.parent() != Some(home)
        || fs::canonicalize(&source)
            .map_err(|error| format!("cannot canonicalize staged Cargo vendor root: {error}"))?
            != source
    {
        return Err("staged Cargo vendor root is redirected".to_owned());
    }
    let packages = fs::read_dir(&source)
        .map_err(|error| format!("cannot enumerate staged Cargo vendor root: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect staged Cargo vendor package: {error}"))?;
    if packages.is_empty() {
        return Err("staged Cargo vendor root is empty".to_owned());
    }
    for package in packages {
        let package = package.path();
        let package_metadata = fs::symlink_metadata(&package)
            .map_err(|error| format!("cannot inspect staged Cargo vendor package: {error}"))?;
        let checksum = package.join(".cargo-checksum.json");
        let checksum_metadata = fs::symlink_metadata(&checksum)
            .map_err(|error| format!("cannot inspect staged Cargo vendor checksum: {error}"))?;
        if package_metadata.file_type().is_symlink()
            || !package_metadata.is_dir()
            || package.parent() != Some(source.as_path())
            || fs::canonicalize(&package).map_err(|error| {
                format!("cannot canonicalize staged Cargo vendor package: {error}")
            })? != package
            || checksum_metadata.file_type().is_symlink()
            || !checksum_metadata.is_file()
            || checksum_metadata.nlink() != 1
            || checksum.parent() != Some(package.as_path())
            || fs::canonicalize(&checksum).map_err(|error| {
                format!("cannot canonicalize staged Cargo vendor checksum: {error}")
            })? != checksum
        {
            return Err(
                "staged Cargo vendor package is not a direct checksummed directory".to_owned(),
            );
        }
    }
    let source_text = path_text(&source, "staged Cargo vendor root")?;
    if !source_text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
    {
        return Err("staged Cargo registry root is not safely representable in TOML".to_owned());
    }
    let config = home.join("config.toml");
    if fs::symlink_metadata(&config).is_ok() {
        return Err("staged Cargo home already contains a configuration file".to_owned());
    }
    fs::write(
        &config,
        format!(
            "[source.crates-io]\nreplace-with = 'hell-staged-registry'\n\n[source.hell-staged-registry]\ndirectory = '{source_text}'\n"
        ),
    )
    .map_err(|error| format!("cannot bind staged Cargo offline source: {error}"))
}

#[cfg(unix)]
fn validate_trusted_cargo_cache_tree(root: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect staged Cargo offline cache: {error}"))?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && metadata.nlink() != 1)
            || fs::canonicalize(&path)
                .map_err(|error| format!("cannot canonicalize staged Cargo cache: {error}"))?
                != path
        {
            return Err("staged Cargo offline cache contains an unbound entry".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "staged Cargo cache entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if metadata.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "staged Cargo cache byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("staged Cargo offline cache exceeds its resource bound".to_owned());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate staged Cargo offline cache: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read staged Cargo cache entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_posix_cargo_cache_tree(
    source: &Path,
    destination: &Path,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect trusted Cargo cache source: {error}"))?;
    if metadata.file_type().is_symlink()
        || (!metadata.is_dir() && !metadata.is_file())
        || (metadata.is_file() && metadata.nlink() != 1)
    {
        return Err("trusted Cargo cache contains a link, special file, or hard link".to_owned());
    }
    if fs::canonicalize(source)
        .map_err(|error| format!("cannot canonicalize trusted Cargo cache source: {error}"))?
        != source
    {
        return Err("trusted Cargo cache source is redirected".to_owned());
    }
    *entries = entries
        .checked_add(1)
        .ok_or_else(|| "trusted Cargo cache entry count overflowed".to_owned())?;
    if *entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT {
        return Err("trusted Cargo cache exceeds its entry bound".to_owned());
    }
    if metadata.is_dir() {
        fs::create_dir_all(destination)
            .map_err(|error| format!("cannot create staged Cargo cache directory: {error}"))?;
        let source_entries = fs::read_dir(source)
            .map_err(|error| format!("cannot enumerate trusted Cargo cache: {error}"))?
            .map(|entry| {
                entry
                    .map(|entry| (entry.file_name(), entry.path()))
                    .map_err(|error| format!("cannot read Cargo cache entry: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source_names = source_entries
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        for (name, path) in source_entries {
            copy_posix_cargo_cache_tree(&path, &destination.join(name), entries, bytes)?;
        }
        let after = fs::symlink_metadata(source)
            .map_err(|error| format!("cannot revalidate trusted Cargo cache directory: {error}"))?;
        let after_names = fs::read_dir(source)
            .map_err(|error| format!("cannot re-enumerate trusted Cargo cache: {error}"))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|error| format!("cannot reread Cargo cache entry: {error}"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if after.file_type().is_symlink()
            || !after.is_dir()
            || after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after_names != source_names
            || fs::canonicalize(destination).map_err(|error| {
                format!("cannot canonicalize staged Cargo cache directory: {error}")
            })? != destination
        {
            return Err("trusted Cargo cache directory changed during staging".to_owned());
        }
    } else {
        let source_sha256 = hell_testkit::sha256_file(source)
            .map_err(|error| format!("cannot hash trusted Cargo cache entry: {error}"))?;
        *bytes = bytes
            .checked_add(metadata.len())
            .ok_or_else(|| "trusted Cargo cache byte count overflowed".to_owned())?;
        if *bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("trusted Cargo cache exceeds its byte bound".to_owned());
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create staged Cargo cache parent: {error}"))?;
        }
        fs::copy(source, destination)
            .map_err(|error| format!("cannot copy trusted Cargo cache entry: {error}"))?;
        let after = fs::symlink_metadata(source)
            .map_err(|error| format!("cannot revalidate trusted Cargo cache entry: {error}"))?;
        let staged_sha256 = hell_testkit::sha256_file(destination)
            .map_err(|error| format!("cannot hash staged Cargo cache entry: {error}"))?;
        if after.file_type().is_symlink()
            || !after.is_file()
            || after.nlink() != 1
            || after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.len() != metadata.len()
            || hell_testkit::sha256_file(source)
                .map_err(|error| format!("cannot rehash trusted Cargo cache entry: {error}"))?
                != source_sha256
            || staged_sha256 != source_sha256
        {
            return Err("trusted Cargo cache entry changed during staging".to_owned());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_posix_cargo_deny_home_with_adapter(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    home: &Path,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
) -> Result<(), String> {
    require_posix_adapter_unchanged(adapter)?;
    let uid = candidate_uid.to_string();
    let trusted_owner = trusted_owner.to_string();
    let gid = trusted_group_id.to_string();
    trusted_status(
        sudo,
        [
            "-n",
            "--",
            path_text(&adapter.adapter, "trusted cargo-deny home normalizer")?,
            "__release-normalize-cargo-deny-home",
            path_text(home, "candidate cargo-deny home")?,
            &uid,
            &trusted_owner,
            &gid,
        ],
    )?;
    require_posix_adapter_unchanged(adapter)
}

#[cfg(unix)]
fn normalize_posix_stack_root_with_adapter(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    root: &Path,
    candidate_uid: u32,
    trusted_group_id: u32,
) -> Result<(), String> {
    require_posix_adapter_unchanged(adapter)?;
    let uid = candidate_uid.to_string();
    let gid = trusted_group_id.to_string();
    trusted_status(
        sudo,
        [
            "-n",
            "--",
            path_text(&adapter.adapter, "trusted Stack-root normalizer")?,
            "__release-normalize-stack-root",
            path_text(root, "candidate Stack root")?,
            &uid,
            &gid,
        ],
    )?;
    require_posix_adapter_unchanged(adapter)
}

#[cfg(unix)]
fn posix_cargo_deny_home_is_exact(target: &Path, home: &Path) -> bool {
    home == target
        .join("release-child-environment")
        .join("cargo-deny-cargo-home")
}

#[cfg(unix)]
fn posix_cargo_deny_metadata_is_exact(parent: &Path, directory: &Path, path: &Path) -> bool {
    let Some(name) = directory.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let Some((process, sequence)) = name
        .strip_prefix("hell-cargo-deny-metadata-")
        .and_then(|suffix| suffix.split_once('-'))
    else {
        return false;
    };
    let canonical_number = |value: &str| {
        value
            .parse::<u64>()
            .is_ok_and(|number| value == number.to_string())
    };
    parent == Path::new("/var/tmp")
        && directory.parent() == Some(parent)
        && canonical_number(process)
        && canonical_number(sequence)
        && path == directory.join("metadata.json")
}

#[cfg(unix)]
fn posix_stack_root_is_exact(root: &Path) -> bool {
    let Some(name) = root.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let Some((process, sequence)) = name
        .strip_prefix("hell-stack-root-")
        .and_then(|suffix| suffix.split_once('-'))
    else {
        return false;
    };
    let canonical_number = |value: &str| {
        value
            .parse::<u64>()
            .is_ok_and(|number| value == number.to_string())
    };
    root.parent() == Some(Path::new("/private/var/tmp"))
        && canonical_number(process)
        && canonical_number(sequence)
}

#[cfg(unix)]
fn validate_posix_cargo_deny_home_post_state(
    home: &Path,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
    advisory_lock: &fs::File,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![home.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    let advisory_root = Path::new("advisory-dbs");
    let mut found_advisory_root = false;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect final cargo-deny cache state: {error}"))?;
        let relative = path
            .strip_prefix(home)
            .map_err(|_| "final cargo-deny cache entry escapes its home".to_owned())?;

        if relative == advisory_root {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != candidate_uid
                || metadata.gid() != trusted_group_id
                || metadata.permissions().mode() & 0o7777 != 0o750
            {
                return Err(
                    "final cargo-deny cache identity or permissions differ from policy".to_owned(),
                );
            }
            found_advisory_root = true;
            entries = entries
                .checked_add(1)
                .ok_or_else(|| "final cargo-deny cache entry count overflowed".to_owned())?;
            if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT {
                return Err("final cargo-deny cache exceeds its resource bound".to_owned());
            }
            // The advisory root is candidate-controlled. The trusted reader
            // group can enumerate directory metadata for launch-policy
            // binding, while candidate-owned lock files remain unreadable to
            // it. Retain the lock descriptor so its final metadata can be
            // checked without opening candidate storage.
            continue;
        }

        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && metadata.nlink() != 1)
            || metadata.uid() != trusted_owner
            || metadata.gid() != trusted_group_id
            || metadata.permissions().mode() & 0o7777
                != if metadata.is_dir() { 0o555 } else { 0o444 }
        {
            return Err(
                "final cargo-deny cache identity or permissions differ from policy".to_owned(),
            );
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "final cargo-deny cache entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if metadata.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "final cargo-deny cache byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("final cargo-deny cache exceeds its resource bound".to_owned());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate final cargo-deny cache: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| {
                            format!("cannot read final cargo-deny cache entry: {error}")
                        })?
                        .path(),
                );
            }
        }
    }

    let lock_metadata = advisory_lock
        .metadata()
        .map_err(|error| format!("cannot inspect final cargo-deny advisory lock: {error}"))?;
    if lock_metadata.file_type().is_symlink()
        || !lock_metadata.is_file()
        || lock_metadata.nlink() != 1
        || lock_metadata.len() != 0
        || lock_metadata.uid() != candidate_uid
        || lock_metadata.gid() != trusted_group_id
        || lock_metadata.permissions().mode() & 0o7777 != 0o660
    {
        return Err("final cargo-deny cache identity or permissions differ from policy".to_owned());
    }
    entries = entries
        .checked_add(1)
        .ok_or_else(|| "final cargo-deny cache entry count overflowed".to_owned())?;
    if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT {
        return Err("final cargo-deny cache exceeds its resource bound".to_owned());
    }
    if !found_advisory_root {
        return Err("final cargo-deny advisory root authority is absent".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_posix_stack_root_post_state(
    root: &Path,
    candidate_uid: u32,
    trusted_group_id: u32,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect final Stack-root state: {error}"))?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && metadata.nlink() != 1)
            || metadata.uid() != candidate_uid
            || metadata.gid() != trusted_group_id
            || (metadata.is_dir() && metadata.permissions().mode() & 0o7777 != 0o750)
            || (metadata.is_file() && metadata.permissions().mode() & 0o7777 != 0o640)
        {
            return Err("final Stack-root identity or permissions differ from policy".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "final Stack-root entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if metadata.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "final Stack-root byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("final Stack root exceeds its resource bound".to_owned());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate final Stack root: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read final Stack-root entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
impl Drop for PosixRustupProtection {
    fn drop(&mut self) {
        let _ = cleanup_posix_rustup_authority(self);
    }
}

#[cfg(unix)]
fn stage_posix_rustup_authority(
    platform: ReleasePlatform,
    sudo: &Path,
    authority: &crate::command::ResolvedPosixRustupAuthority,
) -> Result<PosixRustupProtection, String> {
    let source_inventory = posix_rustup_selected_inventory(
        authority.home(),
        authority.toolchain(),
        "standard Rustup",
    )?;
    let installation_root = posix_adapter_installation_root(platform)?;
    let installation_root_identity = posix_object_identity(&installation_root)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let sequence = POSIX_ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = installation_root.join(format!(
        "hell-rs-posix-rustup-{}-{sequence}",
        std::process::id()
    ));
    let home = directory.join("rustup-home");
    let toolchains = home.join("toolchains");
    let update_hashes = home.join("update-hashes");
    let staged_toolchain = toolchains.join(authority.toolchain());
    let staged_settings = home.join("settings.toml");
    let staged_update_hash = update_hashes.join(authority.toolchain());
    let source_toolchain = authority
        .home()
        .join("toolchains")
        .join(authority.toolchain());
    let source_settings = authority.home().join("settings.toml");
    let source_update_hash = authority
        .home()
        .join("update-hashes")
        .join(authority.toolchain());

    trusted_tool_status(
        sudo,
        &tools.mkdir,
        [
            "-m",
            "0555",
            "--",
            path_text(&directory, "staged Rustup directory")?,
        ],
    )
    .map_err(|error| format!("cannot reserve staged Rustup authority: {error}"))?;
    if platform == ReleasePlatform::MacosAarch64 {
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                platform,
                false,
                path_text(&directory, "staged Rustup authority ACL")?,
            )?,
        )?;
    }
    let directory_identity = posix_object_identity(&directory)?;
    let result = (|| {
        for path in [&home, &toolchains, &update_hashes] {
            trusted_tool_status(
                sudo,
                &tools.mkdir,
                [
                    "-m",
                    "0555",
                    "--",
                    path_text(path, "staged Rustup directory")?,
                ],
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.copy,
            [
                "--",
                path_text(&source_settings, "standard Rustup settings")?,
                path_text(&staged_settings, "staged Rustup settings")?,
            ],
        )?;
        trusted_tool_status(
            sudo,
            &tools.copy,
            [
                "--",
                path_text(&source_update_hash, "standard Rustup update hash")?,
                path_text(&staged_update_hash, "staged Rustup update hash")?,
            ],
        )?;
        trusted_tool_status(
            sudo,
            &tools.copy,
            [
                "-R",
                "--",
                path_text(&source_toolchain, "standard Rustup toolchain")?,
                path_text(&staged_toolchain, "staged Rustup toolchain")?,
            ],
        )?;
        if platform == ReleasePlatform::MacosAarch64 {
            trusted_tool_status(
                sudo,
                &tools.chmod,
                posix_acl_removal_arguments(
                    platform,
                    true,
                    path_text(&home, "staged Rustup ACL authority")?,
                )?,
            )?;
        }
        for (path, label) in [
            (&staged_settings, "staged Rustup settings"),
            (&staged_update_hash, "staged Rustup update hash"),
        ] {
            trusted_tool_status(
                sudo,
                &tools.chmod,
                posix_chmod_arguments(platform, "0444", path_text(path, label)?)?,
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.chmod,
            [
                "-R",
                "a+rX",
                path_text(&staged_toolchain, "staged Rustup toolchain")?,
            ],
        )?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            [
                "-R",
                "a-w",
                path_text(&staged_toolchain, "staged Rustup toolchain")?,
            ],
        )?;
        let protection = PosixRustupProtection {
            platform,
            installation_root: installation_root.clone(),
            installation_root_identity: installation_root_identity.clone(),
            directory: directory.clone(),
            directory_identity: directory_identity.clone(),
            home: home.clone(),
            source_home: authority.home().to_path_buf(),
            toolchain: authority.toolchain().to_os_string(),
            proxy_identity: authority.proxy_identity().clone(),
            rustc_authority: authority.rustc_authority().clone(),
            inventory: source_inventory,
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
        };
        validate_posix_rustup_authority(&protection)?;
        Ok(protection)
    })();
    if result.is_err() {
        let _ = cleanup_posix_rustup_paths(
            platform,
            sudo,
            &tools,
            &installation_root,
            &installation_root_identity,
            &directory,
            &directory_identity,
        );
    }
    result
}

#[cfg(unix)]
fn validate_posix_rustup_authority(protection: &PosixRustupProtection) -> Result<(), String> {
    protection.proxy_identity.revalidate()?;
    protection
        .rustc_authority
        .revalidate(&protection.proxy_identity)?;
    if validate_posix_adapter_installation_root(protection.platform, &protection.installation_root)?
        != protection.installation_root
        || posix_object_identity(&protection.installation_root)?
            != protection.installation_root_identity
        || !posix_rustup_cleanup_is_exact(&protection.installation_root, &protection.directory)
        || posix_object_identity(&protection.directory)? != protection.directory_identity
        || protection.home != protection.directory.join("rustup-home")
    {
        return Err("staged Rustup authority identity changed".to_owned());
    }
    require_exact_directory_members(
        &protection.home,
        &[
            OsString::from("settings.toml"),
            OsString::from("toolchains"),
            OsString::from("update-hashes"),
        ],
        "staged Rustup home",
    )?;
    require_exact_directory_members(
        &protection.home.join("toolchains"),
        std::slice::from_ref(&protection.toolchain),
        "staged Rustup toolchains",
    )?;
    require_exact_directory_members(
        &protection.home.join("update-hashes"),
        std::slice::from_ref(&protection.toolchain),
        "staged Rustup update hashes",
    )?;
    require_posix_read_only_tree(&protection.home, "staged Rustup")?;
    if posix_rustup_selected_inventory(&protection.home, &protection.toolchain, "staged Rustup")?
        != protection.inventory
    {
        return Err("staged Rustup bytes or closed inventory changed".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn posix_rustup_selected_inventory(
    home: &Path,
    toolchain: &std::ffi::OsStr,
    label: &str,
) -> Result<Vec<PosixRustupInventoryEntry>, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![
        home.join("settings.toml"),
        home.join("toolchains"),
        home.join("toolchains").join(toolchain),
        home.join("update-hashes"),
        home.join("update-hashes").join(toolchain),
    ];
    let mut inventory = Vec::new();
    let mut bytes = 0_u64;
    let mut visited = BTreeSet::new();
    while let Some(path) = pending.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }
        let relative = path
            .strip_prefix(home)
            .map_err(|_| format!("{label} selected entry escapes its home"))?
            .to_path_buf();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {label} entry {relative:?}: {error}"))?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && metadata.nlink() != 1)
        {
            return Err(format!(
                "{label} selected inventory contains a symlink, special file, or hard link"
            ));
        }
        let directory = metadata.is_dir();
        let size = if directory { 0 } else { metadata.len() };
        let (next_entries, next_bytes) = posix_rustup_inventory_cost(inventory.len(), bytes, size)
            .ok_or_else(|| format!("{label} selected inventory exceeds its staging bound"))?;
        bytes = next_bytes;
        let sha256 = (!directory)
            .then(|| hell_testkit::sha256_file(&path))
            .transpose()
            .map_err(|error| format!("cannot hash {label} entry {relative:?}: {error}"))?;
        inventory.push(PosixRustupInventoryEntry {
            relative,
            directory,
            size,
            sha256,
            executable: !directory && metadata.permissions().mode() & 0o111 != 0,
        });
        debug_assert_eq!(inventory.len(), next_entries);
        if directory && path != home.join("toolchains") && path != home.join("update-hashes") {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate {label} entry: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read {label} entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    inventory.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(inventory)
}

#[cfg(unix)]
fn posix_rustup_inventory_cost(entries: usize, bytes: u64, next_size: u64) -> Option<(usize, u64)> {
    let entries = entries.checked_add(1)?;
    let bytes = bytes.checked_add(next_size)?;
    (entries <= POSIX_RUSTUP_STAGE_ENTRY_LIMIT && bytes <= POSIX_RUSTUP_STAGE_BYTE_LIMIT)
        .then_some((entries, bytes))
}

#[cfg(unix)]
fn require_exact_directory_members(
    directory: &Path,
    expected: &[OsString],
    label: &str,
) -> Result<(), String> {
    let observed = fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate {label}: {error}"))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|error| format!("cannot read {label} entry: {error}"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed != expected.iter().cloned().collect() {
        return Err(format!("{label} is not an exact closed inventory"));
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_posix_rustup_authority(protection: &PosixRustupProtection) -> Result<(), String> {
    validate_posix_rustup_authority(protection)?;
    cleanup_posix_rustup_paths(
        protection.platform,
        &protection.sudo,
        &protection.tools,
        &protection.installation_root,
        &protection.installation_root_identity,
        &protection.directory,
        &protection.directory_identity,
    )
}

#[cfg(unix)]
fn cleanup_posix_rustup_paths(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    installation_root: &Path,
    installation_root_identity: &PosixObjectIdentity,
    directory: &Path,
    directory_identity: &PosixObjectIdentity,
) -> Result<(), String> {
    if validate_posix_adapter_installation_root(platform, installation_root)? != installation_root
        || posix_object_identity(installation_root)? != *installation_root_identity
        || !posix_rustup_cleanup_is_exact(installation_root, directory)
        || posix_object_identity(directory)? != *directory_identity
    {
        return Err("staged Rustup cleanup authority changed".to_owned());
    }
    trusted_tool_status(
        sudo,
        &tools.remove_file,
        ["-rf", "--", path_text(directory, "staged Rustup cleanup")?],
    )
}

#[cfg(unix)]
fn posix_rustup_cleanup_is_exact(installation_root: &Path, directory: &Path) -> bool {
    directory.parent() == Some(installation_root)
        && directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hell-rs-posix-rustup-"))
}

#[cfg(unix)]
impl Drop for PosixSourceProtection {
    fn drop(&mut self) {
        let _ = cleanup_posix_sources(self);
    }
}

#[cfg(unix)]
fn stage_posix_sources(
    platform: ReleasePlatform,
    sudo: &Path,
    candidate_source: &Path,
    oracle_source: &Path,
    candidate_inventory: &JsonValue,
    oracle_inventory: &JsonValue,
    candidate_sha: &str,
    target: &Path,
    candidate_group: &str,
    trusted_owner: u32,
    candidate_uid: u32,
    trusted_group_id: u32,
) -> Result<PosixSourceProtection, String> {
    require_clean_checkout(candidate_source, candidate_sha, "candidate")?;
    require_clean_checkout(
        oracle_source,
        crate::command::PINNED_ORACLE_SOURCE_COMMIT,
        "oracle",
    )?;
    let installation_root = posix_adapter_installation_root(platform)?;
    let installation_root_identity = posix_object_identity(&installation_root)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let sequence = POSIX_ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = installation_root.join(format!(
        "hell-rs-posix-sources-{}-{sequence}-{}",
        std::process::id(),
        &candidate_sha[..12]
    ));
    let candidate = directory.join("candidate");
    let oracle = directory.join("oracle");
    let stack_work =
        (platform == ReleasePlatform::MacosAarch64).then(|| oracle.join(".stack-work"));
    let transient = directory.join("release-gate-transient");
    let archive_adapter = directory.join("archive-adapter");
    let retained_oracle = directory.join("retained-oracle");
    let directory_text = path_text(&directory, "POSIX source authority")?;
    let candidate_text = path_text(&candidate, "staged candidate source")?;
    let oracle_text = path_text(&oracle, "staged oracle source")?;
    let transient_text = path_text(&transient, "candidate transient authority")?;
    let archive_adapter_text = path_text(&archive_adapter, "native archive adapter authority")?;
    let retained_oracle_text = path_text(&retained_oracle, "retained oracle authority")?;
    let candidate_source_text = path_text(candidate_source, "candidate source")?;
    let oracle_source_text = path_text(oracle_source, "oracle source")?;

    trusted_tool_status(sudo, &tools.mkdir, ["-m", "0755", "--", directory_text])
        .map_err(|error| format!("cannot reserve POSIX source authority: {error}"))?;
    let reserved_directory_identity = posix_object_identity(&directory)?;
    let result = (|| {
        trusted_tool_status(
            sudo,
            &tools.copy,
            ["-R", "--", candidate_source_text, candidate_text],
        )?;
        trusted_tool_status(
            sudo,
            &tools.copy,
            ["-R", "--", oracle_source_text, oracle_text],
        )?;
        if let Some(stack_work) = &stack_work {
            trusted_tool_status(
                sudo,
                &tools.mkdir,
                [
                    "-m",
                    "0750",
                    "--",
                    path_text(stack_work, "candidate Stack work authority")?,
                ],
            )?;
        }
        trusted_tool_status(sudo, &tools.mkdir, ["-m", "2770", "--", transient_text])?;
        trusted_tool_status(
            sudo,
            &tools.mkdir,
            ["-m", "2770", "--", archive_adapter_text],
        )?;
        let trusted_owner_text = trusted_owner.to_string();
        trusted_tool_status(
            sudo,
            &tools.change_owner,
            [trusted_owner_text.as_str(), archive_adapter_text],
        )?;
        trusted_tool_status(
            sudo,
            &tools.change_group,
            [candidate_group, archive_adapter_text],
        )?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(platform, "2770", archive_adapter_text)?,
        )?;
        trusted_tool_status(
            sudo,
            &tools.mkdir,
            ["-m", "0555", "--", retained_oracle_text],
        )?;
        trusted_tool_status(sudo, &tools.change_group, [candidate_group, transient_text])?;
        if platform == ReleasePlatform::MacosAarch64 {
            for protected in [&candidate, &oracle] {
                trusted_tool_status(
                    sudo,
                    &tools.chmod,
                    posix_acl_removal_arguments(
                        platform,
                        true,
                        path_text(protected, "staged protected source")?,
                    )?,
                )?;
            }
        }
        for protected in [&candidate, &oracle] {
            trusted_tool_status(
                sudo,
                &tools.chmod,
                [
                    "-R",
                    "a+rX",
                    path_text(protected, "staged protected source")?,
                ],
            )?;
            trusted_tool_status(
                sudo,
                &tools.chmod,
                [
                    "-R",
                    "a-w",
                    path_text(protected, "staged protected source")?,
                ],
            )?;
        }
        if let Some(stack_work) = &stack_work {
            let candidate_uid = candidate_uid.to_string();
            let trusted_group_id = trusted_group_id.to_string();
            let stack_work_text = path_text(stack_work, "candidate Stack work authority")?;
            trusted_tool_status(
                sudo,
                &tools.change_owner,
                [candidate_uid.as_str(), stack_work_text],
            )?;
            trusted_tool_status(
                sudo,
                &tools.change_group,
                [trusted_group_id.as_str(), stack_work_text],
            )?;
            trusted_tool_status(
                sudo,
                &tools.chmod,
                posix_chmod_arguments(platform, "0750", stack_work_text)?,
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(platform, "0555", directory_text)?,
        )?;
        // This temporary path is never delegated to the candidate. Reserving it
        // early ensures a candidate cannot substitute the cleanup authority.
        if transient.parent() != Some(&directory)
            || archive_adapter.parent() != Some(&directory)
            || retained_oracle.parent() != Some(&directory)
            || target == transient
            || target == archive_adapter
            || target == retained_oracle
        {
            return Err("candidate transient source authority differs from policy".to_owned());
        }
        let protection = PosixSourceProtection {
            platform,
            installation_root: installation_root.clone(),
            installation_root_identity: installation_root_identity.clone(),
            directory: directory.clone(),
            directory_identity: posix_object_identity(&directory)?,
            candidate: candidate.clone(),
            oracle: oracle.clone(),
            stack_work: stack_work.clone(),
            stack_work_identity: stack_work
                .as_deref()
                .map(posix_object_identity)
                .transpose()?,
            stack_work_owner: candidate_uid,
            stack_work_group: trusted_group_id,
            transient: transient.clone(),
            archive_adapter: archive_adapter.clone(),
            archive_adapter_identity: posix_object_identity(&archive_adapter)?,
            archive_adapter_owner: trusted_owner,
            archive_adapter_group: candidate_uid,
            retained_oracle: retained_oracle.clone(),
            retained_oracle_directory_identity: posix_object_identity(&retained_oracle)?,
            retained_oracle_file: None,
            candidate_inventory: candidate_inventory.clone(),
            oracle_inventory: oracle_inventory.clone(),
            candidate_sha: candidate_sha.to_owned(),
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
            active: true,
        };
        validate_posix_sources(&protection)?;
        Ok(protection)
    })();
    if result.is_err() {
        let _ = cleanup_posix_source_paths(
            platform,
            sudo,
            &tools,
            &installation_root,
            &installation_root_identity,
            &directory,
            &posix_object_identity(&directory).unwrap_or(reserved_directory_identity),
        );
    }
    result
}

#[cfg(unix)]
fn validate_posix_sources(protection: &PosixSourceProtection) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !protection.active {
        return Err("POSIX source authority is no longer active".to_owned());
    }
    if validate_posix_adapter_installation_root(protection.platform, &protection.installation_root)?
        != protection.installation_root
        || posix_object_identity(&protection.installation_root)?
            != protection.installation_root_identity
        || !posix_source_cleanup_is_exact(
            &protection.installation_root,
            &protection.directory,
            &protection.candidate,
            &protection.oracle,
            &protection.transient,
            &protection.archive_adapter,
            &protection.retained_oracle,
        )
        || posix_object_identity(&protection.directory)? != protection.directory_identity
    {
        return Err("POSIX source authority identity changed".to_owned());
    }
    let metadata = fs::symlink_metadata(&protection.directory)
        .map_err(|error| format!("cannot inspect POSIX source authority: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o555
    {
        return Err("POSIX source authority permissions changed".to_owned());
    }
    require_exact_directory_members(
        &protection.directory,
        &[
            OsString::from("candidate"),
            OsString::from("oracle"),
            OsString::from("release-gate-transient"),
            OsString::from("archive-adapter"),
            OsString::from("retained-oracle"),
        ],
        "POSIX source authority",
    )?;
    let adapter_metadata = fs::symlink_metadata(&protection.archive_adapter)
        .map_err(|error| format!("cannot inspect native archive adapter authority: {error}"))?;
    if adapter_metadata.file_type().is_symlink()
        || !adapter_metadata.is_dir()
        || posix_object_identity(&protection.archive_adapter)?
            != protection.archive_adapter_identity
        || adapter_metadata.uid() != protection.archive_adapter_owner
        || adapter_metadata.gid() != protection.archive_adapter_group
        || adapter_metadata.permissions().mode() & 0o7777 != 0o2770
    {
        return Err("native archive adapter authority changed".to_owned());
    }
    require_exact_directory_members(
        &protection.archive_adapter,
        &[],
        "native archive adapter authority",
    )?;
    let stack_work_present = if let Some(stack_work) = &protection.stack_work {
        if stack_work != &protection.oracle.join(".stack-work") {
            return Err("candidate Stack work authority escapes staged oracle".to_owned());
        }
        match fs::symlink_metadata(stack_work) {
            Ok(metadata) => {
                let identity = protection.stack_work_identity.as_ref().ok_or_else(|| {
                    "candidate Stack work authority identity is absent".to_owned()
                })?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || posix_object_identity(stack_work)? != *identity
                    || metadata.uid() != protection.stack_work_owner
                    || metadata.gid() != protection.stack_work_group
                    || metadata.permissions().mode() & 0o7777 != 0o750
                    || fs::read_dir(stack_work)
                        .map_err(|error| {
                            format!("cannot enumerate candidate Stack work authority: {error}")
                        })?
                        .next()
                        .is_some()
                {
                    return Err("candidate Stack work authority changed before use".to_owned());
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!(
                    "cannot inspect candidate Stack work authority: {error}"
                ));
            }
        }
    } else {
        if protection.stack_work_identity.is_some() {
            return Err("candidate Stack work authority identity is unexpected".to_owned());
        }
        false
    };
    require_clean_checkout(
        &protection.candidate,
        &protection.candidate_sha,
        "staged candidate",
    )?;
    if stack_work_present {
        if git_head(&protection.oracle)? != crate::command::PINNED_ORACLE_SOURCE_COMMIT {
            return Err("staged oracle checkout differs from its bound commit".to_owned());
        }
    } else {
        require_clean_checkout(
            &protection.oracle,
            crate::command::PINNED_ORACLE_SOURCE_COMMIT,
            "staged oracle",
        )?;
    }
    require_posix_read_only_tree(&protection.candidate, "staged candidate")?;
    require_posix_read_only_tree_except(
        &protection.oracle,
        protection.stack_work.as_deref(),
        "staged oracle",
    )?;
    require_inventory_snapshot(
        &protection.candidate,
        &protection.candidate_inventory,
        "staged candidate",
    )?;
    require_inventory_snapshot(
        &protection.oracle,
        &protection.oracle_inventory,
        "staged oracle",
    )?;
    validate_posix_retained_oracle(protection)
}

#[cfg(unix)]
fn validate_posix_retained_oracle(protection: &PosixSourceProtection) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory_metadata = fs::symlink_metadata(&protection.retained_oracle)
        .map_err(|error| format!("cannot inspect retained oracle authority: {error}"))?;
    if directory_metadata.file_type().is_symlink()
        || !directory_metadata.is_dir()
        || directory_metadata.uid() != 0
        || directory_metadata.gid() != 0
        || posix_object_identity(&protection.retained_oracle)?
            != protection.retained_oracle_directory_identity
    {
        return Err("retained oracle directory identity changed".to_owned());
    }
    match &protection.retained_oracle_file {
        None => {
            if directory_metadata.permissions().mode() & 0o7777 != 0o555 {
                return Err("reserved retained oracle authority permissions changed".to_owned());
            }
            require_exact_directory_members(
                &protection.retained_oracle,
                &[],
                "reserved retained oracle authority",
            )
        }
        Some(file) => {
            let expected_name = file
                .path
                .file_name()
                .expect("retained oracle has a file name")
                .to_os_string();
            if directory_metadata.permissions().mode() & 0o7777 != 0o555
                || file.path.parent() != Some(&protection.retained_oracle)
                || file.path.file_name()
                    != Some(std::ffi::OsStr::new(protection.platform.executable()))
            {
                return Err("sealed retained oracle authority differs from policy".to_owned());
            }
            require_exact_directory_members(
                &protection.retained_oracle,
                std::slice::from_ref(&expected_name),
                "sealed retained oracle authority",
            )?;
            let metadata = fs::symlink_metadata(&file.path)
                .map_err(|error| format!("cannot inspect retained oracle executable: {error}"))?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.permissions().mode() & 0o7777 != 0o555
                || fs::canonicalize(&file.path).ok().as_deref() != Some(file.path.as_path())
                || posix_object_identity(&file.path)? != file.identity
            {
                return Err("retained oracle executable identity changed".to_owned());
            }
            require_executable_digest(&file.path, file.sha256, "retained oracle")
        }
    }
}

#[cfg(unix)]
fn retained_oracle_source_identity(
    path: &Path,
    sha256: hell_testkit::Digest,
) -> Result<(PosixObjectIdentity, u64), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize retained oracle source: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect retained oracle source: {error}"))?;
    if canonical != path
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("retained oracle source is redirected, linked, or writable".to_owned());
    }
    require_executable_digest(path, sha256, "retained oracle source")?;
    Ok((posix_object_identity(path)?, metadata.len()))
}

#[cfg(unix)]
impl PosixSourceProtection {
    fn retain_oracle_copy(
        &mut self,
        source: &UnretainedOracle,
    ) -> Result<hell_testkit::ExecutableIdentity, String> {
        validate_posix_sources(self)?;
        if self.retained_oracle_file.is_some() {
            return Err("retained oracle authority is already sealed".to_owned());
        }
        let source_identity = retained_oracle_source_identity(&source.path, source.sha256)?;
        let retained = self.retained_oracle.join(self.platform.executable());
        if retained.exists() {
            return Err("retained oracle executable already exists".to_owned());
        }
        let destination = path_text(&retained, "retained oracle executable")?;
        let result = (|| {
            trusted_tool_status(
                &self.sudo,
                &self.tools.copy,
                [
                    std::ffi::OsStr::new("--"),
                    source.path.as_os_str(),
                    retained.as_os_str(),
                ],
            )?;
            if self.platform == ReleasePlatform::MacosAarch64 {
                trusted_tool_status(
                    &self.sudo,
                    &self.tools.chmod,
                    posix_acl_removal_arguments(self.platform, false, destination)?,
                )?;
            }
            trusted_tool_status(
                &self.sudo,
                &self.tools.chmod,
                posix_chmod_arguments(self.platform, "0555", destination)?,
            )?;
            if retained_oracle_source_identity(&source.path, source.sha256)? != source_identity {
                return Err("retained oracle source identity changed during copy".to_owned());
            }
            let retained_identity = hell_testkit::verify_executable(
                &retained,
                hell_testkit::ExecutableRole::Oracle,
                Some(source.sha256),
                hell_builtins::LANGUAGE_VERSION,
            )
            .map_err(|error| format!("cannot verify retained oracle copy: {error}"))?;
            let retained_metadata = fs::symlink_metadata(&retained).map_err(|error| {
                format!("cannot inspect retained oracle executable after copy: {error}")
            })?;
            if retained_metadata.len() != source_identity.1 {
                return Err("retained oracle copy size differs from source".to_owned());
            }
            self.retained_oracle_file = Some(PosixRetainedOracleFile {
                path: retained.clone(),
                identity: posix_object_identity(&retained)?,
                sha256: source.sha256,
            });
            validate_posix_sources(self)?;
            Ok(retained_identity)
        })();
        match result {
            Ok(identity) => Ok(identity),
            Err(error) => {
                let cleanup = cleanup_posix_source_paths(
                    self.platform,
                    &self.sudo,
                    &self.tools,
                    &self.installation_root,
                    &self.installation_root_identity,
                    &self.directory,
                    &self.directory_identity,
                );
                if cleanup.is_ok() {
                    self.active = false;
                }
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(format!(
                        "{error}; retained oracle cleanup also failed: {cleanup_error}"
                    )),
                }
            }
        }
    }
}

#[cfg(unix)]
fn require_posix_read_only_tree(root: &Path, label: &str) -> Result<(), String> {
    require_posix_read_only_tree_except(root, None, label)
}

#[cfg(unix)]
fn require_posix_read_only_tree_except(
    root: &Path,
    excluded: Option<&Path>,
    label: &str,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if excluded.is_some_and(|excluded| path == excluded) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {label} authority: {error}"))?;
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || mode & 0o222 != 0
            || if metadata.is_dir() {
                mode & 0o555 != 0o555
            } else {
                !metadata.is_file() || mode & 0o444 != 0o444
            }
        {
            return Err(format!(
                "{label} authority contains a redirected, writable, unreadable, or non-root-owned entry"
            ));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate {label} authority: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read {label} authority entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_posix_archive_adapter_inventory(adapter: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    require_exact_directory_members(
        adapter,
        &[
            OsString::from(".authority"),
            OsString::from(".stack-work"),
            OsString::from("ar"),
            OsString::from("stack.yaml"),
            OsString::from("stack.yaml.lock"),
        ],
        "native archive adapter inventory",
    )?;
    let authority = adapter.join(".authority");
    require_exact_directory_members(
        &authority,
        &[OsString::from("llvm-ar")],
        "native archive archiver authority",
    )?;
    let authority_metadata = fs::symlink_metadata(&authority)
        .map_err(|error| format!("cannot inspect native archive archiver authority: {error}"))?;
    let archiver_metadata = fs::symlink_metadata(authority.join("llvm-ar"))
        .map_err(|error| format!("cannot inspect bound LLVM archiver: {error}"))?;
    let launcher_metadata = fs::symlink_metadata(adapter.join("ar"))
        .map_err(|error| format!("cannot inspect native archive launcher: {error}"))?;
    let stack_yaml_metadata = fs::symlink_metadata(adapter.join("stack.yaml"))
        .map_err(|error| format!("cannot inspect native Stack overlay: {error}"))?;
    let stack_lock_metadata = fs::symlink_metadata(adapter.join("stack.yaml.lock"))
        .map_err(|error| format!("cannot inspect native Stack lock: {error}"))?;
    if authority_metadata.file_type().is_symlink()
        || !authority_metadata.is_dir()
        || authority_metadata.permissions().mode() & 0o7777 != 0o555
        || !archiver_metadata.file_type().is_symlink()
        || !launcher_metadata.file_type().is_symlink()
        || stack_yaml_metadata.file_type().is_symlink()
        || !stack_yaml_metadata.is_file()
        || stack_lock_metadata.file_type().is_symlink()
        || !stack_lock_metadata.is_file()
    {
        return Err(
            "native archive adapter inventory contains an unexpected entry type".to_owned(),
        );
    }
    Ok(())
}

#[cfg(unix)]
fn require_posix_archive_adapter_transition_state(
    parent: &Path,
    parent_identity: &PosixObjectIdentity,
    parent_owner: u32,
    parent_group: u32,
    parent_mode: u32,
    adapter: &Path,
    adapter_identity: &PosixObjectIdentity,
    work_directory: &Path,
    work_directory_identity: &PosixObjectIdentity,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let observed_parent = posix_object_identity(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect native archive adapter authority: {error}"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || !posix_same_object(&observed_parent, parent_identity)
        || parent_metadata.uid() != parent_owner
        || parent_metadata.gid() != parent_group
        || parent_metadata.permissions().mode() & 0o7777 != parent_mode
        || adapter.parent() != Some(parent)
        || work_directory != adapter.join(".stack-work")
        || fs::canonicalize(adapter)
            .map_err(|error| format!("cannot canonicalize native archive adapter: {error}"))?
            != adapter
        || fs::canonicalize(work_directory).map_err(|error| {
            format!("cannot canonicalize candidate Stack work directory: {error}")
        })? != work_directory
    {
        return Err("native archive adapter authority changed during mode transition".to_owned());
    }
    require_exact_directory_members(
        parent,
        &[adapter
            .file_name()
            .ok_or_else(|| "native archive adapter name is absent".to_owned())?
            .to_os_string()],
        "native archive adapter authority",
    )?;
    require_posix_archive_adapter_inventory(adapter)?;
    let observed_adapter = posix_object_identity(adapter)?;
    let observed_work_directory = posix_object_identity(work_directory)?;
    if !posix_same_object(&observed_adapter, adapter_identity)
        || observed_adapter.mode != 0o2755
        || !posix_same_object(&observed_work_directory, work_directory_identity)
        || observed_work_directory.mode != 0o2770
        || observed_adapter.owner != parent_owner
        || observed_adapter.group != parent_group
        || observed_work_directory.owner != parent_owner
        || observed_work_directory.group != parent_group
    {
        return Err(
            "native archive adapter child authority changed during mode transition".to_owned(),
        );
    }
    Ok(())
}

#[cfg(unix)]
fn seal_posix_archive_adapter_authority<'a>(
    protection: &PosixSourceProtection,
    normalizer: &'a PosixAdapterProtection,
    adapter: &Path,
) -> Result<PosixArchiveAdapterSeal<'a>, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let adapter_name = adapter
        .file_name()
        .ok_or_else(|| "native archive adapter name is absent".to_owned())?;
    if !protection.active || adapter.parent() != Some(&protection.archive_adapter) {
        return Err("native archive adapter child is outside its authority".to_owned());
    }
    require_posix_adapter_unchanged(normalizer)?;
    let stack_work = protection
        .stack_work
        .as_ref()
        .ok_or_else(|| "candidate Stack work authority is absent".to_owned())?;
    let stack_work_identity = protection
        .stack_work_identity
        .as_ref()
        .ok_or_else(|| "candidate Stack work authority identity is absent".to_owned())?;
    if stack_work != &protection.oracle.join(".stack-work")
        || posix_object_identity(stack_work)? != *stack_work_identity
    {
        return Err("candidate Stack work authority changed before sealing".to_owned());
    }
    let parent_metadata = fs::symlink_metadata(&protection.archive_adapter)
        .map_err(|error| format!("cannot inspect native archive adapter authority: {error}"))?;
    let adapter_metadata = fs::symlink_metadata(adapter)
        .map_err(|error| format!("cannot inspect native archive adapter: {error}"))?;
    let work_directory = adapter.join(".stack-work");
    let work_metadata = fs::symlink_metadata(&work_directory)
        .map_err(|error| format!("cannot inspect candidate Stack work directory: {error}"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || posix_object_identity(&protection.archive_adapter)?
            != protection.archive_adapter_identity
        || parent_metadata.uid() != protection.archive_adapter_owner
        || parent_metadata.gid() != protection.archive_adapter_group
        || parent_metadata.permissions().mode() & 0o7777 != 0o2770
        || adapter_metadata.file_type().is_symlink()
        || !adapter_metadata.is_dir()
        || adapter_metadata.uid() != protection.archive_adapter_owner
        || adapter_metadata.gid() != protection.archive_adapter_group
        || adapter_metadata.permissions().mode() & 0o7777 != 0o755
        || work_metadata.file_type().is_symlink()
        || !work_metadata.is_dir()
        || work_metadata.uid() != protection.archive_adapter_owner
        || work_metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("native archive adapter authority differs before sealing".to_owned());
    }
    require_exact_directory_members(
        &protection.archive_adapter,
        &[adapter_name.to_os_string()],
        "native archive adapter authority",
    )?;
    let group = protection.archive_adapter_group.to_string();
    for path in [adapter, work_directory.as_path()] {
        trusted_tool_status(
            &protection.sudo,
            &protection.tools.change_group,
            [
                group.as_str(),
                path_text(path, "native archive adapter child")?,
            ],
        )?;
    }
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.chmod,
        posix_chmod_arguments(
            protection.platform,
            "2755",
            path_text(adapter, "native archive adapter")?,
        )?,
    )?;
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.chmod,
        posix_chmod_arguments(
            protection.platform,
            "2770",
            path_text(&work_directory, "candidate Stack work directory")?,
        )?,
    )?;
    let adapter_identity = posix_object_identity(adapter)?;
    let work_directory_identity = posix_object_identity(&work_directory)?;
    require_posix_archive_adapter_transition_state(
        &protection.archive_adapter,
        &protection.archive_adapter_identity,
        protection.archive_adapter_owner,
        protection.archive_adapter_group,
        0o2770,
        adapter,
        &adapter_identity,
        &work_directory,
        &work_directory_identity,
    )?;
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.chmod,
        posix_chmod_arguments(
            protection.platform,
            "2550",
            path_text(
                &protection.archive_adapter,
                "native archive adapter authority",
            )?,
        )?,
    )?;
    let mut sealed = PosixArchiveAdapterSeal {
        platform: protection.platform,
        parent: protection.archive_adapter.clone(),
        parent_identity: protection.archive_adapter_identity.clone(),
        parent_owner: protection.archive_adapter_owner,
        parent_group: protection.archive_adapter_group,
        adapter: adapter.to_path_buf(),
        adapter_identity,
        work_directory,
        work_directory_identity,
        source_parent: protection.directory.clone(),
        source_parent_identity: protection.directory_identity.clone(),
        source: protection.oracle.clone(),
        source_identity: posix_object_identity(&protection.oracle)?,
        stack_work: stack_work.clone(),
        stack_work_identity: stack_work_identity.clone(),
        stack_work_owner: protection.stack_work_owner,
        stack_work_group: protection.stack_work_group,
        normalizer,
        sudo: protection.sudo.clone(),
        tools: protection.tools.clone(),
        active: true,
    };
    if let Err(error) = require_posix_archive_adapter_transition_state(
        &sealed.parent,
        &sealed.parent_identity,
        sealed.parent_owner,
        sealed.parent_group,
        0o2550,
        &sealed.adapter,
        &sealed.adapter_identity,
        &sealed.work_directory,
        &sealed.work_directory_identity,
    ) {
        let restore = sealed.restore_inner();
        if restore.is_ok() {
            sealed.active = false;
        }
        return match restore {
            Ok(()) => Err(error),
            Err(restore_error) => Err(format!(
                "{error}; native archive adapter restoration also failed: {restore_error}"
            )),
        };
    }
    Ok(sealed)
}

#[cfg(unix)]
fn cleanup_posix_sources(protection: &mut PosixSourceProtection) -> Result<(), String> {
    if !protection.active {
        return Ok(());
    }
    validate_posix_sources(protection)?;
    cleanup_posix_source_paths(
        protection.platform,
        &protection.sudo,
        &protection.tools,
        &protection.installation_root,
        &protection.installation_root_identity,
        &protection.directory,
        &protection.directory_identity,
    )?;
    protection.active = false;
    Ok(())
}

#[cfg(unix)]
fn cleanup_posix_source_paths(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    installation_root: &Path,
    installation_root_identity: &PosixObjectIdentity,
    directory: &Path,
    directory_identity: &PosixObjectIdentity,
) -> Result<(), String> {
    if validate_posix_adapter_installation_root(platform, installation_root)? != installation_root
        || posix_object_identity(installation_root)? != *installation_root_identity
        || directory.parent() != Some(installation_root)
        || !directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hell-rs-posix-sources-"))
        || posix_object_identity(directory)? != *directory_identity
    {
        return Err("POSIX source cleanup authority changed".to_owned());
    }
    trusted_tool_status(
        sudo,
        &tools.remove_file,
        ["-rf", "--", path_text(directory, "POSIX source cleanup")?],
    )
}

#[cfg(unix)]
fn posix_source_cleanup_is_exact(
    installation_root: &Path,
    directory: &Path,
    candidate: &Path,
    oracle: &Path,
    transient: &Path,
    archive_adapter: &Path,
    retained_oracle: &Path,
) -> bool {
    directory.parent() == Some(installation_root)
        && directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hell-rs-posix-sources-"))
        && candidate == directory.join("candidate")
        && oracle == directory.join("oracle")
        && transient == directory.join("release-gate-transient")
        && archive_adapter == directory.join("archive-adapter")
        && retained_oracle == directory.join("retained-oracle")
}

fn path_text<'a>(path: &'a Path, label: &str) -> Result<&'a str, String> {
    path.to_str()
        .ok_or_else(|| format!("{label} path is not UTF-8"))
}

#[cfg(unix)]
impl Drop for PosixAdapterProtection {
    fn drop(&mut self) {
        let _ = cleanup_posix_adapter(self);
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixObjectIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct PosixAdapterTools {
    mkdir: crate::command::ResolvedStandardExecutable,
    copy: crate::command::ResolvedStandardExecutable,
    chmod: crate::command::ResolvedStandardExecutable,
    change_owner: crate::command::ResolvedStandardExecutable,
    change_group: crate::command::ResolvedStandardExecutable,
    remove_file: crate::command::ResolvedStandardExecutable,
    remove_directory: crate::command::ResolvedStandardExecutable,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PosixAdapterToolPaths {
    mkdir: &'static str,
    copy: &'static str,
    chmod: &'static str,
    change_owner: &'static str,
    change_group: &'static str,
    remove_file: &'static str,
    remove_directory: &'static str,
}

#[cfg(unix)]
fn posix_adapter_tool_paths(platform: ReleasePlatform) -> Result<PosixAdapterToolPaths, String> {
    match platform {
        ReleasePlatform::LinuxX86_64 => Ok(PosixAdapterToolPaths {
            mkdir: "/usr/bin/mkdir",
            copy: "/usr/bin/cp",
            chmod: "/usr/bin/chmod",
            change_owner: "/usr/bin/chown",
            change_group: "/usr/bin/chgrp",
            remove_file: "/usr/bin/rm",
            remove_directory: "/usr/bin/rmdir",
        }),
        ReleasePlatform::MacosAarch64 => Ok(PosixAdapterToolPaths {
            mkdir: "/bin/mkdir",
            copy: "/bin/cp",
            chmod: "/bin/chmod",
            change_owner: "/usr/sbin/chown",
            change_group: "/usr/bin/chgrp",
            remove_file: "/bin/rm",
            remove_directory: "/bin/rmdir",
        }),
        ReleasePlatform::WindowsX86_64 => {
            Err("Windows platform selected POSIX adapter tools".to_owned())
        }
    }
}

#[cfg(unix)]
fn resolve_posix_adapter_tools(platform: ReleasePlatform) -> Result<PosixAdapterTools, String> {
    let paths = posix_adapter_tool_paths(platform)?;
    let resolve = |path: &str| {
        crate::command::resolve_absolute_standard_executable(Path::new(path))
            .map_err(|error| format!("cannot bind POSIX adapter installation tool: {error}"))
    };
    Ok(PosixAdapterTools {
        mkdir: resolve(paths.mkdir)?,
        copy: resolve(paths.copy)?,
        chmod: resolve(paths.chmod)?,
        change_owner: resolve(paths.change_owner)?,
        change_group: resolve(paths.change_group)?,
        remove_file: resolve(paths.remove_file)?,
        remove_directory: resolve(paths.remove_directory)?,
    })
}

#[cfg(unix)]
fn posix_object_identity(path: &Path) -> Result<PosixObjectIdentity, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect POSIX authority {}: {error}", path.display()))?;
    Ok(PosixObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.permissions().mode() & 0o7777,
    })
}

#[cfg(unix)]
fn posix_same_object(left: &PosixObjectIdentity, right: &PosixObjectIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.owner == right.owner
        && left.group == right.group
}

#[cfg(unix)]
fn posix_adapter_installation_root(platform: ReleasePlatform) -> Result<PathBuf, String> {
    let chain = posix_adapter_authority_chain(platform)?;
    validate_posix_adapter_installation_root(
        platform,
        Path::new(chain.last().expect("POSIX authority chain is nonempty")),
    )
}

#[cfg(unix)]
fn posix_adapter_authority_chain(
    platform: ReleasePlatform,
) -> Result<&'static [&'static str], String> {
    const LINUX: [&str; 3] = ["/", "/var", "/var/tmp"];
    const MACOS: [&str; 4] = ["/", "/private", "/private/var", "/private/var/tmp"];
    match platform {
        ReleasePlatform::LinuxX86_64 => Ok(&LINUX),
        ReleasePlatform::MacosAarch64 => Ok(&MACOS),
        ReleasePlatform::WindowsX86_64 => {
            Err("Windows platform selected the POSIX adapter installation root".to_owned())
        }
    }
}

#[cfg(unix)]
fn validate_posix_adapter_installation_root(
    platform: ReleasePlatform,
    root: &Path,
) -> Result<PathBuf, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let authority_chain = posix_adapter_authority_chain(platform)?;
    if root != Path::new(authority_chain[authority_chain.len() - 1]) {
        return Err("POSIX adapter installation root differs from policy".to_owned());
    }
    for (index, entry) in authority_chain.iter().copied().enumerate() {
        let path = Path::new(entry);
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!("cannot inspect POSIX executable authority {entry}: {error}")
        })?;
        let canonical = fs::canonicalize(path).map_err(|error| {
            format!("cannot canonicalize POSIX executable authority {entry}: {error}")
        })?;
        let mode = metadata.permissions().mode();
        let final_sticky_root = index + 1 == authority_chain.len();
        if canonical != path
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || if final_sticky_root {
                mode & 0o7777 != 0o1777
            } else {
                mode & 0o022 != 0 || mode & 0o005 != 0o005
            }
        {
            return Err(format!(
                "POSIX executable authority {entry} is redirected or differs from its root-owned traversal/sticky policy"
            ));
        }
    }
    Ok(root.to_path_buf())
}

#[cfg(unix)]
fn stage_posix_executable(
    platform: ReleasePlatform,
    sudo: &Path,
    source_path: &Path,
    staged_name: &'static str,
) -> Result<PosixAdapterProtection, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !matches!(staged_name, "hell-ci" | "cargo" | "cargo-deny" | "stack") {
        return Err("trusted POSIX executable name differs from policy".to_owned());
    }
    let original = fs::symlink_metadata(source_path)
        .map_err(|error| format!("cannot inspect trusted POSIX executable: {error}"))?;
    if original.file_type().is_symlink() || !original.is_file() {
        return Err("trusted POSIX executable is not a real file".to_owned());
    }
    let source = fs::canonicalize(source_path)
        .map_err(|error| format!("cannot canonicalize trusted POSIX executable: {error}"))?;
    let source_sha256 = hell_testkit::sha256_file(&source)
        .map_err(|error| format!("cannot hash trusted POSIX adapter: {error}"))?;
    let source_identity = posix_object_identity(&source)?;
    let installation_root = posix_adapter_installation_root(platform)?;
    let installation_root_identity = posix_object_identity(&installation_root)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let sequence = POSIX_ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = installation_root.join(format!(
        "hell-rs-posix-{staged_name}-{}-{sequence}-{}",
        std::process::id(),
        source_sha256.hex()
    ));
    let directory_text = directory
        .to_str()
        .ok_or_else(|| "trusted POSIX adapter directory is not UTF-8".to_owned())?;
    trusted_tool_status(sudo, &tools.mkdir, ["-m", "0555", "--", directory_text])
        .map_err(|error| format!("cannot reserve trusted POSIX adapter directory: {error}"))?;
    let directory_identity = posix_object_identity(&directory)?;
    let staged = directory.join(staged_name);
    let staged_text = staged
        .to_str()
        .ok_or_else(|| "trusted POSIX adapter path is not UTF-8".to_owned())?;
    let source_text = source
        .to_str()
        .ok_or_else(|| "trusted POSIX adapter source is not UTF-8".to_owned())?;
    let mut cleanup = true;
    let result = (|| {
        trusted_tool_status(sudo, &tools.copy, ["--", source_text, staged_text])?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(platform, "0555", staged_text)?,
        )?;

        let canonical_directory = fs::canonicalize(&directory)
            .map_err(|error| format!("cannot canonicalize POSIX adapter directory: {error}"))?;
        let canonical_staged = fs::canonicalize(&staged)
            .map_err(|error| format!("cannot canonicalize staged POSIX adapter: {error}"))?;
        let directory_metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("cannot inspect POSIX adapter directory: {error}"))?;
        let staged_metadata = fs::symlink_metadata(&staged)
            .map_err(|error| format!("cannot inspect staged POSIX adapter: {error}"))?;
        let adapter_identity = posix_object_identity(&staged)?;
        if validate_posix_adapter_installation_root(platform, &installation_root)?
            != installation_root
            || posix_object_identity(&installation_root)? != installation_root_identity
            || posix_object_identity(&source)? != source_identity
            || hell_testkit::sha256_file(&source)
                .map_err(|error| format!("cannot rehash trusted POSIX adapter source: {error}"))?
                != source_sha256
            || canonical_directory != directory
            || canonical_staged != staged
            || directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || staged_metadata.file_type().is_symlink()
            || !staged_metadata.is_file()
            || directory_metadata.uid() != 0
            || directory_metadata.gid() != 0
            || staged_metadata.uid() != 0
            || staged_metadata.gid() != 0
            || directory_metadata.permissions().mode() & 0o7777 != 0o555
            || staged_metadata.permissions().mode() & 0o7777 != 0o555
            || directory_identity != posix_object_identity(&directory)?
            || hell_testkit::sha256_file(&staged)
                .map_err(|error| format!("cannot rehash staged POSIX adapter: {error}"))?
                != source_sha256
        {
            return Err("staged POSIX adapter identity or permissions differ".to_owned());
        }
        Ok(PosixAdapterProtection {
            platform,
            installation_root: installation_root.clone(),
            installation_root_identity: installation_root_identity.clone(),
            directory: directory.clone(),
            directory_identity: directory_identity.clone(),
            adapter: staged.clone(),
            adapter_identity,
            sha256: source_sha256,
            staged_name,
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
        })
    })();
    if result.is_ok() {
        cleanup = false;
    }
    if cleanup {
        let _ = cleanup_posix_adapter_paths(
            platform,
            sudo,
            &tools,
            &installation_root,
            &installation_root_identity,
            &directory,
            &directory_identity,
            &staged,
            staged_name,
        );
    }
    result
}

#[cfg(unix)]
fn cleanup_posix_adapter(protection: &PosixAdapterProtection) -> Result<(), String> {
    if posix_object_identity(&protection.adapter)? != protection.adapter_identity
        || hell_testkit::sha256_file(&protection.adapter)
            .map_err(|error| format!("cannot rehash POSIX adapter before cleanup: {error}"))?
            != protection.sha256
    {
        return Err("POSIX adapter identity changed before cleanup".to_owned());
    }
    cleanup_posix_adapter_paths(
        protection.platform,
        &protection.sudo,
        &protection.tools,
        &protection.installation_root,
        &protection.installation_root_identity,
        &protection.directory,
        &protection.directory_identity,
        &protection.adapter,
        protection.staged_name,
    )
}

#[cfg(unix)]
fn cleanup_posix_adapter_paths(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    installation_root: &Path,
    installation_root_identity: &PosixObjectIdentity,
    directory: &Path,
    directory_identity: &PosixObjectIdentity,
    adapter: &Path,
    staged_name: &str,
) -> Result<(), String> {
    if validate_posix_adapter_installation_root(platform, installation_root)? != installation_root
        || posix_object_identity(installation_root)? != *installation_root_identity
        || !posix_adapter_cleanup_is_exact(installation_root, directory, adapter, staged_name)
        || posix_object_identity(directory)? != *directory_identity
    {
        return Err("POSIX adapter cleanup authority changed".to_owned());
    }
    let adapter_text = adapter
        .to_str()
        .ok_or_else(|| "POSIX adapter cleanup path is not UTF-8".to_owned())?;
    let directory_text = directory
        .to_str()
        .ok_or_else(|| "POSIX adapter cleanup directory is not UTF-8".to_owned())?;
    trusted_tool_status(sudo, &tools.remove_file, ["-f", "--", adapter_text])?;
    trusted_tool_status(sudo, &tools.remove_directory, ["--", directory_text])
}

#[cfg(unix)]
fn posix_chmod_arguments<'a>(
    platform: ReleasePlatform,
    mode: &'a str,
    path: &'a str,
) -> Result<Vec<&'a str>, String> {
    match platform {
        ReleasePlatform::LinuxX86_64 => Ok(vec![mode, "--", path]),
        ReleasePlatform::MacosAarch64 => Ok(vec![mode, path]),
        ReleasePlatform::WindowsX86_64 => {
            Err("Windows platform selected POSIX chmod arguments".to_owned())
        }
    }
}

#[cfg(unix)]
fn posix_acl_removal_arguments(
    platform: ReleasePlatform,
    recursive: bool,
    path: &str,
) -> Result<[&str; 2], String> {
    match platform {
        ReleasePlatform::MacosAarch64 => Ok([if recursive { "-RN" } else { "-N" }, path]),
        ReleasePlatform::LinuxX86_64 | ReleasePlatform::WindowsX86_64 => {
            Err("non-macOS platform selected POSIX ACL removal arguments".to_owned())
        }
    }
}

#[cfg(unix)]
fn posix_adapter_cleanup_is_exact(
    installation_root: &Path,
    directory: &Path,
    adapter: &Path,
    staged_name: &str,
) -> bool {
    directory.parent() == Some(installation_root)
        && adapter.parent() == Some(directory)
        && matches!(staged_name, "hell-ci" | "cargo" | "cargo-deny" | "stack")
        && adapter.file_name() == Some(std::ffi::OsStr::new(staged_name))
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsToolchainFile {
    relative: PathBuf,
    source: crate::command::WindowsBoundFileIdentity,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsToolchainProtection {
    root: PathBuf,
    source_root: PathBuf,
    files: Vec<WindowsToolchainFile>,
    directories: Vec<PathBuf>,
}

#[cfg(windows)]
impl WindowsToolchainProtection {
    fn revalidate(&self) -> Result<(), String> {
        let expected = self
            .directories
            .iter()
            .cloned()
            .map(|path| (path, true))
            .chain(self.files.iter().map(|file| (file.relative.clone(), false)))
            .collect::<BTreeSet<_>>();
        if windows_toolchain_inventory_paths(&self.source_root)? != expected
            || windows_toolchain_inventory_paths(&self.root)? != expected
        {
            return Err("Windows toolchain closed inventory changed before use".to_owned());
        }
        for directory in &self.directories {
            let source = self.source_root.join(directory);
            let staged = self.root.join(directory);
            if !fs::symlink_metadata(&source).is_ok_and(|metadata| metadata.is_dir())
                || !fs::symlink_metadata(&staged).is_ok_and(|metadata| metadata.is_dir())
            {
                return Err("Windows toolchain directory identity changed before use".to_owned());
            }
        }
        for file in &self.files {
            let source = self.source_root.join(&file.relative);
            let staged = self.root.join(&file.relative);
            file.source.revalidate(&source)?;
            let staged_identity = crate::command::WindowsBoundFileIdentity::bind(&staged)?;
            if staged_identity.size() != file.source.size()
                || staged_identity.sha256() != file.source.sha256()
            {
                return Err("staged Windows toolchain file identity changed before use".to_owned());
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
fn windows_toolchain_inventory_paths(root: &Path) -> Result<BTreeSet<(PathBuf, bool)>, String> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let mut inventory = BTreeSet::from([(PathBuf::new(), true)]);
    let mut pending = vec![PathBuf::new()];
    while let Some(relative_parent) = pending.pop() {
        for entry in fs::read_dir(root.join(&relative_parent))
            .map_err(|error| format!("cannot enumerate Windows toolchain authority: {error}"))?
        {
            let entry = entry
                .map_err(|error| format!("cannot inspect Windows toolchain authority: {error}"))?;
            let relative = relative_parent.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("cannot inspect Windows toolchain authority: {error}"))?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err("Windows toolchain authority contains a reparse point".to_owned());
            }
            if metadata.is_dir() {
                inventory.insert((relative.clone(), true));
                pending.push(relative);
            } else if metadata.is_file() {
                inventory.insert((relative, false));
            } else {
                return Err("Windows toolchain authority contains a special entry".to_owned());
            }
        }
    }
    Ok(inventory)
}

#[cfg(windows)]
impl Drop for WindowsToolchainProtection {
    fn drop(&mut self) {
        let _ = windows_confinement::cleanup_tree(&self.root);
    }
}

#[cfg(windows)]
fn stage_windows_toolchain(
    authority: &crate::command::ResolvedWindowsRustupAuthority,
    candidate_root: &Path,
) -> Result<WindowsToolchainProtection, String> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    authority.revalidate()?;
    let source_root = authority.toolchain_root().to_path_buf();
    let parent = candidate_root
        .parent()
        .ok_or_else(|| "candidate root has no authority parent".to_owned())?;
    let sequence = WINDOWS_TOOLCHAIN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = parent.join(format!(
        "windows-rust-toolchain-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root)
        .map_err(|error| format!("cannot create Windows toolchain authority: {error}"))?;

    let mut protection = WindowsToolchainProtection {
        root,
        source_root,
        files: Vec::new(),
        directories: vec![PathBuf::new()],
    };
    let mut pending = vec![PathBuf::new()];
    let mut total_bytes = 0_u64;
    while let Some(relative_parent) = pending.pop() {
        let source_parent = protection.source_root.join(&relative_parent);
        let mut entries = fs::read_dir(&source_parent)
            .map_err(|error| format!("cannot enumerate selected Windows toolchain: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot inspect selected Windows toolchain: {error}"))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            if protection.files.len() + protection.directories.len()
                >= WINDOWS_TOOLCHAIN_STAGE_ENTRY_LIMIT
            {
                return Err("selected Windows toolchain exceeds its entry bound".to_owned());
            }
            let relative = relative_parent.join(entry.file_name());
            if relative.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::Prefix(_)
                        | std::path::Component::RootDir
                        | std::path::Component::ParentDir
                        | std::path::Component::CurDir
                )
            }) {
                return Err("selected Windows toolchain contains a noncanonical path".to_owned());
            }
            let source = protection.source_root.join(&relative);
            let metadata = fs::symlink_metadata(&source)
                .map_err(|error| format!("cannot inspect selected Windows toolchain: {error}"))?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err("selected Windows toolchain contains a reparse point".to_owned());
            }
            let staged = protection.root.join(&relative);
            if metadata.is_dir() {
                fs::create_dir(&staged).map_err(|error| {
                    format!("cannot create staged Windows toolchain directory: {error}")
                })?;
                protection.directories.push(relative.clone());
                pending.push(relative);
            } else if metadata.is_file() {
                let identity = crate::command::WindowsBoundFileIdentity::bind(&source)?;
                total_bytes = total_bytes
                    .checked_add(identity.size())
                    .filter(|bytes| *bytes <= WINDOWS_TOOLCHAIN_STAGE_BYTE_LIMIT)
                    .ok_or_else(|| {
                        "selected Windows toolchain exceeds its byte bound".to_owned()
                    })?;
                fs::copy(&source, &staged).map_err(|error| {
                    format!("cannot copy selected Windows toolchain file: {error}")
                })?;
                protection.files.push(WindowsToolchainFile {
                    relative,
                    source: identity,
                });
            } else {
                return Err("selected Windows toolchain contains a special entry".to_owned());
            }
        }
    }
    windows_confinement::protect_tree(&protection.root, false)?;
    protection.revalidate()?;
    Ok(protection)
}

#[cfg(windows)]
fn establish_candidate_process_confinement(
    _platform: ReleasePlatform,
    candidate_root: &Path,
    oracle_root: &Path,
    _candidate_inventory: &JsonValue,
    _oracle_inventory: &JsonValue,
    _candidate_sha: &str,
    target: &Path,
    output: &Path,
) -> Result<CandidateConfinement, String> {
    let cargo = crate::command::resolve_cargo_executable()?;
    let rustup = crate::command::resolve_windows_rustup_authority(&cargo, candidate_root)?;
    let toolchain = stage_windows_toolchain(&rustup, candidate_root)?;
    let staged_cargo = toolchain.root.join("bin/cargo.exe");
    let staged_rustc = toolchain.root.join("bin/rustc.exe");
    let staged_inventory_files = toolchain
        .files
        .iter()
        .map(|file| toolchain.root.join(&file.relative))
        .collect();
    let staged_inventory_directories = toolchain
        .directories
        .iter()
        .map(|directory| toolchain.root.join(directory))
        .collect();
    let trusted_parent_path = std::env::var_os("PATH")
        .ok_or_else(|| "trusted Windows parent PATH is unavailable".to_owned())?;
    let trusted_parent_system_root = hell_testkit::capture_windows_standard_system_root()
        .map_err(|error| format!("cannot bind trusted Windows SystemRoot: {error}"))?;
    let toolchain_authority = hell_testkit::WindowsToolchainAuthority::new(
        windows_toolchain_executable_authority(
            rustup.cargo_source(),
            rustup.cargo().canonical(),
            staged_cargo.clone(),
        ),
        windows_toolchain_executable_authority(
            rustup.rustc_source(),
            rustup.rustc().canonical(),
            staged_rustc.clone(),
        ),
        toolchain.root.clone(),
        staged_inventory_files,
        staged_inventory_directories,
        trusted_parent_path,
        trusted_parent_system_root,
    )
    .map_err(|error| {
        format!(
            "cannot bind staged Windows Rust toolchain: sourceToolchain={:?} \
             stagedToolchain={:?} cargoInvocation={:?} cargoIdentity={:?} \
             selectedCargo={:?} stagedCargo={staged_cargo:?} rustcInvocation={:?} \
             rustcIdentity={:?} selectedRustc={:?} stagedRustc={staged_rustc:?} \
             failure={error}",
            rustup.toolchain_root(),
            toolchain.root,
            rustup.cargo_source().executable().invocation(),
            rustup.cargo_source().executable().canonical(),
            rustup.cargo().canonical(),
            rustup.rustc_source().executable().invocation(),
            rustup.rustc_source().executable().canonical(),
            rustup.rustc().canonical(),
        )
    })?;
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("cannot resolve trusted driver: {error}"))?;
    let restricted_adapter = windows_restricted_adapter_path(&current_exe)?;
    let (launcher, launcher_sha256) = windows_confinement::protect_launcher(&current_exe)?;
    let (restricted_adapter, restricted_adapter_sha256) =
        windows_confinement::protect_launcher(&restricted_adapter)?;
    windows_confinement::protect_tree(candidate_root, false)?;
    windows_confinement::protect_tree(oracle_root, false)?;
    windows_confinement::protect_tree(output, false)?;
    windows_confinement::protect_tree(target, true)?;
    let policy = hell_testkit::CandidateLaunchPolicy::windows(
        hell_testkit::WindowsLaunchAuthorities::new(
            launcher,
            launcher_sha256,
            restricted_adapter,
            restricted_adapter_sha256,
            toolchain_authority,
        ),
        vec![target.to_path_buf()],
    )
    .map_err(|error| format!("cannot establish Windows candidate launch policy: {error}"))?;
    Ok(CandidateConfinement {
        policy,
        candidate_root: candidate_root.to_path_buf(),
        oracle_root: oracle_root.to_path_buf(),
        _toolchain: toolchain,
    })
}

#[cfg(windows)]
fn windows_toolchain_executable_authority(
    source: &crate::command::ResolvedWindowsToolSourceAuthority,
    selected: &Path,
    staged: PathBuf,
) -> hell_testkit::WindowsToolchainExecutableAuthority {
    match source {
        crate::command::ResolvedWindowsToolSourceAuthority::RustupProxy(executable)
        | crate::command::ResolvedWindowsToolSourceAuthority::CopiedRustupProxy(executable) => {
            hell_testkit::WindowsToolchainExecutableAuthority::rustup_proxy(
                executable.invocation().to_path_buf(),
                executable.canonical().to_path_buf(),
                selected.to_path_buf(),
                staged,
            )
        }
        crate::command::ResolvedWindowsToolSourceAuthority::SelectedToolchain(executable) => {
            hell_testkit::WindowsToolchainExecutableAuthority::selected_toolchain(
                executable.invocation().to_path_buf(),
                executable.canonical().to_path_buf(),
                selected.to_path_buf(),
                staged,
            )
        }
    }
}

#[cfg(any(windows, test))]
fn windows_restricted_adapter_path(launcher: &Path) -> Result<PathBuf, String> {
    if launcher.file_name() != Some(std::ffi::OsStr::new("hell-ci.exe")) {
        return Err("trusted Windows driver has the wrong executable name".to_owned());
    }
    let parent = launcher
        .parent()
        .ok_or_else(|| "trusted Windows driver has no parent".to_owned())?;
    Ok(parent.join("hell-test-helper.exe"))
}

#[cfg(windows)]
mod windows_confinement {
    use super::*;

    pub(super) fn protect_launcher(path: &Path) -> Result<(PathBuf, hell_testkit::Digest), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect trusted Windows launcher: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("trusted Windows launcher is not a real file".to_owned());
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot canonicalize trusted Windows launcher: {error}"))?;
        let digest = hell_testkit::sha256_file(&canonical)
            .map_err(|error| format!("cannot hash trusted Windows launcher: {error}"))?;
        let icacls = resolve_icacls()?;
        set_dacl(&icacls, &canonical, false, false)?;
        if fs::canonicalize(path)
            .map_err(|error| format!("cannot revalidate trusted Windows launcher: {error}"))?
            != canonical
            || hell_testkit::sha256_file(&canonical)
                .map_err(|error| format!("cannot rehash trusted Windows launcher: {error}"))?
                != digest
        {
            return Err("trusted Windows launcher identity changed during confinement".to_owned());
        }
        Ok((canonical, digest))
    }

    pub(super) fn protect_tree(root: &Path, writable: bool) -> Result<(), String> {
        let icacls = resolve_icacls()?;
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| format!("cannot inspect Windows confinement root: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Windows confinement root is not a real directory".to_owned());
        }
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect Windows confinement entry: {error}"))?;
            let is_directory = metadata.is_dir();
            set_dacl(&icacls, &path, writable, is_directory)?;
            if is_directory {
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

    pub(super) fn cleanup_tree(root: &Path) -> Result<(), String> {
        let icacls = resolve_icacls()?;
        run_icacls(&icacls, root, &["/reset", "/T", "/C"])?;
        fs::remove_dir_all(root)
            .map_err(|error| format!("cannot remove Windows toolchain authority: {error}"))
    }

    fn resolve_icacls() -> Result<PathBuf, String> {
        let system_root = std::env::var_os("SystemRoot")
            .ok_or_else(|| "standard SystemRoot is unavailable".to_owned())?;
        let system32 = PathBuf::from(system_root)
            .join("System32")
            .canonicalize()
            .map_err(|error| format!("cannot canonicalize Windows System32: {error}"))?;
        let tool = system32
            .join("icacls.exe")
            .canonicalize()
            .map_err(|error| format!("cannot canonicalize Windows icacls.exe: {error}"))?;
        let metadata = fs::metadata(&tool)
            .map_err(|error| format!("cannot inspect Windows icacls.exe: {error}"))?;
        if !metadata.is_file() || tool.parent() != Some(system32.as_path()) {
            return Err("Windows icacls.exe is not a regular System32 file".to_owned());
        }
        Ok(tool)
    }

    fn set_dacl(
        icacls: &Path,
        path: &Path,
        writable: bool,
        is_directory: bool,
    ) -> Result<(), String> {
        run_icacls(icacls, path, &["/reset"])?;
        let grants = windows_confinement_icacls_grants(writable, is_directory);
        let mut arguments = vec!["/inheritance:r", "/grant:r"];
        arguments.extend(grants);
        run_icacls(icacls, path, &arguments)
    }

    fn run_icacls(icacls: &Path, path: &Path, arguments: &[&str]) -> Result<(), String> {
        let output = std::process::Command::new(icacls)
            .arg(path)
            .args(arguments)
            .output()
            .map_err(|error| format!("cannot launch Windows icacls.exe: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Windows icacls.exe rejected confinement DACL with status {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn windows_confinement_icacls_grants(writable: bool, is_directory: bool) -> [&'static str; 4] {
    match (writable, is_directory) {
        (true, true) => [
            "*S-1-5-32-544:(OI)(CI)(F)",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-11:(OI)(CI)(F)",
            "*S-1-5-12:(OI)(CI)(F)",
        ],
        (false, true) => [
            "*S-1-5-32-544:(OI)(CI)(F)",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-11:(OI)(CI)(RX)",
            "*S-1-5-12:(OI)(CI)(RX)",
        ],
        (true, false) => [
            "*S-1-5-32-544:(F)",
            "*S-1-5-18:(F)",
            "*S-1-5-11:(F)",
            "*S-1-5-12:(F)",
        ],
        (false, false) => [
            "*S-1-5-32-544:(F)",
            "*S-1-5-18:(F)",
            "*S-1-5-11:(RX)",
            "*S-1-5-12:(RX)",
        ],
    }
}

struct CandidateConfinement {
    policy: hell_testkit::CandidateLaunchPolicy,
    #[cfg(unix)]
    _cleanup: PosixPrincipalCleanup,
    #[cfg(unix)]
    _adapter_protection: PosixAdapterProtection,
    #[cfg(unix)]
    _cargo_protection: PosixAdapterProtection,
    #[cfg(unix)]
    _cargo_deny_protection: Option<PosixAdapterProtection>,
    #[cfg(unix)]
    cargo_deny_home_protection: Option<PosixCargoDenyHomeProtection>,
    #[cfg(unix)]
    _stack_protection: Option<PosixAdapterProtection>,
    #[cfg(unix)]
    stack_root_protection: Option<PosixStackRootProtection>,
    #[cfg(unix)]
    _rustup_protection: Option<PosixRustupProtection>,
    #[cfg(unix)]
    source_protection: PosixSourceProtection,
    #[cfg(windows)]
    candidate_root: PathBuf,
    #[cfg(windows)]
    oracle_root: PathBuf,
    #[cfg(windows)]
    _toolchain: WindowsToolchainProtection,
}

impl CandidateConfinement {
    fn cleanup_dependency_policy_cache(&mut self) -> Result<(), String> {
        #[cfg(unix)]
        if let Some(mut protection) = self.cargo_deny_home_protection.take() {
            protection.cleanup()?;
        }
        #[cfg(unix)]
        if let Some(mut protection) = self.stack_root_protection.take() {
            normalize_posix_stack_root_with_adapter(
                &protection.sudo,
                &self._adapter_protection,
                &protection.root,
                protection.candidate_uid,
                protection.trusted_group_id,
            )?;
            protection.cleanup()?;
        }
        Ok(())
    }
    fn archive_launcher(&self) -> Option<&Path> {
        #[cfg(unix)]
        return Some(&self._adapter_protection.adapter);
        #[cfg(windows)]
        return None;
    }

    fn archive_adapter_base<'a>(&'a self, _target: &'a Path) -> &'a Path {
        #[cfg(unix)]
        return &self.source_protection.archive_adapter;
        #[cfg(windows)]
        return _target;
    }

    #[cfg(unix)]
    fn seal_archive_adapter_authority(
        &self,
        adapter: &Path,
    ) -> Result<PosixArchiveAdapterSeal<'_>, String> {
        seal_posix_archive_adapter_authority(
            &self.source_protection,
            &self._adapter_protection,
            adapter,
        )
    }

    #[cfg(unix)]
    fn stack_work_authority(&self) -> Result<&Path, String> {
        self.source_protection
            .stack_work
            .as_deref()
            .ok_or_else(|| "candidate Stack work authority is absent".to_owned())
    }

    fn candidate_root(&self) -> &Path {
        #[cfg(unix)]
        return &self.source_protection.candidate;
        #[cfg(windows)]
        return &self.candidate_root;
    }

    fn oracle_root(&self) -> &Path {
        #[cfg(unix)]
        return &self.source_protection.oracle;
        #[cfg(windows)]
        return &self.oracle_root;
    }

    fn require_bound_sources(&self) -> Result<(), String> {
        #[cfg(unix)]
        return validate_posix_sources(&self.source_protection);
        #[cfg(windows)]
        return Ok(());
    }

    fn retain_oracle(
        &mut self,
        source: &UnretainedOracle,
    ) -> Result<hell_testkit::ExecutableIdentity, String> {
        #[cfg(unix)]
        return self.source_protection.retain_oracle_copy(source);
        #[cfg(windows)]
        return retain_oracle_copy(&self.candidate_root, source.identity()?.clone());
    }
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
fn trusted_tool_status<I, S>(
    sudo: &Path,
    tool: &crate::command::ResolvedStandardExecutable,
    arguments: I,
) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    tool.revalidate()
        .map_err(|error| format!("trusted confinement tool validation failed: {error}"))?;
    let result = CommandSpec::new(sudo.as_os_str(), Duration::from_secs(30))
        .arguments(["-n", "--"])
        .argument(tool.invocation_path())
        .arguments(arguments)
        .run()
        .map_err(|error| format!("trusted confinement command failed: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("trusted confinement command did not succeed".to_owned());
    }
    Ok(())
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
fn require_exact_posix_candidate_identity(
    id: &crate::command::ResolvedStandardExecutable,
    option: &str,
    principal: &str,
    expected: u32,
    label: &str,
) -> Result<(), String> {
    let output = exact_posix_candidate_identity_output(id, option, principal, label)?;
    if !posix_candidate_identity_output_is_exact(&output, expected) {
        return Err(format!(
            "candidate {label} differs from the bound numeric identity"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn exact_posix_candidate_identity_output(
    id: &crate::command::ResolvedStandardExecutable,
    option: &str,
    principal: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    id.revalidate()
        .map_err(|error| format!("trusted candidate identity validation failed: {error}"))?;
    let result = CommandSpec::new(id.invocation_path().as_os_str(), Duration::from_secs(30))
        .arguments([option, principal])
        .run()
        .map_err(|error| format!("trusted candidate identity command failed: {error}"))?;
    if !result.status.success()
        || result.timed_out
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.stderr.is_empty()
    {
        return Err(format!("candidate {label} query did not succeed exactly"));
    }
    Ok(result.stdout)
}

#[cfg(unix)]
fn posix_candidate_identity_output_is_exact(output: &[u8], expected: u32) -> bool {
    output == format!("{expected}\n").as_bytes()
}

#[cfg(unix)]
fn posix_candidate_group_inventory(output: &[u8], primary_gid: u32) -> Option<Vec<u32>> {
    let line = output.strip_suffix(b"\n")?;
    if line.is_empty() {
        return None;
    }
    let mut groups = Vec::new();
    let mut unique = BTreeSet::new();
    for token in line.split(|byte| *byte == b' ') {
        let text = std::str::from_utf8(token).ok()?;
        let group = text.parse::<u32>().ok()?;
        if text != group.to_string() || !unique.insert(group) {
            return None;
        }
        groups.push(group);
        if groups.len() > hell_testkit::POSIX_CANDIDATE_GROUP_LIMIT {
            return None;
        }
    }
    groups.contains(&primary_gid).then_some(groups)
}

#[cfg(unix)]
fn normalize_candidate_cache_with_adapter(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    root: &Path,
    trusted_owner: u32,
    candidate_group: u32,
) -> Result<(), String> {
    require_posix_adapter_unchanged(adapter)?;
    validate_candidate_cache_normalizer_root(root)?;
    if adapter.platform == ReleasePlatform::MacosAarch64 {
        let tools = resolve_posix_adapter_tools(adapter.platform)?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                adapter.platform,
                true,
                path_text(root, "candidate cache ACL boundary")?,
            )?,
        )?;
    }
    let adapter_text = path_text(&adapter.adapter, "trusted candidate cache normalizer")?;
    let root_text = path_text(root, "candidate cache")?;
    let trusted_owner = trusted_owner.to_string();
    let candidate_group = candidate_group.to_string();
    trusted_status(
        sudo,
        [
            "-n",
            "--",
            adapter_text,
            "__release-normalize-candidate-cache",
            root_text,
            &trusted_owner,
            &candidate_group,
        ],
    )
    .map_err(|error| format!("cannot normalize restored candidate cache: {error}"))?;
    require_posix_adapter_unchanged(adapter)
}

#[cfg(unix)]
fn require_posix_adapter_unchanged(protection: &PosixAdapterProtection) -> Result<(), String> {
    if validate_posix_adapter_installation_root(protection.platform, &protection.installation_root)?
        != protection.installation_root
        || posix_object_identity(&protection.installation_root)?
            != protection.installation_root_identity
        || !posix_adapter_cleanup_is_exact(
            &protection.installation_root,
            &protection.directory,
            &protection.adapter,
            protection.staged_name,
        )
        || posix_object_identity(&protection.directory)? != protection.directory_identity
        || posix_object_identity(&protection.adapter)? != protection.adapter_identity
        || hell_testkit::sha256_file(&protection.adapter)
            .map_err(|error| format!("cannot rehash trusted POSIX adapter: {error}"))?
            != protection.sha256
    {
        return Err("trusted POSIX adapter identity changed".to_owned());
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
fn normalize_candidate_cache_tree(
    root: &Path,
    ownership: Option<(u32, u32)>,
) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

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
            if let Some((owner, group)) = ownership {
                std::os::unix::fs::chown(&path, Some(owner), Some(group)).map_err(|error| {
                    format!("cannot restore candidate cache ownership: {error}")
                })?;
            }
            set_posix_mode(&path, 0o2770)?;
            for entry in fs::read_dir(&path).map_err(|error| {
                format!(
                    "cannot enumerate restored candidate cache {}: {error}",
                    path.display()
                )
            })? {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read restored cache entry: {error}"))?
                        .path(),
                );
            }
        } else if file_type.is_file() {
            if metadata.nlink() != 1 {
                return Err("restored candidate cache contains a multiply-linked file".to_owned());
            }
            if let Some((owner, group)) = ownership {
                std::os::unix::fs::chown(&path, Some(owner), Some(group)).map_err(|error| {
                    format!("cannot restore candidate cache ownership: {error}")
                })?;
            }
            let executable = metadata.permissions().mode() & 0o111 != 0;
            set_posix_mode(&path, if executable { 0o770 } else { 0o660 })?;
        } else {
            return Err("restored candidate cache entry is not regular".to_owned());
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn run_posix_candidate_cache_normalizer(arguments: &[OsString]) -> Result<(), String> {
    let [root, owner, group] = arguments else {
        return Err(
            "trusted candidate cache normalizer requires path, owner, and group".to_owned(),
        );
    };
    let root = PathBuf::from(root);
    validate_candidate_cache_normalizer_root(&root)?;
    let owner = owner
        .to_str()
        .ok_or_else(|| "trusted candidate cache owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted candidate cache owner is invalid".to_owned())?;
    let group = group
        .to_str()
        .ok_or_else(|| "trusted candidate cache group is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted candidate cache group is invalid".to_owned())?;
    normalize_candidate_cache_tree(&root, Some((owner, group)))
}

#[cfg(unix)]
pub(crate) fn run_posix_cargo_deny_home_normalizer(arguments: &[OsString]) -> Result<(), String> {
    let [home, candidate_owner, trusted_owner, trusted_group] = arguments else {
        return Err(
            "trusted cargo-deny home normalizer requires path, candidate owner, trusted owner, and trusted group"
                .to_owned(),
        );
    };
    let home = PathBuf::from(home);
    validate_posix_cargo_deny_home_root(&home)?;
    let candidate_owner = candidate_owner
        .to_str()
        .ok_or_else(|| "cargo-deny lock owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "cargo-deny lock owner is invalid".to_owned())?;
    let trusted_owner = trusted_owner
        .to_str()
        .ok_or_else(|| "trusted cargo-deny cache owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted cargo-deny cache owner is invalid".to_owned())?;
    let trusted_group = trusted_group
        .to_str()
        .ok_or_else(|| "trusted cargo-deny cache group is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted cargo-deny cache group is invalid".to_owned())?;
    normalize_cargo_deny_cache_tree(&home, candidate_owner, trusted_owner, trusted_group)
}

#[cfg(unix)]
pub(crate) fn run_posix_stack_root_normalizer(arguments: &[OsString]) -> Result<(), String> {
    let [root, owner, group] = arguments else {
        return Err("trusted Stack-root normalizer requires path, owner, and group".to_owned());
    };
    let root = PathBuf::from(root);
    validate_posix_stack_root(&root)?;
    let owner = owner
        .to_str()
        .ok_or_else(|| "trusted Stack-root owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted Stack-root owner is invalid".to_owned())?;
    let group = group
        .to_str()
        .ok_or_else(|| "trusted Stack-root group is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted Stack-root group is invalid".to_owned())?;
    normalize_candidate_owned_cache_tree(&root, owner, group)
}

#[cfg(unix)]
pub(crate) fn run_posix_stack_work_normalizer(arguments: &[OsString]) -> Result<(), String> {
    let [
        authority,
        authority_device,
        authority_inode,
        source,
        source_device,
        source_inode,
        work,
        work_device,
        work_inode,
        owner,
        group,
    ] = arguments
    else {
        return Err(
            "trusted Stack-work normalizer requires three bound paths, their identities, owner, and group"
                .to_owned(),
        );
    };
    let authority = PathBuf::from(authority);
    let source = PathBuf::from(source);
    let work = PathBuf::from(work);
    let parse_u64 = |value: &OsString, label: &str| {
        value
            .to_str()
            .ok_or_else(|| format!("trusted Stack-work {label} is not UTF-8"))?
            .parse::<u64>()
            .map_err(|_| format!("trusted Stack-work {label} is invalid"))
    };
    let authority_identity = (
        parse_u64(authority_device, "parent device")?,
        parse_u64(authority_inode, "parent inode")?,
    );
    let source_identity = (
        parse_u64(source_device, "source device")?,
        parse_u64(source_inode, "source inode")?,
    );
    let work_identity = (
        parse_u64(work_device, "work device")?,
        parse_u64(work_inode, "work inode")?,
    );
    let owner = owner
        .to_str()
        .ok_or_else(|| "trusted Stack-work owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted Stack-work owner is invalid".to_owned())?;
    let group = group
        .to_str()
        .ok_or_else(|| "trusted Stack-work group is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted Stack-work group is invalid".to_owned())?;
    validate_posix_stack_work(&PosixStackWorkValidation {
        authority: &authority,
        authority_identity,
        source: &source,
        source_identity,
        work: &work,
        work_identity,
        owner,
        group,
    })?;
    normalize_candidate_owned_cache_tree(&work, owner, group)
}

#[cfg(unix)]
fn validate_posix_cargo_deny_home_root(home: &Path) -> Result<(), String> {
    let release_environment = home
        .parent()
        .ok_or_else(|| "candidate cargo-deny home has no parent".to_owned())?;
    let target = release_environment
        .parent()
        .ok_or_else(|| "candidate cargo-deny home has no target parent".to_owned())?;
    let metadata = fs::symlink_metadata(home)
        .map_err(|error| format!("cannot inspect candidate cargo-deny home: {error}"))?;
    if !home.is_absolute()
        || home.file_name() != Some(std::ffi::OsStr::new("cargo-deny-cargo-home"))
        || release_environment.file_name()
            != Some(std::ffi::OsStr::new("release-child-environment"))
        || target.file_name() != Some(std::ffi::OsStr::new("candidate-target"))
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(home)
            .map_err(|error| format!("cannot canonicalize candidate cargo-deny home: {error}"))?
            != home
    {
        return Err("trusted cargo-deny home root differs from policy".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_posix_stack_root(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect candidate Stack root: {error}"))?;
    if !root.is_absolute()
        || !posix_stack_root_is_exact(root)
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(root)
            .map_err(|error| format!("cannot canonicalize candidate Stack root: {error}"))?
            != root
    {
        return Err("trusted Stack root differs from policy".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn posix_stack_work_is_exact(authority: &Path, source: &Path, work: &Path) -> bool {
    let Some(name) = authority.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let Some(suffix) = name.strip_prefix("hell-rs-posix-sources-") else {
        return false;
    };
    let mut components = suffix.split('-');
    let (Some(process), Some(sequence), Some(commit), None) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    ) else {
        return false;
    };
    let canonical_number = |value: &str| {
        value
            .parse::<u64>()
            .is_ok_and(|number| value == number.to_string())
    };
    authority.parent() == Some(Path::new("/private/var/tmp"))
        && canonical_number(process)
        && canonical_number(sequence)
        && commit.len() == 12
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && source == authority.join("oracle")
        && work == source.join(".stack-work")
}

#[cfg(unix)]
struct PosixStackWorkValidation<'a> {
    authority: &'a Path,
    authority_identity: (u64, u64),
    source: &'a Path,
    source_identity: (u64, u64),
    work: &'a Path,
    work_identity: (u64, u64),
    owner: u32,
    group: u32,
}

#[cfg(unix)]
fn validate_posix_stack_work(binding: &PosixStackWorkValidation<'_>) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !posix_stack_work_is_exact(binding.authority, binding.source, binding.work) {
        return Err("trusted Stack-work path differs from policy".to_owned());
    }
    let inspect = |path: &Path, expected: (u64, u64), label: &str| {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fs::canonicalize(path)
                .map_err(|error| format!("cannot canonicalize {label}: {error}"))?
                != path
            || (metadata.dev(), metadata.ino()) != expected
        {
            return Err(format!("{label} identity differs from policy"));
        }
        Ok(metadata)
    };
    let authority_metadata = inspect(
        binding.authority,
        binding.authority_identity,
        "Stack-work parent authority",
    )?;
    let source_metadata = inspect(
        binding.source,
        binding.source_identity,
        "Stack-work source authority",
    )?;
    let work_metadata = inspect(binding.work, binding.work_identity, "Stack-work authority")?;
    if authority_metadata.uid() != 0
        || authority_metadata.gid() != 0
        || authority_metadata.permissions().mode() & 0o7777 != 0o555
        || source_metadata.uid() != 0
        || source_metadata.gid() != 0
        || source_metadata.permissions().mode() & 0o7777 != 0o555
        || work_metadata.uid() != binding.owner
        || work_metadata.gid() != binding.group
        || work_metadata.permissions().mode() & 0o7777 != 0o750
    {
        return Err("trusted Stack-work ownership or mode differs from policy".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_candidate_owned_cache_tree(root: &Path, owner: u32, group: u32) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect candidate cargo-deny cache: {error}"))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink()
            || file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
            || (!file_type.is_dir() && !file_type.is_file())
            || (file_type.is_file() && metadata.nlink() != 1)
        {
            return Err("candidate cargo-deny cache contains a link or special file".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "candidate cargo-deny cache entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if file_type.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "candidate cargo-deny cache byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("candidate cargo-deny cache exceeds its resource bound".to_owned());
        }
        std::os::unix::fs::chown(&path, Some(owner), Some(group)).map_err(|error| {
            format!("cannot bind candidate cargo-deny cache ownership: {error}")
        })?;
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if file_type.is_dir() { 0o750 } else { 0o640 }),
        )
        .map_err(|error| format!("cannot bind candidate cargo-deny cache permissions: {error}"))?;
        if file_type.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate candidate cargo-deny cache: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read cargo-deny cache entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_cargo_deny_cache_tree(
    root: &Path,
    candidate_owner: u32,
    trusted_owner: u32,
    trusted_group: u32,
) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    let lock = Path::new("advisory-dbs").join("db.lock");
    let advisory_root = Path::new("advisory-dbs");
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    let mut found_lock = false;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect cargo-deny cache authority: {error}"))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink()
            || file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
            || (!file_type.is_dir() && !file_type.is_file())
            || (file_type.is_file() && metadata.nlink() != 1)
        {
            return Err("cargo-deny cache authority contains a link or special file".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "cargo-deny cache authority entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if file_type.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "cargo-deny cache authority byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("cargo-deny cache authority exceeds its resource bound".to_owned());
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "cargo-deny cache authority escaped its root".to_owned())?;
        let is_lock = relative == lock;
        let is_advisory_root = relative == advisory_root;
        if is_lock && (!file_type.is_file() || metadata.len() != 0) {
            return Err(
                "cargo-deny advisory lock authority is not an empty regular file".to_owned(),
            );
        }
        let owner = if is_lock || is_advisory_root {
            candidate_owner
        } else {
            trusted_owner
        };
        std::os::unix::fs::chown(&path, Some(owner), Some(trusted_group))
            .map_err(|error| format!("cannot bind cargo-deny cache ownership: {error}"))?;
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(match (is_lock, is_advisory_root) {
                // The lock is intentionally empty synchronization state. It is
                // candidate-owned and trusted-group-writable so either side of
                // the confinement boundary can acquire it, while immutable
                // advisory payloads remain inaccessible for writes.
                (true, _) => 0o660,
                (_, true) => 0o750,
                (_, _) if file_type.is_dir() => 0o555,
                (_, _) => 0o444,
            }),
        )
        .map_err(|error| format!("cannot bind cargo-deny cache permissions: {error}"))?;
        found_lock |= is_lock;
        if file_type.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate cargo-deny cache authority: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read cargo-deny cache entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    if !found_lock {
        return Err("cargo-deny advisory lock authority is absent".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_candidate_cache_normalizer_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() || root.file_name() != Some(std::ffi::OsStr::new("candidate-target")) {
        return Err("trusted candidate cache normalizer root differs from policy".to_owned());
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect candidate cache authority: {error}"))?;
    let canonical = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize candidate cache authority: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || canonical != root {
        return Err("trusted candidate cache normalizer root is redirected".to_owned());
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
    let substitution = crate::mutation::active("candidate-conformance-plan-substitution");
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
    #[cfg(unix)]
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
    #[cfg(not(unix))]
    if platform == ReleasePlatform::LinuxX86_64 {
        return Err("Linux release gates require a POSIX trusted runner".to_owned());
    }
    #[cfg(unix)]
    if platform == ReleasePlatform::LinuxX86_64 {
        command_gate(
            "dependency-policy",
            CommandSpec::cargo_deny(Duration::from_mins(10))
                .arguments(["--frozen", "--all-features", "check", "all"])
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
            release_candidate_build(root),
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
    hell_testkit::verify_compat_tracing_candidate_identity(&candidate)
        .map_err(|error| format!("cannot bind candidate compatibility tracing: {error}"))?;
    let candidate_build_info = candidate
        .build_info
        .as_ref()
        .ok_or_else(|| "verified candidate build info is missing".to_owned())?;
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
    let requested_cases = requested_case_ids
        .iter()
        .map(|case_id| {
            committed_cases
                .get(case_id)
                .cloned()
                .ok_or_else(|| format!("planned committed case {case_id:?} is unavailable"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let workers = hell_testkit::differential_worker_limit();
    let committed_batch = hell_testkit::differential_batch_with_identities(
        oracle,
        &candidate,
        &requested_cases,
        workers,
    )
    .map_err(|error| format!("cannot collect committed differential batch: {error}"))?;
    let mut differential_timing = committed_batch.timing;
    for (case_id, report) in requested_case_ids.iter().zip(committed_batch.reports) {
        let oracle_digest = retain_observation(&report.oracle, &mut observations)?;
        let candidate_digest = retain_observation(&report.candidate, &mut observations)?;
        committed_observations.insert(case_id.clone(), (candidate_digest, oracle_digest));
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
                candidate_build_info_schema_version: candidate_build_info.schema_version,
                candidate_compat_tracing: candidate_build_info.compat_tracing,
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
    let generated = hell_testkit::generated_typed_cases(
        crate::conformance::EXPLORATORY_GENERATOR_SEED,
        crate::conformance::EXPLORATORY_GENERATOR_COUNT,
    );
    let generated_cases = generated
        .iter()
        .map(|generated| hell_testkit::DifferentialCase {
            id: generated.id.clone(),
            source: generated.source.clone(),
            ..hell_testkit::DifferentialCase::default()
        })
        .collect::<Vec<_>>();
    let generated_batch = hell_testkit::differential_batch_with_identities(
        oracle,
        &candidate,
        &generated_cases,
        workers,
    )
    .map_err(|error| format!("cannot collect exploratory differential batch: {error}"))?;
    add_differential_timing(&mut differential_timing, generated_batch.timing);
    for (generated, report) in generated.iter().zip(generated_batch.reports) {
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
            candidate_build_info_schema_version: candidate_build_info.schema_version,
            candidate_compat_tracing: candidate_build_info.compat_tracing,
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
    let manifest =
        crate::conformance::EvidenceManifest::new(crate::conformance::EvidenceManifestInput {
            platform: conformance_platform,
            candidate_sha: plan.resolution.candidate_sha.clone(),
            candidate_executable_sha256: candidate.sha256.hex(),
            release_plan_sha256: plan.plan_sha256.clone(),
            conformance_plan_sha256: conformance_plan.plan_sha256.clone(),
            oracle: oracle_binding,
            records: record_members,
            exploratory_records: exploratory_members,
            observations: observation_members,
            assigned_obligations,
        })?;
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
            (
                "candidateProcessSumMillis",
                number(duration_millis(
                    differential_timing.candidate_process_sum,
                    "candidate process timing",
                )?),
            ),
            ("candidateExecutableSha256", string(&candidate.sha256.hex())),
            (
                "completedDifferentialCases",
                number(
                    u64::try_from(differential_timing.completed_count)
                        .map_err(|_| "completed differential case count overflow")?,
                ),
            ),
            (
                "differentialBatchWallMillis",
                number(duration_millis(
                    differential_timing.wall,
                    "differential batch wall timing",
                )?),
            ),
            (
                "differentialDriverOverheadSumMillis",
                number(duration_millis(
                    differential_timing.driver_overhead_sum,
                    "differential driver timing",
                )?),
            ),
            (
                "differentialWorkerCount",
                number(
                    u64::try_from(differential_timing.worker_count)
                        .map_err(|_| "differential worker count overflow")?,
                ),
            ),
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
            (
                "oracleProcessSumMillis",
                number(duration_millis(
                    differential_timing.oracle_process_sum,
                    "oracle process timing",
                )?),
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

fn add_differential_timing(
    total: &mut hell_testkit::DifferentialBatchTiming,
    batch: hell_testkit::DifferentialBatchTiming,
) {
    total.case_count = total.case_count.saturating_add(batch.case_count);
    total.completed_count = total.completed_count.saturating_add(batch.completed_count);
    total.worker_count = total.worker_count.max(batch.worker_count);
    total.wall = total.wall.saturating_add(batch.wall);
    total.oracle_process_sum = total
        .oracle_process_sum
        .saturating_add(batch.oracle_process_sum);
    total.candidate_process_sum = total
        .candidate_process_sum
        .saturating_add(batch.candidate_process_sum);
    total.driver_overhead_sum = total
        .driver_overhead_sum
        .saturating_add(batch.driver_overhead_sum);
}

fn duration_millis(duration: Duration, label: &str) -> Result<u64, String> {
    u64::try_from(duration.as_millis()).map_err(|_| format!("{label} overflow"))
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

const LINUX_ORACLE_NAME: &str = "hell-linux-amd64";
const LINUX_ORACLE_SHA256: &str =
    "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9";

#[cfg(unix)]
struct LinuxOracleAcquisition {
    output: PathBuf,
    output_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    oracle_identity: Option<(PosixObjectIdentity, u64, hell_testkit::Digest)>,
    active: bool,
}

#[cfg(unix)]
impl LinuxOracleAcquisition {
    fn reserve(output: &Path) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt as _;

        let canonical = fs::canonicalize(output)
            .map_err(|error| format!("cannot canonicalize trusted oracle output: {error}"))?;
        let metadata = fs::symlink_metadata(output)
            .map_err(|error| format!("cannot inspect trusted oracle output: {error}"))?;
        if canonical != output
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(
                "trusted oracle output is redirected or writable by another principal".to_owned(),
            );
        }
        let directory = output.join(".trusted-oracle-acquisition");
        if directory.exists() {
            return Err("trusted oracle acquisition directory already exists".to_owned());
        }
        fs::create_dir(&directory)
            .map_err(|error| format!("cannot reserve trusted oracle acquisition: {error}"))?;
        if let Err(error) = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir(&directory);
            return Err(format!(
                "cannot protect trusted oracle acquisition: {error}"
            ));
        }
        let acquisition = Self {
            output: output.to_path_buf(),
            output_identity: posix_object_identity(output)?,
            directory: directory.clone(),
            directory_identity: posix_object_identity(&directory)?,
            oracle_identity: None,
            active: true,
        };
        acquisition.validate()?;
        Ok(acquisition)
    }

    fn directory(&self) -> &Path {
        &self.directory
    }

    fn bind_path(&mut self, path: &Path, sha256: hell_testkit::Digest) -> Result<(), String> {
        let expected = self.directory.join(LINUX_ORACLE_NAME);
        if path != expected {
            return Err("downloaded Linux oracle path differs from acquisition policy".to_owned());
        }
        require_executable_digest(path, sha256, "downloaded Linux oracle")?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect downloaded Linux oracle: {error}"))?;
        self.oracle_identity = Some((posix_object_identity(path)?, metadata.len(), sha256));
        self.validate()
    }

    fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if !self.active
            || self.directory.parent() != Some(&self.output)
            || self.directory.file_name()
                != Some(std::ffi::OsStr::new(".trusted-oracle-acquisition"))
            || posix_object_identity(&self.output)? != self.output_identity
            || posix_object_identity(&self.directory)? != self.directory_identity
        {
            return Err("trusted oracle acquisition authority changed".to_owned());
        }
        let directory_metadata = fs::symlink_metadata(&self.directory)
            .map_err(|error| format!("cannot inspect trusted oracle acquisition: {error}"))?;
        if directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err("trusted oracle acquisition permissions changed".to_owned());
        }
        match &self.oracle_identity {
            None => {
                require_exact_directory_members(&self.directory, &[], "trusted oracle acquisition")
            }
            Some((expected_identity, expected_size, expected_sha256)) => {
                let oracle = self.directory.join(LINUX_ORACLE_NAME);
                require_exact_directory_members(
                    &self.directory,
                    &[OsString::from(LINUX_ORACLE_NAME)],
                    "trusted oracle acquisition",
                )?;
                let metadata = fs::symlink_metadata(&oracle)
                    .map_err(|error| format!("cannot inspect downloaded Linux oracle: {error}"))?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.len() != *expected_size
                    || fs::canonicalize(&oracle).ok().as_deref() != Some(oracle.as_path())
                    || posix_object_identity(&oracle)? != *expected_identity
                {
                    return Err("downloaded Linux oracle identity changed".to_owned());
                }
                require_executable_digest(&oracle, *expected_sha256, "downloaded Linux oracle")
            }
        }
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.validate()?;
        if self.oracle_identity.is_some() {
            fs::remove_file(self.directory.join(LINUX_ORACLE_NAME))
                .map_err(|error| format!("cannot remove downloaded Linux oracle: {error}"))?;
        }
        fs::remove_dir(&self.directory)
            .map_err(|error| format!("cannot remove trusted oracle acquisition: {error}"))?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for LinuxOracleAcquisition {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct UnretainedOracle {
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(unix)]
    sha256: hell_testkit::Digest,
    #[cfg(windows)]
    identity: Option<hell_testkit::ExecutableIdentity>,
    #[cfg(unix)]
    acquisition: Option<LinuxOracleAcquisition>,
}

impl UnretainedOracle {
    fn native(identity: hell_testkit::ExecutableIdentity) -> Self {
        Self {
            #[cfg(unix)]
            path: identity.path.clone(),
            #[cfg(unix)]
            sha256: identity.sha256,
            #[cfg(windows)]
            identity: Some(identity),
            #[cfg(unix)]
            acquisition: None,
        }
    }

    #[cfg(windows)]
    fn identity(&self) -> Result<&hell_testkit::ExecutableIdentity, String> {
        self.identity
            .as_ref()
            .ok_or_else(|| "unverified oracle cannot be retained on Windows".to_owned())
    }

    fn cleanup(self) -> Result<(), String> {
        #[cfg(unix)]
        {
            let mut this = self;
            if let Some(acquisition) = &mut this.acquisition {
                acquisition.cleanup()?;
            }
        }
        #[cfg(windows)]
        drop(self);
        Ok(())
    }
}

fn acquire_linux_oracle(output: &Path) -> Result<PathBuf, String> {
    const URL: &str =
        "https://github.com/chrisdone/hell/releases/download/2026-05-29/hell-linux-amd64";
    const MAX_ORACLE_BYTES: u64 = 64 * 1024 * 1024;
    #[cfg(unix)]
    require_exact_directory_members(output, &[], "trusted oracle acquisition")?;
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
    if bytes.is_empty() || hell_testkit::sha256_bytes(&bytes).hex() != LINUX_ORACLE_SHA256 {
        return Err("pinned Linux oracle digest differs".to_owned());
    }
    let path = output.join(LINUX_ORACLE_NAME);
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
    _trusted_output: &Path,
    archive_adapter: &crate::command::NativeArchiveAdapter,
) -> Result<UnretainedOracle, String> {
    if platform == ReleasePlatform::LinuxX86_64 {
        #[cfg(not(unix))]
        return Err("Linux oracle acquisition requires a POSIX trusted runner".to_owned());
        #[cfg(unix)]
        let mut acquisition = LinuxOracleAcquisition::reserve(_trusted_output)?;
        #[cfg(unix)]
        let oracle = acquire_linux_oracle(acquisition.directory())?;
        #[cfg(unix)]
        let pinned_sha256 =
            hell_testkit::Digest::from_hex(LINUX_ORACLE_SHA256).map_err(str::to_owned)?;
        #[cfg(unix)]
        acquisition.bind_path(&oracle, pinned_sha256)?;
        #[cfg(unix)]
        return Ok(UnretainedOracle {
            path: oracle,
            sha256: pinned_sha256,
            acquisition: Some(acquisition),
        });
    }
    let build = archive_adapter.stack_build(oracle_source, Duration::from_hours(2));
    let result = build
        .run()
        .map_err(|error| format!("cannot build native oracle: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("native oracle build failed before candidate execution".to_owned());
    }
    let path = archive_adapter.stack_path(oracle_source);
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
    Ok(UnretainedOracle::native(identity))
}

#[cfg(windows)]
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
        ("release-build", release_candidate_build(root)),
    ]
}

fn release_candidate_build(root: &Path) -> CommandSpec {
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
            "--features",
            "compat-tracing",
        ],
    )
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
    let invocation_name = command.display_invocation_name();
    let canonical_identity = command.display_canonical_executable_identity();
    let arguments = command.display_arguments();
    let result = command
        .run()
        .map_err(|error| format!("release gate {name} could not run: {error}"))?;
    let passed = result.status.success() && !result.timed_out;
    evidence.insert(
        name.to_owned(),
        command_evidence(
            &program,
            invocation_name.as_deref(),
            canonical_identity.as_deref(),
            &arguments,
            &result,
        ),
    );
    gates.insert(name, passed);
    passed
        .then_some(())
        .ok_or_else(|| format!("release gate {name} failed"))
}

fn command_evidence(
    program: &str,
    invocation_name: Option<&str>,
    canonical_identity: Option<&str>,
    arguments: &[String],
    result: &CommandResult,
) -> JsonValue {
    let mut evidence = BTreeMap::from([
        (
            "arguments".to_owned(),
            JsonValue::Array(arguments.iter().map(|value| string(value)).collect()),
        ),
        ("program".to_owned(), string(program)),
        ("schemaVersion".to_owned(), number(1)),
        (
            "state".to_owned(),
            string(if result.status.success() && !result.timed_out {
                "passed"
            } else {
                "failed"
            }),
        ),
        (
            "stderrSha256".to_owned(),
            string(&result.stderr_sha256.hex()),
        ),
        (
            "stdoutSha256".to_owned(),
            string(&result.stdout_sha256.hex()),
        ),
    ]);
    if let Some(invocation_name) = invocation_name {
        evidence.insert("invocationName".to_owned(), string(invocation_name));
    }
    if let Some(canonical_identity) = canonical_identity {
        evidence.insert(
            "canonicalExecutableIdentity".to_owned(),
            string(canonical_identity),
        );
    }
    JsonValue::Object(evidence)
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
    CommandSpec::cargo(timeout)
        .arguments(arguments)
        .current_directory(root)
}

fn tool_identities(
    platform: ReleasePlatform,
    candidate_root: &Path,
    oracle_source: &Path,
    archive_adapter: &crate::command::NativeArchiveAdapter,
) -> Result<BTreeMap<String, JsonValue>, String> {
    let mut identities = BTreeMap::new();
    for (name, command) in [
        (
            "cargo",
            CommandSpec::cargo(Duration::from_secs(30))
                .argument("--version")
                .current_directory(candidate_root),
        ),
        (
            "rustc",
            CommandSpec::new("rustc", Duration::from_secs(30))
                .arguments(["--version", "--verbose"])
                .current_directory(candidate_root),
        ),
        (
            "stack",
            CommandSpec::new("stack", Duration::from_secs(30))
                .argument("--numeric-version")
                .current_directory(candidate_root),
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
        if let Some(identity) = archive_adapter.identity_command() {
            identities.insert(
                "llvm-ar".to_owned(),
                string(&tool_output(
                    identity.current_directory(candidate_root),
                    "llvm-ar",
                )?),
            );
        }
        identities.insert(
            "ghc".to_owned(),
            string(&tool_output(
                archive_adapter.stack_ghc_version(oracle_source),
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
        let stderr = String::from_utf8_lossy(&result.stderr);
        let stderr = stderr.chars().take(512).collect::<String>();
        return Err(format!(
            "{label} identity command failed with status {:?}, timedOut={}, stderr={stderr:?}",
            result.status.code(),
            result.timed_out
        ));
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

fn require_clean_checkout(root: &Path, expected_sha: &str, label: &str) -> Result<(), String> {
    require_clean_checkout_except(root, expected_sha, None, label)
}

fn require_clean_checkout_except(
    root: &Path,
    expected_sha: &str,
    excluded: Option<&Path>,
    label: &str,
) -> Result<(), String> {
    if git_head(root)? != expected_sha {
        return Err(format!("{label} checkout differs from its bound commit"));
    }
    let mut command = CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(root)
        .arguments(["status", "--porcelain=v1"])
        .arguments(["--untracked-files=all", "--ignored=matching"]);
    if let Some(excluded) = excluded {
        if excluded.parent() != Some(root)
            || excluded.file_name() != Some(std::ffi::OsStr::new(".stack-work"))
        {
            return Err(format!("{label} checkout exclusion differs from policy"));
        }
        command = command.arguments(["--", ".", ":(top,exclude,literal).stack-work"]);
    }
    let result = command
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot inspect {label} checkout: {error}"))?;
    if !result.status.success() || result.timed_out || !result.stdout.is_empty() {
        return Err(format!("{label} checkout is not an exact clean snapshot"));
    }
    Ok(())
}

fn require_inventory_snapshot(
    root: &Path,
    expected: &JsonValue,
    label: &str,
) -> Result<(), String> {
    let files = json_member(expected.object()?, "files")?.array()?;
    for file in files {
        let file = file.object()?;
        let relative = json_member(file, "path")?.string()?;
        let expected_size = json_member(file, "size")?.number()?;
        let expected_sha256 = json_member(file, "sha256")?.string()?;
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {label} file {relative:?}: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != expected_size
            || hell_testkit::sha256_file(&path)
                .map_err(|error| format!("cannot hash {label} file {relative:?}: {error}"))?
                .hex()
                != expected_sha256
        {
            return Err(format!(
                "{label} file {relative:?} differs from bound inventory"
            ));
        }
    }
    Ok(())
}

fn validate_runner(platform: ReleasePlatform) -> Result<(String, String), String> {
    let runner_os = env::var("RUNNER_OS").ok();
    let runner_arch = env::var("RUNNER_ARCH").ok();
    validate_runner_identity(
        platform,
        runner_os.as_deref(),
        runner_arch.as_deref(),
        env::consts::OS,
        env::consts::ARCH,
    )
}

fn validate_runner_identity(
    platform: ReleasePlatform,
    runner_os: Option<&str>,
    runner_arch: Option<&str>,
    host_os: &str,
    host_arch: &str,
) -> Result<(String, String), String> {
    let expected = platform.runner();
    match (runner_os, runner_arch) {
        (Some(os), Some(arch)) if (os, arch) == expected => Ok((os.to_owned(), arch.to_owned())),
        (None, None) if (host_os, host_arch) == platform_host(platform) => {
            Ok((expected.0.to_owned(), expected.1.to_owned()))
        }
        _ => Err(format!("runner identity does not match {}", platform.id())),
    }
}

const fn platform_host(platform: ReleasePlatform) -> (&'static str, &'static str) {
    match platform {
        ReleasePlatform::LinuxX86_64 => ("linux", "x86_64"),
        ReleasePlatform::MacosAarch64 => ("macos", "aarch64"),
        ReleasePlatform::WindowsX86_64 => ("windows", "x86_64"),
    }
}

fn git_head(root: &Path) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(root)
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
    use super::{
        accept_conformance_plan_binding, release_candidate_build, validate_runner_identity,
        windows_confinement_icacls_grants, windows_restricted_adapter_path,
    };
    use crate::release::schema::ReleasePlatform;

    #[cfg(unix)]
    use super::{
        LINUX_ORACLE_NAME, LinuxOracleAcquisition, PosixAdapterToolPaths,
        configure_staged_cargo_home_directory_source, copy_posix_cargo_cache_tree,
        normalize_candidate_cache_tree, normalize_candidate_owned_cache_tree,
        normalize_cargo_deny_cache_tree, posix_acl_removal_arguments,
        posix_adapter_authority_chain, posix_adapter_cleanup_is_exact,
        posix_adapter_installation_root, posix_adapter_tool_paths, posix_candidate_group_inventory,
        posix_candidate_identity_output_is_exact, posix_cargo_deny_home_is_exact,
        posix_cargo_deny_metadata_is_exact, posix_chmod_arguments, posix_object_identity,
        posix_rustup_cleanup_is_exact, posix_rustup_inventory_cost,
        posix_rustup_selected_inventory, posix_source_cleanup_is_exact, posix_stack_root_is_exact,
        posix_stack_work_is_exact, require_exact_directory_members, require_inventory_snapshot,
        require_posix_archive_adapter_transition_state, reserve_posix_cargo_deny_advisory_lock,
        run_posix_stack_work_normalizer, trusted_cargo_cache_fetch_arguments,
        trusted_cargo_cache_metadata_arguments, trusted_cargo_cache_offline_metadata_arguments,
        trusted_cargo_cache_seed_arguments, trusted_cargo_deny_advisory_arguments,
        trusted_cargo_vendor_arguments, validate_candidate_cache_normalizer_root,
        validate_posix_adapter_installation_root, validate_posix_cargo_deny_home_post_state,
        validate_posix_cargo_deny_home_root, validate_posix_stack_root,
        validate_posix_stack_root_post_state, validate_staged_cargo_metadata,
        validate_staged_vendor_covers_frozen_lock,
    };
    #[cfg(unix)]
    use std::path::Path;

    #[cfg(unix)]
    #[test]
    fn trusted_cargo_cache_seed_is_locked_and_manifest_scoped() {
        let manifest = Path::new("/bound/candidate/Cargo.toml");
        assert_eq!(
            trusted_cargo_cache_seed_arguments(Path::new("/bound/candidate"), manifest).unwrap(),
            [
                "fetch".into(),
                "--locked".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
            ]
        );
        assert_eq!(
            trusted_cargo_cache_metadata_arguments(Path::new("/bound/candidate"), manifest)
                .unwrap(),
            [
                "metadata".into(),
                "--locked".into(),
                "--all-features".into(),
                "--format-version".into(),
                "1".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
            ]
        );
        assert_eq!(
            trusted_cargo_cache_offline_metadata_arguments(Path::new("/bound/candidate"), manifest)
                .unwrap(),
            [
                "metadata".into(),
                "--locked".into(),
                "--offline".into(),
                "--all-features".into(),
                "--format-version".into(),
                "1".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
            ]
        );
        assert_eq!(
            trusted_cargo_cache_fetch_arguments(Path::new("/bound/candidate"), manifest).unwrap(),
            [
                "fetch".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
                "--frozen".into(),
                "--locked".into(),
                "--offline".into(),
            ]
        );
        let cargo_home = Path::new("/private/var/tmp/hell-cargo-seed-1-2");
        let advisory_metadata = cargo_home.join("hell-cargo-deny-metadata.json");
        assert_eq!(
            trusted_cargo_deny_advisory_arguments(cargo_home, &advisory_metadata).unwrap(),
            [
                "--metadata-path".into(),
                advisory_metadata.as_os_str().to_owned(),
                "--all-features".into(),
                "check".into(),
                "advisories".into(),
            ]
        );
        assert!(
            trusted_cargo_deny_advisory_arguments(
                cargo_home,
                &cargo_home.join("unbound-metadata.json")
            )
            .is_err()
        );
        assert_eq!(
            trusted_cargo_vendor_arguments(
                Path::new("/bound/candidate"),
                manifest,
                Path::new("/private/var/tmp/hell-cargo-seed-1-2"),
                Path::new("/private/var/tmp/hell-cargo-seed-1-2/vendor"),
            )
            .unwrap(),
            [
                "vendor".into(),
                "--locked".into(),
                "--versioned-dirs".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
                "/private/var/tmp/hell-cargo-seed-1-2/vendor".into(),
            ]
        );
        assert!(
            trusted_cargo_cache_seed_arguments(Path::new("bound/candidate"), manifest).is_err()
        );
        assert!(
            trusted_cargo_cache_metadata_arguments(Path::new("bound/candidate"), manifest).is_err()
        );
        assert!(
            trusted_cargo_cache_fetch_arguments(Path::new("bound/candidate"), manifest).is_err()
        );
        assert!(
            trusted_cargo_cache_fetch_arguments(
                Path::new("/bound/candidate"),
                Path::new("/bound/Cargo.lock")
            )
            .is_err()
        );
        assert!(
            trusted_cargo_cache_seed_arguments(
                Path::new("/bound/candidate"),
                Path::new("/bound/Cargo.lock")
            )
            .is_err()
        );
        assert!(
            trusted_cargo_cache_metadata_arguments(
                Path::new("/bound/candidate"),
                Path::new("/bound/Cargo.lock")
            )
            .is_err()
        );
        assert!(
            trusted_cargo_vendor_arguments(
                Path::new("/bound/candidate"),
                manifest,
                Path::new("/private/var/tmp/hell-cargo-seed-1-2"),
                Path::new("/private/var/tmp/other/vendor"),
            )
            .is_err()
        );

        let home = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-cargo-directory-source-{}",
                std::process::id()
            ));
        let source = home.join("vendor");
        let package = source.join("known-folders-1.4.2");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join(".cargo-checksum.json"), b"{}\n").unwrap();
        configure_staged_cargo_home_directory_source(&home).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("config.toml")).unwrap(),
            format!(
                "[source.crates-io]\nreplace-with = 'hell-staged-registry'\n\n[source.hell-staged-registry]\ndirectory = '{}'\n",
                source.display()
            )
        );
        assert!(configure_staged_cargo_home_directory_source(&home).is_err());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    fn staged_metadata_fixture(
        candidate: &Path,
        home: &Path,
        registry_manifest: &Path,
    ) -> crate::json::JsonValue {
        use crate::json::JsonValue;
        use std::collections::BTreeMap;

        let workspace_id = "path+file:///candidate/member#0.1.0";
        JsonValue::Object(BTreeMap::from([
            (
                "packages".to_owned(),
                JsonValue::Array(vec![
                    JsonValue::Object(BTreeMap::from([
                        ("id".to_owned(), JsonValue::String(workspace_id.to_owned())),
                        (
                            "manifest_path".to_owned(),
                            JsonValue::String(
                                candidate.join("member/Cargo.toml").display().to_string(),
                            ),
                        ),
                        ("source".to_owned(), JsonValue::Null),
                    ])),
                    JsonValue::Object(BTreeMap::from([
                        (
                            "id".to_owned(),
                            JsonValue::String("registry+reviewed#1.0.0".to_owned()),
                        ),
                        (
                            "manifest_path".to_owned(),
                            JsonValue::String(registry_manifest.display().to_string()),
                        ),
                        (
                            "source".to_owned(),
                            JsonValue::String("registry+reviewed".to_owned()),
                        ),
                    ])),
                ]),
            ),
            (
                "target_directory".to_owned(),
                JsonValue::String(home.join("target").display().to_string()),
            ),
            ("version".to_owned(), JsonValue::Number(1)),
            (
                "workspace_default_members".to_owned(),
                JsonValue::Array(vec![JsonValue::String(workspace_id.to_owned())]),
            ),
            (
                "workspace_members".to_owned(),
                JsonValue::Array(vec![JsonValue::String(workspace_id.to_owned())]),
            ),
            (
                "workspace_root".to_owned(),
                JsonValue::String(candidate.display().to_string()),
            ),
            (
                "x-fixture-home".to_owned(),
                JsonValue::String(home.display().to_string()),
            ),
        ]))
    }

    #[cfg(unix)]
    #[test]
    fn staged_cargo_metadata_binds_schema_workspace_and_package_paths() {
        use crate::json::{JsonValue, canonical_json_bytes};

        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("hell-cargo-metadata-{}", std::process::id()));
        let candidate = root.join("candidate");
        let home = root.join("home");
        let workspace_manifest = candidate.join("member/Cargo.toml");
        let registry_manifest = home.join("vendor/reviewed-1.0.0/Cargo.toml");
        std::fs::create_dir_all(workspace_manifest.parent().unwrap()).unwrap();
        std::fs::create_dir_all(registry_manifest.parent().unwrap()).unwrap();
        std::fs::write(
            &workspace_manifest,
            b"[package]\nname='member'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(
            &registry_manifest,
            b"[package]\nname='reviewed'\nversion='1.0.0'\n",
        )
        .unwrap();
        let valid = staged_metadata_fixture(&candidate, &home, &registry_manifest);
        validate_staged_cargo_metadata(&canonical_json_bytes(&valid).unwrap(), &candidate, &home)
            .unwrap();

        let JsonValue::Object(mut wrong_workspace) = valid.clone() else {
            unreachable!();
        };
        wrong_workspace.insert(
            "workspace_root".to_owned(),
            JsonValue::String(root.join("other").display().to_string()),
        );
        assert!(
            validate_staged_cargo_metadata(
                &canonical_json_bytes(&JsonValue::Object(wrong_workspace)).unwrap(),
                &candidate,
                &home,
            )
            .is_err()
        );

        let escaped = staged_metadata_fixture(&candidate, &home, &workspace_manifest);
        assert!(
            validate_staged_cargo_metadata(
                &canonical_json_bytes(&escaped).unwrap(),
                &candidate,
                &home,
            )
            .is_err()
        );
        assert!(validate_staged_cargo_metadata(b"not-json\n", &candidate, &home).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_vendor_closure_covers_every_frozen_registry_package() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("hell-frozen-vendor-closure-{}", std::process::id()));
        let vendor = root.join("vendor");
        for package in ["flate2-1.1.9", "nix-0.27.1", "winapi-0.3.9"] {
            let package = vendor.join(package);
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(package.join(".cargo-checksum.json"), b"{}\n").unwrap();
        }
        let lock = "\
version = 4\n\
\n\
[[package]]\n\
name = \"hell-ci\"\n\
version = \"0.1.0\"\n\
dependencies = [\n\
 \"flate2\",\n\
]\n\
\n\
[[package]]\n\
name = \"flate2\"\n\
version = \"1.1.9\"\n\
source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
checksum = \"bound\"\n\
\n\
[[package]]\n\
name = \"nix\"\n\
version = \"0.27.1\"\n\
source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
\n\
[[package]]\n\
name = \"winapi\"\n\
version = \"0.3.9\"\n\
source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
";
        validate_staged_vendor_covers_frozen_lock(lock.as_bytes(), &vendor).unwrap();

        std::fs::remove_dir_all(vendor.join("flate2-1.1.9")).unwrap();
        let error = validate_staged_vendor_covers_frozen_lock(lock.as_bytes(), &vendor)
            .expect_err("missing frozen package must fail closed");
        assert!(error.contains("flate2-1.1.9"), "{error}");

        assert!(validate_staged_vendor_covers_frozen_lock(b"", &vendor).is_err());
        assert!(
            validate_staged_vendor_covers_frozen_lock(
                b"[[package]]\nname = \"workspace-only\"\nversion = \"0.1.0\"\n",
                &vendor
            )
            .is_err()
        );
        assert!(
            validate_staged_vendor_covers_frozen_lock(
                b"[[package]]\nname = \"traversal/attempt\"\nversion = \"1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
                &vendor
            )
            .is_err()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_cargo_directory_source_rejects_incomplete_or_redirected_vendors() {
        use std::os::unix::fs::symlink;

        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = temp.join(format!(
            "hell-cargo-directory-source-invalid-{}",
            std::process::id()
        ));
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(configure_staged_cargo_home_directory_source(&empty).is_err());

        let empty_vendor = root.join("empty-vendor");
        std::fs::create_dir_all(empty_vendor.join("vendor")).unwrap();
        assert!(configure_staged_cargo_home_directory_source(&empty_vendor).is_err());

        let missing_checksum = root.join("missing-checksum");
        std::fs::create_dir_all(missing_checksum.join("vendor/package-1.0.0")).unwrap();
        assert!(configure_staged_cargo_home_directory_source(&missing_checksum).is_err());

        let redirected = root.join("redirected");
        let outside = root.join("outside");
        std::fs::create_dir_all(&redirected).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, redirected.join("vendor")).unwrap();
        assert!(configure_staged_cargo_home_directory_source(&redirected).is_err());

        let unsafe_path = root.join("unsafe'path");
        let unsafe_package = unsafe_path.join("vendor/package-1.0.0");
        std::fs::create_dir_all(&unsafe_package).unwrap();
        std::fs::write(unsafe_package.join(".cargo-checksum.json"), b"{}\n").unwrap();
        assert!(configure_staged_cargo_home_directory_source(&unsafe_path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn candidate_identity_output_binds_canonical_supplementary_groups() {
        assert!(posix_candidate_identity_output_is_exact(b"61001\n", 61_001));
        assert!(!posix_candidate_identity_output_is_exact(b"61001", 61_001));
        assert!(!posix_candidate_identity_output_is_exact(
            b"061001\n",
            61_001
        ));
        assert_eq!(
            posix_candidate_group_inventory(b"61001 20 701 100\n", 61_001),
            Some(vec![61_001, 20, 701, 100])
        );
        assert_eq!(
            posix_candidate_group_inventory(b"20 61001 701 100\n", 61_001),
            Some(vec![20, 61_001, 701, 100])
        );
        for invalid in [
            b"".as_slice(),
            b"61001".as_slice(),
            b"061001 20\n".as_slice(),
            b"61001  20\n".as_slice(),
            b"61001 20 61001\n".as_slice(),
            b"20 701\n".as_slice(),
            b"61001\t20\n".as_slice(),
            b"61001 20\n\n".as_slice(),
        ] {
            assert!(posix_candidate_group_inventory(invalid, 61_001).is_none());
        }
        let group_limit = u32::try_from(hell_testkit::POSIX_CANDIDATE_GROUP_LIMIT).unwrap();
        let oversized = (0..group_limit)
            .chain(std::iter::once(61_001))
            .map(|group| group.to_string())
            .collect::<Vec<_>>()
            .join(" ")
            + "\n";
        assert!(posix_candidate_group_inventory(oversized.as_bytes(), 61_001).is_none());
    }

    #[test]
    fn candidate_conformance_plan_substitution_is_rejected() {
        assert!(accept_conformance_plan_binding(true));
        assert!(!accept_conformance_plan_binding(false));
    }

    #[test]
    fn runner_identity_accepts_exact_hosted_or_local_identity() {
        assert_eq!(
            validate_runner_identity(
                ReleasePlatform::MacosAarch64,
                Some("macOS"),
                Some("ARM64"),
                "untrusted",
                "untrusted",
            )
            .unwrap(),
            ("macOS".to_owned(), "ARM64".to_owned())
        );
        assert_eq!(
            validate_runner_identity(
                ReleasePlatform::MacosAarch64,
                None,
                None,
                "macos",
                "aarch64",
            )
            .unwrap(),
            ("macOS".to_owned(), "ARM64".to_owned())
        );
    }

    #[test]
    fn runner_identity_rejects_partial_or_mismatched_identity() {
        assert!(
            validate_runner_identity(
                ReleasePlatform::MacosAarch64,
                Some("macOS"),
                None,
                "macos",
                "aarch64",
            )
            .is_err()
        );
        assert!(
            validate_runner_identity(ReleasePlatform::MacosAarch64, None, None, "linux", "x86_64",)
                .is_err()
        );
    }

    #[test]
    fn release_candidate_build_enables_required_evidence() {
        let command = release_candidate_build(std::path::Path::new("candidate"));
        assert_eq!(
            command.display_arguments(),
            [
                "build",
                "--release",
                "--locked",
                "--package",
                "hell-cli",
                "--bin",
                "hell",
                "--features",
                "compat-tracing",
            ]
        );
    }

    #[test]
    fn windows_confinement_dacl_rights_are_closed_world() {
        assert_eq!(
            windows_confinement_icacls_grants(false, true),
            [
                "*S-1-5-32-544:(OI)(CI)(F)",
                "*S-1-5-18:(OI)(CI)(F)",
                "*S-1-5-11:(OI)(CI)(RX)",
                "*S-1-5-12:(OI)(CI)(RX)",
            ]
        );
        assert_eq!(
            windows_confinement_icacls_grants(true, true),
            [
                "*S-1-5-32-544:(OI)(CI)(F)",
                "*S-1-5-18:(OI)(CI)(F)",
                "*S-1-5-11:(OI)(CI)(F)",
                "*S-1-5-12:(OI)(CI)(F)",
            ]
        );
        assert_eq!(
            windows_confinement_icacls_grants(false, false),
            [
                "*S-1-5-32-544:(F)",
                "*S-1-5-18:(F)",
                "*S-1-5-11:(RX)",
                "*S-1-5-12:(RX)",
            ]
        );
        assert_eq!(
            windows_confinement_icacls_grants(true, false),
            [
                "*S-1-5-32-544:(F)",
                "*S-1-5-18:(F)",
                "*S-1-5-11:(F)",
                "*S-1-5-12:(F)",
            ]
        );
    }

    #[test]
    fn windows_restricted_adapter_is_the_exact_sibling_minimal_executable() {
        let launcher = std::path::Path::new("C:/trusted/ci/hell-ci.exe");
        assert_eq!(
            windows_restricted_adapter_path(launcher).unwrap(),
            std::path::Path::new("C:/trusted/ci/hell-test-helper.exe")
        );
        assert!(
            windows_restricted_adapter_path(std::path::Path::new("C:/trusted/ci/substituted.exe"))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_adapter_authority_uses_fixed_platform_tools_and_exact_cleanup_scope() {
        assert_eq!(
            posix_adapter_tool_paths(ReleasePlatform::LinuxX86_64).unwrap(),
            PosixAdapterToolPaths {
                mkdir: "/usr/bin/mkdir",
                copy: "/usr/bin/cp",
                chmod: "/usr/bin/chmod",
                change_owner: "/usr/bin/chown",
                change_group: "/usr/bin/chgrp",
                remove_file: "/usr/bin/rm",
                remove_directory: "/usr/bin/rmdir",
            }
        );
        assert_eq!(
            posix_adapter_tool_paths(ReleasePlatform::MacosAarch64).unwrap(),
            PosixAdapterToolPaths {
                mkdir: "/bin/mkdir",
                copy: "/bin/cp",
                chmod: "/bin/chmod",
                change_owner: "/usr/sbin/chown",
                change_group: "/usr/bin/chgrp",
                remove_file: "/bin/rm",
                remove_directory: "/bin/rmdir",
            }
        );
        assert!(posix_adapter_tool_paths(ReleasePlatform::WindowsX86_64).is_err());
        assert_eq!(
            posix_adapter_authority_chain(ReleasePlatform::LinuxX86_64).unwrap(),
            ["/", "/var", "/var/tmp"]
        );
        assert_eq!(
            posix_adapter_authority_chain(ReleasePlatform::MacosAarch64).unwrap(),
            ["/", "/private", "/private/var", "/private/var/tmp"]
        );
        assert_eq!(
            posix_chmod_arguments(ReleasePlatform::LinuxX86_64, "0555", "/bound").unwrap(),
            ["0555", "--", "/bound"]
        );
        assert_eq!(
            posix_chmod_arguments(ReleasePlatform::MacosAarch64, "0555", "/bound").unwrap(),
            ["0555", "/bound"]
        );
        assert!(posix_chmod_arguments(ReleasePlatform::WindowsX86_64, "0555", "/bound").is_err());
        assert_eq!(
            posix_acl_removal_arguments(ReleasePlatform::MacosAarch64, false, "/bound").unwrap(),
            ["-N", "/bound"]
        );
        assert_eq!(
            posix_acl_removal_arguments(ReleasePlatform::MacosAarch64, true, "/bound").unwrap(),
            ["-RN", "/bound"]
        );
        assert!(posix_acl_removal_arguments(ReleasePlatform::LinuxX86_64, true, "/bound").is_err());

        #[cfg(target_os = "linux")]
        let (current_platform, root) = (ReleasePlatform::LinuxX86_64, Path::new("/var/tmp"));
        #[cfg(target_os = "macos")]
        let (current_platform, root) =
            (ReleasePlatform::MacosAarch64, Path::new("/private/var/tmp"));
        assert_eq!(
            posix_adapter_installation_root(current_platform).unwrap(),
            root
        );
        assert!(
            validate_posix_adapter_installation_root(current_platform, &std::env::temp_dir())
                .is_err(),
            "an arbitrary writable temporary root must never become executable authority"
        );
        assert!(
            validate_posix_adapter_installation_root(ReleasePlatform::WindowsX86_64, root).is_err()
        );

        let directory = root.join("hell-rs-posix-adapter-bound");
        let adapter = directory.join("hell-ci");
        assert!(posix_adapter_cleanup_is_exact(
            root, &directory, &adapter, "hell-ci"
        ));
        assert!(!posix_adapter_cleanup_is_exact(
            root,
            Path::new("/usr/local"),
            &adapter,
            "hell-ci"
        ));
        assert!(!posix_adapter_cleanup_is_exact(
            root,
            &directory,
            &directory.join("other"),
            "hell-ci"
        ));
        assert!(!posix_adapter_cleanup_is_exact(
            root,
            &directory,
            &directory.join("nested/hell-ci"),
            "hell-ci"
        ));
        assert!(!posix_adapter_cleanup_is_exact(
            root, &directory, &adapter, "cargo"
        ));
        let cargo_deny_directory = root.join("hell-rs-posix-cargo-deny-bound");
        assert!(posix_adapter_cleanup_is_exact(
            root,
            &cargo_deny_directory,
            &cargo_deny_directory.join("cargo-deny"),
            "cargo-deny"
        ));
        let stack_directory = root.join("hell-rs-posix-stack-bound");
        assert!(posix_adapter_cleanup_is_exact(
            root,
            &stack_directory,
            &stack_directory.join("stack"),
            "stack"
        ));

        let sources = root.join("hell-rs-posix-sources-bound");
        let candidate = sources.join("candidate");
        let oracle = sources.join("oracle");
        let transient = sources.join("release-gate-transient");
        let archive_adapter = sources.join("archive-adapter");
        let retained_oracle = sources.join("retained-oracle");
        assert!(posix_source_cleanup_is_exact(
            root,
            &sources,
            &candidate,
            &oracle,
            &transient,
            &archive_adapter,
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            Path::new("/usr/local/hell-rs-posix-sources-bound"),
            &candidate,
            &oracle,
            &transient,
            &archive_adapter,
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            &sources,
            &sources.join("candidate/substituted"),
            &oracle,
            &transient,
            &archive_adapter,
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            &sources,
            &candidate,
            &oracle,
            &sources.join("nested/release-gate-transient"),
            &archive_adapter,
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            &sources,
            &candidate,
            &oracle,
            &transient,
            &sources.join("nested/archive-adapter"),
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            &sources,
            &candidate,
            &oracle,
            &transient,
            &archive_adapter,
            &sources.join("nested/retained-oracle"),
        ));

        let rustup = root.join("hell-rs-posix-rustup-bound");
        assert!(posix_rustup_cleanup_is_exact(root, &rustup));
        assert!(!posix_rustup_cleanup_is_exact(
            root,
            &root.join("rustup-bound")
        ));
        assert!(!posix_rustup_cleanup_is_exact(root, &rustup.join("nested")));
    }

    #[cfg(unix)]
    #[test]
    fn rustup_staging_inventory_is_closed_bounded_and_link_free() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::os::unix::net::UnixListener;

        let root = Path::new("/tmp").join(format!("hell-rustup-inventory-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("rustup-home");
        let toolchain = std::ffi::OsString::from("1.97.1-test");
        let bin = home.join("toolchains").join(&toolchain).join("bin");
        let update_hashes = home.join("update-hashes");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&update_hashes).unwrap();
        std::fs::write(home.join("settings.toml"), b"default_toolchain = none\n").unwrap();
        std::fs::write(update_hashes.join(&toolchain), b"test update hash\n").unwrap();
        std::fs::write(update_hashes.join("unselected-toolchain"), b"unselected\n").unwrap();
        let cargo = bin.join("cargo");
        let data = bin.join("target.json");
        std::fs::write(&cargo, b"cargo bytes\n").unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&data, b"data bytes\n").unwrap();

        let inventory = posix_rustup_selected_inventory(&home, &toolchain, "fixture").unwrap();
        assert!(
            inventory
                .iter()
                .any(|entry| entry.relative.ends_with("bin/cargo") && entry.executable)
        );
        assert!(
            inventory
                .iter()
                .any(|entry| entry.relative.ends_with("bin/target.json") && !entry.executable)
        );
        assert!(inventory.iter().any(|entry| {
            entry.relative == Path::new("update-hashes").join(&toolchain) && !entry.executable
        }));
        assert!(
            inventory
                .iter()
                .all(|entry| !entry.relative.ends_with("unselected-toolchain"))
        );
        require_exact_directory_members(
            &home,
            &[
                std::ffi::OsString::from("settings.toml"),
                std::ffi::OsString::from("toolchains"),
                std::ffi::OsString::from("update-hashes"),
            ],
            "fixture",
        )
        .unwrap();
        std::fs::write(home.join("unbound"), b"extra\n").unwrap();
        assert!(
            require_exact_directory_members(
                &home,
                &[
                    std::ffi::OsString::from("settings.toml"),
                    std::ffi::OsString::from("toolchains"),
                    std::ffi::OsString::from("update-hashes"),
                ],
                "fixture",
            )
            .is_err()
        );
        std::fs::remove_file(home.join("unbound")).unwrap();

        let redirected = bin.join("redirected");
        symlink(&data, &redirected).unwrap();
        assert!(posix_rustup_selected_inventory(&home, &toolchain, "fixture").is_err());
        std::fs::remove_file(&redirected).unwrap();
        let hard_link = bin.join("hard-link");
        std::fs::hard_link(&data, &hard_link).unwrap();
        assert!(posix_rustup_selected_inventory(&home, &toolchain, "fixture").is_err());
        std::fs::remove_file(&hard_link).unwrap();
        let socket = bin.join("socket");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(posix_rustup_selected_inventory(&home, &toolchain, "fixture").is_err());
        drop(listener);
        std::fs::remove_file(&socket).unwrap();

        assert_eq!(posix_rustup_inventory_cost(0, 0, 0), Some((1, 0)));
        assert_eq!(
            posix_rustup_inventory_cost(
                super::POSIX_RUSTUP_STAGE_ENTRY_LIMIT - 1,
                super::POSIX_RUSTUP_STAGE_BYTE_LIMIT,
                0,
            ),
            Some((
                super::POSIX_RUSTUP_STAGE_ENTRY_LIMIT,
                super::POSIX_RUSTUP_STAGE_BYTE_LIMIT,
            ))
        );
        assert!(posix_rustup_inventory_cost(super::POSIX_RUSTUP_STAGE_ENTRY_LIMIT, 0, 0).is_none());
        assert!(posix_rustup_inventory_cost(0, super::POSIX_RUSTUP_STAGE_BYTE_LIMIT, 1).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_source_inventory_rejects_byte_substitution() {
        let root = std::env::temp_dir().join(format!(
            "hell-bound-source-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::create_dir_all(root.join("src")).unwrap();
        let path = root.join("src/lib.rs");
        std::fs::write(&path, b"pub fn bound() {}\n").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let inventory = super::object([
            (
                "files",
                crate::json::JsonValue::Array(vec![super::object([
                    ("mode", super::string("100644")),
                    ("path", super::string("src/lib.rs")),
                    (
                        "sha256",
                        super::string(&hell_testkit::sha256_bytes(&bytes).hex()),
                    ),
                    ("size", super::number(bytes.len() as u64)),
                ])]),
            ),
            ("schemaVersion", super::number(1)),
        ]);
        require_inventory_snapshot(&root, &inventory, "test source").unwrap();
        std::fs::write(&path, b"pub fn swapped() {}\n").unwrap();
        assert!(require_inventory_snapshot(&root, &inventory, "test source").is_err());
        std::fs::remove_dir_all(root).unwrap();
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
        let locked = nested.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("retained"), b"retained\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        normalize_candidate_cache_tree(&root, None).unwrap();
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
        assert!(normalize_candidate_cache_tree(&root, None).is_err());
        std::fs::remove_file(root.join("redirect")).unwrap();
        std::fs::hard_link(&outside, root.join("hard-link")).unwrap();
        assert!(normalize_candidate_cache_tree(&root, None).is_err());
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_file(&outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn candidate_cache_normalizer_accepts_only_the_exact_unredirected_root() {
        use std::os::unix::fs::symlink;

        let authority = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-cache-authority-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let root = authority.join("candidate-target");
        std::fs::create_dir_all(&root).unwrap();
        validate_candidate_cache_normalizer_root(&root).unwrap();

        let wrong_name = authority.join("other-target");
        std::fs::create_dir(&wrong_name).unwrap();
        assert!(validate_candidate_cache_normalizer_root(&wrong_name).is_err());

        let redirected_authority = authority.with_extension("redirected");
        std::fs::create_dir(&redirected_authority).unwrap();
        let redirected = redirected_authority.join("candidate-target");
        symlink(&root, &redirected).unwrap();
        assert!(validate_candidate_cache_normalizer_root(&redirected).is_err());

        std::fs::remove_dir_all(&authority).unwrap();
        std::fs::remove_dir_all(&redirected_authority).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cargo_deny_home_normalizer_is_private_bounded_and_exactly_scoped() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let authority = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-cargo-deny-home-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let target = authority.join("candidate-target");
        let environment = target.join("release-child-environment");
        let home = environment.join("cargo-deny-cargo-home");
        std::fs::create_dir_all(&home).unwrap();
        let cached = home.join("registry-cache");
        std::fs::write(&cached, b"cache\n").unwrap();
        let advisory_lock_authority = reserve_posix_cargo_deny_advisory_lock(&home).unwrap();
        let advisory_root = home.join("advisory-dbs");
        let advisory_lock = advisory_root.join("db.lock");
        validate_posix_cargo_deny_home_root(&home).unwrap();
        assert!(posix_cargo_deny_home_is_exact(&target, &home));
        assert!(!posix_cargo_deny_home_is_exact(
            &authority.join("other-target"),
            &home
        ));

        let identity = std::fs::metadata(&home).unwrap();
        normalize_cargo_deny_cache_tree(&home, identity.uid(), identity.uid(), identity.gid())
            .unwrap();
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o555
        );
        assert_eq!(
            std::fs::metadata(&cached).unwrap().permissions().mode() & 0o777,
            0o444
        );
        assert_eq!(
            std::fs::metadata(&advisory_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&advisory_lock)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        std::fs::set_permissions(&advisory_lock, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(
                &home,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                &advisory_lock_authority,
            )
            .is_err()
        );
        std::fs::set_permissions(&advisory_lock, std::fs::Permissions::from_mode(0o660)).unwrap();
        validate_posix_cargo_deny_home_post_state(
            &home,
            identity.uid(),
            identity.uid(),
            identity.gid(),
            &advisory_lock_authority,
        )
        .unwrap();
        // cargo-deny 0.20.2 opens db.lock through tame-index with
        // read+write+create semantics, so both reopening the reserved lock and
        // creating a replacement lock in the advisory root must succeed for
        // the lock owner after the read-only transition.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&advisory_lock)
            .unwrap();
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(advisory_root.join("regenerated.lock"))
            .unwrap();
        std::fs::remove_file(advisory_root.join("regenerated.lock")).unwrap();
        validate_posix_cargo_deny_home_post_state(
            &home,
            identity.uid(),
            identity.uid(),
            identity.gid(),
            &advisory_lock_authority,
        )
        .unwrap();

        std::fs::set_permissions(&advisory_root, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(
                &home,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                &advisory_lock_authority,
            )
            .is_err()
        );
        std::fs::set_permissions(&advisory_root, std::fs::Permissions::from_mode(0o750)).unwrap();

        std::fs::remove_file(&advisory_lock).unwrap();
        std::fs::write(&advisory_lock, b"replacement\n").unwrap();
        std::fs::set_permissions(&advisory_lock, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(
                &home,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                &advisory_lock_authority,
            )
            .is_err()
        );

        let wrong = environment.join("cargo-home");
        std::fs::create_dir(&wrong).unwrap();
        assert!(validate_posix_cargo_deny_home_root(&wrong).is_err());
        let outside = authority.join("outside");
        std::fs::write(&outside, b"outside\n").unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&outside, home.join("redirect")).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(
                &home,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                &advisory_lock_authority,
            )
            .is_err()
        );
        assert!(
            normalize_cargo_deny_cache_tree(&home, identity.uid(), identity.uid(), identity.gid())
                .is_err()
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_file(home.join("redirect")).unwrap();
        std::fs::hard_link(&outside, home.join("hard-link")).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            normalize_cargo_deny_cache_tree(&home, identity.uid(), identity.uid(), identity.gid())
                .is_err()
        );

        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&advisory_root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&authority).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cargo_deny_metadata_cleanup_authority_is_exactly_scoped() {
        let parent = Path::new("/var/tmp");
        let directory = parent.join("hell-cargo-deny-metadata-12345-17");
        let path = directory.join("metadata.json");
        assert!(posix_cargo_deny_metadata_is_exact(
            parent, &directory, &path
        ));
        assert!(!posix_cargo_deny_metadata_is_exact(
            parent,
            &parent.join("hell-cargo-deny-metadata-012345-17"),
            &path,
        ));
        assert!(!posix_cargo_deny_metadata_is_exact(
            parent,
            &directory,
            &directory.join("other.json"),
        ));
        assert!(!posix_cargo_deny_metadata_is_exact(
            Path::new("/tmp"),
            &Path::new("/tmp").join("hell-cargo-deny-metadata-12345-17"),
            &Path::new("/tmp")
                .join("hell-cargo-deny-metadata-12345-17")
                .join("metadata.json"),
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stack_root_normalizer_is_private_bounded_and_exactly_scoped() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let sequence =
            super::POSIX_STACK_ROOT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = Path::new("/private/var/tmp")
            .join(format!("hell-stack-root-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        validate_posix_stack_root(&root).unwrap();
        assert!(posix_stack_root_is_exact(&root));
        let metadata = std::fs::metadata(&root).unwrap();
        normalize_candidate_owned_cache_tree(&root, metadata.uid(), metadata.gid()).unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o750
        );
        validate_posix_stack_root_post_state(&root, metadata.uid(), metadata.gid()).unwrap();

        let state = root.join("state");
        std::fs::write(&state, b"bounded Stack state\n").unwrap();
        normalize_candidate_owned_cache_tree(&root, metadata.uid(), metadata.gid()).unwrap();
        validate_posix_stack_root_post_state(&root, metadata.uid(), metadata.gid()).unwrap();
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let wrong = Path::new("/private/var/tmp")
            .join(format!("hell-other-root-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&wrong).unwrap();
        assert!(validate_posix_stack_root(&wrong).is_err());
        let outside = Path::new("/private/var/tmp").join(format!(
            "hell-stack-outside-{}-{sequence}",
            std::process::id()
        ));
        std::fs::write(&outside, b"outside\n").unwrap();
        symlink(&outside, root.join("redirect")).unwrap();
        assert!(
            normalize_candidate_owned_cache_tree(&root, metadata.uid(), metadata.gid()).is_err()
        );
        std::fs::remove_file(root.join("redirect")).unwrap();
        std::fs::hard_link(&outside, root.join("hard-link")).unwrap();
        assert!(
            validate_posix_stack_root_post_state(&root, metadata.uid(), metadata.gid()).is_err()
        );

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir(&wrong).unwrap();
        std::fs::remove_file(&outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stack_root_authority_is_the_exact_private_var_tmp_child() {
        let exact = Path::new("/private/var/tmp").join("hell-stack-root-12345-17");
        assert!(posix_stack_root_is_exact(&exact));
        assert!(!posix_stack_root_is_exact(
            &Path::new("/var/tmp").join(exact.file_name().unwrap())
        ));
        assert!(!posix_stack_root_is_exact(
            &Path::new("/private/var/tmp").join("hell-stack-root-12345-not-a-sequence")
        ));
        assert!(!posix_stack_root_is_exact(
            &Path::new("/private/var/tmp").join("hell-stack-root-012345-17")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stack_work_normalizer_is_distinct_from_the_global_stack_root() {
        use std::ffi::OsString;

        let authority =
            Path::new("/private/var/tmp").join("hell-rs-posix-sources-12345-17-abcdef012345");
        let source = authority.join("oracle");
        let work = source.join(".stack-work");
        assert!(posix_stack_work_is_exact(&authority, &source, &work));
        assert!(!posix_stack_work_is_exact(
            &authority,
            &authority.join("candidate"),
            &work
        ));
        assert!(!posix_stack_work_is_exact(
            &authority,
            &source,
            &source.join("nested/.stack-work")
        ));
        assert!(!posix_stack_work_is_exact(
            Path::new("/private/var/tmp/hell-stack-root-12345-17"),
            &source,
            &work
        ));
        let global_root = OsString::from("/private/var/tmp/hell-stack-root-12345-17");
        let rejected = [
            global_root.clone(),
            OsString::from("1"),
            OsString::from("2"),
            global_root.clone(),
            OsString::from("1"),
            OsString::from("2"),
            global_root,
            OsString::from("1"),
            OsString::from("2"),
            OsString::from("3"),
            OsString::from("4"),
        ];
        assert!(run_posix_stack_work_normalizer(&rejected).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn warm_cargo_deny_home_is_bound_after_the_final_whole_target_transition() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let authority = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-warm-cargo-deny-home-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let target = authority.join("candidate-target");
        let home = target
            .join("release-child-environment")
            .join("cargo-deny-cargo-home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("warm-cache"), b"restored cache\n").unwrap();

        normalize_candidate_cache_tree(&target, None).unwrap();
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o7777,
            0o2770
        );

        std::fs::remove_dir_all(&home).unwrap();
        std::fs::create_dir(&home).unwrap();
        let cached = home.join("warm-cache");
        std::fs::write(&cached, b"trusted staged cache\n").unwrap();
        let advisory_root = home.join("advisory-dbs");
        let advisory_lock = advisory_root.join("db.lock");
        std::fs::create_dir(&advisory_root).unwrap();
        std::fs::write(&advisory_lock, b"staged advisory authority\n").unwrap();
        let advisory_lock_authority = reserve_posix_cargo_deny_advisory_lock(&home).unwrap();
        assert_eq!(std::fs::metadata(&advisory_lock).unwrap().len(), 0);
        let metadata = std::fs::metadata(&home).unwrap();
        normalize_cargo_deny_cache_tree(&home, metadata.uid(), metadata.uid(), metadata.gid())
            .unwrap();
        validate_posix_cargo_deny_home_post_state(
            &home,
            metadata.uid(),
            metadata.uid(),
            metadata.gid(),
            &advisory_lock_authority,
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o7777,
            0o555
        );
        assert_eq!(
            std::fs::metadata(&cached).unwrap().permissions().mode() & 0o7777,
            0o444
        );

        normalize_candidate_cache_tree(&target, None).unwrap();
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o7777,
            0o2770
        );
        assert_eq!(
            std::fs::metadata(&cached).unwrap().permissions().mode() & 0o7777,
            0o660
        );
        std::fs::remove_dir_all(&authority).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn archive_adapter_hosted_mode_transition_rejects_cleared_setgid_and_substitution() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-archive-adapter-transition-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let parent = root.join("archive-adapter");
        let adapter = parent.join("hell-ci-adapter");
        let work = adapter.join(".stack-work");
        let authority = adapter.join(".authority");
        std::fs::create_dir_all(&authority).unwrap();
        symlink("/bound/llvm-ar", authority.join("llvm-ar")).unwrap();
        symlink("/bound/hell-ci", adapter.join("ar")).unwrap();
        std::fs::write(adapter.join("stack.yaml"), b"overlay\n").unwrap();
        std::fs::write(adapter.join("stack.yaml.lock"), b"lock\n").unwrap();
        std::fs::create_dir(&work).unwrap();
        std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o555)).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o2770)).unwrap();
        std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o2755)).unwrap();
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o2770)).unwrap();
        let parent_identity = posix_object_identity(&parent).unwrap();
        let adapter_identity = posix_object_identity(&adapter).unwrap();
        let work_identity = posix_object_identity(&work).unwrap();
        let owner = parent_identity.owner;
        let group = parent_identity.group;
        require_posix_archive_adapter_transition_state(
            &parent,
            &parent_identity,
            owner,
            group,
            0o2770,
            &adapter,
            &adapter_identity,
            &work,
            &work_identity,
        )
        .unwrap();

        let authority_sibling = parent.join("unexpected-authority");
        std::fs::create_dir(&authority_sibling).unwrap();
        assert!(
            require_posix_archive_adapter_transition_state(
                &parent,
                &parent_identity,
                owner,
                group,
                0o2770,
                &adapter,
                &adapter_identity,
                &work,
                &work_identity,
            )
            .is_err()
        );
        std::fs::remove_dir(&authority_sibling).unwrap();
        let adapter_sibling = adapter.join("unexpected-output.a");
        std::fs::write(&adapter_sibling, b"unexpected\n").unwrap();
        assert!(
            require_posix_archive_adapter_transition_state(
                &parent,
                &parent_identity,
                owner,
                group,
                0o2770,
                &adapter,
                &adapter_identity,
                &work,
                &work_identity,
            )
            .is_err()
        );
        std::fs::remove_file(&adapter_sibling).unwrap();

        // BSD clears setgid when an unprivileged owner is outside the directory
        // group. The hosted 02550 request therefore became this exact 00550
        // state; it must never be accepted as a completed authority transition.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o550)).unwrap();
        assert!(
            require_posix_archive_adapter_transition_state(
                &parent,
                &parent_identity,
                owner,
                group,
                0o2550,
                &adapter,
                &adapter_identity,
                &work,
                &work_identity,
            )
            .is_err()
        );
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o2550)).unwrap();
        require_posix_archive_adapter_transition_state(
            &parent,
            &parent_identity,
            owner,
            group,
            0o2550,
            &adapter,
            &adapter_identity,
            &work,
            &work_identity,
        )
        .unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o2770)).unwrap();
        require_posix_archive_adapter_transition_state(
            &parent,
            &parent_identity,
            owner,
            group,
            0o2770,
            &adapter,
            &adapter_identity,
            &work,
            &work_identity,
        )
        .unwrap();

        let replacement = parent.join("replacement-adapter");
        let replacement_work = replacement.join(".stack-work");
        let replacement_authority = replacement.join(".authority");
        std::fs::create_dir_all(&replacement_authority).unwrap();
        symlink(
            "/bound/replacement-llvm-ar",
            replacement_authority.join("llvm-ar"),
        )
        .unwrap();
        std::fs::set_permissions(
            &replacement_authority,
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        symlink("/bound/replacement-hell-ci", replacement.join("ar")).unwrap();
        std::fs::write(replacement.join("stack.yaml"), b"replacement-overlay\n").unwrap();
        std::fs::write(replacement.join("stack.yaml.lock"), b"replacement-lock\n").unwrap();
        std::fs::create_dir(&replacement_work).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o2755)).unwrap();
        std::fs::set_permissions(&replacement_work, std::fs::Permissions::from_mode(0o2770))
            .unwrap();
        std::fs::set_permissions(
            adapter.join(".authority"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::remove_dir_all(&adapter).unwrap();
        std::fs::rename(&replacement, &adapter).unwrap();
        std::fs::set_permissions(&adapter, std::fs::Permissions::from_mode(0o2755)).unwrap();
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o2770)).unwrap();
        assert!(
            require_posix_archive_adapter_transition_state(
                &parent,
                &parent_identity,
                owner,
                group,
                0o2770,
                &adapter,
                &adapter_identity,
                &work,
                &work_identity,
            )
            .is_err()
        );
        std::fs::set_permissions(
            adapter.join(".authority"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cargo_deny_cache_copy_rejects_redirected_and_multiply_linked_sources() {
        use std::os::unix::fs::symlink;

        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-cargo-deny-copy-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let source = root.join("source");
        let destination = root.join("destination");
        let registry_index = source.join("registry/index/index.crates.io-test");
        let registry_cache = source.join("registry/cache/index.crates.io-test");
        let registry_source = source.join("registry/src/index.crates.io-test/crate-1.0.0");
        let vendor = source.join("vendor/crate-1.0.0");
        for directory in [&registry_index, &registry_cache, &registry_source, &vendor] {
            std::fs::create_dir_all(directory).unwrap();
        }
        std::fs::write(registry_index.join("config.json"), b"index\n").unwrap();
        std::fs::write(registry_cache.join("crate-1.0.0.crate"), b"crate\n").unwrap();
        std::fs::write(
            registry_source.join(".cargo-checksum.json"),
            b"{\"files\":{}}\n",
        )
        .unwrap();
        std::fs::write(vendor.join(".cargo-checksum.json"), b"{\"files\":{}}\n").unwrap();
        let mut entries = 1;
        let mut bytes = 0;
        copy_posix_cargo_cache_tree(&source, &destination, &mut entries, &mut bytes).unwrap();
        assert_eq!(
            std::fs::read(
                destination.join("registry/cache/index.crates.io-test/crate-1.0.0.crate")
            )
            .unwrap(),
            b"crate\n"
        );
        assert!(
            destination
                .join("registry/index/index.crates.io-test/config.json")
                .is_file()
        );
        assert!(
            destination
                .join("registry/src/index.crates.io-test/crate-1.0.0/.cargo-checksum.json")
                .is_file()
        );
        assert!(
            destination
                .join("vendor/crate-1.0.0/.cargo-checksum.json")
                .is_file()
        );
        assert_eq!(entries, 16, "one entry remains reserved for config.toml");
        let mut bounded_entries = super::POSIX_RUSTUP_STAGE_ENTRY_LIMIT;
        let mut bounded_bytes = 0;
        assert!(
            copy_posix_cargo_cache_tree(
                &source,
                &root.join("over-entry-limit"),
                &mut bounded_entries,
                &mut bounded_bytes,
            )
            .is_err()
        );

        let outside = root.join("outside");
        std::fs::write(&outside, b"outside\n").unwrap();
        symlink(&outside, source.join("redirect")).unwrap();
        assert!(
            copy_posix_cargo_cache_tree(
                &source,
                &root.join("redirected-copy"),
                &mut entries,
                &mut bytes,
            )
            .is_err()
        );
        std::fs::remove_file(source.join("redirect")).unwrap();
        std::fs::hard_link(&outside, source.join("hard-link")).unwrap();
        assert!(
            copy_posix_cargo_cache_tree(
                &source,
                &root.join("hard-link-copy"),
                &mut entries,
                &mut bytes,
            )
            .is_err()
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trusted_oracle_acquisition_rejects_substitution_and_cleans_exact_scope() {
        use std::os::unix::fs::PermissionsExt as _;

        let sequence =
            super::POSIX_ADAPTER_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-trusted-oracle-acquisition-{}-{sequence}",
                std::process::id()
            ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut acquisition = LinuxOracleAcquisition::reserve(&root).unwrap();

        let substituted = acquisition.directory().join("substituted");
        std::fs::write(&substituted, b"substitution\n").unwrap();
        assert!(acquisition.validate().is_err());
        std::fs::remove_file(&substituted).unwrap();
        acquisition.validate().unwrap();

        let oracle = acquisition.directory().join(LINUX_ORACLE_NAME);
        std::fs::write(&oracle, b"pinned oracle bytes\n").unwrap();
        std::fs::set_permissions(&oracle, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sha256 = hell_testkit::sha256_file(&oracle).unwrap();
        acquisition.bind_path(&oracle, sha256).unwrap();
        std::fs::set_permissions(&oracle, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(acquisition.validate().is_err());
        std::fs::set_permissions(&oracle, std::fs::Permissions::from_mode(0o755)).unwrap();
        acquisition.validate().unwrap();

        let directory = acquisition.directory().to_path_buf();
        acquisition.cleanup().unwrap();
        assert!(!directory.exists());
        std::fs::remove_dir(root).unwrap();
    }
}
