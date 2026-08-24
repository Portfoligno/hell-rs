use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
static NESTED_CARGO_SETUP: Mutex<()> = Mutex::new(());
const ASSURANCE_EXECUTION_TIMEOUT: Duration = Duration::from_mins(10);
const ASSURANCE_COMPLETION_RESERVE: Duration = Duration::from_secs(30);
const NESTED_CARGO_SETUP_TIMEOUT: Duration = Duration::from_mins(5);
const FIXTURE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

const EXPECTED: [(&str, &str, &str, &str, &str, &str); 13] = [
    (
        "digest-binding-inverted",
        "REL-DIGEST-BINDING",
        "release-agreement",
        "crates/hell-ci/src/release/decision.rs",
        "agree",
        "known-good",
    ),
    (
        "drop-final-cell",
        "REL-ADMISSION-LEDGER-COMPLETE",
        "ledger",
        "crates/hell-ci/src/conformance/ledger.rs",
        "ConformancePlan::validate",
        "missing-cell",
    ),
    (
        "accept-duplicate-cell",
        "REL-ADMISSION-LEDGER-COMPLETE",
        "ledger",
        "crates/hell-ci/src/conformance/ledger.rs",
        "ConformancePlan::validate",
        "duplicate-cell",
    ),
    (
        "ignore-evidence-platform",
        "REL-EVIDENCE-PLATFORM-BOUND",
        "ledger",
        "crates/hell-ci/src/conformance/evidence.rs",
        "validate_record_binding",
        "linux-evidence-relabeled-as-windows",
    ),
    (
        "compare-exemption-id-only",
        "REL-EXEMPTION-EXACT",
        "exemption",
        "crates/hell-ci/src/conformance/ledger.rs",
        "validate_exemption",
        "exemption-with-mismatched-selector",
    ),
    (
        "use-wall-clock-for-exemption",
        "REL-EXEMPTION-PLAN-TIME",
        "exemption",
        "crates/hell-ci/src/conformance/ledger.rs",
        "validate_exemption",
        "exemption-uses-wall-clock-time",
    ),
    (
        "allow-extra-archive-member",
        "REL-ARCHIVE-EXACT",
        "archive",
        "crates/hell-ci/src/release/archive.rs",
        "validate_evidence_members",
        "extra-archive-member",
    ),
    (
        "ignore-subject",
        "REL-SUBJECTS-EXACT",
        "subjects",
        "crates/hell-ci/src/release/verify.rs",
        "validate_subject_inventory",
        "subject-omitted-from-manifest",
    ),
    (
        "grant-contents-write-to-attest",
        "REL-PRIVILEGE-SPLIT",
        "workflow-permissions",
        "crates/hell-workflow-auditor/src/lib.rs",
        "validate_privilege_split",
        "workflow-attest-contents-write",
    ),
    (
        "grant-id-token-write-to-publish",
        "REL-PRIVILEGE-SPLIT",
        "workflow-permissions",
        "crates/hell-workflow-auditor/src/lib.rs",
        "validate_privilege_split",
        "workflow-publish-id-token-write",
    ),
    (
        "skip-shallow-envelope-verification",
        "REL-ENVELOPE-BOUND",
        "publication-envelope",
        "crates/hell-release-publisher/src/lib.rs",
        "validate_shallow_publication_envelope",
        "publisher-envelope-predecessor-mismatch",
    ),
    (
        "unavailable-governance-is-matched",
        "REL-GOVERNANCE-TRISTATE",
        "governance",
        "crates/hell-ci/src/release/governance.rs",
        "unavailable",
        "governance-ruleset-unavailable-residual",
    ),
    (
        "accept-unknown-publisher-draft",
        "REL-PUBLISH-STATE-CLOSED",
        "publisher-state",
        "crates/hell-release-publisher/src/lib.rs",
        "verify_assets",
        "publisher-unexpected-asset",
    ),
];

struct Fixture {
    root: PathBuf,
    root_identity: DirectoryIdentity,
    nested_cargo_target: PathBuf,
    nested_cargo_target_identity: DirectoryIdentity,
    cleanup_complete: bool,
}

impl Fixture {
    fn new() -> Self {
        let sequence = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-assurance-catalog-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create assurance catalog fixture");
        let root = fs::canonicalize(root).expect("canonicalize assurance catalog fixture");
        let root_identity = DirectoryIdentity::bind(&root, "assurance fixture root")
            .expect("bind assurance fixture root identity");
        let nested_cargo_target = root.join("cargo-target");
        fs::create_dir(&nested_cargo_target)
            .expect("create fixture-owned nested Cargo target directory");
        let nested_cargo_target = fs::canonicalize(nested_cargo_target)
            .expect("canonicalize fixture-owned nested Cargo target directory");
        let nested_cargo_target_identity =
            DirectoryIdentity::bind(&nested_cargo_target, "nested Cargo target")
                .expect("bind nested Cargo target identity");
        assert_eq!(
            nested_cargo_target.parent(),
            Some(root.as_path()),
            "nested Cargo target escaped its fixture authority"
        );
        Self {
            root,
            root_identity,
            nested_cargo_target,
            nested_cargo_target_identity,
            cleanup_complete: false,
        }
    }

    fn assert_nested_cargo_target_isolated_from(&self, repository: &Path) {
        let repository = fs::canonicalize(repository).expect("canonicalize repository root");
        let repository_identity =
            DirectoryIdentity::bind(&repository, "repository root").expect("bind repository root");
        let repository_target = repository.join("target");
        match fs::symlink_metadata(&repository_target) {
            Ok(metadata) => {
                assert!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "repository Cargo target is not a real directory"
                );
                assert_eq!(
                    fs::canonicalize(&repository_target)
                        .expect("canonicalize existing repository Cargo target directory"),
                    repository_target,
                    "repository Cargo target does not remain beneath its canonical parent"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("cannot inspect repository Cargo target directory: {error}"),
        }
        repository_identity
            .revalidate("repository root")
            .expect("revalidate repository root after binding future Cargo target");
        let test_executable = fs::canonicalize(env!("CARGO_BIN_EXE_hell-ci"))
            .expect("canonicalize live hell-ci test executable");
        assert!(
            !self.nested_cargo_target.starts_with(&repository_target)
                && !repository_target.starts_with(&self.nested_cargo_target),
            "nested Cargo target overlaps the repository target directory"
        );
        assert!(
            !test_executable.starts_with(&self.nested_cargo_target),
            "nested Cargo target contains the live hell-ci test executable"
        );
    }

    fn prepare_nested_cargo_target(&self, repository: &Path) -> Result<(), String> {
        let _setup = NESTED_CARGO_SETUP
            .lock()
            .map_err(|_| "nested Cargo setup authority is poisoned".to_owned())?;
        self.revalidate_nested_cargo_target("before setup")?;
        let cargo = CargoInvocationIdentity::resolve()?;
        cargo.revalidate("before setup")?;
        let mut command = Command::new(&cargo.invocation);
        command
            .current_dir(repository)
            .env("CARGO_TARGET_DIR", &self.nested_cargo_target)
            .args([
                "test",
                "--locked",
                "-p",
                "hell-ci",
                "--features",
                "mutation-testing",
                "--test",
                "assurance_primary_mutations",
                "--no-run",
            ]);
        let (execution_deadline, completion_deadline) =
            supervision_deadlines(NESTED_CARGO_SETUP_TIMEOUT, ASSURANCE_COMPLETION_RESERVE);
        let result = hell_testkit::run_supervised_command_until(
            &mut command,
            &[],
            execution_deadline,
            completion_deadline,
            None,
        )
        .map_err(|error| format!("cannot supervise nested Cargo setup: {error}"))?;
        cargo.revalidate("after setup")?;
        self.revalidate_nested_cargo_target("after setup")?;
        validate_terminal_cleanup_receipt(&result)?;
        if !result.status.success() || result.timed_out {
            return Err(format!(
                "nested Cargo setup failed: status={},timedOut={},stderr={}",
                status_diagnostic(result.status.code()),
                result.timed_out,
                bounded_capture_diagnostic(&result.stderr)
            ));
        }
        Ok(())
    }

    fn revalidate_nested_cargo_target(&self, phase: &str) -> Result<(), String> {
        self.nested_cargo_target_identity
            .revalidate("nested Cargo target")
            .map_err(|error| format!("{error} {phase}"))
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let deadline = Instant::now()
            .checked_add(FIXTURE_CLEANUP_TIMEOUT)
            .ok_or_else(|| "fixture cleanup deadline overflowed".to_owned())?;
        let mut failures = Vec::new();
        if self.nested_cargo_target.exists() {
            match self.revalidate_nested_cargo_target("before cleanup") {
                Ok(()) => {
                    if let Err(error) = remove_directory_until(
                        &self.nested_cargo_target,
                        deadline,
                        "nested Cargo target",
                    ) {
                        failures.push(error);
                    }
                }
                Err(error) => failures.push(error),
            }
        }
        if self.root.exists() {
            match self.root_identity.revalidate("assurance fixture root") {
                Ok(()) => {
                    if let Err(error) =
                        remove_directory_until(&self.root, deadline, "assurance fixture root")
                    {
                        failures.push(error);
                    }
                }
                Err(error) => failures.push(error),
            }
        }
        self.cleanup_complete = !self.root.exists();
        if failures.is_empty() && self.cleanup_complete {
            Ok(())
        } else {
            if !self.cleanup_complete {
                failures.push("assurance fixture root remained after cleanup".to_owned());
            }
            Err(failures.join("; additionally, "))
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.cleanup_complete && self.root.exists() {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }
}

struct CargoInvocationIdentity {
    invocation: PathBuf,
    invocation_identity: NativeFilesystemIdentity,
    canonical: PathBuf,
    canonical_identity: NativeFilesystemIdentity,
    sha256: hell_testkit::Digest,
}

impl CargoInvocationIdentity {
    fn resolve() -> Result<Self, String> {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
        let invocation = resolve_executable_invocation(&cargo)?;
        let invocation_metadata = fs::symlink_metadata(&invocation)
            .map_err(|error| format!("cannot bind Cargo setup invocation: {error}"))?;
        #[cfg(unix)]
        let invocation_identity = NativeFilesystemIdentity::bind(&invocation_metadata);
        #[cfg(windows)]
        let invocation_identity = NativeFilesystemIdentity::bind(
            &invocation,
            &invocation_metadata,
            "Cargo setup invocation",
        )?;
        let canonical = fs::canonicalize(&invocation)
            .map_err(|error| format!("cannot canonicalize Cargo setup executable: {error}"))?;
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|error| format!("cannot inspect Cargo setup executable: {error}"))?;
        if !canonical.is_absolute() || !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(
                "Cargo setup executable does not resolve to a canonical regular file".to_owned(),
            );
        }
        let sha256 = hell_testkit::sha256_file(&canonical)
            .map_err(|error| format!("cannot hash Cargo setup executable: {error}"))?;
        #[cfg(unix)]
        let canonical_identity = NativeFilesystemIdentity::bind(&metadata);
        #[cfg(windows)]
        let canonical_identity =
            NativeFilesystemIdentity::bind(&canonical, &metadata, "Cargo setup executable")?;
        Ok(Self {
            invocation,
            invocation_identity,
            canonical,
            canonical_identity,
            sha256,
        })
    }

    fn revalidate(&self, phase: &str) -> Result<(), String> {
        let rebound = fs::canonicalize(&self.invocation).map_err(|error| {
            format!("cannot revalidate Cargo setup executable {phase}: {error}")
        })?;
        let invocation_metadata = fs::symlink_metadata(&self.invocation)
            .map_err(|error| format!("cannot reinspect Cargo setup invocation {phase}: {error}"))?;
        let canonical_metadata = fs::symlink_metadata(&rebound)
            .map_err(|error| format!("cannot reinspect Cargo setup executable {phase}: {error}"))?;
        let digest = hell_testkit::sha256_file(&rebound)
            .map_err(|error| format!("cannot rehash Cargo setup executable {phase}: {error}"))?;
        #[cfg(unix)]
        let invocation_identity = NativeFilesystemIdentity::bind(&invocation_metadata);
        #[cfg(windows)]
        let invocation_identity = NativeFilesystemIdentity::bind(
            &self.invocation,
            &invocation_metadata,
            "Cargo setup invocation",
        )?;
        #[cfg(unix)]
        let canonical_identity = NativeFilesystemIdentity::bind(&canonical_metadata);
        #[cfg(windows)]
        let canonical_identity = NativeFilesystemIdentity::bind(
            &rebound,
            &canonical_metadata,
            "Cargo setup executable",
        )?;
        if rebound != self.canonical
            || invocation_identity != self.invocation_identity
            || canonical_identity != self.canonical_identity
            || digest != self.sha256
        {
            return Err(format!("Cargo setup executable identity changed {phase}"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeFilesystemIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    handle: std::sync::Arc<same_file::Handle>,
}

impl NativeFilesystemIdentity {
    #[cfg(unix)]
    fn bind(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(windows)]
    fn bind(path: &Path, _metadata: &fs::Metadata, label: &str) -> Result<Self, String> {
        same_file::Handle::from_path(path)
            .map(|handle| Self {
                handle: std::sync::Arc::new(handle),
            })
            .map_err(|error| format!("cannot bind native filesystem identity for {label}: {error}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    canonical: PathBuf,
    native: NativeFilesystemIdentity,
}

impl DirectoryIdentity {
    fn bind(path: &Path, label: &str) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!("{label} is not a directory"));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot canonicalize {label}: {error}"))?;
        if canonical != path {
            return Err(format!("{label} is not canonical"));
        }
        #[cfg(unix)]
        let native = NativeFilesystemIdentity::bind(&metadata);
        #[cfg(windows)]
        let native = NativeFilesystemIdentity::bind(path, &metadata, label)?;
        Ok(Self { canonical, native })
    }

    fn revalidate(&self, label: &str) -> Result<(), String> {
        let rebound = Self::bind(&self.canonical, label)?;
        if rebound != *self {
            return Err(format!("{label} identity changed"));
        }
        Ok(())
    }
}

#[test]
fn native_identity_preserves_hard_link_and_substitution_semantics() {
    let mut fixture = Fixture::new();
    let source = fixture.root.join("identity-source");
    let alias = fixture.root.join("identity-alias");
    let copied = fixture.root.join("identity-copy");
    fs::write(&source, b"same bytes").expect("write native identity source");
    fs::hard_link(&source, &alias).expect("create native identity hard-link alias");
    fs::copy(&source, &copied).expect("create same-byte native identity copy");

    let bind = |path: &Path, label: &str| {
        let metadata = fs::symlink_metadata(path).expect("inspect native identity fixture");
        #[cfg(unix)]
        let identity = NativeFilesystemIdentity::bind(&metadata);
        #[cfg(windows)]
        let identity = NativeFilesystemIdentity::bind(path, &metadata, label)
            .expect("bind native identity fixture");
        #[cfg(unix)]
        let _ = (path, label);
        identity
    };
    let source_identity = bind(&source, "native identity source");
    let alias_identity = bind(&alias, "native identity hard-link alias");
    let copied_identity = bind(&copied, "same-byte native identity copy");

    assert_eq!(source_identity, alias_identity);
    assert_ne!(source_identity, copied_identity);
    fixture
        .cleanup()
        .expect("clean up Windows native identity fixture");
}

#[test]
fn assurance_catalog_runs_every_source_bound_baseline_and_selected_mutant() {
    run_fixture_test(|fixture| {
        let repository = repository_root();
        fixture.assert_nested_cargo_target_isolated_from(&repository);
        fixture
            .prepare_nested_cargo_target(&repository)
            .expect("prepare nested Cargo target for full assurance catalog");
        let output = fixture.root.join("mutation");
        let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
        command
            .current_dir(&repository)
            .env("CARGO_TARGET_DIR", &fixture.nested_cargo_target)
            .args(["mutation", "assurance", "--manifest"])
            .arg("compat/assurance-mutants.toml")
            .args(["--repository-root", ".", "--output"])
            .arg(&output);
        let (execution_deadline, completion_deadline) =
            supervision_deadlines(ASSURANCE_EXECUTION_TIMEOUT, ASSURANCE_COMPLETION_RESERVE);
        let result = hell_testkit::run_supervised_command_until(
            &mut command,
            &[],
            execution_deadline,
            completion_deadline,
            None,
        )
        .expect("run source-bound mutation assurance under reserved process-tree supervision");
        assert!(
            !result.timed_out,
            "mutation assurance exceeded its deadline"
        );
        assert_terminal_cleanup_receipt(&result);
        assert!(
            result.status.success(),
            "mutation assurance failed: {}",
            complete_stderr(&result)
        );

        let report_path = output.join("assurance.json");
        let report_bytes = fs::read(&report_path).expect("read mutation assurance report");
        assert_eq!(report_bytes.last(), Some(&b'\n'));
        let report: serde_json::Value =
            serde_json::from_slice(&report_bytes).expect("parse mutation assurance report");
        assert_eq!(report["schemaVersion"], 1);
        assert_eq!(report["state"], "passed");
        assert_eq!(report["catalogId"], "release-assurance-v1");
        assert_eq!(
            report["catalogSha256"],
            hell_testkit::sha256_file(&repository.join("compat/assurance-mutants.toml"))
                .expect("hash source-bound mutation catalog")
                .hex()
        );
        let mutants = report["mutants"]
            .as_array()
            .expect("mutation report contains an ordered mutant array");
        assert_eq!(mutants.len(), EXPECTED.len());
        for (record, (id, claim, module, source, symbol, vector)) in mutants.iter().zip(EXPECTED) {
            assert_eq!(record["id"], id);
            assert_eq!(record["claim"], claim);
            assert_eq!(record["module"], module);
            assert_eq!(record["source"], source);
            assert_eq!(record["symbol"], symbol);
            assert_eq!(record["vectors"], serde_json::json!([vector]));
            assert_eq!(record["detected"], true);
        }
    });
}

#[test]
fn assurance_timeout_retains_terminal_cleanup_reserve_and_removes_isolated_target() {
    run_fixture_test(|fixture| {
        let repository = repository_root();
        fixture.assert_nested_cargo_target_isolated_from(&repository);
        let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
        command
            .arg("__verify-assurance-supervision-timeout-child")
            .env("CARGO_TARGET_DIR", &fixture.nested_cargo_target);
        let (execution_deadline, completion_deadline) =
            supervision_deadlines(Duration::from_millis(100), Duration::from_secs(5));
        let result = hell_testkit::run_supervised_command_until(
            &mut command,
            &[],
            execution_deadline,
            completion_deadline,
            None,
        )
        .expect("assurance timeout child must retain process-tree completion reserve");
        assert!(result.timed_out, "assurance timeout child exited early");
        let termination = result
            .termination
            .expect("assurance timeout child lacks a termination receipt");
        assert!(
            termination.forced && termination.reaped,
            "assurance timeout child was not forced and reaped"
        );
        assert_terminal_cleanup_receipt(&result);
    });
}

#[test]
fn assurance_baseline_failure_retains_bounded_terminal_evidence() {
    run_fixture_test(|fixture| {
        let repository = repository_root();
        fixture.assert_nested_cargo_target_isolated_from(&repository);
        fixture
            .prepare_nested_cargo_target(&repository)
            .expect("prepare nested Cargo target for baseline failure");
        let source_manifest = repository.join("compat/assurance-mutants.toml");
        let source =
            fs::read_to_string(&source_manifest).expect("read assurance mutation manifest");
        let corrupted = source.replacen(
            "\"--test\", \"assurance_primary_mutations\"",
            "\"--test\", \"absent_assurance_target\"",
            1,
        );
        assert_ne!(corrupted, source, "baseline corruption site is absent");
        let manifest = fixture.root.join("corrupted-assurance-mutants.toml");
        fs::write(&manifest, corrupted).expect("write corrupted assurance mutation manifest");
        let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
        command
            .current_dir(&repository)
            .env("CARGO_TARGET_DIR", &fixture.nested_cargo_target)
            .args(["mutation", "assurance", "--manifest"])
            .arg(&manifest)
            .args(["--repository-root", ".", "--output"])
            .arg(fixture.root.join("mutation"));
        let (execution_deadline, completion_deadline) =
            supervision_deadlines(Duration::from_mins(2), ASSURANCE_COMPLETION_RESERVE);
        let result = hell_testkit::run_supervised_command_until(
            &mut command,
            &[],
            execution_deadline,
            completion_deadline,
            None,
        )
        .expect("run corrupted assurance baseline under reserved supervision");
        assert_policy_failure_result(&result, "baseline failure");
        assert_terminal_cleanup_receipt(&result);
        let stderr = complete_stderr(&result);
        let receipt = assurance_failure_receipt(&stderr);
        assert_assurance_failure_receipt(&receipt, "digest-binding-inverted", "baseline");
        let diagnostic = bounded_receipt_diagnostic(&receipt);
        assert_eq!(
            receipt["policyFailure"], "baseline-not-green",
            "{diagnostic}"
        );
        assert_eq!(receipt["timedOut"], false, "{diagnostic}");
        assert_eq!(receipt["stdout"]["captureTruncated"], false, "{diagnostic}");
        assert_eq!(receipt["stderr"]["captureTruncated"], false, "{diagnostic}");
        assert_eq!(
            receipt["stdout"]["evidence"]["kind"], "complete",
            "{diagnostic}"
        );
        assert_eq!(
            receipt["stderr"]["evidence"]["kind"], "complete",
            "{diagnostic}"
        );
    });
}

#[test]
fn assurance_activated_survival_retains_the_exact_activated_argv_receipt() {
    run_fixture_test(|fixture| {
        let repository = repository_root();
        fixture.assert_nested_cargo_target_isolated_from(&repository);
        fixture
            .prepare_nested_cargo_target(&repository)
            .expect("prepare nested Cargo target for activated survival");
        let source = fs::read_to_string(repository.join("compat/assurance-mutants.toml"))
            .expect("read assurance mutation manifest");
        let corrupted = source.replacen(
            "id = \"digest-binding-inverted\"",
            "id = \"digest-binding-inverted-survival-fixture\"",
            1,
        );
        assert_ne!(
            corrupted, source,
            "activated-survival corruption site is absent"
        );
        let manifest = fixture.root.join("surviving-assurance-mutants.toml");
        fs::write(&manifest, corrupted).expect("write surviving assurance mutation manifest");
        let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
        command
            .current_dir(&repository)
            .env("CARGO_TARGET_DIR", &fixture.nested_cargo_target)
            .args(["mutation", "assurance", "--manifest"])
            .arg(&manifest)
            .args(["--repository-root", ".", "--output"])
            .arg(fixture.root.join("mutation"));
        let (execution_deadline, completion_deadline) =
            supervision_deadlines(Duration::from_mins(2), ASSURANCE_COMPLETION_RESERVE);
        let result = hell_testkit::run_supervised_command_until(
            &mut command,
            &[],
            execution_deadline,
            completion_deadline,
            None,
        )
        .expect("run surviving assurance mutant under reserved supervision");
        assert_policy_failure_result(&result, "activated survival");
        assert_terminal_cleanup_receipt(&result);
        let stderr = complete_stderr(&result);
        let receipt = assurance_failure_receipt(&stderr);
        assert_assurance_failure_receipt(
            &receipt,
            "digest-binding-inverted-survival-fixture",
            "activated",
        );
        let diagnostic = bounded_receipt_diagnostic(&receipt);
        assert_eq!(
            receipt["policyFailure"], "activated-survived",
            "{diagnostic}"
        );
        let argv = receipt["command"]["argv"]
            .as_array()
            .expect("activated command argv");
        assert_eq!(argv[argv.len() - 4], "--skip", "{diagnostic}");
        assert_eq!(argv[argv.len() - 3], "__hell_mutant", "{diagnostic}");
        assert_eq!(argv[argv.len() - 2], "--skip", "{diagnostic}");
        assert_eq!(
            argv[argv.len() - 1],
            "digest-binding-inverted-survival-fixture",
            "{diagnostic}"
        );
    });
}

#[test]
fn assurance_fixture_cleanup_preserves_a_primary_failure() {
    let mut fixture = Fixture::new();
    let cleanup = fixture.cleanup();
    assert_eq!(cleanup, Ok(()));
    assert_eq!(
        combine_fixture_failures(Err("primary receipt validation failed".to_owned()), cleanup),
        Err("primary receipt validation failed".to_owned())
    );
}

#[test]
fn assurance_fixture_cleanup_appends_hostile_cleanup_after_the_primary() {
    let mut fixture = Fixture::new();
    fs::rename(
        &fixture.nested_cargo_target,
        fixture.root.join("displaced-cargo-target"),
    )
    .expect("retain original nested target identity away from its bound path");
    fs::create_dir(&fixture.nested_cargo_target)
        .expect("substitute nested target with a different directory identity");
    let cleanup = fixture.cleanup();
    assert!(fixture.cleanup_complete);
    assert!(!fixture.root.exists());
    let combined =
        combine_fixture_failures(Err("primary receipt validation failed".to_owned()), cleanup)
            .expect_err("cleanup-hostile fixture must retain a combined failure");
    assert!(combined.starts_with(
        "primary receipt validation failed; additionally, nested Cargo target identity changed"
    ));
}

#[test]
fn nested_cargo_target_isolation_accepts_a_missing_repository_target() {
    let mut fixture = Fixture::new();
    let repository = fixture.root.join("clean-checkout");
    fs::create_dir(&repository).expect("create clean-checkout repository fixture");
    let repository = fs::canonicalize(repository).expect("canonicalize clean-checkout repository");
    assert!(
        !repository.join("target").exists(),
        "clean-checkout regression requires a missing repository target"
    );

    fixture.assert_nested_cargo_target_isolated_from(&repository);

    let cleanup = fixture.cleanup();
    assert_eq!(cleanup, Ok(()));
    assert!(fixture.cleanup_complete);
    assert!(!fixture.root.exists());
}

fn run_fixture_test(test: impl FnOnce(&Fixture)) {
    let mut fixture = Fixture::new();
    let primary = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&fixture)))
        .map_err(|payload| panic_detail(payload.as_ref()));
    let cleanup = fixture.cleanup();
    if let Err(failure) = combine_fixture_failures(primary, cleanup) {
        panic!("{failure}");
    }
}

fn panic_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(detail) = payload.downcast_ref::<String>() {
        detail.clone()
    } else if let Some(detail) = payload.downcast_ref::<&str>() {
        (*detail).to_owned()
    } else {
        "assurance fixture primary failure has a non-string panic payload".to_owned()
    }
}

fn combine_fixture_failures(
    primary: Result<(), String>,
    cleanup: Result<(), String>,
) -> Result<(), String> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!("{primary}; additionally, {cleanup}")),
    }
}

fn resolve_executable_invocation(program: &OsStr) -> Result<PathBuf, String> {
    let path = Path::new(program);
    let invocation = if path.is_absolute() {
        path.to_path_buf()
    } else {
        if path.components().count() != 1 || program.is_empty() {
            return Err("Cargo setup executable must be absolute or one PATH component".to_owned());
        }
        let search = std::env::var_os("PATH")
            .ok_or_else(|| "PATH is unavailable for Cargo setup".to_owned())?;
        let mut resolved = None;
        for directory in std::env::split_paths(&search) {
            if !directory.is_absolute() {
                return Err("Cargo setup PATH contains a relative directory".to_owned());
            }
            let candidate = directory.join(program);
            if candidate.is_file() || candidate.symlink_metadata().is_ok() {
                resolved = Some(candidate);
                break;
            }
            if Path::new(program).extension().is_none() && !std::env::consts::EXE_SUFFIX.is_empty()
            {
                let mut native_name = program.to_os_string();
                native_name.push(std::env::consts::EXE_SUFFIX);
                let candidate = directory.join(native_name);
                if candidate.is_file() || candidate.symlink_metadata().is_ok() {
                    resolved = Some(candidate);
                    break;
                }
            }
        }
        resolved.ok_or_else(|| "Cargo setup executable is unavailable on PATH".to_owned())?
    };
    let metadata = fs::symlink_metadata(&invocation)
        .map_err(|error| format!("cannot inspect Cargo setup invocation: {error}"))?;
    if !metadata.is_file() && !metadata.file_type().is_symlink() {
        return Err("Cargo setup invocation is not a file or executable alias".to_owned());
    }
    Ok(invocation)
}

fn remove_directory_until(path: &Path, deadline: Instant, label: &str) -> Result<(), String> {
    loop {
        match fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error)
                if Instant::now() < deadline
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::DirectoryNotEmpty
                            | std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::PermissionDenied
                            | std::io::ErrorKind::WouldBlock
                    ) =>
            {
                std::thread::yield_now();
            }
            Err(error) => return Err(format!("cannot remove {label}: {error}")),
        }
    }
}

fn bounded_capture_diagnostic(capture: &hell_testkit::BoundedCapture) -> String {
    let retained = capture.complete.as_ref().map_or_else(
        || {
            format!(
                "{}<middle omitted>{}",
                String::from_utf8_lossy(&capture.prefix),
                String::from_utf8_lossy(&capture.suffix)
            )
        },
        |complete| String::from_utf8_lossy(complete).into_owned(),
    );
    format!(
        "bytes={},sha256={},captureTruncated={},detail={retained:?}",
        capture.total_bytes,
        capture.sha256.hex(),
        capture.truncated
    )
}

fn status_diagnostic(status: Option<i32>) -> String {
    status.map_or_else(|| "none".to_owned(), |code| code.to_string())
}

fn assert_policy_failure_result(result: &hell_testkit::SupervisedOutput, label: &str) {
    if result.status.success() || result.timed_out {
        let termination = result.termination.as_ref().map_or_else(
            || "none".to_owned(),
            |receipt| {
                format!(
                    "cleanupId={:?},forced={},reaped={},quiescence={}",
                    receipt.cleanup_id,
                    receipt.forced,
                    receipt.reaped,
                    result.candidate_quiescence_complete
                )
            },
        );
        panic!(
            "{label} command outcome differs: status={},timedOut={},termination={},stdout={},stderr={}",
            status_diagnostic(result.status.code()),
            result.timed_out,
            termination,
            bounded_capture_diagnostic(&result.stdout),
            bounded_capture_diagnostic(&result.stderr)
        );
    }
}

fn assurance_failure_receipt(stderr: &str) -> serde_json::Value {
    let (_, encoded) = stderr
        .rsplit_once("assuranceCommandFailureReceipt=")
        .expect("assurance failure receipt marker");
    serde_json::from_str(encoded.trim()).expect("parse assurance command failure receipt")
}

fn assert_assurance_failure_receipt(receipt: &serde_json::Value, mutant_id: &str, phase: &str) {
    let diagnostic = bounded_receipt_diagnostic(receipt);
    assert_eq!(receipt["schemaVersion"], 1, "{diagnostic}");
    assert_eq!(receipt["catalogId"], "release-assurance-v1", "{diagnostic}");
    assert_eq!(receipt["mutantId"], mutant_id, "{diagnostic}");
    assert_eq!(receipt["phase"], phase, "{diagnostic}");
    assert_eq!(receipt["command"]["program"], "cargo", "{diagnostic}");
    assert_eq!(
        receipt["command"]["executionDeadlineOffsetMillis"], 900_000,
        "{diagnostic}"
    );
    assert_eq!(
        receipt["command"]["completionDeadlineOffsetMillis"], 930_000,
        "{diagnostic}"
    );
    assert!(
        receipt["command"]["cwd"]["hex"]
            .as_str()
            .is_some_and(|hex| !hex.is_empty()),
        "{diagnostic}"
    );
    assert!(receipt["durationMillis"].is_u64(), "{diagnostic}");
    assert!(receipt["status"]["kind"].as_str().is_some(), "{diagnostic}");
    for stream in ["stdout", "stderr"] {
        assert!(receipt[stream]["totalBytes"].is_u64(), "{diagnostic}");
        assert_eq!(
            receipt[stream]["sha256"]
                .as_str()
                .expect("stream digest")
                .len(),
            64,
            "{diagnostic}"
        );
        assert!(
            receipt[stream]["captureTruncated"].is_boolean(),
            "{diagnostic}"
        );
        assert!(
            receipt[stream]["evidence"]["omittedBytes"].is_u64(),
            "{diagnostic}"
        );
    }
    assert!(receipt["lifecycle"]["cleanupId"].is_u64(), "{diagnostic}");
    assert_eq!(receipt["lifecycle"]["reaped"], true, "{diagnostic}");
    assert!(
        receipt["lifecycle"]["candidateQuiescenceComplete"].is_boolean(),
        "{diagnostic}"
    );
    assert_eq!(receipt["lifecycle"]["stdoutJoined"], true, "{diagnostic}");
    assert_eq!(receipt["lifecycle"]["stderrJoined"], true, "{diagnostic}");
    assert_eq!(receipt["lifecycle"]["stdinJoined"], true, "{diagnostic}");
    let keys = receipt
        .as_object()
        .expect("receipt object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            "catalogId",
            "command",
            "durationMillis",
            "lifecycle",
            "mutantId",
            "phase",
            "policyFailure",
            "schemaVersion",
            "status",
            "stderr",
            "stdout",
            "timedOut",
        ],
        "{diagnostic}"
    );
}

fn bounded_receipt_diagnostic(receipt: &serde_json::Value) -> String {
    const EDGE_BYTES: usize = 4_096;
    let rendered = serde_json::to_string(receipt)
        .unwrap_or_else(|error| format!("cannot render assurance receipt diagnostic: {error}"));
    if rendered.len() <= EDGE_BYTES.saturating_mul(2) {
        rendered
    } else {
        let mut prefix_end = EDGE_BYTES;
        while !rendered.is_char_boundary(prefix_end) {
            prefix_end -= 1;
        }
        let mut suffix_start = rendered.len() - EDGE_BYTES;
        while !rendered.is_char_boundary(suffix_start) {
            suffix_start += 1;
        }
        let prefix = &rendered[..prefix_end];
        let suffix = &rendered[suffix_start..];
        format!(
            "{prefix}<{} receipt bytes omitted>{suffix}",
            suffix_start - prefix_end
        )
    }
}

fn supervision_deadlines(
    execution_timeout: Duration,
    completion_reserve: Duration,
) -> (Instant, Instant) {
    let execution = Instant::now()
        .checked_add(execution_timeout)
        .expect("assurance execution deadline overflowed");
    let completion = execution
        .checked_add(completion_reserve)
        .expect("assurance completion deadline overflowed");
    (execution, completion)
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn complete_stderr(output: &hell_testkit::SupervisedOutput) -> String {
    String::from_utf8_lossy(
        output
            .stderr
            .complete
            .as_deref()
            .unwrap_or(&output.stderr.prefix),
    )
    .into_owned()
}

fn assert_terminal_cleanup_receipt(result: &hell_testkit::SupervisedOutput) {
    validate_terminal_cleanup_receipt(result).unwrap_or_else(|error| panic!("{error}"));
}

fn validate_terminal_cleanup_receipt(
    result: &hell_testkit::SupervisedOutput,
) -> Result<(), String> {
    for expected in ["quiescence-complete", "stdout-joined", "stderr-joined"] {
        if !result
            .phase_timings
            .iter()
            .any(|phase| phase.name == expected)
        {
            return Err(format!(
                "mutation assurance lacks terminal phase {expected}"
            ));
        }
    }
    if result.phase_timings.last().map(|phase| phase.name) != Some("stdin-joined") {
        return Err(
            "mutation assurance did not produce the terminal supervised I/O receipt".to_owned(),
        );
    }
    Ok(())
}
