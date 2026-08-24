use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::command::CommandSpec;
use crate::github_runtime::{GithubRuntime, RunnerIdentity};
use crate::json::{JsonValue, canonical_json_bytes, json_member};
use crate::process_environment::{ExecutableSearchPath, ProcessEnvironment};

use super::governance::{
    TomlDocument, boolean, integer, member, quoted, require_allowed_keys, require_identifier,
    require_keys, string_array,
};
use super::manifest::{read_json, read_regular, write_json_new};
use super::schema::{PLATFORMS, ReleasePlatform, number, object, require_digest, string};

const EXTERNAL_INPUT_DOMAIN: &[u8] = b"hell-rs:external-input-lock:1";
const NATIVE_ENVIRONMENT_DOMAIN: &[u8] = b"hell-rs:native-environment:1";
const NATIVE_ENVIRONMENT_SET_DOMAIN: &[u8] = b"hell-rs:native-environment-set:1";
const MAX_LOCK_BYTES: u64 = 1024 * 1024;
const MAX_TOOL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MSVC_VERSION_BYTES: u64 = 256;
const COLLECTION_TIMEOUT: Duration = Duration::from_mins(5);
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);
const MSVC_TOOLSET_PROBE_ARGUMENTS: &[&str] = &["/?"];
const MSVC_BANNER_PREFIX: &str = "Microsoft (R) C/C++ Optimizing Compiler Version ";
const MSVC_BANNER_SUFFIX: &str = " for x64";
const MSVC_DIAGNOSTIC_LINE_LIMIT: usize = 256;
const MSVC_DIAGNOSTIC_CANDIDATE_LIMIT: usize = 4;
const MSVC_INTEGRATION_FIXTURE_MAX_BYTES: u64 = 8 * 1024 * 1024;
const MSVC_INTEGRATION_PRIMARY_TIMEOUT: Duration = Duration::from_secs(30);
const MSVC_INTEGRATION_CLEANUP_RESERVE: Duration = Duration::from_secs(15);

#[derive(Clone, Debug)]
struct ExternalInputLock {
    lock_id: String,
    inputs: Vec<ExternalInput>,
}

#[derive(Clone, Debug)]
struct ExternalInput {
    id: String,
    kind: String,
    acquisition_phase: String,
    platforms: Vec<String>,
    fields: BTreeMap<String, JsonValue>,
}

#[derive(Clone, Debug)]
struct ToolSpec {
    id: &'static str,
    resolver: ToolResolver,
    arguments: &'static [&'static str],
    output_parser: ToolOutputParser,
    expected_version: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum ToolOutputParser {
    FirstNonEmptyLine,
    ExactNumericVersion,
    MsvcCompilerBanner,
}

#[derive(Clone, Debug)]
enum ToolResolver {
    SearchPath(&'static str),
    MsvcToolset,
}

#[derive(Clone, Debug)]
struct ResolvedTool {
    executable: PathBuf,
    #[cfg(windows)]
    msvc_discovery: Option<MsvcDiscoveryReceipt>,
}

#[derive(Clone, Debug)]
struct BoundNativeFile {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug)]
struct MsvcDiscoveryReceipt {
    vswhere: BoundNativeFile,
    visual_studio_root: PathBuf,
    version_file: BoundNativeFile,
    toolset_version: String,
    compiler: BoundNativeFile,
}

fn resolve_tool(
    search: &ExecutableSearchPath,
    resolver: &ToolResolver,
    deadline: Instant,
) -> Result<ResolvedTool, String> {
    match resolver {
        ToolResolver::SearchPath(executable) => Ok(ResolvedTool {
            executable: search.resolve(OsStr::new(executable))?,
            #[cfg(windows)]
            msvc_discovery: None,
        }),
        #[cfg(windows)]
        ToolResolver::MsvcToolset => {
            let discovery = discover_msvc_toolset(search, deadline)?;
            Ok(ResolvedTool {
                executable: discovery.compiler.path.clone(),
                msvc_discovery: Some(discovery),
            })
        }
        #[cfg(not(windows))]
        ToolResolver::MsvcToolset => {
            let _ = deadline;
            Err("MSVC discovery is unavailable on this host".to_owned())
        }
    }
}

impl BoundNativeFile {
    fn bind(path: &Path, byte_limit: u64, label: &str) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > byte_limit
        {
            return Err(format!("{label} is not one bounded regular file"));
        }
        let canonical = std::fs::canonicalize(path)
            .map_err(|error| format!("cannot canonicalize {label}: {error}"))?;
        let canonical_metadata = std::fs::symlink_metadata(&canonical)
            .map_err(|error| format!("cannot inspect canonical {label}: {error}"))?;
        if !canonical_metadata.is_file()
            || canonical_metadata.file_type().is_symlink()
            || canonical_metadata.len() != metadata.len()
        {
            return Err(format!("{label} canonical identity differs"));
        }
        let sha256 = hell_testkit::sha256_file(&canonical)
            .map_err(|error| format!("cannot hash {label}: {error}"))?
            .hex();
        Ok(Self {
            path: canonical,
            bytes: metadata.len(),
            sha256,
        })
    }

    fn validate(&self, byte_limit: u64, label: &str) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot re-inspect {label}: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != self.bytes
            || metadata.len() == 0
            || metadata.len() > byte_limit
            || std::fs::canonicalize(&self.path).ok().as_deref() != Some(self.path.as_path())
        {
            return Err(format!("{label} identity changed"));
        }
        let digest = hell_testkit::sha256_file(&self.path)
            .map_err(|error| format!("cannot rehash {label}: {error}"))?
            .hex();
        if digest != self.sha256 {
            return Err(format!("{label} content changed"));
        }
        Ok(())
    }

    fn read_verified(&self, byte_limit: u64, label: &str) -> Result<Vec<u8>, String> {
        self.validate(byte_limit, label)?;
        let bytes =
            std::fs::read(&self.path).map_err(|error| format!("cannot read {label}: {error}"))?;
        if u64::try_from(bytes.len()).ok() != Some(self.bytes)
            || hell_testkit::sha256_bytes(&bytes).hex() != self.sha256
        {
            return Err(format!("{label} changed while being read"));
        }
        self.validate(byte_limit, label)?;
        Ok(bytes)
    }
}

fn parse_single_absolute_path(bytes: &[u8], label: &str) -> Result<PathBuf, String> {
    if bytes.is_empty() || bytes.len() > 32 * 1024 {
        return Err(format!("{label} discovery output is not bounded"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| format!("{label} discovery output is not UTF-8"))?;
    let value = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if value.is_empty()
        || value != value.trim()
        || value.contains(['\r', '\n', '\0'])
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} discovery output is not one absolute path"));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label} discovery output is not an absolute path"));
    }
    Ok(path)
}

fn parse_msvc_toolset_version(bytes: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "MSVC default-version file is not UTF-8".to_owned())?;
    let version = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    let components = version.split('.').collect::<Vec<_>>();
    if version.is_empty()
        || version.len() > 64
        || version != version.trim()
        || version.contains(['\r', '\n', '\0'])
        || components.len() < 2
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("MSVC default-version file is not one numeric dotted component".to_owned());
    }
    Ok(version.to_owned())
}

impl MsvcDiscoveryReceipt {
    fn validate(&self) -> Result<(), String> {
        self.vswhere
            .validate(MAX_TOOL_BYTES, "Visual Studio discovery executable")?;
        let root_metadata = std::fs::symlink_metadata(&self.visual_studio_root)
            .map_err(|error| format!("cannot re-inspect Visual Studio root: {error}"))?;
        if !root_metadata.is_dir()
            || root_metadata.file_type().is_symlink()
            || std::fs::canonicalize(&self.visual_studio_root)
                .ok()
                .as_deref()
                != Some(self.visual_studio_root.as_path())
        {
            return Err("Visual Studio root identity changed".to_owned());
        }
        let expected_version_file = self
            .visual_studio_root
            .join("VC")
            .join("Auxiliary")
            .join("Build")
            .join("Microsoft.VCToolsVersion.default.txt");
        let expected_version_metadata = std::fs::symlink_metadata(&expected_version_file)
            .map_err(|error| format!("cannot re-inspect MSVC default-version file: {error}"))?;
        if expected_version_metadata.file_type().is_symlink()
            || std::fs::canonicalize(&expected_version_file)
                .ok()
                .as_deref()
                != Some(self.version_file.path.as_path())
        {
            return Err("MSVC default-version file identity changed".to_owned());
        }
        let version_bytes = self
            .version_file
            .read_verified(MAX_MSVC_VERSION_BYTES, "MSVC default-version file")?;
        if parse_msvc_toolset_version(&version_bytes)? != self.toolset_version {
            return Err("MSVC default-version selection changed".to_owned());
        }
        let expected_compiler = self
            .visual_studio_root
            .join("VC")
            .join("Tools")
            .join("MSVC")
            .join(&self.toolset_version)
            .join("bin")
            .join("Hostx64")
            .join("x64")
            .join("cl.exe");
        let expected_compiler_metadata = std::fs::symlink_metadata(&expected_compiler)
            .map_err(|error| format!("cannot re-inspect selected cl.exe: {error}"))?;
        let canonical_compiler = std::fs::canonicalize(&expected_compiler)
            .map_err(|error| format!("cannot recanonicalize selected cl.exe: {error}"))?;
        if expected_compiler_metadata.file_type().is_symlink()
            || canonical_compiler != self.compiler.path
            || !canonical_compiler.starts_with(&self.visual_studio_root)
        {
            return Err("selected cl.exe identity changed".to_owned());
        }
        self.compiler.validate(MAX_TOOL_BYTES, "selected cl.exe")
    }
}

fn bind_msvc_toolset(
    vswhere: BoundNativeFile,
    selected_root: &Path,
) -> Result<MsvcDiscoveryReceipt, String> {
    let visual_studio_root = std::fs::canonicalize(selected_root)
        .map_err(|error| format!("cannot canonicalize Visual Studio root: {error}"))?;
    let root_metadata = std::fs::symlink_metadata(&visual_studio_root)
        .map_err(|error| format!("cannot inspect Visual Studio root: {error}"))?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err("Visual Studio root is not one canonical directory".to_owned());
    }
    let version_path = visual_studio_root
        .join("VC")
        .join("Auxiliary")
        .join("Build")
        .join("Microsoft.VCToolsVersion.default.txt");
    let version_file = BoundNativeFile::bind(
        &version_path,
        MAX_MSVC_VERSION_BYTES,
        "MSVC default-version file",
    )?;
    if !version_file.path.starts_with(&visual_studio_root) {
        return Err("MSVC default-version file escapes the Visual Studio root".to_owned());
    }
    let version_bytes =
        version_file.read_verified(MAX_MSVC_VERSION_BYTES, "MSVC default-version file")?;
    let toolset_version = parse_msvc_toolset_version(&version_bytes)?;
    let compiler_path = visual_studio_root
        .join("VC")
        .join("Tools")
        .join("MSVC")
        .join(&toolset_version)
        .join("bin")
        .join("Hostx64")
        .join("x64")
        .join("cl.exe");
    let compiler = BoundNativeFile::bind(&compiler_path, MAX_TOOL_BYTES, "selected cl.exe")?;
    if !compiler.path.starts_with(&visual_studio_root) {
        return Err("selected cl.exe escapes the Visual Studio root".to_owned());
    }
    let receipt = MsvcDiscoveryReceipt {
        vswhere,
        visual_studio_root,
        version_file,
        toolset_version,
        compiler,
    };
    receipt.validate()?;
    Ok(receipt)
}

#[cfg(windows)]
fn discover_msvc_toolset(
    search: &ExecutableSearchPath,
    deadline: Instant,
) -> Result<MsvcDiscoveryReceipt, String> {
    if Instant::now() >= deadline {
        return Err("native environment absolute deadline expired".to_owned());
    }
    let vswhere_path = search.resolve(OsStr::new("vswhere.exe"))?;
    let vswhere = BoundNativeFile::bind(
        &vswhere_path,
        MAX_TOOL_BYTES,
        "Visual Studio discovery executable",
    )?;
    let execution_deadline = Instant::now()
        .checked_add(TOOL_TIMEOUT)
        .unwrap_or(deadline)
        .min(deadline);
    let (progress, _receiver) = hell_testkit::SupervisedProgressObserver::bounded(1);
    let result = CommandSpec::new(vswhere.path.clone(), TOOL_TIMEOUT)
        .arguments([
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ])
        .release_candidate_environment()
        .run_until(execution_deadline, deadline, progress)
        .map_err(|error| format!("Visual Studio discovery failed to execute: {error}"))?;
    if result.timed_out
        || !result.status.success()
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.stderr.is_empty()
        || (result.termination.forced && !result.termination.reaped)
    {
        return Err(format!(
            "Visual Studio discovery did not complete cleanly: status={} timedOut={} stdoutTruncated={} stderrTruncated={} stderrBytes={} forced={} reaped={}",
            result.status,
            result.timed_out,
            result.stdout_truncated,
            result.stderr_truncated,
            result.stderr_bytes,
            result.termination.forced,
            result.termination.reaped
        ));
    }
    vswhere.validate(MAX_TOOL_BYTES, "Visual Studio discovery executable")?;
    let selected_root = parse_single_absolute_path(&result.stdout, "Visual Studio installation")?;
    let receipt = bind_msvc_toolset(vswhere, &selected_root)?;
    if Instant::now() >= deadline {
        return Err("native environment absolute deadline expired".to_owned());
    }
    Ok(receipt)
}

#[derive(Clone, Copy, Debug)]
struct MsvcIntegrationDeadlines {
    primary: Instant,
    cleanup: Instant,
}

impl MsvcIntegrationDeadlines {
    fn bind() -> Result<Self, String> {
        let primary = Instant::now()
            .checked_add(MSVC_INTEGRATION_PRIMARY_TIMEOUT)
            .ok_or_else(|| "MSVC integration primary deadline overflowed".to_owned())?;
        let cleanup = primary
            .checked_add(MSVC_INTEGRATION_CLEANUP_RESERVE)
            .ok_or_else(|| "MSVC integration cleanup deadline overflowed".to_owned())?;
        Ok(Self { primary, cleanup })
    }

    fn require_primary(self, phase: &str) -> Result<(), String> {
        if Instant::now() >= self.primary {
            return Err(format!(
                "MSVC integration primary deadline expired during {phase}"
            ));
        }
        Ok(())
    }

    fn require_cleanup(self, phase: &str) -> Result<(), String> {
        if Instant::now() >= self.cleanup {
            return Err(format!(
                "MSVC integration cleanup deadline expired during {phase}"
            ));
        }
        Ok(())
    }

    fn expired_primary() -> Result<Self, String> {
        let primary = Instant::now();
        let cleanup = primary
            .checked_add(MSVC_INTEGRATION_CLEANUP_RESERVE)
            .ok_or_else(|| "MSVC integration cleanup deadline overflowed".to_owned())?;
        Ok(Self { primary, cleanup })
    }
}

fn verify_msvc_discovery_parser_rejections() -> Result<(), String> {
    for invalid in [
        &b"14.44\n14.45"[..],
        &b"../14.44"[..],
        &b"..\\14.44"[..],
        &b"14/44"[..],
        &b"14..44"[..],
        &b"14.44\r\n\r\n"[..],
    ] {
        if parse_msvc_toolset_version(invalid).is_ok() {
            return Err("invalid MSVC toolset version was accepted".to_owned());
        }
    }
    if parse_single_absolute_path(b"relative\\Visual Studio\r\n", "fixture").is_ok() {
        return Err("relative Visual Studio discovery output was accepted".to_owned());
    }
    Ok(())
}

fn resolve_msvc_integration_fixture_source() -> Result<BoundNativeFile, String> {
    #[cfg(windows)]
    let source = {
        let search = ExecutableSearchPath::from_process()?;
        let path = search.resolve(OsStr::new("where.exe"))?;
        BoundNativeFile::bind(
            &path,
            MSVC_INTEGRATION_FIXTURE_MAX_BYTES,
            "MSVC integration fixture source",
        )?
    };
    #[cfg(unix)]
    let source = {
        let authority =
            crate::command::resolve_absolute_standard_executable(Path::new("/usr/bin/true"))?;
        authority.revalidate()?;
        let source = BoundNativeFile::bind(
            authority.invocation_path(),
            MSVC_INTEGRATION_FIXTURE_MAX_BYTES,
            "MSVC integration fixture source",
        )?;
        authority.revalidate()?;
        source
    };
    Ok(source)
}

fn stage_msvc_integration_fixture_identity(
    source: &BoundNativeFile,
    destination: &Path,
    label: &str,
    deadlines: MsvcIntegrationDeadlines,
) -> Result<BoundNativeFile, String> {
    deadlines.require_primary(label)?;
    std::fs::copy(&source.path, destination)
        .map_err(|error| format!("cannot stage {label}: {error}"))?;
    let staged = BoundNativeFile::bind(destination, MSVC_INTEGRATION_FIXTURE_MAX_BYTES, label)?;
    if staged.bytes != source.bytes || staged.sha256 != source.sha256 {
        return Err(format!("staged {label} identity differs from its source"));
    }
    deadlines.require_primary(label)?;
    Ok(staged)
}

fn verify_msvc_discovery_identity_fixture(
    fixture_root: &Path,
    deadlines: MsvcIntegrationDeadlines,
) -> Result<(), String> {
    deadlines.require_primary("fixture path validation")?;
    let root_text = fixture_root
        .to_str()
        .ok_or_else(|| "MSVC discovery fixture path is not UTF-8".to_owned())?;
    let single_path = format!("{root_text}\r\n");
    if parse_single_absolute_path(single_path.as_bytes(), "fixture")? != fixture_root {
        return Err("single Visual Studio discovery path changed".to_owned());
    }
    let multiple_paths = format!("{root_text}\r\n{root_text}\r\n");
    if parse_single_absolute_path(multiple_paths.as_bytes(), "fixture").is_ok() {
        return Err("multi-line Visual Studio discovery output was accepted".to_owned());
    }

    let source = resolve_msvc_integration_fixture_source()?;
    let vswhere_path = fixture_root.join("vswhere.exe");
    let vswhere = stage_msvc_integration_fixture_identity(
        &source,
        &vswhere_path,
        "fixture discovery executable",
        deadlines,
    )?;

    let visual_studio_root = fixture_root.join("Visual Studio");
    let version_path = visual_studio_root
        .join("VC")
        .join("Auxiliary")
        .join("Build")
        .join("Microsoft.VCToolsVersion.default.txt");
    let version = "14.44.35207";
    std::fs::create_dir_all(
        version_path
            .parent()
            .ok_or_else(|| "MSVC version fixture lacks a parent".to_owned())?,
    )
    .map_err(|error| format!("cannot create MSVC version fixture: {error}"))?;
    std::fs::write(&version_path, format!("{version}\r\n"))
        .map_err(|error| format!("cannot write MSVC version fixture: {error}"))?;
    deadlines.require_primary("fixture version staging")?;
    let compiler_path = visual_studio_root
        .join("VC")
        .join("Tools")
        .join("MSVC")
        .join(version)
        .join("bin")
        .join("Hostx64")
        .join("x64")
        .join("cl.exe");
    std::fs::create_dir_all(
        compiler_path
            .parent()
            .ok_or_else(|| "MSVC compiler fixture lacks a parent".to_owned())?,
    )
    .map_err(|error| format!("cannot create MSVC compiler fixture: {error}"))?;
    stage_msvc_integration_fixture_identity(
        &source,
        &compiler_path,
        "fixture compiler executable",
        deadlines,
    )?;
    source.validate(
        MSVC_INTEGRATION_FIXTURE_MAX_BYTES,
        "MSVC integration fixture source",
    )?;
    deadlines.require_primary("fixture staging")?;

    let receipt = bind_msvc_toolset(vswhere, &visual_studio_root)?;
    receipt.validate()?;
    deadlines.require_primary("fixture identity validation")?;

    let mut compiler = std::fs::OpenOptions::new()
        .append(true)
        .open(&compiler_path)
        .map_err(|error| format!("cannot open compiler substitution fixture: {error}"))?;
    std::io::Write::write_all(&mut compiler, &[0])
        .map_err(|error| format!("cannot substitute compiler fixture: {error}"))?;
    compiler
        .sync_all()
        .map_err(|error| format!("cannot synchronize compiler substitution fixture: {error}"))?;
    drop(compiler);
    if receipt.validate().is_ok() {
        return Err("substituted selected cl.exe identity was accepted".to_owned());
    }
    deadlines.require_primary("fixture substitution validation")
}

fn cleanup_msvc_discovery_fixture(
    fixture_root: &Path,
    deadlines: MsvcIntegrationDeadlines,
) -> Result<(), String> {
    let reserve = deadlines.require_cleanup("fixture cleanup start");
    let removal = std::fs::remove_dir_all(fixture_root)
        .map_err(|error| format!("cannot remove MSVC discovery fixture: {error}"));
    let completion = deadlines.require_cleanup("fixture cleanup completion");
    let terminal = combine_msvc_integration_results(
        removal,
        completion,
        "MSVC fixture cleanup deadline check failed",
    );
    combine_msvc_integration_results(reserve, terminal, "MSVC fixture cleanup execution failed")
}

fn combine_msvc_integration_results(
    primary: Result<(), String>,
    secondary: Result<(), String>,
    secondary_context: &str,
) -> Result<(), String> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(secondary)) => Err(secondary),
        (Err(primary), Err(secondary)) => Err(format!(
            "{primary}; additionally, {secondary_context}: {secondary}"
        )),
    }
}

pub(crate) fn verify_msvc_discovery_for_integration() -> Result<(), String> {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    verify_msvc_banner_parser_for_integration()?;
    verify_msvc_discovery_parser_rejections()?;
    let deadlines = MsvcIntegrationDeadlines::bind()?;

    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "hell-msvc-discovery-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&fixture_root)
        .map_err(|error| format!("cannot create MSVC discovery fixture: {error}"))?;
    let primary = verify_msvc_discovery_identity_fixture(&fixture_root, deadlines);
    let cleanup = cleanup_msvc_discovery_fixture(&fixture_root, deadlines);
    combine_msvc_integration_results(primary, cleanup, "MSVC fixture cleanup failed")
}

pub(crate) fn verify_msvc_primary_deadline_expiry_for_integration() -> Result<(), String> {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let deadlines = MsvcIntegrationDeadlines::expired_primary()?;
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "hell-ci-msvc-discovery-expired-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&fixture_root)
        .map_err(|error| format!("cannot create expired MSVC discovery fixture: {error}"))?;
    let primary = match verify_msvc_discovery_identity_fixture(&fixture_root, deadlines) {
        Err(error) if error.contains("MSVC integration primary deadline expired") => Ok(()),
        Err(error) => Err(format!(
            "expired MSVC primary returned a different failure: {error}"
        )),
        Ok(()) => Err("expired MSVC primary was accepted".to_owned()),
    };
    let cleanup = cleanup_msvc_discovery_fixture(&fixture_root, deadlines).and_then(|()| {
        if fixture_root.exists() {
            Err("expired MSVC fixture remained after reserved cleanup".to_owned())
        } else {
            Ok(())
        }
    });
    combine_msvc_integration_results(primary, cleanup, "expired MSVC fixture cleanup failed")
}

fn verify_msvc_banner_parser_for_integration() -> Result<(), String> {
    const BANNER: &str = "Microsoft (R) C/C++ Optimizing Compiler Version 19.44.35207 for x64";
    for (stdout, stderr) in [
        ("C/C++ COMPILER OPTIONS\nUsage: cl [options]", BANNER),
        (BANNER, "C/C++ COMPILER OPTIONS\nUsage: cl [options]"),
    ] {
        if parse_msvc_compiler_banner_output(stdout.as_bytes(), stderr.as_bytes())? != BANNER {
            return Err("valid MSVC compiler banner selection changed".to_owned());
        }
    }
    for (stdout, stderr, expected) in [
        ("C/C++ COMPILER OPTIONS", "", "candidateCount=0"),
        (BANNER, BANNER, "candidateCount=2 invalidCandidateCount=0"),
        (
            "Microsoft (R) C/C++ Optimizing Compiler Version 19.44 for x86",
            "",
            "candidateCount=1 invalidCandidateCount=1",
        ),
        (
            "",
            "Microsoft (R) C/C++ Optimizing Compiler Version 19..44 for x64",
            "stderr:1=",
        ),
        (
            "Microsoft (R) C/C++ Optimizing Compiler Version 19.44\t for x64",
            "",
            "invalidCandidateCount=1",
        ),
    ] {
        let error = parse_msvc_compiler_banner_output(stdout.as_bytes(), stderr.as_bytes())
            .expect_err("invalid MSVC compiler output was accepted");
        if !error.contains(expected) {
            return Err(format!(
                "MSVC compiler banner rejection lacks bounded position evidence: {error}"
            ));
        }
    }
    let invalid_utf8 = parse_msvc_compiler_banner_output(b"", &[0xff])
        .expect_err("non-UTF-8 MSVC compiler output was accepted");
    if invalid_utf8 != "MSVC compiler stderr is not UTF-8" {
        return Err("MSVC compiler UTF-8 rejection changed".to_owned());
    }
    let overlong_banner = format!(
        "{MSVC_BANNER_PREFIX}{}{MSVC_BANNER_SUFFIX}",
        "1".repeat(2048)
    );
    let bounded = parse_msvc_compiler_banner_output(overlong_banner.as_bytes(), b"")
        .expect_err("overlong MSVC compiler banner was accepted");
    if !bounded.contains("candidateCount=1 invalidCandidateCount=1")
        || !bounded.contains("<truncated>")
        || bounded.len() > 1024
    {
        return Err("MSVC compiler diagnostic evidence is not bounded".to_owned());
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ToolReceipt {
    id: String,
    executable_sha256: String,
    output_sha256: String,
    parsed_version: String,
    lock_version: Option<String>,
    #[cfg(windows)]
    authority: Option<hell_testkit::BoundProgramInvocation>,
    #[cfg(windows)]
    resolved_executable: PathBuf,
}

pub(crate) struct NativeEnvironmentCollection {
    summary: String,
    #[cfg(windows)]
    ghc: WindowsNativeGhcAuthority,
}

impl NativeEnvironmentCollection {
    fn summary(self) -> String {
        self.summary
    }

    #[cfg(windows)]
    pub(crate) fn windows_ghc(&self) -> &WindowsNativeGhcAuthority {
        &self.ghc
    }
}

#[cfg(windows)]
#[derive(Clone, Debug)]
pub(crate) struct WindowsNativeGhcAuthority {
    executable: PathBuf,
    program: hell_testkit::BoundProgramInvocation,
    executable_sha256: String,
    output_sha256: String,
    parsed_version: String,
}

#[cfg(windows)]
impl WindowsNativeGhcAuthority {
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn program(&self) -> &hell_testkit::BoundProgramInvocation {
        &self.program
    }

    pub(crate) fn parsed_version(&self) -> &str {
        &self.parsed_version
    }

    pub(crate) fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }

    pub(crate) fn output_sha256(&self) -> &str {
        &self.output_sha256
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.program
            .windows_revalidate_for_integration()
            .map_err(|error| format!("native GHC executable identity changed: {error}"))?;
        if self.program.windows_sha256_for_integration().hex() != self.executable_sha256 {
            return Err("native GHC executable digest changed".to_owned());
        }
        Ok(())
    }

    fn from_receipt(receipt: &ToolReceipt) -> Result<Self, String> {
        let program = receipt
            .authority
            .clone()
            .ok_or_else(|| "native GHC executable authority is absent".to_owned())?;
        let authority = Self {
            executable: receipt.resolved_executable.clone(),
            program,
            executable_sha256: receipt.executable_sha256.clone(),
            output_sha256: receipt.output_sha256.clone(),
            parsed_version: receipt.parsed_version.clone(),
        };
        authority.revalidate()?;
        Ok(authority)
    }

    fn require_receipt(&self, path: &Path) -> Result<(), String> {
        let receipt = read_json(path)?;
        let tools = json_member(receipt.object()?, "tools")?.array()?;
        let mut matches = tools.iter().filter_map(|tool| {
            let fields = tool.object().ok()?;
            (json_member(fields, "id").ok()?.string().ok()? == "ghc").then_some(fields)
        });
        let fields = matches
            .next()
            .ok_or_else(|| "native environment receipt has no GHC tool".to_owned())?;
        if matches.next().is_some()
            || json_member(fields, "executableSha256")?.string()? != self.executable_sha256
            || json_member(fields, "outputSha256")?.string()? != self.output_sha256
            || json_member(fields, "parsedVersion")?.string()? != self.parsed_version
        {
            return Err("native GHC authority differs from its environment receipt".to_owned());
        }
        self.revalidate()
    }
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .is_some_and(|argument| argument == "environment")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let command = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(usage)?;
    let options = Options::parse(&arguments[2..])?;
    match command {
        "collect" => collect_for_platform(
            ReleasePlatform::parse(&required_string(options.platform, "--platform")?)?,
            &required_path(options.external_inputs, "--external-inputs")?,
            &required_path(options.output, "--output")?,
        ),
        "assemble-set" => assemble_set(
            &required_path(options.input, "--input")?,
            &required_path(options.external_inputs, "--external-inputs")?,
            &required_path(options.output, "--output")?,
        ),
        "verify-set" => verify_set_command(
            &required_path(options.input, "--input")?,
            &required_path(options.external_inputs, "--external-inputs")?,
            &required_path(options.output, "--output")?,
        ),
        _ => Err(usage()),
    }
}

pub(crate) fn external_inputs_sha256(path: &Path) -> Result<String, String> {
    let lock = ExternalInputLock::read(path)?;
    domain_digest(EXTERNAL_INPUT_DOMAIN, &lock.json())
}

pub(crate) fn collect_for_platform(
    platform: ReleasePlatform,
    external_inputs: &Path,
    output: &Path,
) -> Result<String, String> {
    collect_for_platform_from_environment(
        platform,
        external_inputs,
        output,
        &ProcessEnvironment::from_process(),
    )
    .map(NativeEnvironmentCollection::summary)
}

pub(crate) fn collect_for_platform_from_environment(
    platform: ReleasePlatform,
    external_inputs: &Path,
    output: &Path,
    environment: &ProcessEnvironment,
) -> Result<NativeEnvironmentCollection, String> {
    let lock = ExternalInputLock::read(external_inputs)?;
    let external_inputs_sha256 = domain_digest(EXTERNAL_INPUT_DOMAIN, &lock.json())?;
    let runtime = GithubRuntime::from_process()?;
    let runner = runtime.runner.as_ref().ok_or_else(|| {
        "native environment collection requires GitHub runner identity".to_owned()
    })?;
    validate_runner(platform, runner)?;
    let deadline = Instant::now()
        .checked_add(COLLECTION_TIMEOUT)
        .ok_or_else(|| "native environment collection deadline overflowed".to_owned())?;
    let search = ExecutableSearchPath::from_environment(environment)?;
    let specs = tool_specs(platform, &lock);
    let mut receipts = Vec::new();
    for spec in specs {
        receipts.push(collect_tool(&search, &spec, deadline)?);
    }
    receipts.sort_by(|left, right| left.id.cmp(&right.id));
    let oracle_source_sha = lock
        .inputs
        .iter()
        .find(|input| input.id == "upstream-oracle-source")
        .and_then(|input| input.fields.get("commit"))
        .and_then(|value| value.string().ok())
        .ok_or_else(|| "external-input lock lacks upstream oracle source commit".to_owned())?;
    let receipt = object([
        ("architecture", string(std::env::consts::ARCH)),
        ("archiveImplementationProtocolVersion", number(1)),
        ("candidateExecutableSha256", JsonValue::Null),
        ("externalInputsSha256", string(&external_inputs_sha256)),
        (
            "githubHostedRunner",
            object([
                ("imageOs", option_string(runner.image_os.as_deref())),
                (
                    "imageVersion",
                    option_string(runner.image_version.as_deref()),
                ),
                ("runnerArchitecture", string(&runner.runner_architecture)),
                ("runnerOs", string(&runner.runner_os)),
            ]),
        ),
        ("kernelVersion", tool_version(&receipts, "kernel")),
        ("logicalPlatformId", string(platform.id())),
        ("operatingSystemName", string(std::env::consts::OS)),
        (
            "operatingSystemVersion",
            option_string(runner.image_version.as_deref()),
        ),
        ("oracleExecutableSha256", JsonValue::Null),
        ("oracleSourceSha", string(oracle_source_sha)),
        ("schemaVersion", number(1)),
        (
            "tools",
            JsonValue::Array(receipts.iter().map(ToolReceipt::json).collect()),
        ),
    ]);
    let bytes = write_json_new(output, &receipt)?;
    let digest = domain_digest_bytes(NATIVE_ENVIRONMENT_DOMAIN, &bytes);
    #[cfg(windows)]
    let ghc = {
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.id == "ghc")
            .ok_or_else(|| "Windows native environment omitted GHC authority".to_owned())?;
        let ghc = WindowsNativeGhcAuthority::from_receipt(receipt)?;
        ghc.require_receipt(output)?;
        ghc
    };
    Ok(NativeEnvironmentCollection {
        summary: format!("collected native environment {} as {digest}", platform.id()),
        #[cfg(windows)]
        ghc,
    })
}

#[cfg(windows)]
pub(crate) fn collect_windows_ghc_authority_for_integration(
    environment: &ProcessEnvironment,
    external_inputs: &Path,
    deadline: Instant,
) -> Result<WindowsNativeGhcAuthority, String> {
    let lock = ExternalInputLock::read(external_inputs)?;
    let spec = tool_specs(ReleasePlatform::WindowsX86_64, &lock)
        .into_iter()
        .find(|spec| spec.id == "ghc")
        .ok_or_else(|| "Windows native environment has no GHC specification".to_owned())?;
    let search = ExecutableSearchPath::from_environment(environment)?;
    WindowsNativeGhcAuthority::from_receipt(&collect_tool(&search, &spec, deadline)?)
}

#[cfg(windows)]
pub(crate) fn windows_native_ghc_authority_for_integration(
    external_inputs: &Path,
) -> Result<crate::WindowsNativeGhcIntegrationReceipt, String> {
    let deadline = Instant::now()
        .checked_add(COLLECTION_TIMEOUT)
        .ok_or_else(|| "Windows native GHC integration deadline overflowed".to_owned())?;
    let environment = ProcessEnvironment::from_process();
    let authority =
        collect_windows_ghc_authority_for_integration(&environment, external_inputs, deadline)?;
    authority.revalidate()?;
    let receipt = crate::WindowsNativeGhcIntegrationReceipt {
        parsed_version: authority.parsed_version().to_owned(),
        executable_sha256: authority.executable_sha256().to_owned(),
        output_sha256: authority.output_sha256().to_owned(),
    };
    authority.revalidate()?;
    Ok(receipt)
}

pub(crate) fn assemble_set(
    input: &Path,
    external_inputs: &Path,
    output: &Path,
) -> Result<String, String> {
    let lock = ExternalInputLock::read(external_inputs)?;
    let expected_external = domain_digest(EXTERNAL_INPUT_DOMAIN, &lock.json())?;
    let inventory = exact_receipt_inventory(input)?;
    let mut records = Vec::new();
    for platform in PLATFORMS {
        let path = inventory
            .get(platform.id())
            .ok_or_else(|| format!("native receipt inventory lacks {}", platform.id()))?;
        let bytes = read_regular(path)?;
        let receipt = read_json(path)?;
        let expected_tools = expected_tool_inventory(platform, &lock)?;
        validate_receipt(
            &receipt,
            platform,
            &expected_external,
            Some(&expected_tools),
        )?;
        records.push(object([
            (
                "nativeEnvironmentSha256",
                string(&domain_digest_bytes(NATIVE_ENVIRONMENT_DOMAIN, &bytes)),
            ),
            ("platformId", string(platform.id())),
            ("receipt", receipt),
        ]));
    }
    let set = object([
        ("externalInputsSha256", string(&expected_external)),
        ("receipts", JsonValue::Array(records)),
        ("schemaVersion", number(1)),
    ]);
    let bytes = write_json_new(output, &set)?;
    let digest = domain_digest_bytes(NATIVE_ENVIRONMENT_SET_DOMAIN, &bytes);
    Ok(format!("assembled native environment set {digest}"))
}

fn verify_set_command(
    input: &Path,
    external_inputs: &Path,
    output: &Path,
) -> Result<String, String> {
    let outcome = verify_set(input, external_inputs);
    let report = match &outcome {
        Ok(digest) => object([
            ("admitted", JsonValue::Bool(true)),
            ("diagnostic", JsonValue::Null),
            ("nativeEnvironmentSetSha256", string(digest)),
            ("schemaVersion", number(1)),
            ("state", string("verified")),
        ]),
        Err(error) => object([
            ("admitted", JsonValue::Bool(false)),
            (
                "diagnostic",
                object([
                    ("code", string("native-environment.set.rejected")),
                    ("message", string(&bounded_message(error))),
                ]),
            ),
            ("nativeEnvironmentSetSha256", JsonValue::Null),
            ("schemaVersion", number(1)),
            ("state", string("rejected")),
        ]),
    };
    write_json_new(output, &report)?;
    let digest = outcome?;
    Ok(format!("verified native environment set {digest}"))
}

pub(crate) fn verify_set(input: &Path, external_inputs: &Path) -> Result<String, String> {
    let lock = ExternalInputLock::read(external_inputs)?;
    let expected_external = domain_digest(EXTERNAL_INPUT_DOMAIN, &lock.json())?;
    let bytes = read_regular(input)?;
    let set = read_json(input)?;
    let fields = set.object()?;
    require_json_keys(
        fields,
        &["externalInputsSha256", "receipts", "schemaVersion"],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 1
        || json_member(fields, "externalInputsSha256")?.string()? != expected_external
    {
        return Err("native environment set schema or external-input binding differs".to_owned());
    }
    let records = json_member(fields, "receipts")?.array()?;
    if records.len() != PLATFORMS.len() {
        return Err("native environment set receipt count differs".to_owned());
    }
    for (record, platform) in records.iter().zip(PLATFORMS) {
        let record = record.object()?;
        require_json_keys(
            record,
            &["nativeEnvironmentSha256", "platformId", "receipt"],
        )?;
        if json_member(record, "platformId")?.string()? != platform.id() {
            return Err("native environment set platform ordering differs".to_owned());
        }
        let receipt = json_member(record, "receipt")?;
        let expected_tools = expected_tool_inventory(platform, &lock)?;
        validate_receipt(receipt, platform, &expected_external, Some(&expected_tools))?;
        let receipt_bytes = canonical_json_bytes(receipt)?;
        let expected_digest = domain_digest_bytes(NATIVE_ENVIRONMENT_DOMAIN, &receipt_bytes);
        if json_member(record, "nativeEnvironmentSha256")?.string()? != expected_digest {
            return Err(format!(
                "native receipt digest differs for {}",
                platform.id()
            ));
        }
    }
    Ok(domain_digest_bytes(NATIVE_ENVIRONMENT_SET_DOMAIN, &bytes))
}

pub(crate) fn verify_receipt(
    path: &Path,
    platform: ReleasePlatform,
    expected_external_inputs: &str,
) -> Result<String, String> {
    let bytes = read_regular(path)?;
    let receipt = read_json(path)?;
    validate_receipt(&receipt, platform, expected_external_inputs, None)?;
    Ok(domain_digest_bytes(NATIVE_ENVIRONMENT_DOMAIN, &bytes))
}

fn validate_receipt(
    receipt: &JsonValue,
    platform: ReleasePlatform,
    external_inputs: &str,
    expected_tools: Option<&BTreeMap<String, Option<String>>>,
) -> Result<(), String> {
    let fields = receipt.object()?;
    require_json_keys(
        fields,
        &[
            "architecture",
            "archiveImplementationProtocolVersion",
            "candidateExecutableSha256",
            "externalInputsSha256",
            "githubHostedRunner",
            "kernelVersion",
            "logicalPlatformId",
            "operatingSystemName",
            "operatingSystemVersion",
            "oracleExecutableSha256",
            "oracleSourceSha",
            "schemaVersion",
            "tools",
        ],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 1
        || json_member(fields, "archiveImplementationProtocolVersion")?.number()? != 1
        || json_member(fields, "logicalPlatformId")?.string()? != platform.id()
        || json_member(fields, "externalInputsSha256")?.string()? != external_inputs
    {
        return Err(format!(
            "native receipt binding differs for {}",
            platform.id()
        ));
    }
    let tools = json_member(fields, "tools")?.array()?;
    if tools.is_empty() {
        return Err(format!("native receipt has no tools for {}", platform.id()));
    }
    let mut prior = None::<String>;
    let mut actual_tools = BTreeMap::new();
    for tool in tools {
        let fields = tool.object()?;
        require_json_keys(
            fields,
            &[
                "executableSha256",
                "id",
                "lockVersion",
                "outputSha256",
                "parsedVersion",
            ],
        )?;
        let id = json_member(fields, "id")?.string()?.to_owned();
        if prior.as_ref().is_some_and(|prior| prior >= &id) {
            return Err("native tool receipt inventory is not strictly ordered".to_owned());
        }
        prior = Some(id.clone());
        let lock_version = match json_member(fields, "lockVersion")? {
            JsonValue::Null => None,
            value => Some(value.string()?.to_owned()),
        };
        let parsed_version = json_member(fields, "parsedVersion")?.string()?;
        if lock_version
            .as_ref()
            .is_some_and(|version| !locked_tool_version_matches(&id, parsed_version, version))
        {
            return Err("native tool receipt version differs from its lock version".to_owned());
        }
        actual_tools.insert(id, lock_version);
        require_digest(
            json_member(fields, "executableSha256")?.string()?,
            "native executable digest",
        )?;
        require_digest(
            json_member(fields, "outputSha256")?.string()?,
            "native tool output digest",
        )?;
    }
    if expected_tools.is_some_and(|expected| expected != &actual_tools) {
        return Err(format!(
            "native tool receipt inventory differs for {}",
            platform.id()
        ));
    }
    Ok(())
}

pub(crate) fn fuzz_parse_receipt(receipt: &JsonValue) -> Result<(), String> {
    let fields = receipt.object()?;
    let platform = ReleasePlatform::parse(json_member(fields, "logicalPlatformId")?.string()?)?;
    let external_inputs = json_member(fields, "externalInputsSha256")?.string()?;
    require_digest(external_inputs, "native external-input digest")?;
    validate_receipt(receipt, platform, external_inputs, None)
}

impl ToolReceipt {
    fn json(&self) -> JsonValue {
        object([
            ("executableSha256", string(&self.executable_sha256)),
            ("id", string(&self.id)),
            ("lockVersion", option_string(self.lock_version.as_deref())),
            ("outputSha256", string(&self.output_sha256)),
            ("parsedVersion", string(&self.parsed_version)),
        ])
    }
}

fn collect_tool(
    search: &ExecutableSearchPath,
    spec: &ToolSpec,
    deadline: Instant,
) -> Result<ToolReceipt, String> {
    if Instant::now() >= deadline {
        return Err("native environment absolute deadline expired".to_owned());
    }
    let resolved = resolve_tool(search, &spec.resolver, deadline)?;
    let executable = resolved.executable;
    let metadata = std::fs::symlink_metadata(&executable)
        .map_err(|error| format!("cannot inspect native tool {}: {error}", spec.id))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_TOOL_BYTES {
        return Err(format!(
            "native tool {} is not one bounded regular file",
            spec.id
        ));
    }
    let executable_sha256 = hell_testkit::sha256_file(&executable)
        .map_err(|error| format!("cannot hash native tool {}: {error}", spec.id))?
        .hex();
    let execution_deadline = Instant::now()
        .checked_add(TOOL_TIMEOUT)
        .unwrap_or(deadline)
        .min(deadline);
    let (progress, _receiver) = hell_testkit::SupervisedProgressObserver::bounded(1);
    let result = CommandSpec::new(executable.clone(), TOOL_TIMEOUT)
        .arguments(spec.arguments.iter().copied())
        .release_candidate_environment()
        .run_until(execution_deadline, deadline, progress)
        .map_err(|error| format!("native tool {} failed to execute: {error}", spec.id))?;
    if result.timed_out
        || !result.status.success()
        || result.stdout_truncated
        || result.stderr_truncated
        || (result.termination.forced && !result.termination.reaped)
    {
        return Err(format!(
            "native tool {} did not complete cleanly: status={} timedOut={} stdoutTruncated={} stderrTruncated={} forced={} reaped={}",
            spec.id,
            result.status,
            result.timed_out,
            result.stdout_truncated,
            result.stderr_truncated,
            result.termination.forced,
            result.termination.reaped
        ));
    }
    let stdout_bytes = result.stdout.len();
    let mut output = result.stdout;
    output.push(0);
    output.extend_from_slice(&result.stderr);
    let output_sha256 = hell_testkit::sha256_bytes(&output).hex();
    let parsed_version = parse_tool_output(
        spec.id,
        spec.output_parser,
        &output[..stdout_bytes],
        &output[stdout_bytes + 1..],
    )?;
    if spec
        .expected_version
        .as_ref()
        .is_some_and(|expected| !locked_tool_version_matches(spec.id, &parsed_version, expected))
    {
        return Err(format!(
            "native tool {} differs from external-input lock",
            spec.id
        ));
    }
    let after = hell_testkit::sha256_file(&executable)
        .map_err(|error| format!("cannot rehash native tool {}: {error}", spec.id))?
        .hex();
    if after != executable_sha256 || Instant::now() >= deadline {
        return Err(format!(
            "native tool {} changed or exceeded its deadline",
            spec.id
        ));
    }
    #[cfg(windows)]
    if let Some(discovery) = &resolved.msvc_discovery {
        discovery.validate()?;
    }
    Ok(ToolReceipt {
        id: spec.id.to_owned(),
        executable_sha256,
        output_sha256,
        parsed_version,
        lock_version: spec.expected_version.clone(),
        #[cfg(windows)]
        authority: Some(
            hell_testkit::BoundProgramInvocation::new_until(
                executable.clone(),
                executable.clone(),
                deadline,
            )
            .map_err(|error| format!("cannot retain native tool {}: {error}", spec.id))?,
        ),
        #[cfg(windows)]
        resolved_executable: executable,
    })
}

fn parse_tool_output(
    id: &str,
    parser: ToolOutputParser,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<String, String> {
    match parser {
        ToolOutputParser::FirstNonEmptyLine => parse_version_output(id, stdout, stderr),
        ToolOutputParser::ExactNumericVersion => {
            parse_exact_numeric_version_output(id, stdout, stderr)
        }
        ToolOutputParser::MsvcCompilerBanner => parse_msvc_compiler_banner_output(stdout, stderr),
    }
}

fn parse_exact_numeric_version_output(
    id: &str,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<String, String> {
    let stdout =
        std::str::from_utf8(stdout).map_err(|_| format!("native tool {id} output is not UTF-8"))?;
    let stderr =
        std::str::from_utf8(stderr).map_err(|_| format!("native tool {id} output is not UTF-8"))?;
    let mut values = stdout
        .split(['\r', '\n'])
        .chain(stderr.split(['\r', '\n']))
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let value = values
        .next()
        .ok_or_else(|| format!("native tool {id} produced no numeric version"))?;
    if values.next().is_some() || normalized_numeric_version(value).is_none() {
        return Err(format!(
            "native tool {id} output is not one exact numeric version"
        ));
    }
    Ok(value.to_owned())
}

fn normalized_numeric_version(value: &str) -> Option<&str> {
    (value == value.trim()
        && !value.is_empty()
        && value.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        }))
    .then_some(value)
}

fn locked_tool_version_matches(id: &str, parsed: &str, expected: &str) -> bool {
    if id == "ghc" {
        return normalized_numeric_version(parsed) == Some(expected)
            && normalized_numeric_version(expected).is_some();
    }
    parsed
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '+'))
        })
        .any(|field| field == expected)
}

fn parse_version_output(id: &str, stdout: &[u8], stderr: &[u8]) -> Result<String, String> {
    let stdout =
        std::str::from_utf8(stdout).map_err(|_| format!("native tool {id} output is not UTF-8"))?;
    let stderr =
        std::str::from_utf8(stderr).map_err(|_| format!("native tool {id} output is not UTF-8"))?;
    let line = stdout
        .split(['\r', '\n'])
        .chain(stderr.split(['\r', '\n']))
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| format!("native tool {id} produced no version line"))?;
    if line.len() > 1024 || line.chars().any(char::is_control) {
        return Err(format!("native tool {id} version line is invalid"));
    }
    Ok(line.to_owned())
}

#[derive(Default)]
struct MsvcBannerSelection {
    candidate_count: usize,
    invalid_candidate_count: usize,
    selected: Option<String>,
    evidence: Vec<String>,
}

fn parse_msvc_compiler_banner_output(stdout: &[u8], stderr: &[u8]) -> Result<String, String> {
    let stdout =
        std::str::from_utf8(stdout).map_err(|_| "MSVC compiler stdout is not UTF-8".to_owned())?;
    let stderr =
        std::str::from_utf8(stderr).map_err(|_| "MSVC compiler stderr is not UTF-8".to_owned())?;
    let mut selection = MsvcBannerSelection::default();
    observe_msvc_banner_lines("stdout", stdout, &mut selection);
    observe_msvc_banner_lines("stderr", stderr, &mut selection);
    if selection.candidate_count == 1 && selection.invalid_candidate_count == 0 {
        return selection
            .selected
            .ok_or_else(|| "MSVC compiler banner selection lost its candidate".to_owned());
    }
    Err(msvc_banner_selection_error(&selection, stdout, stderr))
}

fn observe_msvc_banner_lines(stream: &str, text: &str, selection: &mut MsvcBannerSelection) {
    for (index, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if !line.starts_with(MSVC_BANNER_PREFIX) {
            continue;
        }
        selection.candidate_count = selection.candidate_count.saturating_add(1);
        let valid =
            !raw_line.chars().any(char::is_control) && validate_msvc_compiler_banner(line).is_ok();
        if valid {
            selection.selected = Some(line.to_owned());
        } else {
            selection.invalid_candidate_count = selection.invalid_candidate_count.saturating_add(1);
        }
        if selection.evidence.len() < MSVC_DIAGNOSTIC_CANDIDATE_LIMIT {
            selection.evidence.push(format!(
                "{stream}:{}=\"{}\"",
                index + 1,
                bounded_escaped_msvc_line(raw_line)
            ));
        }
    }
}

fn msvc_banner_selection_error(
    selection: &MsvcBannerSelection,
    stdout: &str,
    stderr: &str,
) -> String {
    let omitted = selection
        .candidate_count
        .saturating_sub(selection.evidence.len());
    format!(
        "MSVC compiler version banner selection failed: candidateCount={} invalidCandidateCount={} candidates=[{}] omittedCandidates={} stdoutFirst={} stderrFirst={}",
        selection.candidate_count,
        selection.invalid_candidate_count,
        selection.evidence.join(", "),
        omitted,
        first_msvc_line_evidence("stdout", stdout),
        first_msvc_line_evidence("stderr", stderr)
    )
}

fn first_msvc_line_evidence(stream: &str, text: &str) -> String {
    text.lines()
        .enumerate()
        .find_map(|(index, raw_line)| {
            let line = raw_line.trim();
            (!line.is_empty()).then(|| {
                format!(
                    "{stream}:{}=\"{}\"",
                    index + 1,
                    bounded_escaped_msvc_line(raw_line)
                )
            })
        })
        .unwrap_or_else(|| "none".to_owned())
}

fn bounded_escaped_msvc_line(line: &str) -> String {
    let mut escaped = String::new();
    for character in line.chars() {
        let fragment = character.escape_default().to_string();
        if escaped.len().saturating_add(fragment.len()) > MSVC_DIAGNOSTIC_LINE_LIMIT {
            escaped.push_str("<truncated>");
            break;
        }
        escaped.push_str(&fragment);
    }
    escaped
}

fn validate_msvc_compiler_banner(banner: &str) -> Result<(), String> {
    let version = banner
        .strip_prefix(MSVC_BANNER_PREFIX)
        .and_then(|value| value.strip_suffix(MSVC_BANNER_SUFFIX))
        .ok_or_else(|| "MSVC compiler version banner is invalid".to_owned())?;
    if banner.len() > 1024
        || banner.chars().any(char::is_control)
        || version.is_empty()
        || version.starts_with('.')
        || version.ends_with('.')
        || version.split('.').any(str::is_empty)
        || !version
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
    {
        return Err("MSVC compiler version banner is invalid".to_owned());
    }
    Ok(())
}

fn tool_version(receipts: &[ToolReceipt], id: &str) -> JsonValue {
    receipts
        .iter()
        .find(|receipt| receipt.id == id)
        .map_or(JsonValue::Null, |receipt| string(&receipt.parsed_version))
}

fn tool_specs(platform: ReleasePlatform, lock: &ExternalInputLock) -> Vec<ToolSpec> {
    let mut specs = vec![
        ToolSpec {
            id: "cargo",
            resolver: ToolResolver::SearchPath("cargo"),
            arguments: &["-Vv"],
            output_parser: ToolOutputParser::FirstNonEmptyLine,
            expected_version: None,
        },
        ToolSpec {
            id: "rustc",
            resolver: ToolResolver::SearchPath("rustc"),
            arguments: &["-vV"],
            output_parser: ToolOutputParser::FirstNonEmptyLine,
            expected_version: None,
        },
    ];
    match platform {
        ReleasePlatform::LinuxX86_64 => specs.extend([
            ToolSpec {
                id: "kernel",
                resolver: ToolResolver::SearchPath("uname"),
                arguments: &["-srvmo"],
                output_parser: ToolOutputParser::FirstNonEmptyLine,
                expected_version: None,
            },
            ToolSpec {
                id: "linker",
                resolver: ToolResolver::SearchPath("cc"),
                arguments: &["--version"],
                output_parser: ToolOutputParser::FirstNonEmptyLine,
                expected_version: None,
            },
        ]),
        ReleasePlatform::MacosAarch64 => specs.extend([
            ToolSpec {
                id: "apple-sdk",
                resolver: ToolResolver::SearchPath("xcrun"),
                arguments: &["--show-sdk-version"],
                output_parser: ToolOutputParser::FirstNonEmptyLine,
                expected_version: None,
            },
            ToolSpec {
                id: "kernel",
                resolver: ToolResolver::SearchPath("uname"),
                arguments: &["-srvmo"],
                output_parser: ToolOutputParser::FirstNonEmptyLine,
                expected_version: None,
            },
            ToolSpec {
                id: "linker",
                resolver: ToolResolver::SearchPath("clang"),
                arguments: &["--version"],
                output_parser: ToolOutputParser::FirstNonEmptyLine,
                expected_version: None,
            },
        ]),
        ReleasePlatform::WindowsX86_64 => specs.extend([
            ToolSpec {
                id: "kernel",
                resolver: ToolResolver::SearchPath("rustc"),
                arguments: &["-vV"],
                output_parser: ToolOutputParser::FirstNonEmptyLine,
                expected_version: None,
            },
            ToolSpec {
                id: "msvc-toolset",
                resolver: ToolResolver::MsvcToolset,
                arguments: MSVC_TOOLSET_PROBE_ARGUMENTS,
                output_parser: ToolOutputParser::MsvcCompilerBanner,
                expected_version: None,
            },
        ]),
    }
    for (id, executable, arguments) in [
        ("stack", "stack", &["--numeric-version"][..]),
        ("ghc", "ghc", &["--numeric-version"][..]),
        ("llvm", "llvm-ar", &["--version"][..]),
        ("cargo-deny", "cargo-deny", &["--version"][..]),
    ] {
        if let Some(input) = lock.input_for_tool(id, platform) {
            specs.push(ToolSpec {
                id,
                resolver: ToolResolver::SearchPath(executable),
                arguments,
                output_parser: if id == "ghc" {
                    ToolOutputParser::ExactNumericVersion
                } else {
                    ToolOutputParser::FirstNonEmptyLine
                },
                expected_version: input
                    .fields
                    .get("version")
                    .and_then(|value| value.string().ok())
                    .map(str::to_owned),
            });
        }
    }
    specs
}

fn expected_tool_inventory(
    platform: ReleasePlatform,
    lock: &ExternalInputLock,
) -> Result<BTreeMap<String, Option<String>>, String> {
    let mut inventory = BTreeMap::new();
    for spec in tool_specs(platform, lock) {
        if inventory
            .insert(spec.id.to_owned(), spec.expected_version)
            .is_some()
        {
            return Err(format!(
                "native tool specification inventory contains duplicate {}",
                spec.id
            ));
        }
    }
    Ok(inventory)
}

fn validate_runner(platform: ReleasePlatform, runner: &RunnerIdentity) -> Result<(), String> {
    let (expected_os, expected_arch) = platform.runner();
    if runner.runner_os != expected_os || runner.runner_architecture != expected_arch {
        return Err(format!(
            "GitHub runner identity differs from logical platform {}",
            platform.id()
        ));
    }
    Ok(())
}

impl ExternalInputLock {
    fn read(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect external-input lock: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_LOCK_BYTES
        {
            return Err("external-input lock is not one bounded regular file".to_owned());
        }
        let bytes = read_regular(path)?;
        if !bytes.ends_with(b"\n") {
            return Err("external-input lock lacks its trailing newline".to_owned());
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "external-input lock is not UTF-8".to_owned())?;
        let document = TomlDocument::parse(text)?;
        document.require_table_inventory(&[""])?;
        document.require_array_inventory(&["input"])?;
        let root = document.table("")?;
        require_keys(root, &["lock-id", "schema-version"])?;
        if integer(member(root, "schema-version")?)? != 1 {
            return Err("unsupported external-input lock schema".to_owned());
        }
        let lock_id = quoted(member(root, "lock-id")?)?;
        require_identifier(&lock_id, "external-input lock ID")?;
        let mut ids = BTreeSet::new();
        let mut inputs = Vec::new();
        for table in document.arrays("input")? {
            require_allowed_keys(
                table,
                &[
                    "acquisition-phase",
                    "cache-permitted",
                    "commit",
                    "expected-filename",
                    "id",
                    "kind",
                    "maximum-compressed-bytes",
                    "maximum-expanded-bytes",
                    "media-type",
                    "package",
                    "platform",
                    "platforms",
                    "repository",
                    "sha256",
                    "timeout-seconds",
                    "toolchain",
                    "version",
                ],
            )?;
            for required in ["acquisition-phase", "id", "kind"] {
                if !table.contains_key(required) {
                    return Err(format!("external input lacks {required}"));
                }
            }
            let id = quoted(member(table, "id")?)?;
            require_identifier(&id, "external input ID")?;
            if !ids.insert(id.clone()) {
                return Err(format!("duplicate external input {id}"));
            }
            let kind = quoted(member(table, "kind")?)?;
            let acquisition_phase = quoted(member(table, "acquisition-phase")?)?;
            let platforms = table
                .get("platforms")
                .map(|value| string_array(value))
                .transpose()?
                .unwrap_or_default();
            let mut fields = BTreeMap::new();
            for (key, value) in table {
                let json = match key.as_str() {
                    "cache-permitted" => JsonValue::Bool(boolean(value)?),
                    "maximum-compressed-bytes" | "maximum-expanded-bytes" | "timeout-seconds" => {
                        number(integer(value)?)
                    }
                    "platforms" => JsonValue::Array(
                        string_array(value)?
                            .iter()
                            .map(|value| string(value))
                            .collect(),
                    ),
                    _ => string(&quoted(value)?),
                };
                fields.insert(key.clone(), json);
            }
            validate_external_input(&id, &kind, &fields)?;
            inputs.push(ExternalInput {
                id,
                kind,
                acquisition_phase,
                platforms,
                fields,
            });
        }
        Ok(Self { lock_id, inputs })
    }

    fn json(&self) -> JsonValue {
        object([
            (
                "inputs",
                JsonValue::Array(
                    self.inputs
                        .iter()
                        .map(|input| JsonValue::Object(input.fields.clone()))
                        .collect(),
                ),
            ),
            ("lockId", string(&self.lock_id)),
            ("schemaVersion", number(1)),
        ])
    }

    fn input_for_tool(&self, id: &str, platform: ReleasePlatform) -> Option<&ExternalInput> {
        self.inputs.iter().find(|input| {
            input.id == id
                && matches!(input.kind.as_str(), "tool-version" | "cargo-package")
                && input.acquisition_phase == "native-platform"
                && (input.platforms.is_empty()
                    || input.platforms.iter().any(|value| value == platform.id()))
        })
    }
}

fn validate_external_input(
    id: &str,
    kind: &str,
    fields: &BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let required: &[&str] = match kind {
        "git-commit" => &["commit", "repository"],
        "https-file" => &[
            "expected-filename",
            "maximum-compressed-bytes",
            "maximum-expanded-bytes",
            "media-type",
            "sha256",
            "timeout-seconds",
        ],
        "tool-version" => &["version"],
        "cargo-package" => &["package", "version"],
        _ => return Err(format!("external input {id} has unsupported kind {kind}")),
    };
    if required.iter().any(|key| !fields.contains_key(*key)) {
        return Err(format!("external input {id} lacks kind-specific fields"));
    }
    if let Some(value) = fields.get("sha256") {
        require_digest(value.string()?, "external-input digest")?;
    }
    for key in [
        "maximum-compressed-bytes",
        "maximum-expanded-bytes",
        "timeout-seconds",
    ] {
        if fields
            .get(key)
            .is_some_and(|value| value.number().ok().is_some_and(|value| value == 0))
        {
            return Err(format!("external input {id} has a zero bound"));
        }
    }
    Ok(())
}

fn exact_receipt_inventory(root: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut inventory = BTreeMap::new();
    let entries = std::fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate native receipt root: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read native receipt entry: {error}"))?;
        let metadata = entry
            .file_type()
            .map_err(|error| format!("cannot inspect native receipt entry: {error}"))?;
        if !metadata.is_dir() || metadata.is_symlink() {
            return Err("native receipt root contains an unexpected non-directory".to_owned());
        }
        let platform = entry
            .file_name()
            .into_string()
            .map_err(|_| "native receipt platform name is not UTF-8".to_owned())?;
        ReleasePlatform::parse(&platform)?;
        let mut children = std::fs::read_dir(entry.path())
            .map_err(|error| format!("cannot enumerate native receipt platform: {error}"))?;
        let receipt = children
            .next()
            .transpose()
            .map_err(|error| format!("cannot read native receipt file: {error}"))?
            .ok_or_else(|| format!("native receipt directory {platform} is empty"))?;
        if children.next().is_some()
            || receipt.file_name() != OsStr::new("native-environment.json")
            || !receipt
                .file_type()
                .map_err(|error| format!("cannot inspect native receipt file: {error}"))?
                .is_file()
        {
            return Err(format!(
                "native receipt directory {platform} inventory differs"
            ));
        }
        inventory.insert(platform, receipt.path());
    }
    if inventory.len() != PLATFORMS.len() {
        return Err("native receipt platform inventory differs".to_owned());
    }
    Ok(inventory)
}

fn domain_digest(domain: &[u8], value: &JsonValue) -> Result<String, String> {
    Ok(domain_digest_bytes(domain, &canonical_json_bytes(value)?))
}

fn domain_digest_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(bytes);
    hell_testkit::sha256_bytes(&input).hex()
}

fn option_string(value: Option<&str>) -> JsonValue {
    value.map_or(JsonValue::Null, string)
}

fn bounded_message(value: &str) -> String {
    value.chars().take(4096).collect()
}

fn require_json_keys(
    values: &BTreeMap<String, JsonValue>,
    expected: &[&str],
) -> Result<(), String> {
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(format!("JSON key inventory differs: {observed:?}"));
    }
    Ok(())
}

#[derive(Default)]
struct Options {
    external_inputs: Option<PathBuf>,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    platform: Option<String>,
}

impl Options {
    fn parse(arguments: &[OsString]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            let flag = arguments[index]
                .to_str()
                .ok_or_else(|| "environment option name must be UTF-8".to_owned())?;
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            index += 1;
            match flag {
                "--external-inputs" => set_path(&mut options.external_inputs, value, flag)?,
                "--input" => set_path(&mut options.input, value, flag)?,
                "--output" => set_path(&mut options.output, value, flag)?,
                "--platform" => {
                    if options.platform.is_some() {
                        return Err(format!("{flag} was provided more than once"));
                    }
                    options.platform = Some(
                        value
                            .to_str()
                            .ok_or_else(|| "platform ID must be UTF-8".to_owned())?
                            .to_owned(),
                    );
                }
                _ => return Err(format!("unknown environment option {flag:?}")),
            }
        }
        Ok(options)
    }
}

fn set_path(target: &mut Option<PathBuf>, value: &OsString, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}

fn required_path(value: Option<PathBuf>, flag: &str) -> Result<PathBuf, String> {
    value.ok_or_else(|| format!("environment command requires {flag}"))
}

fn required_string(value: Option<String>, flag: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("environment command requires {flag}"))
}

fn usage() -> String {
    "usage: hell-ci environment collect --platform ID --external-inputs PATH --output PATH | assemble-set|verify-set --input PATH --external-inputs PATH --output PATH".to_owned()
}
