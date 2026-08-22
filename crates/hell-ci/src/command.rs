#[cfg(target_os = "macos")]
use std::cell::Cell;
use std::cell::RefCell;
#[cfg(unix)]
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
#[cfg(any(unix, windows))]
use std::io::Read as _;
use std::io::Write as _;
#[cfg(any(unix, windows))]
use std::io::{Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "macos")]
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

#[cfg(any(unix, windows))]
use hell_digest::Sha256;
#[cfg(target_os = "macos")]
use hell_testkit::sha256_bytes;
use hell_testkit::{
    BoundProgramInvocation, Digest, SupervisedProgressObserver, run_supervised_command,
    run_supervised_command_until, run_supervised_command_with_bound_program,
    run_supervised_command_with_bound_program_until, sha256_file,
};

#[cfg(unix)]
static CARGO_MULTICALL_VERIFIER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: OsString,
    pub arguments: Vec<OsString>,
    pub current_directory: Option<PathBuf>,
    pub environment: Vec<(OsString, OsString)>,
    pub clear_environment: bool,
    pub process_scope: ProcessScope,
    pub timeout: Duration,
    canonical_executable_identity: Option<PathBuf>,
    invocation_name: Option<OsString>,
    program_resolution_error: Option<String>,
    native_toolchain: Option<Arc<BoundNativeToolchain>>,
    #[cfg(target_os = "macos")]
    native_toolchain_query_deadline: Option<Instant>,
    #[cfg(target_os = "macos")]
    native_archiver: Option<BoundNativeArchiver>,
    #[cfg(target_os = "macos")]
    native_archiver_deadlines: Option<(Instant, Instant)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCargoExecutable {
    invocation_path: PathBuf,
    canonical_identity: PathBuf,
    invocation_name: OsString,
}

impl ResolvedCargoExecutable {
    pub(crate) fn invocation_path(&self) -> &Path {
        &self.invocation_path
    }

    pub(crate) fn canonical_identity(&self) -> &Path {
        &self.canonical_identity
    }
}

#[cfg(windows)]
#[derive(Clone)]
pub(crate) struct WindowsBoundFileIdentity {
    _guard: Arc<fs::File>,
    handle: Arc<same_file::Handle>,
    canonical: PathBuf,
    size: u64,
    sha256: Digest,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsFileIdentityPhase {
    ResolvedExecutable,
    ResolvedExecutableRevalidation,
    ToolchainSourceBinding,
    ToolchainSourceRevalidation,
    StagedToolchainBinding,
    StagedToolchainPostSeal,
}

#[cfg(windows)]
impl WindowsFileIdentityPhase {
    fn label(self) -> &'static str {
        match self {
            Self::ResolvedExecutable => "resolved-executable",
            Self::ResolvedExecutableRevalidation => "resolved-executable-revalidation",
            Self::ToolchainSourceBinding => "toolchain-source-binding",
            Self::ToolchainSourceRevalidation => "toolchain-source-revalidation",
            Self::StagedToolchainBinding => "staged-toolchain-binding",
            Self::StagedToolchainPostSeal => "staged-toolchain-post-seal",
        }
    }

    fn follows_dacl_seal(self) -> bool {
        self == Self::StagedToolchainPostSeal
    }
}

#[cfg(windows)]
fn bounded_windows_identity_path(path: &Path) -> String {
    const LIMIT: usize = 240;

    let mut bounded = String::new();
    let mut bytes = 0;
    for character in path.to_string_lossy().chars() {
        let character = if character.is_control() {
            '?'
        } else {
            character
        };
        if bytes + character.len_utf8() > LIMIT {
            bounded.push_str("...");
            break;
        }
        bounded.push(character);
        bytes += character.len_utf8();
    }
    bounded
}

#[cfg(windows)]
impl std::fmt::Debug for WindowsBoundFileIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowsBoundFileIdentity")
            .field("handle", &self.handle)
            .field("canonical", &self.canonical)
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl PartialEq for WindowsBoundFileIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
            && self.canonical == other.canonical
            && self.size == other.size
            && self.sha256 == other.sha256
    }
}

#[cfg(windows)]
impl Eq for WindowsBoundFileIdentity {}

#[cfg(windows)]
impl WindowsBoundFileIdentity {
    pub(crate) fn bind(path: &Path) -> Result<Self, String> {
        Self::bind_until(
            path,
            Instant::now()
                .checked_add(Duration::from_secs(30 * 60))
                .unwrap_or_else(Instant::now),
        )
    }

    pub(crate) fn bind_until(path: &Path, deadline: Instant) -> Result<Self, String> {
        Self::bind_until_at(
            path,
            deadline,
            WindowsFileIdentityPhase::ResolvedExecutable,
            path.file_name().map(Path::new).unwrap_or(path),
        )
    }

    pub(crate) fn bind_until_at(
        path: &Path,
        deadline: Instant,
        phase: WindowsFileIdentityPhase,
        diagnostic_path: &Path,
    ) -> Result<Self, String> {
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        let follows_dacl_seal = phase.follows_dacl_seal();
        let phase = phase.label();
        let diagnostic_path = bounded_windows_identity_path(diagnostic_path);
        let guard = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|error| {
                format!(
                    "cannot lock Windows file identity: phase={} path={} access=read \
                     share=read daclSealed={} osCode={:?}: {error}",
                    phase,
                    diagnostic_path,
                    follows_dacl_seal,
                    error.raw_os_error(),
                )
            })?;
        let metadata = guard.metadata().map_err(|error| {
            format!(
                "cannot inspect locked Windows file: phase={phase} path={diagnostic_path}: {error}"
            )
        })?;
        if !metadata.is_file() {
            return Err(format!(
                "Windows file identity is not regular: phase={phase} path={diagnostic_path}"
            ));
        }
        let canonical = fs::canonicalize(path).map_err(|error| {
            format!(
                "cannot canonicalize locked Windows file: phase={phase} path={diagnostic_path}: \
                 {error}"
            )
        })?;
        let sha256 = hell_testkit::sha256_retained_windows_file_until(&guard, deadline).map_err(
            |error| {
                format!(
                    "cannot hash locked Windows file: phase={phase} path={diagnostic_path}: {error}"
                )
            },
        )?;
        Ok(Self {
            _guard: Arc::new(guard),
            handle: Arc::new(same_file::Handle::from_path(&canonical).map_err(|error| {
                format!(
                    "cannot bind safe Windows file handle: phase={phase} \
                         path={diagnostic_path}: {error}"
                )
            })?),
            canonical,
            size: metadata.len(),
            sha256,
        })
    }

    pub(crate) fn revalidate(&self, path: &Path) -> Result<(), String> {
        if Self::bind(path)? != *self {
            return Err("Windows file identity changed before use".to_owned());
        }
        Ok(())
    }

    pub(crate) fn revalidate_until(&self, path: &Path, deadline: Instant) -> Result<(), String> {
        self.revalidate_until_at(
            path,
            deadline,
            WindowsFileIdentityPhase::ResolvedExecutableRevalidation,
            path.file_name().map(Path::new).unwrap_or(path),
        )
    }

    pub(crate) fn revalidate_until_at(
        &self,
        path: &Path,
        deadline: Instant,
        phase: WindowsFileIdentityPhase,
        diagnostic_path: &Path,
    ) -> Result<(), String> {
        if Self::bind_until_at(path, deadline, phase, diagnostic_path)? != *self {
            return Err(format!(
                "Windows file identity changed before use: phase={} path={}",
                phase.label(),
                bounded_windows_identity_path(diagnostic_path),
            ));
        }
        Ok(())
    }

    pub(crate) fn copy_to_new_until(
        &self,
        destination: &Path,
        deadline: Instant,
        diagnostic_path: &Path,
    ) -> Result<(), String> {
        let diagnostic_path = bounded_windows_identity_path(diagnostic_path);
        let mut source = self._guard.as_ref();
        source.seek(SeekFrom::Start(0)).map_err(|error| {
            format!(
                "cannot rewind retained Windows toolchain source: phase=toolchain-retained-copy \
                 path={diagnostic_path}: {error}"
            )
        })?;
        let mut destination = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| {
                format!(
                    "cannot create staged Windows toolchain file: phase=toolchain-retained-copy \
                     path={diagnostic_path}: {error}"
                )
            })?;
        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            if Instant::now() >= deadline {
                return Err(format!(
                    "Windows toolchain retained copy exceeded its deadline: \
                     phase=toolchain-retained-copy path={diagnostic_path}"
                ));
            }
            let read = source.read(&mut buffer).map_err(|error| {
                format!(
                    "cannot read retained Windows toolchain source: \
                     phase=toolchain-retained-copy path={diagnostic_path}: {error}"
                )
            })?;
            if read == 0 {
                break;
            }
            destination.write_all(&buffer[..read]).map_err(|error| {
                format!(
                    "cannot write staged Windows toolchain file: \
                     phase=toolchain-retained-copy path={diagnostic_path}: {error}"
                )
            })?;
            if Instant::now() >= deadline {
                return Err(format!(
                    "Windows toolchain retained copy exceeded its deadline after write: \
                     phase=toolchain-retained-copy path={diagnostic_path}"
                ));
            }
            digest.update(&buffer[..read]);
            copied =
                copied
                    .checked_add(u64::try_from(read).map_err(|_| {
                        "Windows toolchain copy length does not fit in u64".to_owned()
                    })?)
                    .ok_or_else(|| "Windows toolchain copy length overflowed".to_owned())?;
        }
        if copied != self.size || digest.finish() != self.sha256 {
            return Err(format!(
                "retained Windows toolchain copy differs from its source receipt: \
                 phase=toolchain-retained-copy path={diagnostic_path}"
            ));
        }
        destination.sync_all().map_err(|error| {
            format!(
                "cannot sync staged Windows toolchain file: phase=toolchain-retained-copy \
                 path={diagnostic_path}: {error}"
            )
        })?;
        if Instant::now() >= deadline {
            return Err(format!(
                "Windows toolchain retained copy exceeded its deadline after sync: \
                 phase=toolchain-retained-copy path={diagnostic_path}"
            ));
        }
        Ok(())
    }

    pub(crate) fn promote_program_invocation_until(
        &self,
        path: &Path,
        deadline: Instant,
    ) -> Result<hell_testkit::BoundProgramInvocation, String> {
        if path != self.canonical {
            return Err("promoted Windows file path differs from its staged receipt".to_owned());
        }
        let retained_file = self
            ._guard
            .try_clone()
            .map_err(|error| format!("cannot clone retained Windows staged file: {error}"))?;
        hell_testkit::BoundProgramInvocation::promote_windows_retained_file_until(
            self.canonical.clone(),
            retained_file,
            self.size,
            self.sha256,
            deadline,
        )
        .map_err(|error| format!("cannot promote retained Windows staged file: {error}"))
    }

    pub(crate) fn revalidate_retained_path_until_at(
        &self,
        path: &Path,
        deadline: Instant,
        phase: WindowsFileIdentityPhase,
        diagnostic_path: &Path,
    ) -> Result<(), String> {
        let phase = phase.label();
        let diagnostic_path = bounded_windows_identity_path(diagnostic_path);
        if Instant::now() >= deadline {
            return Err(format!(
                "retained Windows file revalidation exceeded its deadline: phase={phase} \
                 path={diagnostic_path}"
            ));
        }
        let canonical = fs::canonicalize(path).map_err(|error| {
            format!(
                "cannot canonicalize retained Windows file: phase={phase} \
                 path={diagnostic_path}: {error}"
            )
        })?;
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!(
                "cannot inspect retained Windows file path: phase={phase} \
                 path={diagnostic_path}: {error}"
            )
        })?;
        if canonical != self.canonical || !metadata.is_file() || metadata.len() != self.size {
            return Err(format!(
                "retained Windows file path identity changed: phase={phase} \
                 path={diagnostic_path}"
            ));
        }
        let current = same_file::Handle::from_path(&canonical).map_err(|error| {
            format!(
                "cannot bind retained Windows file path: phase={phase} path={diagnostic_path}: \
                 {error}"
            )
        })?;
        if current != *self.handle {
            return Err(format!(
                "retained Windows file handle identity changed: phase={phase} \
                 path={diagnostic_path}"
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "retained Windows file revalidation exceeded its deadline: phase={phase} \
                 path={diagnostic_path}"
            ));
        }
        Ok(())
    }

    pub(crate) fn sha256(&self) -> Digest {
        self.sha256
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    fn same_file(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

#[cfg(windows)]
#[derive(Clone, Debug)]
pub(crate) struct ResolvedWindowsExecutableIdentity {
    invocation: PathBuf,
    canonical: PathBuf,
    file: WindowsBoundFileIdentity,
}

#[cfg(windows)]
impl ResolvedWindowsExecutableIdentity {
    fn bind(resolved: &ResolvedCargoExecutable, logical_name: &str) -> Result<Self, String> {
        if resolved.invocation_name.as_os_str() != OsStr::new(logical_name)
            || !resolved.invocation_path.is_absolute()
            || !windows_executable_stem_is(&resolved.invocation_path, logical_name)
            || fs::canonicalize(&resolved.invocation_path).ok().as_deref()
                != Some(resolved.canonical_identity.as_path())
            || fs::canonicalize(&resolved.canonical_identity)
                .ok()
                .as_deref()
                != Some(resolved.canonical_identity.as_path())
        {
            return Err(format!(
                "resolved Windows {logical_name} identity differs from policy"
            ));
        }
        let identity = Self {
            invocation: resolved.invocation_path.clone(),
            canonical: resolved.canonical_identity.clone(),
            file: WindowsBoundFileIdentity::bind(&resolved.canonical_identity)?,
        };
        identity.revalidate(logical_name)?;
        Ok(identity)
    }

    pub(crate) fn invocation(&self) -> &Path {
        &self.invocation
    }

    pub(crate) fn canonical(&self) -> &Path {
        &self.canonical
    }

    pub(crate) fn revalidate(&self, logical_name: &str) -> Result<(), String> {
        if !windows_executable_stem_is(&self.invocation, logical_name)
            || fs::canonicalize(&self.invocation).ok().as_deref() != Some(self.canonical.as_path())
            || fs::canonicalize(&self.canonical).ok().as_deref() != Some(self.canonical.as_path())
        {
            return Err(format!(
                "resolved Windows {logical_name} path changed before use"
            ));
        }
        self.file.revalidate(&self.canonical)
    }

    fn revalidate_until(&self, logical_name: &str, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline
            || !windows_executable_stem_is(&self.invocation, logical_name)
            || fs::canonicalize(&self.invocation).ok().as_deref() != Some(self.canonical.as_path())
            || fs::canonicalize(&self.canonical).ok().as_deref() != Some(self.canonical.as_path())
        {
            return Err(format!(
                "resolved Windows {logical_name} path changed before use"
            ));
        }
        self.file.revalidate_until(&self.canonical, deadline)
    }
}

#[cfg(windows)]
fn windows_executable_stem_is(path: &Path, logical_name: &str) -> bool {
    path.file_stem()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case(logical_name))
        && has_native_windows_extension(path)
}

#[cfg(windows)]
#[derive(Clone, Debug)]
pub(crate) struct ResolvedWindowsRustupAuthority {
    cargo_source: ResolvedWindowsToolSourceAuthority,
    rustc_source: ResolvedWindowsToolSourceAuthority,
    rustup: ResolvedWindowsExecutableIdentity,
    home: PathBuf,
    toolchain: OsString,
    toolchain_root: PathBuf,
    cargo: ResolvedWindowsExecutableIdentity,
    rustc: ResolvedWindowsExecutableIdentity,
}

#[cfg(windows)]
#[derive(Clone, Debug)]
pub(crate) enum ResolvedWindowsToolSourceAuthority {
    RustupProxy(ResolvedWindowsExecutableIdentity),
    /// A hosted-profile copy in the same standard bin directory as Rustup.
    CopiedRustupProxy(ResolvedWindowsExecutableIdentity),
    SelectedToolchain(ResolvedWindowsExecutableIdentity),
}

#[cfg(windows)]
impl ResolvedWindowsToolSourceAuthority {
    pub(crate) fn executable(&self) -> &ResolvedWindowsExecutableIdentity {
        match self {
            Self::RustupProxy(executable)
            | Self::CopiedRustupProxy(executable)
            | Self::SelectedToolchain(executable) => executable,
        }
    }

    fn revalidate(
        &self,
        logical_name: &str,
        rustup: &ResolvedWindowsExecutableIdentity,
        selected: &ResolvedWindowsExecutableIdentity,
    ) -> Result<(), String> {
        let executable = self.executable();
        executable.revalidate(logical_name)?;
        match self {
            Self::RustupProxy(_) if executable.file.same_file(&rustup.file) => Ok(()),
            Self::CopiedRustupProxy(_)
                if windows_standard_copied_proxy_matches(executable, rustup)? =>
            {
                Ok(())
            }
            Self::SelectedToolchain(_)
                if executable.file.same_file(&selected.file)
                    && executable.canonical == selected.canonical =>
            {
                Ok(())
            }
            Self::RustupProxy(_) => Err(format!(
                "Windows {logical_name} no longer matches the standard Rustup proxy"
            )),
            Self::CopiedRustupProxy(_) => Err(format!(
                "Windows {logical_name} no longer matches the standard copied Rustup proxy"
            )),
            Self::SelectedToolchain(_) => Err(format!(
                "Windows {logical_name} no longer matches the selected toolchain executable"
            )),
        }
    }

    fn revalidate_until(
        &self,
        logical_name: &str,
        rustup: &ResolvedWindowsExecutableIdentity,
        selected: &ResolvedWindowsExecutableIdentity,
        deadline: Instant,
    ) -> Result<(), String> {
        let executable = self.executable();
        executable.revalidate_until(logical_name, deadline)?;
        match self {
            Self::RustupProxy(_) if executable.file.same_file(&rustup.file) => Ok(()),
            Self::CopiedRustupProxy(_)
                if !executable.file.same_file(&rustup.file)
                    && executable.canonical != rustup.canonical
                    && executable.canonical.parent() == rustup.canonical.parent()
                    && executable.invocation.parent() == rustup.invocation.parent()
                    && executable.file.size() == rustup.file.size()
                    && executable.file.sha256() == rustup.file.sha256() =>
            {
                Ok(())
            }
            Self::SelectedToolchain(_)
                if executable.file.same_file(&selected.file)
                    && executable.canonical == selected.canonical =>
            {
                Ok(())
            }
            _ => Err(format!(
                "Windows {logical_name} no longer matches its retained tool source"
            )),
        }
    }
}

#[cfg(windows)]
impl ResolvedWindowsRustupAuthority {
    pub(crate) fn toolchain_root(&self) -> &Path {
        &self.toolchain_root
    }

    pub(crate) fn cargo_source(&self) -> &ResolvedWindowsToolSourceAuthority {
        &self.cargo_source
    }

    pub(crate) fn rustc_source(&self) -> &ResolvedWindowsToolSourceAuthority {
        &self.rustc_source
    }

    pub(crate) fn cargo(&self) -> &ResolvedWindowsExecutableIdentity {
        &self.cargo
    }

    pub(crate) fn rustc(&self) -> &ResolvedWindowsExecutableIdentity {
        &self.rustc
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.rustup.revalidate("rustup")?;
        if fs::canonicalize(&self.home).ok().as_deref() != Some(self.home.as_path())
            || fs::canonicalize(&self.toolchain_root).ok().as_deref()
                != Some(self.toolchain_root.as_path())
            || self.toolchain_root != self.home.join("toolchains").join(&self.toolchain)
        {
            return Err("selected Windows Rustup authority changed before use".to_owned());
        }
        self.cargo.revalidate("cargo")?;
        self.rustc.revalidate("rustc")?;
        self.cargo_source
            .revalidate("cargo", &self.rustup, &self.cargo)?;
        self.rustc_source
            .revalidate("rustc", &self.rustup, &self.rustc)
    }

    pub(crate) fn revalidate_until(&self, deadline: Instant) -> Result<(), String> {
        self.rustup.revalidate_until("rustup", deadline)?;
        if Instant::now() >= deadline
            || fs::canonicalize(&self.home).ok().as_deref() != Some(self.home.as_path())
            || fs::canonicalize(&self.toolchain_root).ok().as_deref()
                != Some(self.toolchain_root.as_path())
            || self.toolchain_root != self.home.join("toolchains").join(&self.toolchain)
        {
            return Err("selected Windows Rustup authority changed before use".to_owned());
        }
        self.cargo.revalidate_until("cargo", deadline)?;
        self.rustc.revalidate_until("rustc", deadline)?;
        self.cargo_source
            .revalidate_until("cargo", &self.rustup, &self.cargo, deadline)?;
        self.rustc_source
            .revalidate_until("rustc", &self.rustup, &self.rustc, deadline)
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedPosixRustupProxyIdentity {
    cargo_invocation: PathBuf,
    cargo: PathBuf,
    rustup_invocation: PathBuf,
    rustup: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl ResolvedPosixRustupProxyIdentity {
    pub(crate) fn cargo_invocation(&self) -> &Path {
        &self.cargo_invocation
    }

    pub(crate) fn cargo(&self) -> &Path {
        &self.cargo
    }

    pub(crate) fn rustup(&self) -> &Path {
        &self.rustup
    }

    pub(crate) fn rustup_invocation(&self) -> &Path {
        &self.rustup_invocation
    }

    pub(crate) fn device(&self) -> u64 {
        self.device
    }

    pub(crate) fn inode(&self) -> u64 {
        self.inode
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        let cargo = resolved_tool_candidate(&self.cargo_invocation, true, false)
            .ok_or_else(|| "resolved Cargo proxy is no longer executable".to_owned())?;
        let rustup = resolved_standard_candidate(&self.rustup_invocation)
            .ok_or_else(|| "resolved standard rustup is no longer executable".to_owned())?;
        if cargo.invocation_path != self.cargo_invocation
            || cargo.canonical_identity != self.cargo
            || cargo.invocation_name.as_os_str() != OsStr::new("cargo")
            || rustup.canonical_identity != self.rustup
            || self.rustup_invocation.file_name() != Some(OsStr::new("rustup"))
            || self.cargo_invocation.file_name() != Some(OsStr::new("cargo"))
        {
            return Err("resolved Cargo/Rustup proxy paths changed before use".to_owned());
        }
        let cargo_metadata = fs::metadata(&self.cargo)
            .map_err(|error| format!("cannot revalidate resolved Cargo proxy: {error}"))?;
        let rustup_metadata = fs::metadata(&self.rustup)
            .map_err(|error| format!("cannot revalidate resolved standard rustup: {error}"))?;
        if cargo_metadata.dev() != self.device
            || cargo_metadata.ino() != self.inode
            || rustup_metadata.dev() != self.device
            || rustup_metadata.ino() != self.inode
        {
            return Err("resolved Cargo/Rustup proxy file identity changed before use".to_owned());
        }
        Ok(())
    }

    fn bind(
        cargo: &ResolvedCargoExecutable,
        rustup: &ResolvedStandardExecutable,
    ) -> Result<Option<Self>, String> {
        use std::os::unix::fs::MetadataExt as _;

        if cargo.invocation_name.as_os_str() != OsStr::new("cargo")
            || cargo.invocation_path.file_name() != Some(OsStr::new("cargo"))
            || rustup.invocation_path.file_name() != Some(OsStr::new("rustup"))
        {
            return Ok(None);
        }
        let cargo_metadata = fs::metadata(&cargo.canonical_identity)
            .map_err(|error| format!("cannot inspect resolved Cargo proxy: {error}"))?;
        let rustup_metadata = fs::metadata(&rustup.canonical_identity)
            .map_err(|error| format!("cannot inspect resolved standard rustup: {error}"))?;
        if !cargo_metadata.is_file()
            || !rustup_metadata.is_file()
            || cargo_metadata.dev() != rustup_metadata.dev()
            || cargo_metadata.ino() != rustup_metadata.ino()
        {
            return Ok(None);
        }
        let identity = Self {
            cargo_invocation: cargo.invocation_path.clone(),
            cargo: cargo.canonical_identity.clone(),
            rustup_invocation: rustup.invocation_path.clone(),
            rustup: rustup.canonical_identity.clone(),
            device: cargo_metadata.dev(),
            inode: cargo_metadata.ino(),
        };
        identity.revalidate()?;
        Ok(Some(identity))
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResolvedPosixCargoAuthority {
    Native {
        cargo: ResolvedPosixCanonicalExecutableIdentity,
        standard_rustup: ResolvedPosixStandardExecutableIdentity,
    },
    Rustup(ResolvedPosixRustupAuthority),
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedPosixCanonicalExecutableIdentity {
    canonical: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl ResolvedPosixCanonicalExecutableIdentity {
    fn bind(canonical: &Path) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::metadata(canonical)
            .map_err(|error| format!("cannot inspect canonical executable identity: {error}"))?;
        if fs::canonicalize(canonical).ok().as_deref() != Some(canonical) || !metadata.is_file() {
            return Err("canonical executable identity is not a regular canonical file".to_owned());
        }
        Ok(Self {
            canonical: canonical.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn revalidate(&self) -> Result<(), String> {
        let observed = Self::bind(&self.canonical)?;
        if observed.device != self.device || observed.inode != self.inode {
            return Err("canonical executable identity changed before use".to_owned());
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedPosixStandardExecutableIdentity {
    invocation: PathBuf,
    canonical: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl ResolvedPosixStandardExecutableIdentity {
    pub(crate) fn invocation(&self) -> &Path {
        &self.invocation
    }

    pub(crate) fn canonical(&self) -> &Path {
        &self.canonical
    }

    pub(crate) fn device(&self) -> u64 {
        self.device
    }

    pub(crate) fn inode(&self) -> u64 {
        self.inode
    }

    fn bind(executable: &ResolvedStandardExecutable) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        executable.revalidate()?;
        let metadata = fs::metadata(&executable.canonical_identity)
            .map_err(|error| format!("cannot inspect standard executable identity: {error}"))?;
        Ok(Self {
            invocation: executable.invocation_path.clone(),
            canonical: executable.canonical_identity.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn revalidate(&self) -> Result<(), String> {
        let executable = resolved_standard_candidate(&self.invocation)
            .ok_or_else(|| "standard executable is no longer available".to_owned())?;
        let observed = Self::bind(&executable)?;
        if observed.canonical != self.canonical
            || observed.device != self.device
            || observed.inode != self.inode
        {
            return Err("standard executable identity changed before use".to_owned());
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResolvedPosixRustcAuthority {
    RustupProxy {
        standard: ResolvedPosixStandardExecutableIdentity,
    },
    SelectedToolchain {
        standard: ResolvedPosixStandardExecutableIdentity,
        selected: ResolvedPosixCanonicalExecutableIdentity,
    },
}

#[cfg(unix)]
impl ResolvedPosixRustcAuthority {
    pub(crate) fn standard(&self) -> &ResolvedPosixStandardExecutableIdentity {
        match self {
            Self::RustupProxy { standard } | Self::SelectedToolchain { standard, .. } => standard,
        }
    }

    fn bind(
        rustc: &ResolvedStandardExecutable,
        proxy: &ResolvedPosixRustupProxyIdentity,
        selected: &Path,
    ) -> Result<Self, String> {
        let standard = ResolvedPosixStandardExecutableIdentity::bind(rustc)?;
        if standard.invocation.file_name() != Some(OsStr::new("rustc")) {
            return Err("standard Rust compiler invocation is not named rustc".to_owned());
        }
        if standard.device == proxy.device && standard.inode == proxy.inode {
            let authority = Self::RustupProxy { standard };
            authority.revalidate(proxy)?;
            return Ok(authority);
        }
        let selected = ResolvedPosixCanonicalExecutableIdentity::bind(selected)?;
        if standard.canonical != selected.canonical
            || standard.device != selected.device
            || standard.inode != selected.inode
        {
            return Err(
                "standard rustc is neither the Rustup proxy nor the selected toolchain compiler"
                    .to_owned(),
            );
        }
        let authority = Self::SelectedToolchain { standard, selected };
        authority.revalidate(proxy)?;
        Ok(authority)
    }

    pub(crate) fn revalidate(
        &self,
        proxy: &ResolvedPosixRustupProxyIdentity,
    ) -> Result<(), String> {
        let standard = self.standard();
        standard.revalidate()?;
        match self {
            Self::RustupProxy { .. } => {
                if standard.device != proxy.device || standard.inode != proxy.inode {
                    return Err("standard rustc no longer matches the Rustup proxy".to_owned());
                }
            }
            Self::SelectedToolchain { selected, .. } => {
                selected.revalidate()?;
                if standard.canonical != selected.canonical
                    || standard.device != selected.device
                    || standard.inode != selected.inode
                {
                    return Err(
                        "standard rustc no longer matches the selected toolchain compiler"
                            .to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedPosixRustupAuthority {
    proxy_identity: ResolvedPosixRustupProxyIdentity,
    rustc_authority: ResolvedPosixRustcAuthority,
    home: PathBuf,
    toolchain: OsString,
}

#[cfg(unix)]
impl ResolvedPosixRustupAuthority {
    pub(crate) fn proxy_identity(&self) -> &ResolvedPosixRustupProxyIdentity {
        &self.proxy_identity
    }

    pub(crate) fn rustc_authority(&self) -> &ResolvedPosixRustcAuthority {
        &self.rustc_authority
    }

    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn toolchain(&self) -> &OsStr {
        &self.toolchain
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedStandardExecutable {
    invocation_path: PathBuf,
    canonical_identity: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    parent_owner: u32,
    parent_group: u32,
    parent_mode: u32,
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    bytes: u64,
}

#[cfg(unix)]
impl ResolvedStandardExecutable {
    pub(crate) fn invocation_path(&self) -> &Path {
        &self.invocation_path
    }

    pub(crate) fn canonical_identity(&self) -> &Path {
        &self.canonical_identity
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        let observed = resolved_standard_candidate(&self.invocation_path)
            .ok_or_else(|| "resolved standard tool is no longer executable".to_owned())?;
        if observed != *self {
            return Err("resolved standard tool identity changed before spawn".to_owned());
        }
        Ok(())
    }

    pub(crate) fn posix_authority(
        &self,
        role: hell_testkit::PosixProcessToolRole,
    ) -> hell_testkit::PosixExecutableAuthority {
        self.posix_authority_with_invocation(role, self.invocation_path.clone())
    }

    pub(crate) fn posix_authority_with_invocation(
        &self,
        role: hell_testkit::PosixProcessToolRole,
        invocation: PathBuf,
    ) -> hell_testkit::PosixExecutableAuthority {
        hell_testkit::PosixExecutableAuthority::with_parent_metadata(
            role,
            invocation,
            hell_testkit::PosixExecutableParentMetadata::new(
                self.parent_device,
                self.parent_inode,
                self.parent_owner,
                self.parent_group,
                self.parent_mode,
            ),
            self.canonical_identity.clone(),
            hell_testkit::PosixExecutableMetadata::new(
                self.device,
                self.inode,
                self.owner,
                self.group,
                self.mode,
                self.bytes,
            ),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessScope {
    IsolatedTree,
}

pub(crate) struct NativeArchiveAdapter {
    _directory: Option<AdapterDirectory>,
    bound_toolchain: Option<Arc<BoundNativeToolchain>>,
    llvm_ar: Option<BoundNativeArchiver>,
    llvm_ar_version: Option<String>,
    path: Option<OsString>,
    stack_yaml: Option<PathBuf>,
    temporary_directory: Option<PathBuf>,
    #[cfg(target_os = "macos")]
    input_broker: Option<NativeArchiveInputBroker>,
}

#[derive(Clone, Debug)]
pub(crate) struct BoundNativeArchiver {
    path: PathBuf,
    canonical: PathBuf,
    #[cfg(target_os = "macos")]
    distribution: BoundSealedNativeManifest,
    #[cfg(target_os = "macos")]
    load_graph: NativeArchiverLoadGraph,
    #[cfg(target_os = "macos")]
    external_dependencies: Vec<BoundNativeArchiverDependency>,
    #[cfg(target_os = "macos")]
    otool: ResolvedStandardExecutable,
    #[cfg(target_os = "macos")]
    validation_passes: Arc<NativeArchiverValidationPassCounters>,
    sha256: Digest,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeArchiverValidationPassCounts {
    full_closure: u64,
    load_graph: u64,
    spawn_preflight: u64,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct NativeArchiverValidationPassCounters {
    full_closure: AtomicU64,
    load_graph: AtomicU64,
    spawn_preflight: AtomicU64,
}

#[cfg(target_os = "macos")]
impl NativeArchiverValidationPassCounters {
    fn counts(&self) -> NativeArchiverValidationPassCounts {
        NativeArchiverValidationPassCounts {
            full_closure: self.full_closure.load(Ordering::Relaxed),
            load_graph: self.load_graph.load(Ordering::Relaxed),
            spawn_preflight: self.spawn_preflight.load(Ordering::Relaxed),
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct BoundNativeArchiverDependency {
    guard: Arc<fs::File>,
    ancestors: Vec<BoundNativeArchiverAncestor>,
    path: PathBuf,
    canonical: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    sha256: Digest,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct BoundNativeArchiverAncestor {
    guard: Option<Arc<fs::File>>,
    path: PathBuf,
    symlink_target: Option<PathBuf>,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
enum NativeArchiverOwnerAuthority {
    TrustedPublisher { uid: u32 },
    RestrictedConsumer { uid: u32, groups: Vec<u32> },
}

#[cfg(target_os = "macos")]
impl NativeArchiverOwnerAuthority {
    fn admits_owner(&self, owner: u32) -> bool {
        match self {
            Self::TrustedPublisher { uid } => owner == 0 || owner == *uid,
            Self::RestrictedConsumer { uid, .. } => owner != *uid,
        }
    }

    fn permits_file_mode(&self, owner: u32, group: u32, mode: u32) -> bool {
        match self {
            Self::TrustedPublisher { .. } => mode & 0o022 == 0,
            Self::RestrictedConsumer { uid, groups } => {
                let candidate_write = if owner == *uid {
                    mode & 0o200 != 0
                } else if groups.contains(&group) {
                    mode & 0o020 != 0
                } else {
                    mode & 0o002 != 0
                };
                !candidate_write
            }
        }
    }

    fn permits_ancestor_mode(&self, owner: u32, group: u32, mode: u32, is_directory: bool) -> bool {
        match self {
            Self::TrustedPublisher { .. } => true,
            Self::RestrictedConsumer { uid, groups } => {
                let candidate_write = if owner == *uid {
                    mode & 0o200 != 0
                } else if groups.contains(&group) {
                    mode & 0o020 != 0
                } else {
                    mode & 0o002 != 0
                };
                !candidate_write || (is_directory && owner != *uid && mode & 0o1000 != 0)
            }
        }
    }
}

#[cfg(target_os = "macos")]
struct AcquiredNativeArchiverSource {
    source_prefix: PathBuf,
    files: Vec<AcquiredNativeArchiverFile>,
    load_graph: NativeArchiverLoadGraph,
    external_dependencies: Vec<BoundNativeArchiverDependency>,
    otool: ResolvedStandardExecutable,
}

#[cfg(target_os = "macos")]
struct AcquiredNativeArchiverFile {
    relative: PathBuf,
    source: BoundNativeArchiverDependency,
    bytes: Vec<u8>,
    sha256: Digest,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeArchiverLoadGraph {
    edges: Vec<NativeArchiverLoadEdge>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeArchiverLoadEdge {
    source: PathBuf,
    load_name: String,
    target: NativeArchiverLoadTarget,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeArchiverLoadTarget {
    Staged(PathBuf),
    External(PathBuf),
    System(PathBuf),
}

#[cfg(target_os = "macos")]
fn record_native_archiver_load_edge(
    edges: &mut BTreeMap<(PathBuf, String), NativeArchiverLoadTarget>,
    source: PathBuf,
    load_name: String,
    target: NativeArchiverLoadTarget,
) -> Result<(), String> {
    const LOAD_EDGE_LIMIT: usize = 1_024;

    let key = (source, load_name);
    if let Some(existing) = edges.get(&key) {
        if existing != &target {
            return Err(
                "Mach-O load edge resolves inconsistently across run-path contexts".to_owned(),
            );
        }
        return Ok(());
    }
    if edges.len() >= LOAD_EDGE_LIMIT {
        return Err("native archiver load graph exceeds the edge-count policy".to_owned());
    }
    edges.insert(key, target);
    Ok(())
}

#[cfg(target_os = "macos")]
fn finish_native_archiver_load_graph(
    edges: BTreeMap<(PathBuf, String), NativeArchiverLoadTarget>,
) -> NativeArchiverLoadGraph {
    NativeArchiverLoadGraph {
        edges: edges
            .into_iter()
            .map(|((source, load_name), target)| NativeArchiverLoadEdge {
                source,
                load_name,
                target,
            })
            .collect(),
    }
}

#[derive(Clone, Debug)]
struct BoundNativeToolchain {
    adapter_authorities: Vec<BoundNativeDirectory>,
    ghc_distribution: BoundNativeManifest,
    ghc_bin: BoundNativeDirectory,
    ghc: BoundNativeFile,
    ghc_provenance: Option<StagedNativeGhcProvenance>,
    stack_distribution: BoundNativeManifest,
    stack_bin: BoundNativeDirectory,
    stack: BoundNativeFile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundNativeToolchainInventory {
    ghc_distribution: BoundNativeManifest,
    stack_distribution: BoundNativeManifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundNativeManifest {
    root: PathBuf,
    entries: Vec<BoundNativeManifestEntry>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct BoundSealedNativeManifest {
    root: PathBuf,
    entries: Vec<BoundNativeManifestEntry>,
    guards: Vec<Option<Arc<fs::File>>>,
    directory_children: BTreeMap<PathBuf, Vec<OsString>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundNativeManifestEntry {
    relative: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    kind: BoundNativeManifestEntryKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BoundNativeManifestEntryKind {
    Directory,
    File { size: u64, sha256: Digest },
    Symlink { target: PathBuf },
}

#[derive(Clone, Debug)]
struct StagedNativeGhcProvenance {
    source_root: PathBuf,
    version: String,
    libdir: PathBuf,
    settings: PathBuf,
    package_db: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundNativeDirectory {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[derive(Clone, Debug)]
struct BoundNativeFile {
    invocation: PathBuf,
    canonical: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    sha256: Digest,
}

impl BoundNativeToolchain {
    #[cfg(target_os = "macos")]
    fn retain_sealed_adapter_authority(&mut self, trusted_group: u32) -> Result<(), String> {
        self.adapter_authorities =
            rebind_sealed_native_adapter_authorities(&self.adapter_authorities, trusted_group)?;
        self.revalidate()
    }

    #[cfg(unix)]
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        for authority in &self.adapter_authorities {
            authority.revalidate("native archive adapter authority")?;
        }
        self.ghc_distribution
            .revalidate("staged GHC distribution")?;
        self.ghc_bin.revalidate("staged GHC bin directory")?;
        self.ghc.revalidate("staged GHC executable")?;
        if let Some(provenance) = &self.ghc_provenance {
            provenance.revalidate(&self.ghc_distribution.root)?;
        }
        self.stack_distribution
            .revalidate("staged Stack distribution")?;
        self.stack_bin.revalidate("staged Stack bin directory")?;
        self.stack.revalidate("staged Stack executable")
    }

    #[cfg(target_os = "macos")]
    fn revalidate_ghc_query_authority(&self, deadline: Instant) -> Result<(), String> {
        for authority in &self.adapter_authorities {
            authority.revalidate_until("native archive adapter authority", deadline)?;
        }
        let root = self
            .ghc_distribution
            .entries
            .first()
            .filter(|entry| entry.relative.as_os_str().is_empty())
            .ok_or_else(|| "staged GHC manifest has no root receipt".to_owned())?;
        revalidate_native_manifest_entry(&self.ghc_distribution.root, root, true)?;
        self.ghc_bin
            .revalidate_until("staged GHC bin directory", deadline)?;
        self.ghc.revalidate_until("staged GHC executable", deadline)
    }

    #[cfg(target_os = "macos")]
    fn revalidate_until(&self, deadline: Instant) -> Result<(), String> {
        require_optional_native_deadline(Some(deadline), "native toolchain revalidation")?;
        for authority in &self.adapter_authorities {
            authority.revalidate_until("native archive adapter authority", deadline)?;
        }
        self.ghc_distribution
            .revalidate_until("staged GHC distribution", deadline)?;
        self.ghc_bin
            .revalidate_until("staged GHC bin directory", deadline)?;
        self.ghc
            .revalidate_until("staged GHC executable", deadline)?;
        if let Some(provenance) = &self.ghc_provenance {
            provenance.revalidate(&self.ghc_distribution.root)?;
        }
        self.stack_distribution
            .revalidate_until("staged Stack distribution", deadline)?;
        self.stack_bin
            .revalidate_until("staged Stack bin directory", deadline)?;
        self.stack
            .revalidate_until("staged Stack executable", deadline)
    }

    #[cfg(not(unix))]
    fn revalidate(&self) -> Result<(), String> {
        Err("the bound native toolchain requires a POSIX host".to_owned())
    }
}

impl BoundNativeToolchainInventory {
    #[cfg(unix)]
    pub(crate) fn bind(adapter: &Path) -> Result<Self, String> {
        let adapter_metadata = fs::symlink_metadata(adapter)
            .map_err(|error| format!("cannot inspect native toolchain adapter: {error}"))?;
        if adapter_metadata.file_type().is_symlink() || !adapter_metadata.is_dir() {
            return Err("native toolchain adapter is not an exact directory".to_owned());
        }
        let canonical_adapter = fs::canonicalize(adapter)
            .map_err(|error| format!("cannot canonicalize native toolchain adapter: {error}"))?;
        let toolchain = canonical_adapter.join(".toolchain");
        Ok(Self {
            ghc_distribution: BoundNativeManifest::bind(&toolchain.join("system-ghc-9.8.2"), true)?,
            stack_distribution: BoundNativeManifest::bind(&toolchain.join("system-tools"), true)?,
        })
    }

    #[cfg(unix)]
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.ghc_distribution
            .revalidate("staged GHC distribution")?;
        self.stack_distribution
            .revalidate("staged Stack distribution")
    }
}

impl BoundNativeManifest {
    #[cfg(unix)]
    fn bind(root: &Path, require_frozen: bool) -> Result<Self, String> {
        Self::bind_until(root, require_frozen, None)
    }

    #[cfg(unix)]
    fn bind_until(
        root: &Path,
        require_frozen: bool,
        deadline: Option<Instant>,
    ) -> Result<Self, String> {
        Self::bind_internal(root, require_frozen, deadline, true)
    }

    #[cfg(target_os = "macos")]
    fn bind_source_inventory_until(root: &Path, deadline: Option<Instant>) -> Result<Self, String> {
        Self::bind_internal(root, false, deadline, false)
    }

    #[cfg(unix)]
    fn bind_internal(
        root: &Path,
        require_frozen: bool,
        deadline: Option<Instant>,
        hash_files: bool,
    ) -> Result<Self, String> {
        Self::bind_internal_with_limits(
            root,
            require_frozen,
            deadline,
            hash_files,
            NATIVE_GHC_ENTRY_LIMIT,
            NATIVE_GHC_DEPTH_LIMIT,
        )
    }

    #[cfg(unix)]
    fn bind_internal_with_limits(
        root: &Path,
        require_frozen: bool,
        deadline: Option<Instant>,
        hash_files: bool,
        entry_limit: usize,
        depth_limit: usize,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        let root_metadata = fs::symlink_metadata(root)
            .map_err(|error| format!("cannot inspect native toolchain manifest: {error}"))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err("native toolchain manifest root is not an exact directory".to_owned());
        }
        let canonical_root = fs::canonicalize(root)
            .map_err(|error| format!("cannot canonicalize native toolchain manifest: {error}"))?;
        let mut pending = vec![PathBuf::new()];
        let mut entries = Vec::new();
        let mut acl_paths = Vec::new();
        let mut bytes = 0u64;
        while let Some(relative) = pending.pop() {
            require_optional_native_deadline(deadline, "native toolchain inventory")?;
            if entries.len() >= entry_limit {
                return Err("native toolchain exceeds the entry-count policy".to_owned());
            }
            if relative.components().count() > depth_limit {
                return Err("native toolchain exceeds the depth policy".to_owned());
            }
            let path = canonical_root.join(&relative);
            let before = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot bind native toolchain member: {error}"))?;
            let mode = before.mode() & 0o7777;
            let kind = if before.file_type().is_symlink() {
                let target = fs::read_link(&path)
                    .map_err(|error| format!("cannot read native toolchain symlink: {error}"))?;
                let resolved = fs::canonicalize(&path)
                    .map_err(|error| format!("cannot resolve native toolchain symlink: {error}"))?;
                if !resolved.starts_with(&canonical_root) {
                    return Err("native toolchain symlink escapes its distribution root".to_owned());
                }
                BoundNativeManifestEntryKind::Symlink { target }
            } else if before.is_dir() {
                if require_frozen && mode != 0o555 {
                    return Err("staged toolchain directory is not frozen".to_owned());
                }
                if require_frozen {
                    acl_paths.push(path.clone());
                }
                let mut children = Vec::new();
                for child in fs::read_dir(&path).map_err(|error| {
                    format!("cannot enumerate native toolchain manifest: {error}")
                })? {
                    require_optional_native_deadline(deadline, "native toolchain enumeration")?;
                    if entries
                        .len()
                        .saturating_add(pending.len())
                        .saturating_add(children.len())
                        >= entry_limit
                    {
                        return Err("native toolchain exceeds the entry-count policy".to_owned());
                    }
                    children.push(child.map_err(|error| {
                        format!("cannot enumerate native toolchain manifest: {error}")
                    })?);
                }
                children.sort_by_key(fs::DirEntry::file_name);
                for child in children.into_iter().rev() {
                    pending.push(relative.join(child.file_name()));
                }
                BoundNativeManifestEntryKind::Directory
            } else if before.is_file() {
                if require_frozen && mode != 0o444 && mode != 0o555 {
                    return Err("staged toolchain file is not frozen".to_owned());
                }
                if require_frozen {
                    acl_paths.push(path.clone());
                }
                let sha256 = if hash_files {
                    match deadline {
                        Some(deadline) => sha256_file_until(&path, deadline)?,
                        None => sha256_file(&path).map_err(|error| {
                            format!("cannot hash native toolchain member: {error}")
                        })?,
                    }
                } else {
                    Digest::default()
                };
                let after = fs::symlink_metadata(&path).map_err(|error| {
                    format!("cannot revalidate hashed native toolchain member: {error}")
                })?;
                if !same_native_metadata(&before, &after) {
                    return Err("native toolchain member changed while it was bound".to_owned());
                }
                bytes = bytes
                    .checked_add(after.len())
                    .ok_or_else(|| "native toolchain byte count overflowed".to_owned())?;
                if bytes > NATIVE_GHC_BYTE_LIMIT {
                    return Err("native toolchain exceeds the byte-count policy".to_owned());
                }
                BoundNativeManifestEntryKind::File {
                    size: after.len(),
                    sha256,
                }
            } else {
                return Err("native toolchain contains a special file".to_owned());
            };
            let after = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot revalidate native toolchain member: {error}"))?;
            if !same_native_metadata(&before, &after) {
                return Err("native toolchain member changed while it was bound".to_owned());
            }
            entries.push(BoundNativeManifestEntry {
                relative,
                device: after.dev(),
                inode: after.ino(),
                uid: after.uid(),
                gid: after.gid(),
                mode,
                modified_seconds: after.mtime(),
                modified_nanoseconds: after.mtime_nsec(),
                changed_seconds: after.ctime(),
                changed_nanoseconds: after.ctime_nsec(),
                kind,
            });
        }
        require_native_acl_free_until(
            acl_paths.iter().map(PathBuf::as_path),
            "staged native toolchain manifest",
            deadline,
        )?;
        entries.sort_by(|left, right| left.relative.cmp(&right.relative));
        Ok(Self {
            root: canonical_root,
            entries,
        })
    }

    #[cfg(unix)]
    fn revalidate(&self, label: &str) -> Result<(), String> {
        let observed = Self::bind(&self.root, true)?;
        if observed != *self {
            return Err(format!("{label} manifest changed before use"));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn revalidate_until(&self, label: &str, deadline: Instant) -> Result<(), String> {
        let observed = Self::bind_until(&self.root, true, Some(deadline))?;
        if observed != *self {
            return Err(format!("{label} manifest changed before use"));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn revalidate_member(
        &self,
        relative: &Path,
        label: &str,
        deadline: Instant,
    ) -> Result<(), String> {
        let expected = self
            .entries
            .binary_search_by(|entry| entry.relative.as_path().cmp(relative))
            .ok()
            .and_then(|index| self.entries.get(index))
            .ok_or_else(|| format!("{label} is absent from the retained manifest"))?;
        let path = self.root.join(relative);
        revalidate_native_manifest_entry(&path, expected, true)?;
        if let BoundNativeManifestEntryKind::File { sha256, .. } = expected.kind
            && sha256_file_until(&path, deadline)? != sha256
        {
            return Err(format!("{label} content changed before use"));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl BoundSealedNativeManifest {
    fn bind(manifest: BoundNativeManifest, deadline: Instant) -> Result<Self, String> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let mut guards = Vec::with_capacity(manifest.entries.len());
        let mut directory_children = BTreeMap::new();
        for entry in &manifest.entries {
            require_optional_native_deadline(
                Some(deadline),
                "sealed LLVM closure receipt binding",
            )?;
            let path = manifest.root.join(&entry.relative);
            revalidate_native_manifest_entry(&path, entry, true)?;
            match entry.kind {
                BoundNativeManifestEntryKind::Directory => {
                    let guard = Arc::new(
                        fs::OpenOptions::new()
                            .read(true)
                            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
                            .open(&path)
                            .map_err(|error| {
                                format!("cannot retain sealed LLVM directory: {error}")
                            })?,
                    );
                    let metadata = guard.metadata().map_err(|error| {
                        format!("cannot inspect sealed LLVM directory handle: {error}")
                    })?;
                    if metadata.dev() != entry.device || metadata.ino() != entry.inode {
                        return Err(
                            "sealed LLVM directory changed while retaining its receipt".to_owned()
                        );
                    }
                    let children = Self::read_directory_children(&path, deadline)?;
                    directory_children.insert(entry.relative.clone(), children);
                    guards.push(Some(guard));
                }
                BoundNativeManifestEntryKind::File { .. } => {
                    let guard = Arc::new(
                        fs::OpenOptions::new()
                            .read(true)
                            .custom_flags(nix::libc::O_NOFOLLOW)
                            .open(&path)
                            .map_err(|error| format!("cannot retain sealed LLVM file: {error}"))?,
                    );
                    let metadata = guard.metadata().map_err(|error| {
                        format!("cannot inspect sealed LLVM file handle: {error}")
                    })?;
                    if metadata.dev() != entry.device || metadata.ino() != entry.inode {
                        return Err(
                            "sealed LLVM file changed while retaining its receipt".to_owned()
                        );
                    }
                    guards.push(Some(guard));
                }
                BoundNativeManifestEntryKind::Symlink { .. } => guards.push(None),
            }
        }
        Ok(Self {
            root: manifest.root,
            entries: manifest.entries,
            guards,
            directory_children,
        })
    }

    fn revalidate_until(&self, label: &str, deadline: Instant) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        if self.guards.len() != self.entries.len() {
            return Err(format!("{label} retained receipt is incomplete"));
        }
        for (entry, guard) in self.entries.iter().zip(&self.guards) {
            require_optional_native_deadline(Some(deadline), "sealed LLVM closure revalidation")?;
            let path = self.root.join(&entry.relative);
            revalidate_native_manifest_entry(&path, entry, true)?;
            match (&entry.kind, guard) {
                (BoundNativeManifestEntryKind::Directory, Some(guard))
                | (BoundNativeManifestEntryKind::File { .. }, Some(guard)) => {
                    let metadata = guard.metadata().map_err(|error| {
                        format!("cannot inspect sealed LLVM retained handle: {error}")
                    })?;
                    if metadata.dev() != entry.device
                        || metadata.ino() != entry.inode
                        || metadata.uid() != entry.uid
                        || metadata.gid() != entry.gid
                        || metadata.mode() & 0o7777 != entry.mode
                        || metadata.mtime() != entry.modified_seconds
                        || metadata.mtime_nsec() != entry.modified_nanoseconds
                        || metadata.ctime() != entry.changed_seconds
                        || metadata.ctime_nsec() != entry.changed_nanoseconds
                    {
                        return Err(format!("{label} retained handle identity changed"));
                    }
                }
                (BoundNativeManifestEntryKind::Symlink { .. }, None) => {}
                _ => return Err(format!("{label} retained handle topology changed")),
            }
            if matches!(entry.kind, BoundNativeManifestEntryKind::Directory) {
                let expected = self
                    .directory_children
                    .get(&entry.relative)
                    .ok_or_else(|| format!("{label} directory inventory is absent"))?;
                if Self::read_directory_children(&path, deadline)? != *expected {
                    return Err(format!("{label} directory inventory changed before use"));
                }
            }
        }
        Ok(())
    }

    fn revalidate_member_chain_until(
        &self,
        relative: &Path,
        label: &str,
        deadline: Instant,
    ) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        let mut members = vec![PathBuf::new()];
        let mut member = PathBuf::new();
        for component in relative.components() {
            let std::path::Component::Normal(component) = component else {
                return Err(format!("{label} has a non-canonical retained path"));
            };
            member.push(component);
            members.push(member.clone());
        }
        for relative in members {
            require_optional_native_deadline(
                Some(deadline),
                "sealed LLVM member-chain revalidation",
            )?;
            let index = self
                .entries
                .binary_search_by(|entry| entry.relative.cmp(&relative))
                .map_err(|_| format!("{label} retained member chain is incomplete"))?;
            let expected = &self.entries[index];
            let path = self.root.join(&relative);
            revalidate_native_manifest_entry(&path, expected, true)?;
            match (
                &expected.kind,
                self.guards.get(index).and_then(Option::as_ref),
            ) {
                (BoundNativeManifestEntryKind::Directory, Some(guard))
                | (BoundNativeManifestEntryKind::File { .. }, Some(guard)) => {
                    let metadata = guard.metadata().map_err(|error| {
                        format!("cannot inspect {label} retained member handle: {error}")
                    })?;
                    if metadata.dev() != expected.device
                        || metadata.ino() != expected.inode
                        || metadata.uid() != expected.uid
                        || metadata.gid() != expected.gid
                        || metadata.mode() & 0o7777 != expected.mode
                    {
                        return Err(format!("{label} retained member handle changed"));
                    }
                }
                (BoundNativeManifestEntryKind::Symlink { .. }, None) => {}
                _ => return Err(format!("{label} retained member topology changed")),
            }
            if matches!(expected.kind, BoundNativeManifestEntryKind::Directory) {
                let expected_children = self
                    .directory_children
                    .get(&relative)
                    .ok_or_else(|| format!("{label} retained directory inventory is absent"))?;
                if Self::read_directory_children(&path, deadline)? != *expected_children {
                    return Err(format!("{label} retained directory inventory changed"));
                }
            }
        }
        Ok(())
    }

    fn read_directory_children(path: &Path, deadline: Instant) -> Result<Vec<OsString>, String> {
        let mut children = Vec::new();
        for child in fs::read_dir(path)
            .map_err(|error| format!("cannot enumerate sealed LLVM directory: {error}"))?
        {
            require_optional_native_deadline(Some(deadline), "sealed LLVM directory enumeration")?;
            if children.len() >= NATIVE_GHC_ENTRY_LIMIT {
                return Err("sealed LLVM directory exceeds the entry-count policy".to_owned());
            }
            children.push(
                child
                    .map_err(|error| format!("cannot read sealed LLVM directory: {error}"))?
                    .file_name(),
            );
        }
        children.sort();
        Ok(children)
    }
}

#[cfg(unix)]
fn sha256_file_until(path: &Path, deadline: Instant) -> Result<Digest, String> {
    sha256_file_until_with_label(path, deadline, "native toolchain member hash")
}

#[cfg(unix)]
fn sha256_file_until_with_label(
    path: &Path,
    deadline: Instant,
    phase: &str,
) -> Result<Digest, String> {
    use std::io::Read as _;

    let mut file = fs::File::open(path)
        .map_err(|error| format!("cannot open native toolchain member: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        require_optional_native_deadline(Some(deadline), phase)?;
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash native toolchain member: {error}"))?;
        if read == 0 {
            return Ok(digest.finish());
        }
        digest.update(&buffer[..read]);
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn require_native_acl_free<'a, I>(paths: I, label: &str) -> Result<(), String>
where
    I: IntoIterator<Item = &'a Path>,
{
    require_native_acl_free_until(paths, label, None)
}

#[cfg(target_os = "macos")]
fn require_native_acl_free_until<'a, I>(
    paths: I,
    label: &str,
    deadline: Option<Instant>,
) -> Result<(), String>
where
    I: IntoIterator<Item = &'a Path>,
{
    const ACL_AUDIT_BATCH_SIZE: usize = 256;

    let ls = resolve_absolute_standard_executable(Path::new("/bin/ls"))
        .map_err(|error| format!("cannot bind fixed macOS ACL audit tool: {error}"))?;
    let paths = paths.into_iter().collect::<Vec<_>>();
    for batch in paths.chunks(ACL_AUDIT_BATCH_SIZE) {
        require_optional_native_deadline(deadline, "native toolchain ACL audit")?;
        ls.revalidate()
            .map_err(|error| format!("fixed macOS ACL audit tool changed: {error}"))?;
        let timeout = deadline.map_or(Duration::from_secs(30), |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(30))
        });
        if timeout.is_zero() {
            return Err("native toolchain ACL audit exceeded its absolute deadline".to_owned());
        }
        let audit = run_with_optional_native_deadline(
            CommandSpec::new(ls.invocation_path(), timeout)
                .arguments(["-lde"])
                .arguments(batch.iter().copied().map(Path::as_os_str))
                .environment("LC_ALL", "C"),
            deadline,
        )
        .map_err(|error| format!("cannot audit {label} ACLs: {error}"))?;
        if !audit.status.success() || audit.timed_out || audit.stdout_truncated {
            return Err(format!(
                "cannot audit {label} ACLs with the fixed macOS tool"
            ));
        }
        if audit.stdout.split(|byte| *byte == b'\n').any(|line| {
            let Some(entry) = line.strip_prefix(b" ") else {
                return false;
            };
            let digits = entry
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            digits != 0 && entry.get(digits) == Some(&b':')
        }) {
            return Err(format!("{label} retains a macOS access-control list"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn require_optional_native_deadline(deadline: Option<Instant>, phase: &str) -> Result<(), String> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        Err(format!(
            "staged native toolchain absolute deadline expired before {phase}"
        ))
    } else {
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn require_native_acl_free_until<'a, I>(
    paths: I,
    label: &str,
    deadline: Option<Instant>,
) -> Result<(), String>
where
    I: IntoIterator<Item = &'a Path>,
{
    require_optional_native_deadline(deadline, label)?;
    require_native_acl_free(paths, label)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn require_native_acl_free<'a, I>(paths: I, label: &str) -> Result<(), String>
where
    I: IntoIterator<Item = &'a Path>,
{
    let _ = paths.into_iter();
    let _ = label;
    Ok(())
}

#[cfg(target_os = "macos")]
fn strip_staged_native_acls(root: &Path) -> Result<(), String> {
    strip_staged_native_acls_until(root, None)
}

#[cfg(target_os = "macos")]
fn strip_staged_native_acls_until(root: &Path, deadline: Option<Instant>) -> Result<(), String> {
    run_fixed_macos_chmod_until(
        [OsStr::new("-RN"), root.as_os_str()],
        "remove staged native toolchain ACLs",
        deadline,
    )
}

#[cfg(target_os = "macos")]
fn run_fixed_macos_chmod<I, S>(arguments: I, action: &str) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    run_fixed_macos_chmod_until(arguments, action, None)
}

#[cfg(target_os = "macos")]
fn run_fixed_macos_chmod_until<I, S>(
    arguments: I,
    action: &str,
    deadline: Option<Instant>,
) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let chmod = resolve_absolute_standard_executable(Path::new("/bin/chmod"))
        .map_err(|error| format!("cannot bind fixed macOS ACL tool: {error}"))?;
    chmod
        .revalidate()
        .map_err(|error| format!("fixed macOS ACL tool changed: {error}"))?;
    require_optional_native_deadline(deadline, action)?;
    let timeout = deadline.map_or(Duration::from_secs(30), |deadline| {
        deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(30))
    });
    let result = run_with_optional_native_deadline(
        CommandSpec::new(chmod.invocation_path(), timeout).arguments(arguments),
        deadline,
    )
    .map_err(|error| format!("cannot {action}: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err(format!("fixed macOS ACL tool could not {action}"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_with_optional_native_deadline(
    command: CommandSpec,
    deadline: Option<Instant>,
) -> Result<CommandResult, CommandRunError> {
    match deadline {
        None => command.run(),
        Some(completion_deadline) => {
            let execution_deadline = Instant::now()
                .checked_add(command.timeout)
                .unwrap_or(completion_deadline)
                .min(completion_deadline);
            let completion_deadline = completion_deadline
                .checked_add(STAGED_NATIVE_TOOLCHAIN_CLEANUP_RESERVE)
                .unwrap_or(completion_deadline);
            let (progress, _progress_receiver) = SupervisedProgressObserver::bounded(1);
            command.run_until(execution_deadline, completion_deadline, progress)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn strip_staged_native_acls(_root: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_staged_native_acl_policy_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = Path::new("/private/tmp").join(format!(
        "hell-ci-native-acl-verifier-{}-{sequence}",
        std::process::id()
    ));
    if root.exists() {
        return Err("native ACL verifier root already exists".to_owned());
    }
    fs::create_dir(&root).map_err(|error| format!("cannot create ACL verifier root: {error}"))?;
    let source = root.join("source");
    let destination_parent = root.join("destination-parent");
    let destination = destination_parent.join("staged");
    let result = (|| {
        fs::create_dir(&source)
            .map_err(|error| format!("cannot create ACL verifier source: {error}"))?;
        fs::create_dir(source.join("nested"))
            .map_err(|error| format!("cannot create ACL verifier source child: {error}"))?;
        fs::write(source.join("nested/payload"), b"staged-native-acl-probe\n")
            .map_err(|error| format!("cannot write ACL verifier payload: {error}"))?;
        fs::write(
            source.join("nested/alternate"),
            b"alternate-native-payload\n",
        )
        .map_err(|error| format!("cannot write ACL verifier alternate payload: {error}"))?;
        symlink("nested/payload", source.join("payload-link"))
            .map_err(|error| format!("cannot create ACL verifier symlink: {error}"))?;
        if BoundNativeManifest::bind_internal_with_limits(&source, false, None, false, 2, 128)
            .is_ok()
        {
            return Err("bounded source inventory accepted an oversize tree".to_owned());
        }
        if BoundNativeManifest::bind_internal_with_limits(&source, false, None, false, 32, 1)
            .is_ok()
        {
            return Err("bounded source inventory accepted an over-depth tree".to_owned());
        }
        if BoundNativeManifest::bind_internal_with_limits(
            &source,
            false,
            Some(Instant::now()),
            false,
            32,
            128,
        )
        .is_ok()
        {
            return Err("expired source inventory performed late enumeration".to_owned());
        }
        let base_transaction = StagedNativeToolchainTransaction::new()?;
        let (phase_sender, phase_receiver) = std::sync::mpsc::sync_channel(32);
        let transaction = StagedNativeToolchainTransaction::with_deadlines_and_progress(
            base_transaction.execution_deadline,
            base_transaction.completion_deadline,
            Some(phase_sender),
        )?;
        let source_receipt = BoundNativeManifest::bind_source_inventory_until(&source, None)?;
        let payload_relative = Path::new("nested").join("payload");
        let payload_receipt = source_receipt
            .entries
            .iter()
            .find(|entry| entry.relative == payload_relative)
            .ok_or_else(|| "ACL verifier source payload receipt is absent".to_owned())?;
        let payload_size = usize::try_from(
            fs::symlink_metadata(source.join(&payload_relative))
                .map_err(|error| format!("cannot inspect ACL verifier payload: {error}"))?
                .len(),
        )
        .map_err(|_| "ACL verifier payload size does not fit memory".to_owned())?;
        fs::write(source.join(&payload_relative), vec![b'x'; payload_size])
            .map_err(|error| format!("cannot mutate ACL verifier source payload: {error}"))?;
        if revalidate_native_manifest_entry(&source.join(&payload_relative), payload_receipt, false)
            .is_ok()
        {
            return Err("source content mutation retained its copy authority".to_owned());
        }
        fs::write(source.join(&payload_relative), b"staged-native-acl-probe\n")
            .map_err(|error| format!("cannot restore ACL verifier source payload: {error}"))?;

        let symlink_receipt = BoundNativeManifest::bind_source_inventory_until(&source, None)?;
        let link_relative = Path::new("payload-link");
        let link_receipt = symlink_receipt
            .entries
            .iter()
            .find(|entry| entry.relative == link_relative)
            .ok_or_else(|| "ACL verifier source symlink receipt is absent".to_owned())?;
        fs::remove_file(source.join(link_relative))
            .and_then(|()| symlink("nested/alternate", source.join(link_relative)))
            .map_err(|error| format!("cannot retarget ACL verifier source symlink: {error}"))?;
        if revalidate_native_manifest_entry(&source.join(link_relative), link_receipt, false)
            .is_ok()
        {
            return Err("source symlink retarget retained its copy authority".to_owned());
        }
        fs::remove_file(source.join(link_relative))
            .and_then(|()| symlink("nested/payload", source.join(link_relative)))
            .map_err(|error| format!("cannot restore ACL verifier source symlink: {error}"))?;

        let executable_a = source.join("executable-a");
        let executable_b = source.join("executable-b");
        fs::write(&executable_a, b"executable-a\n")
            .and_then(|()| fs::write(&executable_b, b"executable-b\n"))
            .map_err(|error| format!("cannot create query authority fixture: {error}"))?;
        fs::set_permissions(&executable_a, fs::Permissions::from_mode(0o555))
            .and_then(|()| fs::set_permissions(&executable_b, fs::Permissions::from_mode(0o555)))
            .map_err(|error| format!("cannot freeze query authority fixture: {error}"))?;
        let executable_alias = source.join("executable-alias");
        symlink("executable-a", &executable_alias)
            .map_err(|error| format!("cannot bind query authority fixture: {error}"))?;
        let executable_receipt = BoundNativeFile::bind(&executable_alias, 0o555)?;
        fs::remove_file(&executable_alias)
            .and_then(|()| symlink("executable-b", &executable_alias))
            .map_err(|error| format!("cannot retarget query authority fixture: {error}"))?;
        if executable_receipt
            .revalidate_until(
                "query authority retarget fixture",
                transaction.execution_deadline,
            )
            .is_ok()
        {
            return Err("query executable retarget retained its spawn authority".to_owned());
        }
        fs::create_dir(&destination_parent)
            .map_err(|error| format!("cannot create ACL verifier destination: {error}"))?;
        run_fixed_macos_chmod(
            [
                OsStr::new("+a"),
                OsStr::new("everyone allow write,file_inherit,directory_inherit"),
                destination_parent.as_os_str(),
            ],
            "seed the inherited staged-toolchain ACL",
        )?;

        let manifest = copy_and_freeze_native_directory(&source, &destination, Some(&transaction))?;
        let expected_copy_passes = StagedNativeManifestPassCounts {
            source_inventory: 1,
            source_postflight: 1,
            staged_final: 1,
            query_preflight: 0,
            query_postflight: 0,
        };
        transaction.require_manifest_passes(expected_copy_passes)?;
        let receipts = phase_receiver.try_iter().collect::<Vec<_>>();
        for phase in [
            "source-inventory",
            "freeze-and-acl",
            "source-postflight",
            "staged-final-manifest",
        ] {
            if !receipts.iter().any(|receipt| {
                matches!(receipt, StagedNativeToolchainProgress::Phase(observed) if observed == phase)
            }) {
                return Err(format!("staged copy omitted typed {phase} boundary"));
            }
        }
        if !receipts.iter().any(|receipt| {
            matches!(receipt, StagedNativeToolchainProgress::ManifestPasses(observed) if *observed == expected_copy_passes)
        }) {
            return Err("staged copy omitted its exact typed manifest-pass receipt".to_owned());
        }
        let staged_link = fs::read_link(destination.join("payload-link"))
            .map_err(|error| format!("cannot read staged transaction symlink: {error}"))?;
        if staged_link
            != fs::canonicalize(&destination)
                .map_err(|error| format!("cannot canonicalize staged transaction: {error}"))?
                .join("nested")
                .join("payload")
        {
            return Err("staged transaction symlink target was not relocated exactly".to_owned());
        }
        let expired = Instant::now();
        let expired_transaction = StagedNativeToolchainTransaction {
            execution_deadline: expired,
            completion_deadline: expired,
            phase_sender: None,
            manifest_passes: Cell::new(StagedNativeManifestPassCounts::default()),
        };
        let late_destination = destination_parent.join("late-staged");
        if copy_and_freeze_native_directory(&source, &late_destination, Some(&expired_transaction))
            .is_ok()
            || late_destination.exists()
        {
            return Err("expired staging transaction launched late copy work".to_owned());
        }
        let payload = destination.join("nested/payload");
        run_fixed_macos_chmod(
            [
                OsStr::new("+a"),
                OsStr::new("everyone allow write"),
                payload.as_os_str(),
            ],
            "seed the retained-manifest ACL mutation",
        )?;
        if require_native_acl_free([payload.as_path()], "ACL mutation probe").is_ok() {
            return Err("macOS did not retain the staged ACL mutation probe".to_owned());
        }
        if manifest.revalidate("staged ACL mutation probe").is_ok() {
            return Err("retained staged-toolchain ACL mutation was not rejected".to_owned());
        }
        Ok(())
    })();
    make_native_tree_removable(&destination);
    let _ = run_fixed_macos_chmod(
        [OsStr::new("-RN"), destination_parent.as_os_str()],
        "clean the native ACL verifier",
    );
    let _ = fs::remove_dir_all(&root);
    result
}

#[cfg(unix)]
fn same_native_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.file_type() == right.file_type()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(target_os = "macos")]
fn bind_native_adapter_authorities(
    adapter_root: &Path,
) -> Result<Vec<BoundNativeDirectory>, String> {
    bind_native_adapter_authorities_with_modes(adapter_root, [0o755, 0o700, 0o770])
}

#[cfg(target_os = "macos")]
fn bind_native_adapter_authorities_with_modes(
    adapter_root: &Path,
    modes: [u32; 3],
) -> Result<Vec<BoundNativeDirectory>, String> {
    let work = adapter_root.join(".stack-work");
    let temporary = work.join("tmp");
    let mut authorities = vec![
        BoundNativeDirectory::bind(adapter_root, modes[0])?,
        BoundNativeDirectory::bind(&work, modes[1])?,
        BoundNativeDirectory::bind(&temporary, modes[2])?,
    ];
    let archive = adapter_root.join(".authority");
    match fs::symlink_metadata(&archive) {
        Ok(_) => authorities.push(BoundNativeDirectory::bind(&archive, 0o555)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect native archive authority directory: {error}"
            ));
        }
    }
    Ok(authorities)
}

#[cfg(target_os = "macos")]
fn rebind_sealed_native_adapter_authorities(
    initial: &[BoundNativeDirectory],
    trusted_group: u32,
) -> Result<Vec<BoundNativeDirectory>, String> {
    let adapter_root = initial
        .first()
        .ok_or_else(|| "initial native archive adapter authority is absent".to_owned())?;
    let sealed =
        bind_native_adapter_authorities_with_modes(&adapter_root.path, [0o2755, 0o3770, 0o2770])?;
    if sealed.len() != initial.len() {
        return Err("sealed native archive adapter authority inventory changed".to_owned());
    }
    for (position, (before, after)) in initial.iter().zip(&sealed).enumerate() {
        let same_object = before.path == after.path
            && before.device == after.device
            && before.inode == after.inode
            && before.uid == after.uid;
        if position < 3 {
            if !same_object || after.gid != trusted_group {
                return Err(
                    "sealed native archive adapter authority identity differs from its initial receipt"
                        .to_owned(),
                );
            }
        } else if before != after {
            return Err(
                "native archive archiver authority changed during the trusted seal transition"
                    .to_owned(),
            );
        }
    }
    Ok(sealed)
}

impl StagedNativeGhcProvenance {
    #[cfg(unix)]
    fn revalidate(&self, staged_root: &Path) -> Result<(), String> {
        if self.version != PINNED_NATIVE_GHC_VERSION {
            return Err("staged GHC version differs from policy".to_owned());
        }
        for (path, label, directory) in [
            (&self.libdir, "libdir", true),
            (&self.settings, "settings", false),
            (&self.package_db, "global package database", true),
        ] {
            let canonical = fs::canonicalize(path)
                .map_err(|error| format!("cannot revalidate staged GHC {label}: {error}"))?;
            let metadata = fs::symlink_metadata(&canonical)
                .map_err(|error| format!("cannot inspect staged GHC {label}: {error}"))?;
            if canonical != *path
                || !canonical.starts_with(staged_root)
                || canonical.starts_with(&self.source_root)
                || metadata.file_type().is_symlink()
                || (directory && !metadata.is_dir())
                || (!directory && !metadata.is_file())
            {
                return Err(format!("staged GHC {label} differs from policy"));
            }
        }
        Ok(())
    }
}

impl BoundNativeDirectory {
    #[cfg(target_os = "macos")]
    fn bind(path: &Path, expected_mode: u32) -> Result<Self, String> {
        Self::bind_with_deadline(path, expected_mode, None)
    }

    #[cfg(target_os = "macos")]
    fn bind_until(path: &Path, expected_mode: u32, deadline: Instant) -> Result<Self, String> {
        Self::bind_with_deadline(path, expected_mode, Some(deadline))
    }

    #[cfg(target_os = "macos")]
    fn bind_with_deadline(
        path: &Path,
        expected_mode: u32,
        deadline: Option<Instant>,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        require_optional_native_deadline(deadline, "staged native directory bind")?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect staged toolchain directory: {error}"))?;
        let mode = metadata.mode() & 0o7777;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || mode != expected_mode {
            return Err("staged toolchain directory differs from policy".to_owned());
        }
        require_native_acl_free_until([path], "staged native directory", deadline)?;
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode,
        })
    }

    #[cfg(unix)]
    fn revalidate(&self, label: &str) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot revalidate {label}: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() & 0o7777 != self.mode
        {
            return Err(format!("{label} identity changed before use"));
        }
        require_native_acl_free([self.path.as_path()], label)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn revalidate_until(&self, label: &str, deadline: Instant) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        require_optional_native_deadline(Some(deadline), label)?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot revalidate {label}: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() & 0o7777 != self.mode
        {
            return Err(format!("{label} identity changed before use"));
        }
        require_native_acl_free_until([self.path.as_path()], label, Some(deadline))
    }
}

impl BoundNativeFile {
    #[cfg(target_os = "macos")]
    fn bind(invocation: &Path, expected_mode: u32) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        let canonical = fs::canonicalize(invocation)
            .map_err(|error| format!("cannot canonicalize staged executable: {error}"))?;
        let metadata = fs::metadata(invocation)
            .map_err(|error| format!("cannot inspect staged executable: {error}"))?;
        let mode = metadata.mode() & 0o7777;
        if !metadata.is_file() || mode != expected_mode {
            return Err("staged executable differs from policy".to_owned());
        }
        require_native_acl_free([invocation], "staged native executable")?;
        Ok(Self {
            invocation: invocation.to_owned(),
            canonical,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode,
            size: metadata.len(),
            sha256: sha256_file(invocation)
                .map_err(|error| format!("cannot hash staged executable: {error}"))?,
        })
    }

    #[cfg(unix)]
    fn revalidate(&self, label: &str) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        let canonical = fs::canonicalize(&self.invocation)
            .map_err(|error| format!("cannot canonicalize {label}: {error}"))?;
        let metadata = fs::metadata(&self.invocation)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        let digest = sha256_file(&self.invocation)
            .map_err(|error| format!("cannot hash {label}: {error}"))?;
        if canonical != self.canonical
            || !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() & 0o7777 != self.mode
            || metadata.len() != self.size
            || digest != self.sha256
        {
            return Err(format!("{label} identity changed before use"));
        }
        require_native_acl_free([self.invocation.as_path()], label)?;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn revalidate_until(&self, label: &str, deadline: Instant) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        require_optional_native_deadline(Some(deadline), label)?;
        let canonical = fs::canonicalize(&self.invocation)
            .map_err(|error| format!("cannot canonicalize {label}: {error}"))?;
        let metadata = fs::metadata(&self.invocation)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        if canonical != self.canonical
            || !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() & 0o7777 != self.mode
            || metadata.len() != self.size
            || sha256_file_until(&self.invocation, deadline)? != self.sha256
        {
            return Err(format!("{label} identity changed before use"));
        }
        require_native_acl_free_until([self.invocation.as_path()], label, Some(deadline))
    }
}

impl BoundNativeArchiver {
    #[cfg(target_os = "macos")]
    pub(crate) fn bind_existing_for_publisher(path: &Path) -> Result<Self, String> {
        Self::bind_existing_with_owner_authority(
            path,
            NativeArchiverOwnerAuthority::TrustedPublisher {
                uid: nix::unistd::geteuid().as_raw(),
            },
        )
    }

    #[cfg(target_os = "macos")]
    fn bind_existing_with_owner_authority(
        path: &Path,
        owner_authority: NativeArchiverOwnerAuthority,
    ) -> Result<Self, String> {
        let transaction = NativeArchiverTransaction::new()?;
        Self::bind_existing_with_owner_authority_and_transaction(path, owner_authority, transaction)
    }

    #[cfg(target_os = "macos")]
    fn bind_existing_with_owner_authority_and_transaction(
        path: &Path,
        owner_authority: NativeArchiverOwnerAuthority,
        transaction: NativeArchiverTransaction,
    ) -> Result<Self, String> {
        let distribution = path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "staged LLVM archiver has no distribution root".to_owned())?;
        let otool = resolve_absolute_standard_executable(Path::new("/usr/bin/otool"))?;
        let (_, load_graph, external_dependencies) = acquire_native_archiver_load_graph(
            path,
            distribution,
            &otool,
            &transaction,
            &owner_authority,
        )?;
        Self::bind(
            path,
            load_graph,
            external_dependencies,
            otool,
            Some((
                transaction.execution_deadline,
                transaction.completion_deadline,
            )),
        )
    }

    #[cfg(target_os = "macos")]
    fn bind(
        path: &Path,
        load_graph: NativeArchiverLoadGraph,
        external_dependencies: Vec<BoundNativeArchiverDependency>,
        otool: ResolvedStandardExecutable,
        deadlines: Option<(Instant, Instant)>,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect staged LLVM archiver: {error}"))?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot canonicalize staged LLVM archiver: {error}"))?;
        let mode = metadata.mode() & 0o7777;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || mode & 0o111 == 0
            || mode & 0o6000 != 0
            || metadata.nlink() != 1
        {
            return Err("native-archiver-source stage predicate staged-metadata failed".to_owned());
        }
        let distribution_root = path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "staged LLVM archiver has no distribution root".to_owned())?;
        let (execution_deadline, completion_deadline) = match deadlines {
            Some(deadlines) => deadlines,
            None => {
                let execution_deadline = Instant::now()
                    .checked_add(Duration::from_secs(30))
                    .ok_or_else(|| "native archiver binding deadline overflowed".to_owned())?;
                (
                    execution_deadline,
                    execution_deadline
                        .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
                        .unwrap_or(execution_deadline),
                )
            }
        };
        let distribution =
            BoundNativeManifest::bind_until(distribution_root, true, Some(execution_deadline))?;
        let distribution = BoundSealedNativeManifest::bind(distribution, execution_deadline)?;
        require_native_acl_free_until([path], "staged LLVM archiver", Some(execution_deadline))?;
        let bound = Self {
            path: path.to_owned(),
            canonical,
            distribution,
            load_graph,
            external_dependencies,
            otool,
            validation_passes: Arc::new(NativeArchiverValidationPassCounters {
                full_closure: AtomicU64::new(1),
                load_graph: AtomicU64::new(0),
                spawn_preflight: AtomicU64::new(0),
            }),
            sha256: sha256_file_until_with_label(
                path,
                execution_deadline,
                "staged LLVM archiver program hash",
            )?,
        };
        bound.revalidate_until(execution_deadline, completion_deadline)?;
        let transaction = NativeArchiverTransaction {
            execution_deadline,
            completion_deadline,
        };
        for dependency in &bound.external_dependencies {
            dependency.revalidate_full_until(transaction)?;
        }
        let observed = inspect_native_archiver_load_graph(
            &bound.path,
            &bound.distribution.root,
            &bound.otool,
            &bound.external_dependencies,
            Some((execution_deadline, completion_deadline)),
        )?;
        bound
            .validation_passes
            .load_graph
            .fetch_add(1, Ordering::Relaxed);
        if observed != bound.load_graph {
            return Err("staged LLVM archiver load graph changed after staging".to_owned());
        }
        Ok(bound)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| "native archiver revalidation deadline overflowed".to_owned())?;
        let completion_deadline = deadline
            .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
            .unwrap_or(deadline);
        self.revalidate_until(deadline, completion_deadline)
    }

    #[cfg(target_os = "macos")]
    fn revalidate_for_spawn(&self) -> Result<(), String> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| "native archiver revalidation deadline overflowed".to_owned())?;
        let completion_deadline = deadline
            .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
            .unwrap_or(deadline);
        self.revalidate_for_spawn_until(deadline, completion_deadline)
    }

    #[cfg(target_os = "macos")]
    fn revalidate_until(
        &self,
        execution_deadline: Instant,
        completion_deadline: Instant,
    ) -> Result<(), String> {
        require_optional_native_deadline(
            Some(execution_deadline),
            "staged LLVM archiver revalidation",
        )?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot revalidate staged LLVM archiver: {error}"))?;
        let canonical = fs::canonicalize(&self.path)
            .map_err(|error| format!("cannot canonicalize staged LLVM archiver: {error}"))?;
        let digest = sha256_file_until_with_label(
            &self.path,
            execution_deadline,
            "staged LLVM archiver program hash",
        )?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || canonical != self.canonical
            || digest != self.sha256
        {
            return Err("native-archiver-source stage predicate staged-identity failed".to_owned());
        }
        self.distribution
            .revalidate_until("staged LLVM archiver distribution", execution_deadline)?;
        let transaction = NativeArchiverTransaction {
            execution_deadline,
            completion_deadline,
        };
        for dependency in &self.external_dependencies {
            dependency.revalidate_until(transaction)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn revalidate_for_spawn_until(
        &self,
        execution_deadline: Instant,
        completion_deadline: Instant,
    ) -> Result<(), String> {
        self.revalidate_until(execution_deadline, completion_deadline)?;
        self.validation_passes
            .spawn_preflight
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn revalidate_for_brokered_spawn_until(&self, deadline: Instant) -> Result<(), String> {
        require_optional_native_deadline(Some(deadline), "brokered LLVM archiver revalidation")?;
        let relative_archiver = self
            .path
            .strip_prefix(&self.distribution.root)
            .map_err(|_| "brokered LLVM archiver escapes its sealed distribution".to_owned())?;
        self.distribution.revalidate_member_chain_until(
            relative_archiver,
            "brokered LLVM archiver",
            deadline,
        )?;
        if sha256_file_until_with_label(
            &self.path,
            deadline,
            "brokered LLVM archiver program hash",
        )? != self.sha256
        {
            return Err("brokered LLVM archiver program content changed".to_owned());
        }
        for edge in &self.load_graph.edges {
            if let NativeArchiverLoadTarget::Staged(relative) = &edge.target {
                self.distribution.revalidate_member_chain_until(
                    relative,
                    "brokered LLVM dependency",
                    deadline,
                )?;
            }
        }
        let transaction = NativeArchiverTransaction {
            execution_deadline: deadline,
            completion_deadline: deadline,
        };
        for dependency in &self.external_dependencies {
            dependency.revalidate_until(transaction)?;
        }
        self.validation_passes
            .spawn_preflight
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(target_os = "macos")]
    fn command<I, S>(&self, timeout: Duration, arguments: I) -> CommandSpec
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let mut command = CommandSpec::new(&self.canonical, timeout).arguments(arguments);
        command.canonical_executable_identity = Some(self.canonical.clone());
        command.invocation_name = Some(OsString::from("llvm-ar"));
        command.native_archiver = Some(self.clone());
        command
    }
}

#[cfg(target_os = "macos")]
impl BoundNativeArchiverDependency {
    fn bind_until(
        path: &Path,
        transaction: NativeArchiverTransaction,
        owner_authority: &NativeArchiverOwnerAuthority,
    ) -> Result<Self, String> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        transaction.require_execution("Mach-O dependency binding")?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot canonicalize Mach-O dependency: {error}"))?;
        let guard = Arc::new(
            fs::File::open(&canonical)
                .map_err(|error| format!("cannot open Mach-O dependency: {error}"))?,
        );
        let metadata = guard
            .metadata()
            .map_err(|error| format!("cannot inspect Mach-O dependency: {error}"))?;
        let mode = metadata.mode() & 0o7777;
        if !metadata.is_file()
            || !owner_authority.admits_owner(metadata.uid())
            || !owner_authority.permits_file_mode(metadata.uid(), metadata.gid(), mode)
            || mode & 0o6000 != 0
            || metadata.len() == 0
        {
            return Err("Mach-O dependency does not satisfy the source predicate".to_owned());
        }
        let mut ancestor_paths = BTreeMap::<PathBuf, ()>::new();
        for terminal in [path, canonical.as_path()] {
            let parent = terminal
                .parent()
                .ok_or_else(|| "Mach-O dependency has no parent authority".to_owned())?;
            let mut current = PathBuf::new();
            for component in parent.components() {
                current.push(component.as_os_str());
                ancestor_paths.insert(current.clone(), ());
            }
        }
        if fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect Mach-O dependency logical leaf: {error}"))?
            .file_type()
            .is_symlink()
        {
            ancestor_paths.insert(path.to_owned(), ());
        }
        let mut ancestors = Vec::new();
        for path in ancestor_paths.into_keys() {
            transaction.require_execution("Mach-O dependency ancestor binding")?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect Mach-O dependency ancestor: {error}"))?;
            let symlink_target = if metadata.file_type().is_symlink() {
                Some(fs::read_link(&path).map_err(|error| {
                    format!("cannot read Mach-O dependency ancestor symlink: {error}")
                })?)
            } else {
                None
            };
            let guard = if symlink_target.is_some() {
                None
            } else {
                Some(Arc::new(
                    fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(nix::libc::O_NOFOLLOW)
                        .open(&path)
                        .map_err(|error| {
                            format!("cannot open Mach-O dependency ancestor: {error}")
                        })?,
                ))
            };
            let handle = match &guard {
                Some(guard) => guard.metadata().map_err(|error| {
                    format!("cannot inspect Mach-O dependency ancestor handle: {error}")
                })?,
                None => metadata.clone(),
            };
            let ancestor_mode = metadata.mode() & 0o7777;
            if (!metadata.file_type().is_symlink() && !handle.is_dir())
                || metadata.dev() != handle.dev()
                || metadata.ino() != handle.ino()
                || (symlink_target.is_none()
                    && (!owner_authority.admits_owner(metadata.uid())
                        || !owner_authority.permits_ancestor_mode(
                            metadata.uid(),
                            metadata.gid(),
                            ancestor_mode,
                            metadata.is_dir(),
                        )))
            {
                return Err(format!(
                    "Mach-O dependency ancestor does not satisfy the authority predicate: path={},uid={},gid={},mode=0o{ancestor_mode:04o},authority={owner_authority:?}",
                    path.display(),
                    metadata.uid(),
                    metadata.gid(),
                ));
            }
            ancestors.push(BoundNativeArchiverAncestor {
                guard,
                path,
                symlink_target,
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: ancestor_mode,
            });
        }
        require_native_archiver_acl_free(
            ancestors
                .iter()
                .map(|ancestor| ancestor.path.as_path())
                .chain(std::iter::once(canonical.as_path())),
            "Mach-O dependency authority",
            transaction,
        )?;
        Ok(Self {
            guard,
            ancestors,
            path: path.to_owned(),
            canonical: canonical.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode,
            size: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
            sha256: sha256_file_until(&canonical, transaction.execution_deadline)?,
        })
    }

    fn revalidate(&self) -> Result<(), String> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| "Mach-O dependency deadline overflowed".to_owned())?;
        let completion_deadline = deadline
            .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
            .unwrap_or(deadline);
        self.revalidate_full_until(NativeArchiverTransaction {
            execution_deadline: deadline,
            completion_deadline,
        })
    }

    fn revalidate_full_until(&self, transaction: NativeArchiverTransaction) -> Result<(), String> {
        self.revalidate_until(transaction)?;
        if sha256_file_until_with_label(
            &self.canonical,
            transaction.execution_deadline,
            "Mach-O dependency hash",
        )? != self.sha256
        {
            return Err("Mach-O dependency content changed before use".to_owned());
        }
        Ok(())
    }

    fn revalidate_until(&self, transaction: NativeArchiverTransaction) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        transaction.require_execution("Mach-O dependency revalidation")?;
        let handle = self
            .guard
            .metadata()
            .map_err(|error| format!("cannot revalidate Mach-O dependency handle: {error}"))?;
        let canonical = fs::canonicalize(&self.path)
            .map_err(|error| format!("cannot revalidate Mach-O dependency path: {error}"))?;
        let path = fs::metadata(&self.path)
            .map_err(|error| format!("cannot inspect Mach-O dependency path: {error}"))?;
        if canonical != self.canonical
            || handle.dev() != self.device
            || handle.ino() != self.inode
            || path.dev() != self.device
            || path.ino() != self.inode
            || handle.uid() != self.uid
            || handle.gid() != self.gid
            || handle.mode() & 0o7777 != self.mode
            || handle.len() != self.size
            || handle.mtime() != self.modified_seconds
            || handle.mtime_nsec() != self.modified_nanoseconds
            || handle.ctime() != self.changed_seconds
            || handle.ctime_nsec() != self.changed_nanoseconds
        {
            return Err("Mach-O dependency identity changed before use".to_owned());
        }
        for ancestor in &self.ancestors {
            transaction.require_execution("Mach-O dependency ancestor revalidation")?;
            let handle = match &ancestor.guard {
                Some(guard) => Some(guard.metadata().map_err(|error| {
                    format!("cannot revalidate Mach-O dependency ancestor handle: {error}")
                })?),
                None => None,
            };
            let path = fs::symlink_metadata(&ancestor.path).map_err(|error| {
                format!("cannot revalidate Mach-O dependency ancestor path: {error}")
            })?;
            let symlink_target = if path.file_type().is_symlink() {
                Some(fs::read_link(&ancestor.path).map_err(|error| {
                    format!("cannot revalidate Mach-O dependency ancestor symlink: {error}")
                })?)
            } else {
                None
            };
            if symlink_target != ancestor.symlink_target
                || (symlink_target.is_none() && !path.is_dir())
                || handle
                    .as_ref()
                    .is_some_and(|handle| handle.dev() != ancestor.device)
                || handle
                    .as_ref()
                    .is_some_and(|handle| handle.ino() != ancestor.inode)
                || path.dev() != ancestor.device
                || path.ino() != ancestor.inode
                || path.uid() != ancestor.uid
                || path.gid() != ancestor.gid
                || path.mode() & 0o7777 != ancestor.mode
            {
                return Err("Mach-O dependency ancestor identity changed before use".to_owned());
            }
        }
        require_native_archiver_acl_free(
            self.ancestors
                .iter()
                .map(|ancestor| ancestor.path.as_path())
                .chain(std::iter::once(self.canonical.as_path())),
            "Mach-O dependency authority",
            transaction,
        )?;
        Ok(())
    }
}

pub(crate) struct NativeStackProvenance {
    pub(crate) source: PathBuf,
    pub(crate) source_commit: &'static str,
    pub(crate) stack_yaml_sha256: Digest,
    pub(crate) stack_lock_sha256: Digest,
    pub(crate) effective_stack_yaml: PathBuf,
    pub(crate) effective_stack_yaml_sha256: Digest,
    pub(crate) llvm_ar: Option<PathBuf>,
    pub(crate) llvm_ar_sha256: Option<Digest>,
    pub(crate) llvm_ar_version: Option<String>,
}

struct AdapterDirectory {
    path: PathBuf,
    #[cfg(target_os = "macos")]
    cleanup_root: Option<BoundNativeCleanupRoot>,
}

impl AdapterDirectory {
    fn path(&self) -> &Path {
        &self.path
    }

    fn close(&mut self) -> Result<(), String> {
        #[cfg(not(target_os = "macos"))]
        {
            fs::remove_dir_all(&self.path)
                .map_err(|error| format!("cannot remove native adapter directory: {error}"))?;
            Ok(())
        }
        #[cfg(target_os = "macos")]
        {
            let transaction = StagedNativeToolchainTransaction::cleanup_only()?;
            self.close_with_transaction(&transaction)
        }
    }

    #[cfg(target_os = "macos")]
    fn close_until(&mut self, completion_deadline: Instant) -> Result<(), String> {
        let transaction = StagedNativeToolchainTransaction {
            execution_deadline: Instant::now(),
            completion_deadline,
            phase_sender: None,
            manifest_passes: Cell::new(StagedNativeManifestPassCounts::default()),
        };
        self.close_with_transaction(&transaction)
    }

    #[cfg(target_os = "macos")]
    fn close_with_transaction(
        &mut self,
        transaction: &StagedNativeToolchainTransaction,
    ) -> Result<(), String> {
        let Some(cleanup_root) = self.cleanup_root.take() else {
            return Ok(());
        };
        match fs::symlink_metadata(&cleanup_root.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                cleanup_root.require_absent(transaction.completion_deadline)?;
            }
            Ok(_) => remove_native_tree_until(&cleanup_root, transaction)?,
            Err(error) => {
                return Err(format!(
                    "cannot inspect native adapter before cleanup: {error}"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn native_archive_adapter_constructor_failure<T>(
    primary: String,
    cleanup: Result<(), String>,
) -> Result<T, String> {
    match cleanup {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(format!(
            "{primary}; native archive adapter constructor cleanup also failed: {cleanup}"
        )),
    }
}

impl Drop for AdapterDirectory {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {}
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            use std::os::unix::fs::PermissionsExt as _;

            make_native_tree_removable(&self.path.join(".toolchain/system-ghc-9.8.2"));
            make_native_tree_removable(&self.path.join(".toolchain/system-tools"));
            let authority = self.path.join(".authority");
            if fs::symlink_metadata(&authority).is_ok_and(|metadata| metadata.is_dir())
                && fs::set_permissions(&authority, fs::Permissions::from_mode(0o755)).is_err()
            {
                return;
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn make_native_tree_removable(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        _ => return,
    }
    let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
    let children = match fs::read_dir(root) {
        Ok(children) => children,
        Err(_) => return,
    };
    for child in children.flatten() {
        make_native_tree_removable(&child.path());
    }
}

static ADAPTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const PINNED_NATIVE_GHC_VERSION: &str = "9.8.2";
#[cfg(target_os = "macos")]
const PINNED_NATIVE_GHC_PAYLOAD: &str = "ghc-9.8.2";
const NATIVE_GHC_ENTRY_LIMIT: usize = 250_000;
const NATIVE_GHC_BYTE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
const NATIVE_GHC_DEPTH_LIMIT: usize = 128;
#[cfg(target_os = "macos")]
const STAGED_NATIVE_TOOLCHAIN_TIMEOUT: Duration = Duration::from_secs(20 * 60);
#[cfg(target_os = "macos")]
const STAGED_NATIVE_TOOLCHAIN_CLEANUP_RESERVE: Duration = Duration::from_secs(2 * 60);
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVER_EXECUTION_BUDGET: Duration = Duration::from_secs(90);
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVER_COMPLETION_BUDGET: Duration = Duration::from_secs(2 * 60);

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeArchiveAdapterConstructionEnvelope {
    execution_deadline: Instant,
    completion_deadline: Instant,
    archiver_execution_deadline: Instant,
    archiver_completion_deadline: Instant,
}

#[cfg(target_os = "macos")]
impl NativeArchiveAdapterConstructionEnvelope {
    pub(crate) fn new() -> Result<Self, String> {
        let started = Instant::now();
        let completion_deadline = started
            .checked_add(STAGED_NATIVE_TOOLCHAIN_TIMEOUT)
            .ok_or_else(|| "native archive adapter construction deadline overflowed".to_owned())?;
        let execution_deadline = completion_deadline
            .checked_sub(STAGED_NATIVE_TOOLCHAIN_CLEANUP_RESERVE)
            .ok_or_else(|| {
                "native archive adapter construction cleanup reserve underflowed".to_owned()
            })?;
        let archiver_execution_deadline = started
            .checked_add(NATIVE_ARCHIVER_EXECUTION_BUDGET)
            .ok_or_else(|| "native archiver execution deadline overflowed".to_owned())?;
        let archiver_completion_deadline =
            started
                .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
                .ok_or_else(|| "native archiver completion deadline overflowed".to_owned())?;
        Self::with_deadlines(
            execution_deadline,
            completion_deadline,
            archiver_execution_deadline,
            archiver_completion_deadline,
        )
    }

    pub(crate) fn with_deadlines(
        execution_deadline: Instant,
        completion_deadline: Instant,
        archiver_execution_deadline: Instant,
        archiver_completion_deadline: Instant,
    ) -> Result<Self, String> {
        if Instant::now() >= archiver_execution_deadline
            || archiver_execution_deadline >= archiver_completion_deadline
            || archiver_completion_deadline > execution_deadline
            || execution_deadline >= completion_deadline
        {
            return Err("native archive adapter construction deadlines are not ordered".to_owned());
        }
        Ok(Self {
            execution_deadline,
            completion_deadline,
            archiver_execution_deadline,
            archiver_completion_deadline,
        })
    }

    fn archiver_transaction(self) -> Result<NativeArchiverTransaction, String> {
        if Instant::now() >= self.archiver_execution_deadline
            || self.archiver_execution_deadline >= self.archiver_completion_deadline
        {
            return Err("native archiver sub-deadlines are not ordered".to_owned());
        }
        Ok(NativeArchiverTransaction {
            execution_deadline: self.archiver_execution_deadline,
            completion_deadline: self.archiver_completion_deadline,
        })
    }

    fn toolchain_transaction(self) -> Result<StagedNativeToolchainTransaction, String> {
        StagedNativeToolchainTransaction::with_deadlines(
            self.execution_deadline,
            self.completion_deadline,
        )
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct NativeArchiverTransaction {
    execution_deadline: Instant,
    completion_deadline: Instant,
}

#[cfg(target_os = "macos")]
impl NativeArchiverTransaction {
    fn new() -> Result<Self, String> {
        let started = Instant::now();
        let execution_deadline = started
            .checked_add(NATIVE_ARCHIVER_EXECUTION_BUDGET)
            .ok_or_else(|| "native archiver execution deadline overflowed".to_owned())?;
        let completion_deadline = started
            .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
            .ok_or_else(|| "native archiver completion deadline overflowed".to_owned())?;
        Ok(Self {
            execution_deadline,
            completion_deadline,
        })
    }

    fn require_execution(&self, phase: &str) -> Result<(), String> {
        if Instant::now() >= self.execution_deadline {
            Err(format!(
                "native archiver absolute deadline expired before {phase}"
            ))
        } else {
            Ok(())
        }
    }

    fn command_deadline(&self, timeout: Duration) -> Result<Instant, String> {
        self.require_execution("command launch")?;
        Ok(Instant::now()
            .checked_add(timeout)
            .unwrap_or(self.execution_deadline)
            .min(self.execution_deadline))
    }

    fn run(&self, mut command: CommandSpec) -> Result<CommandResult, CommandRunError> {
        let execution_deadline = self.command_deadline(command.timeout).map_err(|error| {
            CommandRunError::new(
                CommandRunPhase::ProgramResolution,
                std::io::Error::new(std::io::ErrorKind::TimedOut, error),
            )
        })?;
        command.native_archiver_deadlines = Some((execution_deadline, self.completion_deadline));
        let (progress, _receiver) = SupervisedProgressObserver::bounded(1);
        command.run_until(execution_deadline, self.completion_deadline, progress)
    }
}

#[cfg(target_os = "macos")]
fn require_native_archiver_acl_free<'a, I>(
    paths: I,
    label: &str,
    transaction: NativeArchiverTransaction,
) -> Result<(), String>
where
    I: IntoIterator<Item = &'a Path>,
{
    const ACL_AUDIT_BATCH_SIZE: usize = 256;

    let ls = resolve_absolute_standard_executable(Path::new("/bin/ls"))
        .map_err(|error| format!("cannot bind fixed macOS ACL audit tool: {error}"))?;
    let paths = paths.into_iter().collect::<Vec<_>>();
    for batch in paths.chunks(ACL_AUDIT_BATCH_SIZE) {
        transaction.require_execution("native archiver ACL audit")?;
        ls.revalidate()
            .map_err(|error| format!("fixed macOS ACL audit tool changed: {error}"))?;
        let timeout = transaction
            .execution_deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(30));
        if timeout.is_zero() {
            return Err("native archiver ACL audit exceeded its absolute deadline".to_owned());
        }
        let audit = transaction
            .run(
                CommandSpec::new(ls.invocation_path(), timeout)
                    .arguments(["-lde"])
                    .arguments(batch.iter().copied().map(Path::as_os_str))
                    .environment("LC_ALL", "C"),
            )
            .map_err(|error| format!("cannot audit {label} ACLs: {error}"))?;
        if !audit.status.success() || audit.timed_out || audit.stdout_truncated {
            return Err(format!(
                "cannot audit {label} ACLs with the fixed macOS tool"
            ));
        }
        if audit.stdout.split(|byte| *byte == b'\n').any(|line| {
            let Some(entry) = line.strip_prefix(b" ") else {
                return false;
            };
            let digits = entry
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            digits != 0 && entry.get(digits) == Some(&b':')
        }) {
            return Err(format!("{label} retains a macOS access-control list"));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
struct StagedNativeToolchainTransaction {
    execution_deadline: Instant,
    completion_deadline: Instant,
    phase_sender: Option<SyncSender<StagedNativeToolchainProgress>>,
    manifest_passes: Cell<StagedNativeManifestPassCounts>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StagedNativeManifestPassCounts {
    pub(crate) source_inventory: u32,
    pub(crate) source_postflight: u32,
    pub(crate) staged_final: u32,
    pub(crate) query_preflight: u32,
    pub(crate) query_postflight: u32,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
pub(crate) enum StagedNativeToolchainProgress {
    Phase(String),
    ManifestPasses(StagedNativeManifestPassCounts),
}

#[cfg(target_os = "macos")]
struct BoundNativeCleanupRoot {
    path: PathBuf,
    guard: fs::File,
    parent_guard: fs::File,
    parent: BoundNativeDirectory,
    device: u64,
    inode: u64,
}

#[cfg(target_os = "macos")]
struct BoundNativeCleanupFile {
    path: PathBuf,
    guard: fs::File,
    parent_guard: fs::File,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    parent_device: u64,
    parent_inode: u64,
}

#[cfg(target_os = "macos")]
impl BoundNativeCleanupFile {
    fn bind(path: &Path, deadline: Instant) -> Result<Self, String> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        require_optional_native_deadline(Some(deadline), "verifier launcher bind")?;
        let parent = path
            .parent()
            .ok_or_else(|| "verifier launcher has no parent".to_owned())?;
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|error| format!("cannot canonicalize verifier launcher parent: {error}"))?;
        let leaf = path
            .file_name()
            .ok_or_else(|| "verifier launcher has no leaf".to_owned())?;
        let path = canonical_parent.join(leaf);
        let parent_guard = fs::File::open(&canonical_parent)
            .map_err(|error| format!("cannot retain verifier launcher parent: {error}"))?;
        let guard = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| format!("cannot retain verifier launcher: {error}"))?;
        let metadata = guard
            .metadata()
            .map_err(|error| format!("cannot bind verifier launcher: {error}"))?;
        let parent_metadata = parent_guard
            .metadata()
            .map_err(|error| format!("cannot bind verifier launcher parent: {error}"))?;
        if !metadata.is_file()
            || !parent_metadata.is_dir()
            || fs::canonicalize(&path).ok().as_deref() != Some(path.as_path())
        {
            return Err("verifier launcher is redirected".to_owned());
        }
        require_optional_native_deadline(Some(deadline), "verifier launcher bind")?;
        Ok(Self {
            path,
            guard,
            parent_guard,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            size: metadata.len(),
            parent_device: parent_metadata.dev(),
            parent_inode: parent_metadata.ino(),
        })
    }

    fn remove_until(&self, deadline: Instant) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        require_optional_native_deadline(Some(deadline), "verifier launcher cleanup")?;
        let retained = self
            .guard
            .metadata()
            .map_err(|error| format!("cannot revalidate retained verifier launcher: {error}"))?;
        let retained_parent = self.parent_guard.metadata().map_err(|error| {
            format!("cannot revalidate retained verifier launcher parent: {error}")
        })?;
        let current = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot revalidate verifier launcher: {error}"))?;
        if !retained.is_file()
            || retained.dev() != self.device
            || retained.ino() != self.inode
            || retained.uid() != self.uid
            || retained.gid() != self.gid
            || retained.mode() & 0o7777 != self.mode
            || retained.len() != self.size
            || !retained_parent.is_dir()
            || retained_parent.dev() != self.parent_device
            || retained_parent.ino() != self.parent_inode
            || current.file_type().is_symlink()
            || !current.is_file()
            || current.dev() != self.device
            || current.ino() != self.inode
            || current.uid() != self.uid
            || current.gid() != self.gid
            || current.mode() & 0o7777 != self.mode
            || current.len() != self.size
        {
            return Err("verifier launcher identity changed before cleanup".to_owned());
        }
        fs::remove_file(&self.path)
            .map_err(|error| format!("cannot remove verifier launcher: {error}"))?;
        require_optional_native_deadline(Some(deadline), "verifier launcher absence")?;
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err("verifier launcher remains after cleanup".to_owned()),
            Err(error) => Err(format!("cannot attest verifier launcher absence: {error}")),
        }
    }
}

#[cfg(target_os = "macos")]
impl BoundNativeCleanupRoot {
    fn bind(path: &Path, deadline: Instant) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        require_optional_native_deadline(Some(deadline), "staged cleanup root bind")?;
        let parent = path
            .parent()
            .ok_or_else(|| "staged cleanup root has no parent".to_owned())?;
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|error| format!("cannot canonicalize staged cleanup parent: {error}"))?;
        let file_name = path
            .file_name()
            .ok_or_else(|| "staged cleanup root has no leaf".to_owned())?;
        let path = canonical_parent.join(file_name);
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("cannot canonicalize staged cleanup root: {error}"))?;
        let parent_guard = fs::File::open(&canonical_parent)
            .map_err(|error| format!("cannot retain staged cleanup parent: {error}"))?;
        let guard = fs::File::open(&path)
            .map_err(|error| format!("cannot retain staged cleanup root: {error}"))?;
        let metadata = guard
            .metadata()
            .map_err(|error| format!("cannot bind staged cleanup root: {error}"))?;
        if canonical != path || metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("staged cleanup root is redirected".to_owned());
        }
        let parent_mode = fs::symlink_metadata(&canonical_parent)
            .map_err(|error| format!("cannot inspect staged cleanup parent: {error}"))?
            .mode()
            & 0o7777;
        Ok(Self {
            path,
            guard,
            parent_guard,
            parent: BoundNativeDirectory::bind_until(&canonical_parent, parent_mode, deadline)?,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn revalidate(&self, deadline: Instant) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        self.revalidate_handles(deadline)?;
        self.parent
            .revalidate_until("staged cleanup parent", deadline)?;
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot revalidate staged cleanup root: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || fs::canonicalize(&self.path).ok().as_deref() != Some(self.path.as_path())
        {
            return Err("staged cleanup root identity changed".to_owned());
        }
        Ok(())
    }

    fn require_absent(&self, deadline: Instant) -> Result<(), String> {
        self.revalidate_handles(deadline)?;
        self.parent
            .revalidate_until("staged cleanup parent", deadline)?;
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err("staged cleanup root remains after cleanup".to_owned()),
            Err(error) => Err(format!("cannot attest staged cleanup absence: {error}")),
        }
    }

    fn revalidate_handles(&self, deadline: Instant) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        require_optional_native_deadline(Some(deadline), "staged cleanup retained handles")?;
        let root = self
            .guard
            .metadata()
            .map_err(|error| format!("cannot revalidate retained cleanup root: {error}"))?;
        let parent = self
            .parent_guard
            .metadata()
            .map_err(|error| format!("cannot revalidate retained cleanup parent: {error}"))?;
        if !root.is_dir() || root.dev() != self.device || root.ino() != self.inode {
            return Err("retained staged cleanup root identity changed".to_owned());
        }
        if !parent.is_dir()
            || parent.dev() != self.parent.device
            || parent.ino() != self.parent.inode
            || parent.uid() != self.parent.uid
            || parent.gid() != self.parent.gid
            || parent.mode() & 0o7777 != self.parent.mode
        {
            return Err("retained staged cleanup parent identity changed".to_owned());
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl StagedNativeToolchainTransaction {
    fn new() -> Result<Self, String> {
        let completion_deadline = Instant::now()
            .checked_add(STAGED_NATIVE_TOOLCHAIN_TIMEOUT)
            .ok_or_else(|| "staged toolchain deadline overflowed".to_owned())?;
        let execution_deadline = completion_deadline
            .checked_sub(STAGED_NATIVE_TOOLCHAIN_CLEANUP_RESERVE)
            .ok_or_else(|| "staged toolchain cleanup reserve underflowed".to_owned())?;
        Self::with_deadlines(execution_deadline, completion_deadline)
    }

    fn with_deadlines(
        execution_deadline: Instant,
        completion_deadline: Instant,
    ) -> Result<Self, String> {
        Self::with_deadlines_and_progress(execution_deadline, completion_deadline, None)
    }

    fn with_deadlines_and_progress(
        execution_deadline: Instant,
        completion_deadline: Instant,
        phase_sender: Option<SyncSender<StagedNativeToolchainProgress>>,
    ) -> Result<Self, String> {
        if Instant::now() >= execution_deadline || execution_deadline >= completion_deadline {
            return Err("staged toolchain absolute deadlines are not ordered".to_owned());
        }
        Ok(Self {
            execution_deadline,
            completion_deadline,
            phase_sender,
            manifest_passes: Cell::new(StagedNativeManifestPassCounts::default()),
        })
    }

    fn cleanup_only() -> Result<Self, String> {
        let completion_deadline = Instant::now()
            .checked_add(STAGED_NATIVE_TOOLCHAIN_CLEANUP_RESERVE)
            .ok_or_else(|| "staged toolchain cleanup deadline overflowed".to_owned())?;
        Ok(Self {
            execution_deadline: Instant::now(),
            completion_deadline,
            phase_sender: None,
            manifest_passes: Cell::new(StagedNativeManifestPassCounts::default()),
        })
    }

    fn phase(&self, phase: &str) -> Result<(), String> {
        self.require_remaining(phase)?;
        self.publish_phase(phase)
    }

    fn cleanup_phase(&self, phase: &str) -> Result<(), String> {
        self.require_cleanup_remaining(phase)?;
        self.publish_phase(phase)
    }

    fn publish_phase(&self, phase: &str) -> Result<(), String> {
        if let Some(sender) = &self.phase_sender {
            sender
                .try_send(StagedNativeToolchainProgress::Phase(phase.to_owned()))
                .map_err(|error| {
                    format!("cannot publish staged toolchain phase receipt: {error}")
                })?;
        }
        emit_staged_toolchain_phase(phase)
    }

    fn record_manifest_pass(
        &self,
        update: impl FnOnce(&mut StagedNativeManifestPassCounts),
    ) -> Result<(), String> {
        let mut passes = self.manifest_passes.get();
        update(&mut passes);
        self.manifest_passes.set(passes);
        if let Some(sender) = &self.phase_sender {
            sender
                .try_send(StagedNativeToolchainProgress::ManifestPasses(passes))
                .map_err(|error| format!("cannot publish staged manifest pass receipt: {error}"))?;
        }
        Ok(())
    }

    fn require_manifest_passes(
        &self,
        expected: StagedNativeManifestPassCounts,
    ) -> Result<(), String> {
        let observed = self.manifest_passes.get();
        if observed != expected {
            return Err(format!(
                "staged manifest pass topology differs: expected={expected:?}, observed={observed:?}"
            ));
        }
        if let Some(sender) = &self.phase_sender {
            sender
                .try_send(StagedNativeToolchainProgress::ManifestPasses(observed))
                .map_err(|error| {
                    format!("cannot publish final staged manifest pass receipt: {error}")
                })?;
        }
        Ok(())
    }

    fn require_remaining(&self, phase: &str) -> Result<Duration, String> {
        let remaining = self
            .execution_deadline
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(format!(
                "staged native toolchain absolute deadline expired before {phase}"
            ))
        } else {
            Ok(remaining)
        }
    }

    fn command_deadlines(&self, phase: &str) -> Result<(Duration, Instant), String> {
        let execution_budget = self.require_remaining(phase)?.min(Duration::from_secs(30));
        let execution_deadline = Instant::now()
            .checked_add(execution_budget)
            .unwrap_or(self.execution_deadline)
            .min(self.execution_deadline);
        Ok((execution_budget, execution_deadline))
    }

    fn require_cleanup_remaining(&self, phase: &str) -> Result<(), String> {
        if Instant::now() >= self.completion_deadline {
            Err(format!(
                "staged native toolchain cleanup deadline expired before {phase}"
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(target_os = "macos")]
fn emit_staged_toolchain_phase(phase: &str) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "hell-progress-subphase={phase}")
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("cannot publish staged toolchain progress: {error}"))
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
enum AdapterDirectoryCreationProbe {
    None,
    FailAfterCreate,
    FailRootMetadata,
    FailPathMetadata,
    FailParentClone,
    SubstituteAfterCreate,
}

#[cfg(target_os = "macos")]
struct BoundCreatedAdapterRoot {
    path: PathBuf,
    guard: fs::File,
    parent_guard: fs::File,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(target_os = "macos")]
impl BoundCreatedAdapterRoot {
    fn require_promoted(
        &self,
        root: &BoundNativeCleanupRoot,
        parent: &BoundNativeDirectory,
        deadline: Instant,
    ) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        require_optional_native_deadline(Some(deadline), "created adapter receipt promotion")?;
        let created = self
            .guard
            .metadata()
            .map_err(|error| format!("cannot revalidate created adapter handle: {error}"))?;
        let created_parent = self
            .parent_guard
            .metadata()
            .map_err(|error| format!("cannot revalidate created adapter parent handle: {error}"))?;
        let promoted = root
            .guard
            .metadata()
            .map_err(|error| format!("cannot inspect promoted adapter handle: {error}"))?;
        let promoted_parent = root
            .parent_guard
            .metadata()
            .map_err(|error| format!("cannot inspect promoted adapter parent handle: {error}"))?;
        let current = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot inspect promoted adapter path: {error}"))?;
        if root.path != self.path
            || root.parent.path != parent.path
            || root.device != self.device
            || root.inode != self.inode
            || root.parent.device != parent.device
            || root.parent.inode != parent.inode
            || root.parent.uid != parent.uid
            || root.parent.gid != parent.gid
            || root.parent.mode != parent.mode
            || !created.is_dir()
            || created.dev() != self.device
            || created.ino() != self.inode
            || created.uid() != self.uid
            || created.gid() != self.gid
            || created.mode() & 0o7777 != self.mode
            || !created_parent.is_dir()
            || created_parent.dev() != parent.device
            || created_parent.ino() != parent.inode
            || created_parent.uid() != parent.uid
            || created_parent.gid() != parent.gid
            || created_parent.mode() & 0o7777 != parent.mode
            || promoted.dev() != self.device
            || promoted.ino() != self.inode
            || promoted.uid() != self.uid
            || promoted.gid() != self.gid
            || promoted.mode() & 0o7777 != self.mode
            || promoted_parent.dev() != parent.device
            || promoted_parent.ino() != parent.inode
            || current.file_type().is_symlink()
            || !current.is_dir()
            || current.dev() != self.device
            || current.ino() != self.inode
            || current.uid() != self.uid
            || current.gid() != self.gid
            || current.mode() & 0o7777 != self.mode
        {
            return Err("created adapter root changed during receipt promotion".to_owned());
        }
        require_optional_native_deadline(Some(deadline), "created adapter receipt promotion")
    }
}

#[cfg(target_os = "macos")]
fn cleanup_unbound_created_adapter_root(
    path: &Path,
    parent: &BoundNativeDirectory,
    deadline: Instant,
) -> Result<(), String> {
    require_optional_native_deadline(Some(deadline), "unbound created adapter cleanup")?;
    parent.revalidate_until("created adapter parent", deadline)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect unbound created adapter root: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("unbound created adapter root is not an exact directory".to_owned());
    }
    if fs::read_dir(path)
        .map_err(|error| format!("cannot enumerate unbound created adapter root: {error}"))?
        .next()
        .is_some()
    {
        return Err("unbound created adapter root is not empty".to_owned());
    }
    fs::remove_dir(path)
        .map_err(|error| format!("cannot remove unbound created adapter root: {error}"))?;
    require_optional_native_deadline(Some(deadline), "unbound created adapter absence")?;
    parent.revalidate_until("created adapter parent", deadline)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("unbound created adapter root remains".to_owned()),
        Err(error) => Err(format!(
            "cannot attest unbound created adapter absence: {error}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn cleanup_created_adapter_root(
    path: &Path,
    created: &BoundCreatedAdapterRoot,
    parent: &BoundNativeDirectory,
    deadline: Instant,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    require_optional_native_deadline(Some(deadline), "created adapter cleanup")?;
    parent.revalidate_until("created adapter parent", deadline)?;
    let retained = created
        .guard
        .metadata()
        .map_err(|error| format!("cannot revalidate created adapter handle: {error}"))?;
    let retained_parent = created
        .parent_guard
        .metadata()
        .map_err(|error| format!("cannot revalidate created adapter parent handle: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect created adapter cleanup root: {error}"))?;
    if !retained.is_dir()
        || retained.dev() != created.device
        || retained.ino() != created.inode
        || retained.uid() != created.uid
        || retained.gid() != created.gid
        || retained.mode() & 0o7777 != created.mode
        || !retained_parent.is_dir()
        || retained_parent.dev() != parent.device
        || retained_parent.ino() != parent.inode
        || retained_parent.uid() != parent.uid
        || retained_parent.gid() != parent.gid
        || retained_parent.mode() & 0o7777 != parent.mode
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.dev() != created.device
        || metadata.ino() != created.inode
        || metadata.uid() != created.uid
        || metadata.gid() != created.gid
        || metadata.mode() & 0o7777 != created.mode
    {
        return Err("created adapter cleanup root identity changed".to_owned());
    }
    if fs::read_dir(path)
        .map_err(|error| format!("cannot enumerate created adapter cleanup root: {error}"))?
        .next()
        .is_some()
    {
        return Err("created adapter cleanup root is not empty".to_owned());
    }
    fs::remove_dir(path)
        .map_err(|error| format!("cannot remove created adapter cleanup root: {error}"))?;
    require_optional_native_deadline(Some(deadline), "created adapter cleanup absence")?;
    parent.revalidate_until("created adapter parent", deadline)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("created adapter cleanup root remains".to_owned()),
        Err(error) => Err(format!(
            "cannot attest created adapter cleanup absence: {error}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn adapter_directory_creation_failure<T>(
    primary: String,
    cleanup: Result<(), String>,
) -> Result<T, String> {
    match cleanup {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(format!(
            "{primary}; created adapter cleanup also failed: {cleanup}"
        )),
    }
}

fn create_adapter_directory(base: &Path) -> Result<AdapterDirectory, String> {
    #[cfg(target_os = "macos")]
    return create_adapter_directory_with_probe(base, AdapterDirectoryCreationProbe::None);
    #[cfg(not(target_os = "macos"))]
    for _ in 0..16 {
        let sequence = ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "hell-ci-archive-adapter-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                return Ok(AdapterDirectory { path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!("cannot create macOS archive adapter: {error}"));
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    Err("cannot allocate a collision-free macOS archive adapter directory".to_owned())
}

#[cfg(target_os = "macos")]
fn create_adapter_directory_with_probe(
    base: &Path,
    probe: AdapterDirectoryCreationProbe,
) -> Result<AdapterDirectory, String> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

    let cleanup_transaction = StagedNativeToolchainTransaction::cleanup_only()?;
    let canonical_base = fs::canonicalize(base)
        .map_err(|error| format!("cannot canonicalize native adapter parent: {error}"))?;
    let base_metadata = fs::symlink_metadata(&canonical_base)
        .map_err(|error| format!("cannot inspect native adapter parent: {error}"))?;
    if base_metadata.file_type().is_symlink() || !base_metadata.is_dir() {
        return Err("native adapter parent is not an exact directory".to_owned());
    }
    let parent = BoundNativeDirectory::bind_until(
        &canonical_base,
        base_metadata.mode() & 0o7777,
        cleanup_transaction.completion_deadline,
    )?;
    let parent_guard = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(&canonical_base)
        .map_err(|error| format!("cannot retain native adapter parent: {error}"))?;
    let parent_handle = parent_guard
        .metadata()
        .map_err(|error| format!("cannot inspect retained native adapter parent: {error}"))?;
    if !parent_handle.is_dir()
        || parent_handle.dev() != parent.device
        || parent_handle.ino() != parent.inode
        || parent_handle.uid() != parent.uid
        || parent_handle.gid() != parent.gid
        || parent_handle.mode() & 0o7777 != parent.mode
    {
        return Err("retained native adapter parent identity changed".to_owned());
    }
    for _ in 0..16 {
        let sequence = ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = canonical_base.join(format!(
            "hell-ci-archive-adapter-{}-{sequence}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => {
                let guard = match fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
                    .open(&path)
                {
                    Ok(guard) => guard,
                    Err(error) => {
                        return adapter_directory_creation_failure(
                            format!("cannot retain newly created native adapter root: {error}"),
                            cleanup_unbound_created_adapter_root(
                                &path,
                                &parent,
                                cleanup_transaction.completion_deadline,
                            ),
                        );
                    }
                };
                let created_parent_guard =
                    if matches!(probe, AdapterDirectoryCreationProbe::FailParentClone) {
                        return adapter_directory_creation_failure(
                            "injected created adapter parent clone failure".to_owned(),
                            cleanup_unbound_created_adapter_root(
                                &path,
                                &parent,
                                cleanup_transaction.completion_deadline,
                            ),
                        );
                    } else {
                        match parent_guard.try_clone() {
                            Ok(parent_guard) => parent_guard,
                            Err(error) => {
                                return adapter_directory_creation_failure(
                                    format!("cannot retain created adapter parent handle: {error}"),
                                    cleanup_unbound_created_adapter_root(
                                        &path,
                                        &parent,
                                        cleanup_transaction.completion_deadline,
                                    ),
                                );
                            }
                        }
                    };
                let metadata = if matches!(probe, AdapterDirectoryCreationProbe::FailRootMetadata) {
                    return adapter_directory_creation_failure(
                        "injected created adapter handle metadata failure".to_owned(),
                        cleanup_unbound_created_adapter_root(
                            &path,
                            &parent,
                            cleanup_transaction.completion_deadline,
                        ),
                    );
                } else {
                    match guard.metadata() {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            return adapter_directory_creation_failure(
                                format!("cannot inspect retained native adapter root: {error}"),
                                cleanup_unbound_created_adapter_root(
                                    &path,
                                    &parent,
                                    cleanup_transaction.completion_deadline,
                                ),
                            );
                        }
                    }
                };
                let created = BoundCreatedAdapterRoot {
                    path: path.clone(),
                    guard,
                    parent_guard: created_parent_guard,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    mode: metadata.mode() & 0o7777,
                };
                let path_metadata =
                    if matches!(probe, AdapterDirectoryCreationProbe::FailPathMetadata) {
                        return adapter_directory_creation_failure(
                            "injected created adapter path metadata failure".to_owned(),
                            cleanup_created_adapter_root(
                                &path,
                                &created,
                                &parent,
                                cleanup_transaction.completion_deadline,
                            ),
                        );
                    } else {
                        match fs::symlink_metadata(&path) {
                            Ok(metadata) => metadata,
                            Err(error) => {
                                return adapter_directory_creation_failure(
                                    format!(
                                        "cannot inspect newly created native adapter root: {error}"
                                    ),
                                    cleanup_created_adapter_root(
                                        &path,
                                        &created,
                                        &parent,
                                        cleanup_transaction.completion_deadline,
                                    ),
                                );
                            }
                        }
                    };
                if !metadata.is_dir()
                    || path_metadata.file_type().is_symlink()
                    || !path_metadata.is_dir()
                    || path_metadata.dev() != metadata.dev()
                    || path_metadata.ino() != metadata.ino()
                {
                    return adapter_directory_creation_failure(
                        "newly created native adapter root is not an exact directory".to_owned(),
                        cleanup_created_adapter_root(
                            &path,
                            &created,
                            &parent,
                            cleanup_transaction.completion_deadline,
                        ),
                    );
                }
                if matches!(probe, AdapterDirectoryCreationProbe::SubstituteAfterCreate) {
                    fs::remove_dir(&path).map_err(|error| {
                        format!("cannot remove adapter substitution probe root: {error}")
                    })?;
                    builder.create(&path).map_err(|error| {
                        format!("cannot install adapter substitution directory: {error}")
                    })?;
                    fs::write(path.join("collision"), b"collision\n").map_err(|error| {
                        format!("cannot install adapter substitution marker: {error}")
                    })?;
                }
                if matches!(probe, AdapterDirectoryCreationProbe::FailAfterCreate) {
                    return adapter_directory_creation_failure(
                        "injected native adapter initialization failure".to_owned(),
                        cleanup_created_adapter_root(
                            &path,
                            &created,
                            &parent,
                            cleanup_transaction.completion_deadline,
                        ),
                    );
                }
                let cleanup_root = match BoundNativeCleanupRoot::bind(
                    &path,
                    cleanup_transaction.completion_deadline,
                ) {
                    Ok(cleanup_root) => cleanup_root,
                    Err(primary) => {
                        return adapter_directory_creation_failure(
                            primary,
                            cleanup_created_adapter_root(
                                &path,
                                &created,
                                &parent,
                                cleanup_transaction.completion_deadline,
                            ),
                        );
                    }
                };
                if let Err(primary) = created.require_promoted(
                    &cleanup_root,
                    &parent,
                    cleanup_transaction.completion_deadline,
                ) {
                    return adapter_directory_creation_failure(
                        primary,
                        cleanup_created_adapter_root(
                            &path,
                            &created,
                            &parent,
                            cleanup_transaction.completion_deadline,
                        ),
                    );
                }
                return Ok(AdapterDirectory {
                    path,
                    cleanup_root: Some(cleanup_root),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!("cannot create macOS archive adapter: {error}"));
            }
        }
    }
    Err("cannot allocate a collision-free macOS archive adapter directory".to_owned())
}

#[cfg(unix)]
pub(crate) fn verify_native_archive_adapter_cleanup_for_integration(
    base: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let base = fs::canonicalize(base)
        .map_err(|error| format!("cannot canonicalize adapter cleanup verifier base: {error}"))?;
    let base_guard = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&base)
        .map_err(|error| format!("cannot retain adapter cleanup verifier base: {error}"))?;
    let expected_base = base_guard
        .metadata()
        .map_err(|error| format!("cannot bind adapter cleanup verifier base: {error}"))?;
    if !expected_base.is_dir()
        || fs::read_dir(&base)
            .map_err(|error| format!("cannot enumerate adapter cleanup verifier base: {error}"))?
            .next()
            .is_some()
    {
        return Err("adapter cleanup verifier base is not an empty exact directory".to_owned());
    }

    let mut scope = create_adapter_directory(&base)?;
    let scope_path = scope.path().to_owned();
    let primary = (|| {
        verify_native_archive_stack_package_authority_for_integration(&scope_path)?;
        let mut partial = create_adapter_directory(&scope_path)?;
        let partial_path = partial.path().to_owned();
        fs::write(partial_path.join("member.o"), b"partial\n")
            .map_err(|error| format!("cannot write partial adapter fixture: {error}"))?;
        partial.close()?;
        if fs::symlink_metadata(&partial_path).is_ok() {
            return Err("explicit adapter close left partial setup behind".to_owned());
        }

        #[cfg(target_os = "macos")]
        {
            for (probe, expected) in [
                (
                    AdapterDirectoryCreationProbe::FailParentClone,
                    "injected created adapter parent clone failure",
                ),
                (
                    AdapterDirectoryCreationProbe::FailRootMetadata,
                    "injected created adapter handle metadata failure",
                ),
                (
                    AdapterDirectoryCreationProbe::FailPathMetadata,
                    "injected created adapter path metadata failure",
                ),
            ] {
                let failure = match create_adapter_directory_with_probe(&scope_path, probe) {
                    Err(error) => error,
                    Ok(mut unexpected) => {
                        unexpected.close()?;
                        return Err(
                            "partial adapter receipt initialization unexpectedly succeeded"
                                .to_owned(),
                        );
                    }
                };
                if failure != expected
                    || fs::read_dir(&scope_path)
                        .map_err(|error| {
                            format!("cannot inspect partial adapter receipt scope: {error}")
                        })?
                        .next()
                        .is_some()
                {
                    return Err(
                        "partial adapter receipt failure did not clean its exact root".to_owned(),
                    );
                }
            }

            let failure = match create_adapter_directory_with_probe(
                &scope_path,
                AdapterDirectoryCreationProbe::FailAfterCreate,
            ) {
                Err(error) => error,
                Ok(mut unexpected) => {
                    unexpected.close()?;
                    return Err("injected adapter initialization unexpectedly succeeded".to_owned());
                }
            };
            if failure != "injected native adapter initialization failure"
                || fs::read_dir(&scope_path)
                    .map_err(|error| format!("cannot inspect post-failure adapter scope: {error}"))?
                    .next()
                    .is_some()
            {
                return Err("pre-receipt adapter cleanup did not attest exact absence".to_owned());
            }

            let substitution = match create_adapter_directory_with_probe(
                &scope_path,
                AdapterDirectoryCreationProbe::SubstituteAfterCreate,
            ) {
                Err(error) => error,
                Ok(mut unexpected) => {
                    unexpected.close()?;
                    return Err(
                        "substituted adapter initialization unexpectedly succeeded".to_owned()
                    );
                }
            };
            let cleanup = substitution
                .strip_prefix(
                    "created adapter root changed during receipt promotion; created adapter cleanup also failed: ",
                )
                .filter(|cleanup| !cleanup.is_empty())
                .ok_or_else(|| {
                    "pre-receipt adapter failure did not preserve primary-before-cleanup ordering"
                        .to_owned()
                })?;
            if !cleanup.contains("identity changed") {
                return Err(
                    "pre-receipt adapter substitution returned an unrelated failure".to_owned(),
                );
            }
            let collision = fs::read_dir(&scope_path)
                .map_err(|error| format!("cannot enumerate adapter collision probe: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("cannot inspect adapter collision probe: {error}"))?;
            if collision.len() != 1
                || !collision[0]
                    .file_type()
                    .map_err(|error| format!("cannot type adapter collision probe: {error}"))?
                    .is_dir()
                || fs::read(collision[0].path().join("collision"))
                    .map_err(|error| format!("cannot read adapter collision probe: {error}"))?
                    != b"collision\n"
            {
                return Err("pre-receipt adapter cleanup deleted its substitution".to_owned());
            }

            let mut expired = create_adapter_directory(&scope_path)?;
            let expired_path = expired.path().to_owned();
            fs::write(expired_path.join("member.o"), b"expired\n")
                .map_err(|error| format!("cannot write expired adapter fixture: {error}"))?;
            let before = fs::symlink_metadata(&expired_path)
                .map_err(|error| format!("cannot bind expired adapter fixture: {error}"))?;
            let composite = native_archive_adapter_constructor_failure::<()>(
                "partial adapter setup failed".to_owned(),
                expired.close_until(Instant::now()),
            )
            .expect_err("expired adapter cleanup must preserve the primary failure");
            let cleanup = composite
                .strip_prefix(
                    "partial adapter setup failed; native archive adapter constructor cleanup also failed: ",
                )
                .filter(|cleanup| !cleanup.is_empty())
                .ok_or_else(|| {
                    "adapter cleanup composite did not preserve primary-before-cleanup ordering"
                        .to_owned()
                })?;
            if !cleanup.contains("deadline expired") {
                return Err("expired adapter cleanup returned an unrelated failure".to_owned());
            }
            let after = fs::symlink_metadata(&expired_path)
                .map_err(|error| format!("expired adapter cleanup mutated its root: {error}"))?;
            if after.file_type().is_symlink()
                || !after.is_dir()
                || after.dev() != before.dev()
                || after.ino() != before.ino()
                || after.uid() != before.uid()
                || after.gid() != before.gid()
                || after.mode() & 0o7777 != before.mode() & 0o7777
            {
                return Err("expired adapter cleanup changed its exact root".to_owned());
            }
            drop(expired);
            if fs::symlink_metadata(&expired_path).is_err() {
                return Err("macOS AdapterDirectory Drop retried failed cleanup".to_owned());
            }
        }
        Ok(())
    })();

    let cleanup = scope.close();
    let parent_attestation = (|| {
        if fs::symlink_metadata(&scope_path).is_ok() {
            return Err("adapter cleanup verifier scope remains after close".to_owned());
        }
        let retained = base_guard
            .metadata()
            .map_err(|error| format!("cannot revalidate retained verifier base: {error}"))?;
        let current = fs::symlink_metadata(&base)
            .map_err(|error| format!("cannot revalidate adapter cleanup verifier base: {error}"))?;
        if current.file_type().is_symlink()
            || !current.is_dir()
            || current.dev() != expected_base.dev()
            || current.ino() != expected_base.ino()
            || current.uid() != expected_base.uid()
            || current.gid() != expected_base.gid()
            || current.mode() & 0o7777 != expected_base.mode() & 0o7777
            || retained.dev() != expected_base.dev()
            || retained.ino() != expected_base.ino()
        {
            return Err("adapter cleanup changed its retained parent authority".to_owned());
        }
        Ok(())
    })();

    let mut failures = Vec::new();
    if let Err(error) = primary {
        failures.push(format!("primary: {error}"));
    }
    if let Err(error) = cleanup {
        failures.push(format!("cleanup: {error}"));
    }
    if let Err(error) = parent_attestation {
        failures.push(format!("parent-attestation: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(target_os = "macos")]
fn copy_and_freeze_native_directory(
    source_root: &Path,
    destination_root: &Path,
    transaction: Option<&StagedNativeToolchainTransaction>,
) -> Result<BoundNativeManifest, String> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let source_root = fs::canonicalize(source_root)
        .map_err(|error| format!("cannot canonicalize native toolchain source: {error}"))?;
    let deadline = transaction.map(|transaction| transaction.execution_deadline);
    if let Some(transaction) = transaction {
        transaction.phase("source-inventory")?;
    }
    let mut source_manifest =
        BoundNativeManifest::bind_source_inventory_until(&source_root, deadline)?;
    if let Some(transaction) = transaction {
        transaction.record_manifest_pass(|passes| passes.source_inventory += 1)?;
    }
    fs::create_dir(destination_root)
        .map_err(|error| format!("cannot create staged native toolchain: {error}"))?;

    let mut directories = vec![destination_root.to_owned()];
    let mut symlinks = Vec::new();
    let mut bytes = 0u64;
    for entry in source_manifest
        .entries
        .iter_mut()
        .filter(|entry| !entry.relative.as_os_str().is_empty())
    {
        if let Some(transaction) = transaction {
            transaction.require_remaining("payload copy")?;
        }
        let source = source_root.join(&entry.relative);
        let destination = destination_root.join(&entry.relative);
        revalidate_native_manifest_entry(&source, entry, false)?;
        match entry.kind.clone() {
            BoundNativeManifestEntryKind::Directory => {
                fs::create_dir(&destination).map_err(|error| {
                    format!("cannot create staged toolchain directory: {error}")
                })?;
                directories.push(destination.clone());
            }
            BoundNativeManifestEntryKind::File { size, .. } => {
                let (copied, copied_sha256) =
                    copy_native_file_with_receipt(&source, &destination, entry, transaction)?;
                bytes = bytes
                    .checked_add(copied)
                    .ok_or_else(|| "native toolchain byte count overflowed".to_owned())?;
                if bytes > NATIVE_GHC_BYTE_LIMIT {
                    return Err("native toolchain exceeds the byte-count policy".to_owned());
                }
                revalidate_native_manifest_entry(&source, entry, false)?;
                if copied != size {
                    return Err("native toolchain member changed while it was copied".to_owned());
                }
                entry.kind = BoundNativeManifestEntryKind::File {
                    size,
                    sha256: copied_sha256,
                };
            }
            BoundNativeManifestEntryKind::Symlink { .. } => {
                let canonical = fs::canonicalize(&source)
                    .map_err(|error| format!("cannot resolve native toolchain symlink: {error}"))?;
                let relative = canonical.strip_prefix(&source_root).map_err(|_| {
                    "native toolchain symlink escapes its distribution root".to_owned()
                })?;
                let destination_parent = destination_root
                    .parent()
                    .ok_or_else(|| "staged toolchain destination has no parent".to_owned())?;
                let destination_leaf = destination_root
                    .file_name()
                    .ok_or_else(|| "staged toolchain destination has no leaf".to_owned())?;
                let staged_target = fs::canonicalize(destination_parent)
                    .map_err(|error| {
                        format!("cannot canonicalize staged toolchain parent: {error}")
                    })?
                    .join(destination_leaf)
                    .join(relative);
                symlink(&staged_target, &destination).map_err(|error| {
                    format!("cannot relocate native toolchain symlink: {error}")
                })?;
                symlinks.push((destination, staged_target));
            }
        }
    }

    if let Some(transaction) = transaction {
        transaction.phase("freeze-and-acl")?;
    }
    strip_staged_native_acls_until(destination_root, deadline)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        require_optional_native_deadline(deadline, "native toolchain directory freeze")?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o555))
            .map_err(|error| format!("cannot freeze staged toolchain directory: {error}"))?;
    }
    let canonical_destination = fs::canonicalize(destination_root)
        .map_err(|error| format!("cannot canonicalize staged toolchain root: {error}"))?;
    for (link, expected_target) in symlinks {
        require_optional_native_deadline(deadline, "native toolchain symlink validation")?;
        let observed = fs::canonicalize(&link)
            .map_err(|error| format!("cannot validate staged toolchain symlink: {error}"))?;
        let expected = fs::canonicalize(&expected_target)
            .map_err(|error| format!("cannot validate staged toolchain target: {error}"))?;
        if observed != expected || !observed.starts_with(&canonical_destination) {
            return Err("staged toolchain symlink differs from policy".to_owned());
        }
    }
    if let Some(transaction) = transaction {
        transaction.phase("source-postflight")?;
    }
    let source_postflight = BoundNativeManifest::bind_until(&source_root, false, deadline)?;
    if let Some(transaction) = transaction {
        transaction.record_manifest_pass(|passes| passes.source_postflight += 1)?;
    }
    require_native_manifests_equal(
        &source_postflight,
        &source_manifest,
        deadline,
        "native toolchain source changed while it was copied",
    )?;
    if let Some(transaction) = transaction {
        transaction.phase("staged-final-manifest")?;
    }
    let staged_manifest = BoundNativeManifest::bind_until(&canonical_destination, true, deadline)?;
    if let Some(transaction) = transaction {
        transaction.record_manifest_pass(|passes| passes.staged_final += 1)?;
    }
    require_staged_manifest_content(&source_manifest, &staged_manifest, deadline)?;
    Ok(staged_manifest)
}

#[cfg(target_os = "macos")]
fn require_native_manifests_equal(
    observed: &BoundNativeManifest,
    expected: &BoundNativeManifest,
    deadline: Option<Instant>,
    label: &str,
) -> Result<(), String> {
    if observed.root != expected.root || observed.entries.len() != expected.entries.len() {
        return Err(label.to_owned());
    }
    for (observed, expected) in observed.entries.iter().zip(&expected.entries) {
        require_optional_native_deadline(deadline, "native manifest exact comparison")?;
        if observed != expected {
            return Err(label.to_owned());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_staged_manifest_content(
    source_manifest: &BoundNativeManifest,
    staged_manifest: &BoundNativeManifest,
    deadline: Option<Instant>,
) -> Result<(), String> {
    if source_manifest.entries.len() != staged_manifest.entries.len() {
        return Err("staged native toolchain inventory differs from its source".to_owned());
    }
    for (source, staged) in source_manifest.entries.iter().zip(&staged_manifest.entries) {
        require_optional_native_deadline(deadline, "staged manifest equivalence")?;
        let kind_matches = match (&source.kind, &staged.kind) {
            (BoundNativeManifestEntryKind::Directory, BoundNativeManifestEntryKind::Directory) => {
                true
            }
            (
                BoundNativeManifestEntryKind::Symlink { .. },
                BoundNativeManifestEntryKind::Symlink {
                    target: staged_target,
                },
            ) => {
                let source_link = source_manifest.root.join(&source.relative);
                let resolved = fs::canonicalize(source_link).map_err(|error| {
                    format!("cannot resolve copied native toolchain symlink: {error}")
                })?;
                let relative = resolved
                    .strip_prefix(&source_manifest.root)
                    .map_err(|_| "copied native toolchain symlink escapes its source".to_owned())?;
                *staged_target == staged_manifest.root.join(relative)
            }
            (
                BoundNativeManifestEntryKind::File {
                    size: source_size,
                    sha256: source_sha256,
                },
                BoundNativeManifestEntryKind::File {
                    size: staged_size,
                    sha256: staged_sha256,
                },
            ) => source_size == staged_size && source_sha256 == staged_sha256,
            _ => false,
        };
        if source.relative != staged.relative || !kind_matches {
            return Err(format!(
                "staged native toolchain content differs from its source at {:?}: source={:?}, staged={:?}",
                source.relative, source.kind, staged.kind
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn copy_native_file_with_receipt(
    source: &Path,
    destination: &Path,
    expected: &BoundNativeManifestEntry,
    transaction: Option<&StagedNativeToolchainTransaction>,
) -> Result<(u64, Digest), String> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let mut source_file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(source)
        .map_err(|error| format!("cannot open native toolchain source member: {error}"))?;
    let source_before = source_file
        .metadata()
        .map_err(|error| format!("cannot bind native toolchain source handle: {error}"))?;
    if !source_before.is_file()
        || source_before.dev() != expected.device
        || source_before.ino() != expected.inode
        || source_before.uid() != expected.uid
        || source_before.gid() != expected.gid
        || source_before.mode() & 0o7777 != expected.mode
    {
        return Err("native toolchain source handle differs from its manifest".to_owned());
    }
    let mut destination_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("cannot create staged toolchain member: {error}"))?;
    let mut digest = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        if let Some(transaction) = transaction {
            transaction.require_remaining("payload copy chunk")?;
        }
        let read = source_file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read native toolchain source member: {error}"))?;
        if read == 0 {
            break;
        }
        destination_file
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot write staged toolchain member: {error}"))?;
        digest.update(&buffer[..read]);
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| "native copy count overflowed")?)
            .ok_or_else(|| "native copy count overflowed".to_owned())?;
    }
    destination_file
        .flush()
        .map_err(|error| format!("cannot flush staged toolchain member: {error}"))?;
    let source_after = source_file
        .metadata()
        .map_err(|error| format!("cannot revalidate native toolchain source handle: {error}"))?;
    if !same_native_metadata(&source_before, &source_after) {
        return Err("native toolchain source changed while it was copied".to_owned());
    }
    let mode = if expected.mode & 0o111 == 0 {
        0o444
    } else {
        0o555
    };
    destination_file
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot freeze staged toolchain member: {error}"))?;
    let destination_metadata = destination_file
        .metadata()
        .map_err(|error| format!("cannot bind staged toolchain member: {error}"))?;
    if destination_metadata.len() != copied
        || destination_metadata.mode() & 0o7777 != mode
        || copied != source_before.len()
    {
        return Err("staged toolchain handle differs from its copy receipt".to_owned());
    }
    Ok((copied, digest.finish()))
}

#[cfg(target_os = "macos")]
fn revalidate_native_manifest_entry(
    path: &Path,
    expected: &BoundNativeManifestEntry,
    require_frozen: bool,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot revalidate native toolchain source: {error}"))?;
    let mode = metadata.mode() & 0o7777;
    let kind_matches = match &expected.kind {
        BoundNativeManifestEntryKind::Directory => metadata.is_dir(),
        BoundNativeManifestEntryKind::File { size, .. } => {
            metadata.is_file() && metadata.len() == *size
        }
        BoundNativeManifestEntryKind::Symlink { target } => {
            metadata.file_type().is_symlink()
                && fs::read_link(path).ok().as_deref() == Some(target.as_path())
        }
    };
    if !kind_matches
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || metadata.uid() != expected.uid
        || metadata.gid() != expected.gid
        || mode != expected.mode
        || metadata.mtime() != expected.modified_seconds
        || metadata.mtime_nsec() != expected.modified_nanoseconds
        || metadata.ctime() != expected.changed_seconds
        || metadata.ctime_nsec() != expected.changed_nanoseconds
        || (require_frozen
            && ((!metadata.file_type().is_symlink() && metadata.is_dir() && mode != 0o555)
                || (metadata.is_file() && mode != 0o444 && mode != 0o555)))
    {
        return Err("native toolchain member identity changed before use".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn installed_native_ghc_payload(source_root: &Path) -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;

    let expected = source_root.join("lib").join(PINNED_NATIVE_GHC_PAYLOAD);
    let payload = fs::canonicalize(&expected)
        .map_err(|error| format!("cannot canonicalize installed GHC native payload: {error}"))?;
    if payload != expected || !payload.starts_with(source_root) {
        return Err("installed GHC native payload is redirected".to_owned());
    }
    let bin = payload.join("bin");
    let lib = payload.join("lib");
    // GHCup's public `ghci` and `runhaskell` entries are launcher aliases,
    // not required members of the relocatable native payload. The release
    // contract binds only the native compiler entry point here; the complete
    // payload manifest below still retains every installed auxiliary. A
    // future launcher operation must use typed arguments to this exact GHC or
    // separately bind the exact native auxiliary it needs.
    let ghc = bin.join("ghc");
    let canonical_ghc = fs::canonicalize(&ghc)
        .map_err(|error| format!("cannot resolve installed native GHC: {error}"))?;
    let ghc_metadata = fs::metadata(&canonical_ghc)
        .map_err(|error| format!("cannot inspect installed native GHC: {error}"))?;
    if !canonical_ghc.starts_with(&bin)
        || !ghc_metadata.is_file()
        || ghc_metadata.permissions().mode() & 0o111 == 0
    {
        return Err("installed native GHC escapes the GHC payload or is not executable".to_owned());
    }
    #[cfg(target_os = "macos")]
    {
        let mut magic = [0u8; 4];
        fs::File::open(&canonical_ghc)
            .and_then(|mut file| file.read_exact(&mut magic))
            .map_err(|error| format!("cannot identify installed native GHC: {error}"))?;
        if !matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        ) {
            return Err("installed native GHC is not a Mach-O executable".to_owned());
        }
    }
    let settings = lib.join("settings");
    let package_db = lib.join("package.conf.d");
    for (path, label, directory) in [
        (&lib, "libdir", true),
        (&settings, "settings", false),
        (&package_db, "global package database", true),
    ] {
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot resolve installed GHC {label}: {error}"))?;
        let metadata = fs::symlink_metadata(&canonical)
            .map_err(|error| format!("cannot inspect installed GHC {label}: {error}"))?;
        if canonical != *path
            || !canonical.starts_with(&payload)
            || metadata.file_type().is_symlink()
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            return Err(format!(
                "installed GHC {label} differs from native payload policy"
            ));
        }
    }
    Ok(payload)
}

#[cfg(target_os = "macos")]
fn stage_native_toolchain(
    adapter_root: &Path,
    transaction: &StagedNativeToolchainTransaction,
) -> Result<BoundNativeToolchain, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    transaction.phase("acquisition")?;
    let ghc = resolve_standard_path_executable(OsStr::new("ghc"))?;
    let source_ghc = ghc.canonical_identity();
    let source_bin = source_ghc
        .parent()
        .filter(|path| path.file_name() == Some(OsStr::new("bin")))
        .ok_or_else(|| "pinned GHC executable is not inside an exact bin directory".to_owned())?;
    let source_root = source_bin
        .parent()
        .filter(|path| path.file_name() == Some(OsStr::new(PINNED_NATIVE_GHC_VERSION)))
        .ok_or_else(|| "standard GHC is not from the pinned 9.8.2 distribution".to_owned())?;
    let source_entry = source_bin.join("ghc");
    if fs::canonicalize(&source_entry)
        .map_err(|error| format!("cannot resolve pinned GHC entry point: {error}"))?
        != source_ghc
    {
        return Err("pinned GHC entry point differs from the resolved standard GHC".to_owned());
    }
    let source_payload = installed_native_ghc_payload(source_root)?;

    let toolchain = adapter_root.join(".toolchain");
    fs::create_dir(&toolchain)
        .map_err(|error| format!("cannot create staged toolchain authority: {error}"))?;
    let staged_root = toolchain.join("system-ghc-9.8.2");
    transaction.phase("payload-copy")?;
    let ghc_distribution =
        copy_and_freeze_native_directory(&source_payload, &staged_root, Some(transaction))?;
    transaction.phase("staged-inventory")?;
    let staged_root = fs::canonicalize(&staged_root)
        .map_err(|error| format!("cannot canonicalize frozen staged GHC root: {error}"))?;
    let staged_bin = staged_root.join("bin");
    let staged_ghc = staged_bin.join("ghc");
    let staged_ghc_canonical = fs::canonicalize(&staged_ghc)
        .map_err(|error| format!("cannot resolve staged GHC entry point: {error}"))?;
    if staged_ghc_canonical.parent() != Some(staged_bin.as_path()) {
        return Err("staged GHC entry point escapes its bound bin authority".to_owned());
    }

    transaction.phase("stack-staging")?;
    let stack = resolve_standard_path_executable(OsStr::new("stack"))?;
    let stack_source = stack.canonical_identity();
    let stack_metadata = fs::metadata(stack_source)
        .map_err(|error| format!("cannot inspect standard Stack executable: {error}"))?;
    if !stack_metadata.is_file() || stack_metadata.permissions().mode() & 0o111 == 0 {
        return Err("standard Stack authority is not executable".to_owned());
    }
    let stack_source_digest = sha256_file_until(stack_source, transaction.execution_deadline)?;
    let stack_source_identity = (
        stack_metadata.dev(),
        stack_metadata.ino(),
        stack_metadata.uid(),
        stack_metadata.gid(),
        stack_metadata.mode(),
        stack_metadata.len(),
    );
    let stack_root = toolchain.join("system-tools");
    let stack_bin = stack_root.join("bin");
    fs::create_dir_all(&stack_bin)
        .map_err(|error| format!("cannot create staged Stack directory: {error}"))?;
    let staged_stack = stack_bin.join("stack");
    let stack_entry = BoundNativeManifestEntry {
        relative: PathBuf::new(),
        device: stack_metadata.dev(),
        inode: stack_metadata.ino(),
        uid: stack_metadata.uid(),
        gid: stack_metadata.gid(),
        mode: stack_metadata.mode() & 0o7777,
        modified_seconds: stack_metadata.mtime(),
        modified_nanoseconds: stack_metadata.mtime_nsec(),
        changed_seconds: stack_metadata.ctime(),
        changed_nanoseconds: stack_metadata.ctime_nsec(),
        kind: BoundNativeManifestEntryKind::File {
            size: stack_metadata.len(),
            sha256: stack_source_digest,
        },
    };
    let (copied_stack_bytes, copied_stack_digest) = copy_native_file_with_receipt(
        stack_source,
        &staged_stack,
        &stack_entry,
        Some(transaction),
    )?;
    transaction.require_remaining("Stack copy postflight")?;
    let stack_source_after = fs::metadata(stack_source)
        .map_err(|error| format!("cannot revalidate standard Stack executable: {error}"))?;
    let stack_source_after_identity = (
        stack_source_after.dev(),
        stack_source_after.ino(),
        stack_source_after.uid(),
        stack_source_after.gid(),
        stack_source_after.mode(),
        stack_source_after.len(),
    );
    let staged_stack_metadata = fs::symlink_metadata(&staged_stack)
        .map_err(|error| format!("cannot inspect staged Stack executable: {error}"))?;
    if copied_stack_bytes != stack_source_identity.5
        || staged_stack_metadata.len() != copied_stack_bytes
        || stack_source_after_identity != stack_source_identity
        || copied_stack_digest != stack_source_digest
    {
        return Err("standard Stack executable changed while it was copied".to_owned());
    }
    strip_staged_native_acls_until(&stack_root, Some(transaction.execution_deadline))?;
    fs::set_permissions(&staged_stack, fs::Permissions::from_mode(0o555))
        .map_err(|error| format!("cannot freeze staged Stack executable: {error}"))?;
    fs::set_permissions(&stack_bin, fs::Permissions::from_mode(0o555))
        .map_err(|error| format!("cannot freeze staged Stack bin directory: {error}"))?;
    fs::set_permissions(
        stack_bin
            .parent()
            .ok_or_else(|| "staged Stack directory has no parent".to_owned())?,
        fs::Permissions::from_mode(0o555),
    )
    .map_err(|error| format!("cannot freeze staged Stack root: {error}"))?;
    strip_staged_native_acls_until(&toolchain, Some(transaction.execution_deadline))?;
    fs::set_permissions(&toolchain, fs::Permissions::from_mode(0o555))
        .map_err(|error| format!("cannot freeze staged toolchain authority: {error}"))?;

    let mut toolchain = BoundNativeToolchain {
        adapter_authorities: bind_native_adapter_authorities(adapter_root)?,
        ghc_distribution,
        ghc_bin: BoundNativeDirectory::bind(&staged_bin, 0o555)?,
        ghc: BoundNativeFile::bind(&staged_ghc, 0o555)?,
        ghc_provenance: None,
        stack_distribution: BoundNativeManifest::bind_until(
            &stack_root,
            true,
            Some(transaction.execution_deadline),
        )?,
        stack_bin: BoundNativeDirectory::bind(&stack_bin, 0o555)?,
        stack: BoundNativeFile::bind(&staged_stack, 0o555)?,
    };
    toolchain.ghc_provenance = Some(prepare_staged_native_ghc_provenance(
        &toolchain,
        source_root,
        transaction,
    )?);
    transaction.phase("final-manifest")?;
    toolchain.revalidate_ghc_query_authority(transaction.execution_deadline)?;
    toolchain
        .ghc_provenance
        .as_ref()
        .ok_or_else(|| "staged GHC provenance was not retained".to_owned())?
        .revalidate(&toolchain.ghc_distribution.root)?;
    transaction.require_manifest_passes(StagedNativeManifestPassCounts {
        source_inventory: 1,
        source_postflight: 1,
        staged_final: 1,
        query_preflight: 1,
        query_postflight: 1,
    })?;
    Ok(toolchain)
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_staged_native_toolchain_for_integration(
    adapter_root: &Path,
) -> Result<(), String> {
    let transaction = StagedNativeToolchainTransaction::new()?;
    verify_staged_native_toolchain_with_transaction(adapter_root, &transaction)
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_staged_native_toolchain_until(
    adapter_root: &Path,
    execution_deadline: Instant,
    completion_deadline: Instant,
    phase_sender: SyncSender<StagedNativeToolchainProgress>,
) -> Result<(), String> {
    let transaction = StagedNativeToolchainTransaction::with_deadlines_and_progress(
        execution_deadline,
        completion_deadline,
        Some(phase_sender),
    )?;
    verify_staged_native_toolchain_with_transaction(adapter_root, &transaction)
}

#[cfg(target_os = "macos")]
fn verify_staged_native_toolchain_with_transaction(
    adapter_root: &Path,
    transaction: &StagedNativeToolchainTransaction,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    if adapter_root.exists() {
        return Err("staged native toolchain probe root already exists".to_owned());
    }
    fs::create_dir(adapter_root)
        .map_err(|error| format!("cannot create staged toolchain probe root: {error}"))?;
    let cleanup_root =
        match BoundNativeCleanupRoot::bind(adapter_root, transaction.execution_deadline) {
            Ok(root) => root,
            Err(primary) => {
                let cleanup = fs::remove_dir(adapter_root);
                return match cleanup {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(format!(
                        "{primary}; empty staged toolchain root cleanup also failed: {cleanup}"
                    )),
                };
            }
        };
    let result = (|| {
        transaction.require_remaining("adapter work setup")?;
        prepare_adapter_work_directory(adapter_root)?;
        let toolchain = stage_native_toolchain(adapter_root, transaction)?;
        let provenance = toolchain
            .ghc_provenance
            .as_ref()
            .ok_or_else(|| "staged GHC provenance was not retained".to_owned())?;
        provenance.revalidate(&toolchain.ghc_distribution.root)?;

        transaction.phase("mutation-negative")?;
        fs::set_permissions(&provenance.settings, fs::Permissions::from_mode(0o644))
            .map_err(|error| format!("cannot open staged GHC mutation probe: {error}"))?;
        let mut settings = fs::OpenOptions::new()
            .append(true)
            .open(&provenance.settings)
            .map_err(|error| format!("cannot open staged GHC settings probe: {error}"))?;
        settings
            .write_all(b"\n# retained-manifest-mutation-probe\n")
            .map_err(|error| format!("cannot mutate staged GHC settings probe: {error}"))?;
        settings
            .flush()
            .map_err(|error| format!("cannot flush staged GHC settings probe: {error}"))?;
        let settings_relative = provenance
            .settings
            .strip_prefix(&toolchain.ghc_distribution.root)
            .map_err(|_| "staged GHC settings escaped its retained manifest".to_owned())?;
        if toolchain
            .ghc_distribution
            .revalidate_member(
                settings_relative,
                "staged GHC settings mutation probe",
                transaction.execution_deadline,
            )
            .is_ok()
        {
            return Err("staged GHC non-entrypoint mutation was not rejected".to_owned());
        }
        Ok(())
    })();
    let cleanup = transaction
        .cleanup_phase("cleanup")
        .and_then(|()| remove_native_tree_until(&cleanup_root, transaction));
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(format!("staged toolchain cleanup failed: {cleanup}")),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; staged toolchain cleanup also failed: {cleanup}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn remove_native_tree_until(
    root: &BoundNativeCleanupRoot,
    transaction: &StagedNativeToolchainTransaction,
) -> Result<(), String> {
    root.revalidate(transaction.completion_deadline)?;
    remove_native_directory_until(&root.path, root.device, root.inode, transaction)?;
    root.require_absent(transaction.completion_deadline)
}

#[cfg(target_os = "macos")]
fn remove_native_directory_until(
    root: &Path,
    expected_device: u64,
    expected_inode: u64,
    transaction: &StagedNativeToolchainTransaction,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    transaction.require_cleanup_remaining("staged toolchain cleanup")?;
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect staged toolchain cleanup root: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
    {
        return Err("staged toolchain cleanup root is not an exact directory".to_owned());
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot open staged toolchain cleanup root: {error}"))?;
    let children = fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate staged toolchain cleanup root: {error}"))?;
    for child in children {
        transaction.require_cleanup_remaining("staged toolchain cleanup traversal")?;
        let child = child.map_err(|error| {
            format!("cannot enumerate staged toolchain cleanup member: {error}")
        })?;
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect staged toolchain cleanup member: {error}"))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            remove_native_directory_until(&path, metadata.dev(), metadata.ino(), transaction)?;
        } else {
            fs::remove_file(&path)
                .map_err(|error| format!("cannot remove staged toolchain member: {error}"))?;
        }
    }
    let final_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot revalidate staged toolchain directory: {error}"))?;
    if final_metadata.file_type().is_symlink()
        || !final_metadata.is_dir()
        || final_metadata.dev() != expected_device
        || final_metadata.ino() != expected_inode
    {
        return Err("staged toolchain directory changed during cleanup".to_owned());
    }
    fs::remove_dir(root)
        .map_err(|error| format!("cannot remove staged toolchain directory: {error}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_native_archive_seal_rebinding_for_integration(
    adapter_root: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if adapter_root.exists() {
        return Err("native archive seal probe root already exists".to_owned());
    }
    fs::create_dir(adapter_root)
        .map_err(|error| format!("cannot create native archive seal probe root: {error}"))?;
    prepare_adapter_work_directory(adapter_root)?;
    let authority = adapter_root.join(".authority");
    fs::create_dir(&authority)
        .map_err(|error| format!("cannot create native archive seal probe authority: {error}"))?;
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o555))
        .map_err(|error| format!("cannot freeze native archive seal probe authority: {error}"))?;
    let result = (|| {
        let initial = bind_native_adapter_authorities(adapter_root)?;
        let work = adapter_root.join(".stack-work");
        let temporary = work.join("tmp");
        let trusted_group = fs::symlink_metadata(adapter_root)
            .map_err(|error| format!("cannot inspect native archive seal probe: {error}"))?
            .gid();
        for (path, mode) in [
            (adapter_root, 0o2755),
            (work.as_path(), 0o3770),
            (temporary.as_path(), 0o2770),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
                format!("cannot apply native archive seal probe transition: {error}")
            })?;
        }
        if initial.iter().all(|bound| {
            bound
                .revalidate("initial native archive seal probe")
                .is_ok()
        }) {
            return Err("initial native archive receipt accepted the seal transition".to_owned());
        }
        let sealed = rebind_sealed_native_adapter_authorities(&initial, trusted_group)?;
        for bound in &sealed {
            bound.revalidate("sealed native archive adapter authority")?;
        }
        fs::set_permissions(&work, fs::Permissions::from_mode(0o770)).map_err(|error| {
            format!("cannot mutate sealed native archive probe authority: {error}")
        })?;
        if sealed.iter().all(|bound| {
            bound
                .revalidate("mutated native archive seal probe")
                .is_ok()
        }) {
            return Err("sealed native archive receipt accepted a mode mutation".to_owned());
        }
        Ok(())
    })();
    make_native_tree_removable(adapter_root);
    let cleanup = fs::remove_dir_all(adapter_root)
        .map_err(|error| format!("cannot remove native archive seal probe: {error}"));
    result.and(cleanup)
}

#[cfg(target_os = "macos")]
fn prepare_staged_native_ghc_provenance(
    toolchain: &BoundNativeToolchain,
    source_root: &Path,
    transaction: &StagedNativeToolchainTransaction,
) -> Result<StagedNativeGhcProvenance, String> {
    let source_root = fs::canonicalize(source_root)
        .map_err(|error| format!("cannot canonicalize original GHC prefix: {error}"))?;
    transaction.phase("provenance-preflight")?;
    toolchain.revalidate_until(transaction.execution_deadline)?;
    transaction.record_manifest_pass(|passes| passes.query_preflight += 1)?;
    let version = run_staged_native_ghc_query(toolchain, "--numeric-version", transaction)?;
    if version != PINNED_NATIVE_GHC_VERSION {
        return Err(format!(
            "staged GHC version {version:?} differs from pinned {PINNED_NATIVE_GHC_VERSION}"
        ));
    }
    let libdir = canonical_staged_ghc_query_path(
        toolchain,
        &source_root,
        "--print-libdir",
        "libdir",
        transaction,
    )?;
    let settings = fs::canonicalize(libdir.join("settings"))
        .map_err(|error| format!("cannot resolve staged GHC settings: {error}"))?;
    let package_db = canonical_staged_ghc_query_path(
        toolchain,
        &source_root,
        "--print-global-package-db",
        "global package database",
        transaction,
    )?;
    let provenance = StagedNativeGhcProvenance {
        source_root,
        version,
        libdir,
        settings,
        package_db,
    };
    provenance.revalidate(&toolchain.ghc_distribution.root)?;
    transaction.phase("provenance-postflight")?;
    toolchain.revalidate_until(transaction.execution_deadline)?;
    transaction.record_manifest_pass(|passes| passes.query_postflight += 1)?;
    Ok(provenance)
}

#[cfg(target_os = "macos")]
fn run_staged_native_ghc_query(
    toolchain: &BoundNativeToolchain,
    argument: &str,
    transaction: &StagedNativeToolchainTransaction,
) -> Result<String, String> {
    let phase = match argument {
        "--numeric-version" => "version-query",
        "--print-libdir" => "libdir-query",
        "--print-global-package-db" => "package-db-query",
        _ => return Err("staged GHC query argument is outside the typed protocol".to_owned()),
    };
    transaction.phase(phase)?;
    let (query_timeout, query_deadline) = transaction.command_deadlines(phase)?;
    toolchain.revalidate_ghc_query_authority(query_deadline)?;
    let path = std::env::join_paths([
        toolchain.ghc_bin.path.as_path(),
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .map_err(|error| format!("cannot construct staged GHC query PATH: {error}"))?;
    let mut command = CommandSpec::new(toolchain.ghc.canonical.as_os_str(), query_timeout)
        .argument(argument)
        .release_candidate_environment()
        .environment("PATH", path);
    command.canonical_executable_identity = Some(toolchain.ghc.canonical.clone());
    command.invocation_name = Some(OsString::from("ghc"));
    command.native_toolchain = Some(Arc::new(toolchain.clone()));
    command.native_toolchain_query_deadline = Some(query_deadline);
    let (progress, _progress_receiver) = SupervisedProgressObserver::bounded(1);
    let result = command
        .run_until(query_deadline, transaction.completion_deadline, progress)
        .map_err(|error| format!("cannot query staged GHC with {argument}: {error}"))?;
    if result.timed_out || !result.status.success() {
        return Err(format!("staged GHC query {argument} did not succeed"));
    }
    let output = std::str::from_utf8(&result.stdout)
        .map_err(|_| format!("staged GHC query {argument} was not UTF-8"))?;
    let value = output.strip_suffix('\n').unwrap_or(output);
    let value = value.strip_suffix('\r').unwrap_or(value);
    if value.is_empty() || value.lines().count() != 1 || value != value.trim() {
        return Err(format!(
            "staged GHC query {argument} did not return one exact value"
        ));
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "macos")]
fn canonical_staged_ghc_query_path(
    toolchain: &BoundNativeToolchain,
    source_root: &Path,
    argument: &str,
    label: &str,
    transaction: &StagedNativeToolchainTransaction,
) -> Result<PathBuf, String> {
    let value = run_staged_native_ghc_query(toolchain, argument, transaction)?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("staged GHC {label} is not absolute"));
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("cannot canonicalize staged GHC {label}: {error}"))?;
    if !canonical.starts_with(&toolchain.ghc_distribution.root)
        || canonical.starts_with(source_root)
    {
        return Err(format!("staged GHC {label} leaks its original prefix"));
    }
    Ok(canonical)
}

#[cfg(target_os = "macos")]
fn accepted_llvm_ar_version(output: &str) -> bool {
    output.lines().any(|line| {
        matches!(
            line.trim(),
            "Homebrew LLVM version 18.1.8" | "Homebrew LLVM version 22.1.8"
        )
    })
}

#[cfg(target_os = "macos")]
fn acquire_native_archiver_source(
    transaction: &NativeArchiverTransaction,
) -> Result<AcquiredNativeArchiverSource, String> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| "native-archiver-source discover predicate PATH-absent failed".to_owned())?;
    acquire_native_archiver_source_from(std::env::split_paths(&path), transaction)
}

#[cfg(target_os = "macos")]
fn acquire_native_archiver_source_from<I>(
    search: I,
    transaction: &NativeArchiverTransaction,
) -> Result<AcquiredNativeArchiverSource, String>
where
    I: IntoIterator<Item = PathBuf>,
{
    const PATH_ENTRY_LIMIT: usize = 256;
    const DIAGNOSTIC_LIMIT: usize = 8;

    let mut diagnostics = Vec::new();
    for (index, directory) in search.into_iter().enumerate() {
        transaction.require_execution("PATH inventory")?;
        if index >= PATH_ENTRY_LIMIT {
            return Err(format!(
                "native-archiver-source discover predicate PATH-entry-limit-{PATH_ENTRY_LIMIT} failed"
            ));
        }
        if !directory.is_absolute() {
            diagnostics.push("PATH-entry-absolute".to_owned());
            continue;
        }
        let candidate = directory.join("llvm-ar");
        if fs::symlink_metadata(&candidate).is_err() {
            continue;
        }
        match acquire_native_archiver_candidate(&candidate, transaction) {
            Ok(source) => return Ok(source),
            Err(error) if diagnostics.len() < DIAGNOSTIC_LIMIT => diagnostics.push(error),
            Err(_) => {}
        }
    }
    Err(format!(
        "cannot acquire native-archiver-source from standard PATH: {}",
        diagnostics.join(", ")
    ))
}

#[cfg(target_os = "macos")]
fn acquire_native_archiver_candidate(
    logical: &Path,
    transaction: &NativeArchiverTransaction,
) -> Result<AcquiredNativeArchiverSource, String> {
    transaction.require_execution("source acquisition")?;
    let canonical = fs::canonicalize(logical).map_err(|error| {
        format!("native-archiver-source discover predicate canonical-target failed: {error}")
    })?;
    if !canonical.is_absolute() {
        return Err(
            "native-archiver-source discover predicate canonical-absolute failed".to_owned(),
        );
    }
    let source_bin = canonical
        .parent()
        .filter(|parent| parent.file_name() == Some(OsStr::new("bin")))
        .ok_or_else(|| "native-archiver-source is not inside one bin directory".to_owned())?;
    let prefix = source_bin
        .parent()
        .ok_or_else(|| "native-archiver-source has no distribution prefix".to_owned())?
        .to_owned();
    let otool = resolve_absolute_standard_executable(Path::new("/usr/bin/otool"))?;
    let (files, load_graph, external_dependencies) = acquire_native_archiver_load_graph(
        logical,
        &prefix,
        &otool,
        transaction,
        &NativeArchiverOwnerAuthority::TrustedPublisher {
            uid: nix::unistd::geteuid().as_raw(),
        },
    )?;
    Ok(AcquiredNativeArchiverSource {
        source_prefix: fs::canonicalize(&prefix)
            .map_err(|error| format!("cannot retain LLVM source prefix: {error}"))?,
        files,
        load_graph,
        external_dependencies,
        otool,
    })
}

#[cfg(target_os = "macos")]
fn acquire_native_archiver_load_graph(
    logical: &Path,
    prefix: &Path,
    otool: &ResolvedStandardExecutable,
    transaction: &NativeArchiverTransaction,
    owner_authority: &NativeArchiverOwnerAuthority,
) -> Result<
    (
        Vec<AcquiredNativeArchiverFile>,
        NativeArchiverLoadGraph,
        Vec<BoundNativeArchiverDependency>,
    ),
    String,
> {
    enum PendingLoad {
        Staged(PathBuf, PathBuf, Vec<PathBuf>),
        External(PathBuf, Vec<PathBuf>),
    }

    const FILE_LIMIT: usize = 128;
    const BYTE_LIMIT: u64 = 512 * 1024 * 1024;
    const CONTEXT_LIMIT: usize = 512;

    let canonical_prefix = fs::canonicalize(prefix)
        .map_err(|error| format!("cannot canonicalize LLVM distribution prefix: {error}"))?;
    let executable = fs::canonicalize(logical)
        .map_err(|error| format!("cannot canonicalize LLVM archiver: {error}"))?;
    let executable_relative = executable
        .strip_prefix(&canonical_prefix)
        .map_err(|_| "LLVM archiver escapes its distribution prefix".to_owned())?
        .to_owned();
    let executable_directory = executable
        .parent()
        .ok_or_else(|| "LLVM archiver has no parent directory".to_owned())?
        .to_owned();
    let mut pending = vec![PendingLoad::Staged(
        executable_relative,
        logical.to_owned(),
        Vec::new(),
    )];
    let mut staged = BTreeMap::<PathBuf, AcquiredNativeArchiverFile>::new();
    let mut staged_visited = BTreeMap::<(PathBuf, Vec<PathBuf>), ()>::new();
    let mut external = BTreeMap::<PathBuf, BoundNativeArchiverDependency>::new();
    let mut external_visited = BTreeMap::<(PathBuf, Vec<PathBuf>), ()>::new();
    let mut edges = BTreeMap::new();
    let mut bytes = 0u64;
    while let Some(next) = pending.pop() {
        transaction.require_execution("Mach-O closure inventory")?;
        if staged_visited.len().saturating_add(external_visited.len()) >= CONTEXT_LIMIT {
            return Err("native archiver load graph exceeds the context-count policy".to_owned());
        }
        let (source_key, source_path, inherited_rpaths, inspection) = match next {
            PendingLoad::Staged(relative, source_path, inherited_rpaths) => {
                if staged_visited
                    .insert((relative.clone(), inherited_rpaths.clone()), ())
                    .is_some()
                {
                    continue;
                }
                let canonical = if let Some(source) = staged.get(&relative) {
                    source.source.canonical.clone()
                } else {
                    if staged.len().saturating_add(external.len()) >= FILE_LIMIT {
                        return Err(
                            "native archiver load closure exceeds the file-count policy".to_owned()
                        );
                    }
                    let source = read_native_archiver_source_file(
                        &source_path,
                        &relative,
                        transaction,
                        owner_authority,
                    )?;
                    bytes = bytes.checked_add(source.source.size).ok_or_else(|| {
                        "native archiver load closure byte count overflowed".to_owned()
                    })?;
                    if bytes > BYTE_LIMIT {
                        return Err(
                            "native archiver load closure exceeds the byte-count policy".to_owned()
                        );
                    }
                    let canonical = source.source.canonical.clone();
                    staged.insert(relative.clone(), source);
                    canonical
                };
                let inspection = inspect_macho_file(&canonical, otool, Some(*transaction))?;
                (relative, canonical, inherited_rpaths, inspection)
            }
            PendingLoad::External(source_path, inherited_rpaths) => {
                if external_visited
                    .insert((source_path.clone(), inherited_rpaths.clone()), ())
                    .is_some()
                {
                    continue;
                }
                let dependency = external.get(&source_path).ok_or_else(|| {
                    "native archiver external dependency receipt is absent".to_owned()
                })?;
                dependency.revalidate_until(*transaction)?;
                let inspection = inspect_macho_file(&source_path, otool, Some(*transaction))?;
                (
                    source_path.clone(),
                    source_path,
                    inherited_rpaths,
                    inspection,
                )
            }
        };
        let active_rpaths = resolve_macho_rpath_roots(
            &source_path,
            &executable_directory,
            &inspection.rpaths,
            &inherited_rpaths,
        )?;
        for load_name in inspection.load_names {
            let resolved = resolve_macho_load_name(
                &load_name,
                &source_path,
                &executable_directory,
                &active_rpaths,
            )?;
            let target = if let Some(system) = normalized_native_system_library(&resolved)? {
                NativeArchiverLoadTarget::System(system)
            } else if resolved.canonical.starts_with(&canonical_prefix) {
                let target_relative = normalized_staged_load_path(
                    &resolved.logical,
                    &canonical_prefix,
                    &resolved.canonical,
                )?;
                pending.push(PendingLoad::Staged(
                    target_relative.clone(),
                    resolved.canonical,
                    active_rpaths.clone(),
                ));
                NativeArchiverLoadTarget::Staged(target_relative)
            } else {
                let canonical = resolved.canonical;
                if !external.contains_key(&canonical) {
                    if staged.len().saturating_add(external.len()) >= FILE_LIMIT {
                        return Err(
                            "native archiver load closure exceeds the file-count policy".to_owned()
                        );
                    }
                    let dependency = BoundNativeArchiverDependency::bind_until(
                        &resolved.logical,
                        *transaction,
                        owner_authority,
                    )?;
                    bytes = bytes.checked_add(dependency.size).ok_or_else(|| {
                        "native archiver load closure byte count overflowed".to_owned()
                    })?;
                    if bytes > BYTE_LIMIT {
                        return Err(
                            "native archiver load closure exceeds the byte-count policy".to_owned()
                        );
                    }
                    external.insert(canonical.clone(), dependency);
                }
                pending.push(PendingLoad::External(
                    canonical.clone(),
                    active_rpaths.clone(),
                ));
                NativeArchiverLoadTarget::External(canonical)
            };
            record_native_archiver_load_edge(&mut edges, source_key.clone(), load_name, target)?;
        }
    }
    Ok((
        staged.into_values().collect(),
        finish_native_archiver_load_graph(edges),
        external.into_values().collect(),
    ))
}

#[cfg(target_os = "macos")]
fn normalized_staged_load_path(
    logical: &Path,
    canonical_prefix: &Path,
    canonical: &Path,
) -> Result<PathBuf, String> {
    if !canonical.starts_with(canonical_prefix) {
        return Err(
            "loader-relative Mach-O dependency escapes the LLVM distribution prefix".to_owned(),
        );
    }
    let relative = logical.strip_prefix(canonical_prefix).map_err(|_| {
        "loader-relative Mach-O dependency escapes the LLVM distribution prefix".to_owned()
    })?;
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(value) => normalized.push(value),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir if normalized.pop() => {}
            _ => {
                return Err(
                    "loader-relative Mach-O dependency escapes the LLVM distribution prefix"
                        .to_owned(),
                );
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err("Mach-O dependency has an empty staged topology path".to_owned());
    }
    Ok(normalized)
}

#[cfg(target_os = "macos")]
fn read_native_archiver_source_file(
    path: &Path,
    relative: &Path,
    transaction: &NativeArchiverTransaction,
    owner_authority: &NativeArchiverOwnerAuthority,
) -> Result<AcquiredNativeArchiverFile, String> {
    const SOURCE_SIZE_LIMIT: u64 = 256 * 1024 * 1024;

    let source = BoundNativeArchiverDependency::bind_until(path, *transaction, owner_authority)?;
    if relative == Path::new("bin").join("llvm-ar") && source.mode & 0o111 == 0 {
        return Err("native-archiver-source open predicate executable-mode failed".to_owned());
    }
    if source.size > SOURCE_SIZE_LIMIT {
        return Err("native-archiver-source open predicate source-size failed".to_owned());
    }
    let capacity = usize::try_from(source.size)
        .map_err(|_| "native-archiver-source open predicate source-size failed".to_owned())?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut opened = &*source.guard;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        transaction.require_execution("opened source copy")?;
        let read = opened.read(&mut buffer).map_err(|error| {
            format!("native-archiver-source copy predicate opened-source-read failed: {error}")
        })?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() as u64 > SOURCE_SIZE_LIMIT {
            return Err("native-archiver-source open predicate source-size failed".to_owned());
        }
    }
    source.revalidate_until(*transaction)?;
    let sha256 = sha256_bytes(&bytes);
    if bytes.len() as u64 != source.size || sha256 != source.sha256 {
        return Err("native-archiver-source copy predicate source-retarget failed".to_owned());
    }
    Ok(AcquiredNativeArchiverFile {
        relative: relative.to_owned(),
        source,
        bytes,
        sha256,
    })
}

#[cfg(target_os = "macos")]
struct MachOInspection {
    load_names: Vec<String>,
    rpaths: Vec<String>,
}

#[cfg(target_os = "macos")]
fn inspect_macho_file(
    path: &Path,
    otool: &ResolvedStandardExecutable,
    transaction: Option<NativeArchiverTransaction>,
) -> Result<MachOInspection, String> {
    let commands = run_bound_otool(otool, [OsStr::new("-l"), path.as_os_str()], transaction)?;
    parse_macho_load_commands(&commands)
}

#[cfg(target_os = "macos")]
fn parse_macho_load_commands(commands: &str) -> Result<MachOInspection, String> {
    const LOAD_NAME_LIMIT: usize = 256;
    const RPATH_LIMIT: usize = 64;

    let mut load_names = Vec::new();
    let mut rpaths = Vec::new();
    enum ExpectedMachOValue {
        None,
        LoadName,
        Rpath,
    }
    let mut expected = ExpectedMachOValue::None;
    for line in commands.lines() {
        let line = line.trim();
        if let Some(command) = line.strip_prefix("cmd ") {
            if !matches!(expected, ExpectedMachOValue::None) {
                return Err("otool omitted a required Mach-O load-command value".to_owned());
            }
            expected = match command {
                "LC_LOAD_DYLIB"
                | "LC_LOAD_WEAK_DYLIB"
                | "LC_REEXPORT_DYLIB"
                | "LC_LOAD_UPWARD_DYLIB"
                | "LC_LAZY_LOAD_DYLIB" => ExpectedMachOValue::LoadName,
                "LC_RPATH" => ExpectedMachOValue::Rpath,
                _ => ExpectedMachOValue::None,
            };
            continue;
        }
        match expected {
            ExpectedMachOValue::LoadName if line.starts_with("name ") => {
                let value = line
                    .strip_prefix("name ")
                    .ok_or_else(|| "otool emitted a malformed load name".to_owned())?;
                let (name, _) = value
                    .split_once(" (offset ")
                    .ok_or_else(|| "otool emitted a malformed load name".to_owned())?;
                if name.is_empty() {
                    return Err("otool emitted an empty Mach-O load edge".to_owned());
                }
                load_names.push(name.to_owned());
                if load_names.len() > LOAD_NAME_LIMIT {
                    return Err("Mach-O load command count exceeds policy".to_owned());
                }
                expected = ExpectedMachOValue::None;
            }
            ExpectedMachOValue::Rpath if line.starts_with("path ") => {
                let value = line
                    .strip_prefix("path ")
                    .ok_or_else(|| "otool emitted a malformed LC_RPATH".to_owned())?;
                let (path, _) = value
                    .split_once(" (offset ")
                    .ok_or_else(|| "otool emitted a malformed LC_RPATH".to_owned())?;
                if !rpaths.iter().any(|observed| observed == path) {
                    rpaths.push(path.to_owned());
                }
                if rpaths.len() > RPATH_LIMIT {
                    return Err("Mach-O LC_RPATH count exceeds policy".to_owned());
                }
                expected = ExpectedMachOValue::None;
            }
            _ => {}
        }
    }
    if !matches!(expected, ExpectedMachOValue::None) {
        return Err("otool ended before a required Mach-O load-command value".to_owned());
    }
    load_names.sort();
    load_names.dedup();
    Ok(MachOInspection { load_names, rpaths })
}

#[cfg(target_os = "macos")]
fn run_bound_otool<I, A>(
    otool: &ResolvedStandardExecutable,
    arguments: I,
    transaction: Option<NativeArchiverTransaction>,
) -> Result<String, String>
where
    I: IntoIterator<Item = A>,
    A: AsRef<OsStr>,
{
    if let Some(transaction) = transaction {
        transaction.require_execution("otool authority revalidation")?;
    }
    otool.revalidate()?;
    if let Some(transaction) = transaction {
        transaction.require_execution("otool authority command launch")?;
    }
    let mut command = CommandSpec::new(otool.invocation_path(), Duration::from_secs(30)).arguments(
        arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_os_string()),
    );
    command.canonical_executable_identity = Some(otool.canonical_identity().to_owned());
    command.invocation_name = Some(OsString::from("otool"));
    let result = match transaction {
        Some(transaction) => transaction.run(command),
        None => command.run(),
    }
    .map_err(|error| format!("cannot inspect Mach-O load graph: {error}"))?;
    require_complete_native_archiver_stdout("mach-o-inspection", &result)?;
    String::from_utf8(result.stdout).map_err(|_| "otool Mach-O load graph is not UTF-8".to_owned())
}

#[cfg(target_os = "macos")]
struct ResolvedMachOLoad {
    logical: PathBuf,
    canonical: PathBuf,
}

#[cfg(target_os = "macos")]
fn resolve_macho_load_name(
    load_name: &str,
    loader: &Path,
    executable_directory: &Path,
    rpath_roots: &[PathBuf],
) -> Result<ResolvedMachOLoad, String> {
    let loader_directory = loader
        .parent()
        .ok_or_else(|| "Mach-O loader has no parent directory".to_owned())?;
    if let Some(suffix) = load_name.strip_prefix("@loader_path/") {
        let logical = loader_directory.join(suffix);
        let canonical = fs::canonicalize(&logical)
            .map_err(|error| format!("cannot resolve @loader_path dependency: {error}"))?;
        return Ok(ResolvedMachOLoad { logical, canonical });
    }
    if let Some(suffix) = load_name.strip_prefix("@executable_path/") {
        let logical = executable_directory.join(suffix);
        let canonical = fs::canonicalize(&logical)
            .map_err(|error| format!("cannot resolve @executable_path dependency: {error}"))?;
        return Ok(ResolvedMachOLoad { logical, canonical });
    }
    if let Some(suffix) = load_name.strip_prefix("@rpath/") {
        for root in rpath_roots {
            let logical = root.join(suffix);
            if let Ok(candidate) = fs::canonicalize(&logical) {
                return Ok(ResolvedMachOLoad {
                    logical,
                    canonical: candidate,
                });
            }
        }
        return Err("Mach-O @rpath dependency is unresolved".to_owned());
    }
    let path = Path::new(load_name);
    if !path.is_absolute() {
        return Err("Mach-O dependency uses an unsupported load spelling".to_owned());
    }
    let canonical = fs::canonicalize(path).or_else(|error| {
        let system_spelling = path.components().all(|component| {
            !matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) && (path.starts_with("/usr/lib")
            || path.starts_with("/System/Library"));
        if system_spelling {
            Ok(path.to_owned())
        } else {
            Err(format!(
                "cannot resolve absolute Mach-O dependency: {error}"
            ))
        }
    })?;
    Ok(ResolvedMachOLoad {
        logical: path.to_owned(),
        canonical,
    })
}

#[cfg(target_os = "macos")]
fn resolve_macho_rpath_roots(
    loader: &Path,
    executable_directory: &Path,
    rpaths: &[String],
    inherited: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    const RPATH_ROOT_LIMIT: usize = 64;

    let loader_directory = loader
        .parent()
        .ok_or_else(|| "Mach-O loader has no parent directory".to_owned())?;
    let mut roots = Vec::new();
    for rpath in rpaths {
        let root = if rpath == "@loader_path" {
            loader_directory.to_owned()
        } else if let Some(value) = rpath.strip_prefix("@loader_path/") {
            loader_directory.join(value)
        } else if rpath == "@executable_path" {
            executable_directory.to_owned()
        } else if let Some(value) = rpath.strip_prefix("@executable_path/") {
            executable_directory.join(value)
        } else if Path::new(rpath).is_absolute() {
            PathBuf::from(rpath)
        } else {
            return Err("Mach-O LC_RPATH uses an unsupported relative spelling".to_owned());
        };
        if !roots.contains(&root) {
            roots.push(root);
        }
        if roots.len() > RPATH_ROOT_LIMIT {
            return Err("Mach-O run-path stack exceeds the bounded policy".to_owned());
        }
    }
    for root in inherited {
        if !roots.contains(root) {
            roots.push(root.clone());
        }
        if roots.len() > RPATH_ROOT_LIMIT {
            return Err("Mach-O run-path stack exceeds the bounded policy".to_owned());
        }
    }
    Ok(roots)
}

#[cfg(target_os = "macos")]
fn normalized_native_system_library(
    resolved: &ResolvedMachOLoad,
) -> Result<Option<PathBuf>, String> {
    let path = &resolved.canonical;
    if !path.is_absolute() {
        return Err("Mach-O dependency canonical target is not absolute".to_owned());
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err("Mach-O dependency canonical target is not normalized".to_owned());
    }
    if path.starts_with("/usr/lib") || path.starts_with("/System/Library") {
        Ok(Some(path.clone()))
    } else {
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
fn inspect_native_archiver_load_graph(
    executable: &Path,
    distribution: &Path,
    otool: &ResolvedStandardExecutable,
    external_dependencies: &[BoundNativeArchiverDependency],
    deadlines: Option<(Instant, Instant)>,
) -> Result<NativeArchiverLoadGraph, String> {
    const CONTEXT_LIMIT: usize = 512;

    let transaction =
        deadlines.map(
            |(execution_deadline, completion_deadline)| NativeArchiverTransaction {
                execution_deadline,
                completion_deadline,
            },
        );
    let executable_directory = executable
        .parent()
        .ok_or_else(|| "staged LLVM archiver has no parent directory".to_owned())?;
    let mut pending = vec![(Path::new("bin").join("llvm-ar"), Vec::<PathBuf>::new())];
    let mut visited = BTreeMap::<(PathBuf, Vec<PathBuf>), ()>::new();
    let mut edges = BTreeMap::new();
    let mut external_pending = Vec::<(PathBuf, Vec<PathBuf>)>::new();
    let mut external_visited = BTreeMap::<(PathBuf, Vec<PathBuf>), ()>::new();
    loop {
        while let Some((relative, inherited_rpaths)) = pending.pop() {
            if visited.len().saturating_add(external_visited.len()) >= CONTEXT_LIMIT {
                return Err(
                    "native archiver load graph exceeds the context-count policy".to_owned(),
                );
            }
            if visited
                .insert((relative.clone(), inherited_rpaths.clone()), ())
                .is_some()
            {
                continue;
            }
            let path = distribution.join(&relative);
            require_optional_native_deadline(
                deadlines.map(|(execution_deadline, _)| execution_deadline),
                "staged LLVM load graph inspection",
            )?;
            let inspection = inspect_macho_file(&path, otool, transaction)?;
            let active_rpaths = resolve_macho_rpath_roots(
                &path,
                executable_directory,
                &inspection.rpaths,
                &inherited_rpaths,
            )?;
            for load_name in inspection.load_names {
                let resolved = resolve_macho_load_name(
                    &load_name,
                    &path,
                    executable_directory,
                    &active_rpaths,
                )?;
                let target = if let Some(system) = normalized_native_system_library(&resolved)? {
                    NativeArchiverLoadTarget::System(system)
                } else if resolved.canonical.starts_with(distribution) {
                    let target_relative = normalized_staged_load_path(
                        &resolved.logical,
                        distribution,
                        &resolved.canonical,
                    )?;
                    pending.push((target_relative.clone(), active_rpaths.clone()));
                    NativeArchiverLoadTarget::Staged(target_relative)
                } else {
                    let dependency = external_dependencies
                        .iter()
                        .find(|dependency| dependency.canonical == resolved.canonical)
                        .ok_or_else(|| {
                            "staged LLVM archiver resolved an unbound external dependency"
                                .to_owned()
                        })?;
                    match transaction {
                        Some(transaction) => dependency.revalidate_until(transaction)?,
                        None => dependency.revalidate()?,
                    }
                    external_pending.push((dependency.canonical.clone(), active_rpaths.clone()));
                    NativeArchiverLoadTarget::External(dependency.canonical.clone())
                };
                record_native_archiver_load_edge(&mut edges, relative.clone(), load_name, target)?;
            }
        }
        while let Some((source_path, inherited_rpaths)) = external_pending.pop() {
            if visited.len().saturating_add(external_visited.len()) >= CONTEXT_LIMIT {
                return Err(
                    "native archiver load graph exceeds the context-count policy".to_owned(),
                );
            }
            require_optional_native_deadline(
                deadlines.map(|(execution_deadline, _)| execution_deadline),
                "external LLVM load graph inspection",
            )?;
            if external_visited
                .insert((source_path.clone(), inherited_rpaths.clone()), ())
                .is_some()
            {
                continue;
            }
            let dependency = external_dependencies
                .iter()
                .find(|dependency| dependency.canonical == source_path)
                .ok_or_else(|| "external LLVM dependency receipt is absent".to_owned())?;
            match transaction {
                Some(transaction) => dependency.revalidate_until(transaction)?,
                None => dependency.revalidate()?,
            }
            let inspection = inspect_macho_file(&source_path, otool, transaction)?;
            let active_rpaths = resolve_macho_rpath_roots(
                &source_path,
                executable_directory,
                &inspection.rpaths,
                &inherited_rpaths,
            )?;
            for load_name in inspection.load_names {
                let resolved = resolve_macho_load_name(
                    &load_name,
                    &source_path,
                    executable_directory,
                    &active_rpaths,
                )?;
                let target = if let Some(system) = normalized_native_system_library(&resolved)? {
                    NativeArchiverLoadTarget::System(system)
                } else if resolved.canonical.starts_with(distribution) {
                    let target_relative = normalized_staged_load_path(
                        &resolved.logical,
                        distribution,
                        &resolved.canonical,
                    )?;
                    pending.push((target_relative.clone(), active_rpaths.clone()));
                    NativeArchiverLoadTarget::Staged(target_relative)
                } else {
                    let target = external_dependencies
                        .iter()
                        .find(|dependency| dependency.canonical == resolved.canonical)
                        .ok_or_else(|| {
                            "external LLVM dependency resolved an unbound load edge".to_owned()
                        })?;
                    match transaction {
                        Some(transaction) => target.revalidate_until(transaction)?,
                        None => target.revalidate()?,
                    }
                    external_pending.push((target.canonical.clone(), active_rpaths.clone()));
                    NativeArchiverLoadTarget::External(target.canonical.clone())
                };
                record_native_archiver_load_edge(
                    &mut edges,
                    source_path.clone(),
                    load_name,
                    target,
                )?;
            }
        }
        if pending.is_empty() {
            break;
        }
    }
    Ok(finish_native_archiver_load_graph(edges))
}

#[cfg(target_os = "macos")]
fn command_result_failure(role: &str, result: &CommandResult) -> String {
    format!(
        "{role} failed: status={:?}, timed_out={}, duration={:?}, stdout_bytes={}, stderr_bytes={}, stdout_sha256={}, stderr_sha256={}, stdout_truncated={}, stderr_truncated={}, stderr={:?}",
        result.status.code(),
        result.timed_out,
        result.duration,
        result.stdout_bytes,
        result.stderr_bytes,
        result.stdout_sha256.hex(),
        result.stderr_sha256.hex(),
        result.stdout_truncated,
        result.stderr_truncated,
        String::from_utf8_lossy(&result.stderr),
    )
}

#[cfg(target_os = "macos")]
fn require_complete_native_archiver_stdout(
    role: &str,
    result: &CommandResult,
) -> Result<(), String> {
    if result.timed_out || !result.status.success() || result.stdout_truncated {
        Err(command_result_failure(role, result))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn install_staged_native_archive_adapter(
    adapter_root: &Path,
    confined_launcher: &Path,
    source: &AcquiredNativeArchiverSource,
    transaction: &NativeArchiverTransaction,
) -> Result<BoundNativeArchiver, String> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};

    let authority = adapter_root.join(".authority");
    fs::create_dir(&authority)
        .map_err(|error| format!("cannot create macOS archive authority: {error}"))?;
    let input_staging = authority.join("inputs");
    fs::create_dir(&input_staging).map_err(|error| {
        format!("cannot create native archive input staging authority: {error}")
    })?;
    fs::set_permissions(&input_staging, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!("cannot confine native archive input staging authority: {error}")
    })?;
    symlink(confined_launcher, adapter_root.join("ar"))
        .map_err(|error| format!("cannot install macOS archive adapter: {error}"))?;
    let distribution = authority.join("llvm");
    fs::create_dir(&distribution)
        .map_err(|error| format!("cannot create staged LLVM prefix: {error}"))?;
    let mut directories = BTreeMap::<PathBuf, ()>::new();
    directories.insert(distribution.clone(), ());
    for file in &source.files {
        transaction.require_execution("closure staging")?;
        file.source.revalidate_until(*transaction)?;
        let destination = distribution.join(&file.relative);
        let parent = destination
            .parent()
            .ok_or_else(|| "staged LLVM member has no parent".to_owned())?;
        let relative_parent = parent
            .strip_prefix(&distribution)
            .map_err(|_| "staged LLVM member escapes its prefix".to_owned())?;
        let mut current = distribution.clone();
        for component in relative_parent.components() {
            current.push(component.as_os_str());
            if !directories.contains_key(&current) {
                fs::create_dir(&current).map_err(|error| {
                    format!("cannot create staged LLVM prefix directory: {error}")
                })?;
                directories.insert(current.clone(), ());
            }
        }
        let executable = file.relative == Path::new("bin").join("llvm-ar");
        let mode = if executable { 0o555 } else { 0o444 };
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&destination)
            .map_err(|error| format!("cannot stage LLVM closure member: {error}"))?;
        output
            .write_all(&file.bytes)
            .and_then(|()| output.sync_all())
            .map_err(|error| format!("cannot copy staged LLVM closure member: {error}"))?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot freeze staged LLVM closure member: {error}"))?;
        if sha256_file_until(&destination, transaction.execution_deadline)? != file.sha256 {
            return Err("staged LLVM closure member digest differs from source".to_owned());
        }
        file.source.revalidate_until(*transaction)?;
    }
    let staged = distribution.join("bin").join("llvm-ar");
    strip_staged_native_acls_until(&authority, Some(transaction.execution_deadline))?;
    let mut directories = directories.into_keys().collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        transaction.require_execution("closure freeze")?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o555))
            .map_err(|error| format!("cannot freeze staged LLVM prefix: {error}"))?;
    }
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o555))
        .map_err(|error| format!("cannot confine macOS archive authority: {error}"))?;
    let bound = BoundNativeArchiver::bind(
        &staged,
        source.load_graph.clone(),
        source.external_dependencies.clone(),
        source.otool.clone(),
        Some((
            transaction.execution_deadline,
            transaction.completion_deadline,
        )),
    )?;
    let source_digest = source
        .files
        .iter()
        .find(|file| file.relative == Path::new("bin").join("llvm-ar"))
        .ok_or_else(|| "native archiver source closure lacks bin/llvm-ar".to_owned())?
        .sha256;
    if bound.sha256 != source_digest {
        return Err("native-archiver-source stage predicate staged-digest failed".to_owned());
    }
    Ok(bound)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn install_native_archive_adapter(
    adapter_root: &Path,
    confined_launcher: &Path,
    llvm_ar: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::symlink;

    let authority = adapter_root.join(".authority");
    fs::create_dir(&authority)
        .map_err(|error| format!("cannot create macOS archive authority: {error}"))?;
    symlink(confined_launcher, adapter_root.join("ar"))
        .map_err(|error| format!("cannot install macOS archive adapter: {error}"))?;
    bind_and_freeze_native_archive_authority(&authority, llvm_ar)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn bind_and_freeze_native_archive_authority(
    authority: &Path,
    llvm_ar: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let bound = authority.join("llvm-ar");
    let source_canonical = fs::canonicalize(llvm_ar)
        .map_err(|error| format!("cannot canonicalize LLVM archiver: {error}"))?;
    let source_metadata =
        fs::metadata(llvm_ar).map_err(|error| format!("cannot inspect LLVM archiver: {error}"))?;
    let source_mode = source_metadata.permissions().mode() & 0o7777;
    let source_digest =
        sha256_file(llvm_ar).map_err(|error| format!("cannot hash LLVM archiver: {error}"))?;
    if !source_metadata.is_file() || source_mode & 0o111 == 0 {
        return Err("LLVM archiver authority source is not executable".to_owned());
    }

    symlink(llvm_ar, &bound).map_err(|error| format!("cannot bind LLVM archiver: {error}"))?;
    let validate = || {
        if fs::read_link(&bound).ok().as_deref() != Some(llvm_ar) {
            return Err("bound LLVM archiver target differs from policy".to_owned());
        }
        let observed_canonical = fs::canonicalize(&bound)
            .map_err(|error| format!("cannot canonicalize bound LLVM archiver: {error}"))?;
        let observed_metadata = fs::metadata(&bound)
            .map_err(|error| format!("cannot inspect bound LLVM archiver: {error}"))?;
        let observed_digest = sha256_file(&bound)
            .map_err(|error| format!("cannot hash bound LLVM archiver: {error}"))?;
        if observed_canonical != source_canonical
            || !observed_metadata.is_file()
            || observed_metadata.permissions().mode() & 0o7777 != source_mode
            || observed_digest != source_digest
        {
            return Err("bound LLVM archiver identity differs from policy".to_owned());
        }
        Ok(())
    };
    validate()?;
    strip_staged_native_acls(authority)?;
    fs::set_permissions(authority, fs::Permissions::from_mode(0o555))
        .map_err(|error| format!("cannot confine macOS archive authority: {error}"))?;
    validate()
}

impl NativeArchiveAdapter {
    pub(crate) fn for_macos(
        enabled: bool,
        base: &Path,
        source: &Path,
        confined_launcher: Option<&Path>,
    ) -> Result<Self, String> {
        if !enabled {
            return Ok(Self {
                _directory: None,
                bound_toolchain: None,
                llvm_ar: None,
                llvm_ar_version: None,
                path: None,
                stack_yaml: None,
                temporary_directory: None,
                #[cfg(target_os = "macos")]
                input_broker: None,
            });
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (base, source, confined_launcher);
            Err("the macOS native archive adapter requires a macOS host".to_owned())
        }
        #[cfg(target_os = "macos")]
        {
            let envelope = NativeArchiveAdapterConstructionEnvelope::new()?;
            Self::for_macos_with_envelope(true, base, source, confined_launcher, Some(envelope))
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn for_macos_with_envelope(
        enabled: bool,
        base: &Path,
        source: &Path,
        confined_launcher: Option<&Path>,
        envelope: Option<NativeArchiveAdapterConstructionEnvelope>,
    ) -> Result<Self, String> {
        if !enabled {
            return Ok(Self {
                _directory: None,
                bound_toolchain: None,
                llvm_ar: None,
                llvm_ar_version: None,
                path: None,
                stack_yaml: None,
                temporary_directory: None,
                input_broker: None,
            });
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (base, source, confined_launcher, envelope);
            Err("the macOS native archive adapter requires a macOS host".to_owned())
        }
        #[cfg(target_os = "macos")]
        {
            let envelope = envelope.ok_or_else(|| {
                "macOS native archive adapter construction envelope is absent".to_owned()
            })?;
            let archiver_transaction = envelope.archiver_transaction()?;
            let source_archiver = acquire_native_archiver_source(&archiver_transaction)?;
            let mut directory = Some(create_adapter_directory(base)?);
            let result = (|| {
                let adapter_root = directory
                    .as_ref()
                    .ok_or_else(|| {
                        "native archive adapter directory was consumed early".to_owned()
                    })?
                    .path();
                prepare_adapter_work_directory(adapter_root)?;
                let temporary_directory = adapter_root.join(".stack-work/tmp");
                let executable = match confined_launcher {
                    Some(path) => fs::canonicalize(path).map_err(|error| {
                        format!("cannot bind confined archive adapter: {error}")
                    })?,
                    None => std::env::current_exe()
                        .map_err(|error| format!("cannot locate CI driver executable: {error}"))?,
                };
                let bound_llvm_ar = install_staged_native_archive_adapter(
                    adapter_root,
                    &executable,
                    &source_archiver,
                    &archiver_transaction,
                )?;
                let version = archiver_transaction
                    .run(bound_llvm_ar.command(Duration::from_secs(30), ["--version"]))
                    .map_err(|error| format!("cannot identify staged LLVM archiver: {error}"))?;
                require_complete_native_archiver_stdout("native-archiver-identity", &version)?;
                let version = std::str::from_utf8(&version.stdout)
                    .map_err(|_| "staged LLVM archiver identity is not UTF-8".to_owned())?;
                if !accepted_llvm_ar_version(version) {
                    return Err(
                        "staged LLVM archiver version differs from native CI policy".to_owned()
                    );
                }
                let llvm_ar_version = version.trim().to_owned();
                let work = adapter_root.join(".stack-work");
                fs::write(work.join("member.o"), b"native-archive-adapter\n")
                    .map_err(|error| format!("cannot write archiver probe member: {error}"))?;
                let inner = archiver_transaction
                    .run(
                        bound_llvm_ar
                            .command(Duration::from_secs(30), ["qcls", "inner.a", "member.o"])
                            .current_directory(&work),
                    )
                    .map_err(|error| format!("cannot build archiver probe input: {error}"))?;
                if !inner.status.success() || inner.timed_out {
                    return Err(command_result_failure(
                        "native-archiver-inner-probe",
                        &inner,
                    ));
                }
                fs::write(work.join("response.rsp"), b"inner.a\n")
                    .map_err(|error| format!("cannot write archiver response probe: {error}"))?;
                let probe = archiver_transaction
                    .run(
                        bound_llvm_ar
                            .command(Duration::from_secs(30), ["qL", "outer.a", "@response.rsp"])
                            .current_directory(&work),
                    )
                    .map_err(|error| format!("cannot probe LLVM archiver: {error}"))?;
                if !probe.status.success() || probe.timed_out {
                    return Err(command_result_failure(
                        "native-archiver-response-probe",
                        &probe,
                    ));
                }
                let table = archiver_transaction
                    .run(
                        bound_llvm_ar
                            .command(Duration::from_secs(30), ["t", "outer.a"])
                            .current_directory(&work),
                    )
                    .map_err(|error| {
                        format!("cannot inspect archiver flattening probe: {error}")
                    })?;
                if !table.status.success() || table.timed_out {
                    return Err(command_result_failure(
                        "native-archiver-table-probe",
                        &table,
                    ));
                }
                if table.stdout != b"member.o\n" {
                    return Err(
                        "LLVM archiver did not flatten the nested archive exactly".to_owned()
                    );
                }
                clean_native_archive_probe(&work)?;
                let toolchain_transaction = envelope.toolchain_transaction()?;
                let bound_toolchain = Arc::new(stage_native_toolchain(
                    adapter_root,
                    &toolchain_transaction,
                )?);
                let path = native_archive_path(
                    adapter_root,
                    &bound_toolchain.stack_bin.path,
                    &bound_toolchain.ghc_bin.path,
                )?;
                let stack_yaml = write_native_stack_overlay(
                    adapter_root,
                    source,
                    &bound_toolchain.ghc_bin.path,
                )?;
                bound_llvm_ar
                    .revalidate_until(envelope.execution_deadline, envelope.completion_deadline)?;
                let adapter = Self {
                    _directory: directory.take(),
                    bound_toolchain: Some(bound_toolchain),
                    llvm_ar: Some(bound_llvm_ar),
                    llvm_ar_version: Some(llvm_ar_version),
                    path: Some(path),
                    stack_yaml: Some(stack_yaml),
                    temporary_directory: Some(temporary_directory),
                    input_broker: None,
                };
                Ok(adapter)
            })();
            match result {
                Ok(adapter) => Ok(adapter),
                Err(primary) => native_archive_adapter_constructor_failure(
                    primary,
                    directory
                        .as_mut()
                        .map(|directory| directory.close_until(envelope.completion_deadline))
                        .unwrap_or(Ok(())),
                ),
            }
        }
    }

    #[cfg(unix)]
    pub(crate) fn directory_path(&self) -> Option<&Path> {
        self._directory.as_ref().map(AdapterDirectory::path)
    }

    pub(crate) fn close(mut self) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        if self.input_broker.is_some() {
            return Err(
                "active native archive input broker requires deadline-bound cleanup".to_owned(),
            );
        }
        if let Some(directory) = self._directory.as_mut() {
            directory.close()?;
        }
        self._directory = None;
        Ok(())
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn close_until(mut self, completion_deadline: Instant) -> Result<(), String> {
        if let Some(broker) = self.input_broker.as_mut() {
            broker.close_until(completion_deadline)?;
        }
        self.input_broker = None;
        if let Some(directory) = self._directory.as_mut() {
            directory.close_until(completion_deadline)?;
        }
        self._directory = None;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn retain_sealed_authority(
        &mut self,
        trusted_group: u32,
        candidate_uid: u32,
        authorization_deadline: Option<Instant>,
    ) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            if let Some(llvm_ar) = &self.llvm_ar {
                llvm_ar.revalidate()?;
            }
            let mut rebound = self
                .bound_toolchain
                .as_deref()
                .ok_or_else(|| "native archive adapter toolchain authority is absent".to_owned())?
                .clone();
            rebound.retain_sealed_adapter_authority(trusted_group)?;
            self.bound_toolchain = Some(Arc::new(rebound));
            let adapter_root = self
                ._directory
                .as_ref()
                .ok_or_else(|| "native archive adapter directory is absent".to_owned())?
                .path();
            if self.input_broker.is_some() {
                return Err("native archive input broker was started more than once".to_owned());
            }
            let archiver = self
                .llvm_ar
                .as_ref()
                .ok_or_else(|| "native archive broker archiver authority is absent".to_owned())?
                .clone();
            let authorization_deadline = authorization_deadline.ok_or_else(|| {
                "native archive broker parent authorization deadline is absent".to_owned()
            })?;
            self.input_broker = Some(NativeArchiveInputBroker::start(
                &adapter_root.join(".authority/inputs"),
                candidate_uid,
                archiver,
                authorization_deadline,
            )?);
            if let Some(llvm_ar) = &self.llvm_ar {
                llvm_ar.revalidate()?;
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (trusted_group, candidate_uid, authorization_deadline);
            Err("the sealed native archive authority requires a macOS host".to_owned())
        }
    }

    pub(crate) fn apply(&self, mut command: CommandSpec) -> CommandSpec {
        if let Some(bound_toolchain) = &self.bound_toolchain
            && let Err(error) = bound_toolchain.revalidate()
        {
            command.program_resolution_error = Some(error);
        }
        #[cfg(target_os = "macos")]
        if let Some(llvm_ar) = &self.llvm_ar
            && let Err(error) = llvm_ar.revalidate()
        {
            command.program_resolution_error = Some(error);
        }
        command.native_toolchain.clone_from(&self.bound_toolchain);
        #[cfg(target_os = "macos")]
        command.native_archiver.clone_from(&self.llvm_ar);
        let command = match &self.path {
            Some(path) => command.environment("PATH", path),
            None => command,
        };
        match &self.temporary_directory {
            Some(temporary_directory) => command.environment("TMPDIR", temporary_directory),
            None => command,
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn stop_input_broker_until(
        &mut self,
        completion_deadline: Instant,
    ) -> Result<(), String> {
        if let Some(broker) = self.input_broker.as_mut() {
            broker.close_until(completion_deadline)?;
        }
        self.input_broker = None;
        Ok(())
    }

    pub(crate) fn identity_command(&self) -> Option<CommandSpec> {
        self.llvm_ar.as_ref().map(|llvm_ar| {
            #[cfg(target_os = "macos")]
            let command = llvm_ar.command(Duration::from_secs(30), ["--version"]);
            #[cfg(not(target_os = "macos"))]
            let command =
                CommandSpec::new(llvm_ar.path(), Duration::from_secs(30)).argument("--version");
            command
        })
    }

    pub(crate) fn stack_build(&self, source: &Path, timeout: Duration) -> CommandSpec {
        let stack_yaml = self.stack_yaml_path();
        self.apply(native_stack_build(source, stack_yaml, timeout))
            .current_directory(self.stack_command_directory(source))
    }

    pub(crate) fn stack_path(&self, source: &Path) -> CommandSpec {
        let stack_yaml = self.stack_yaml_path();
        self.apply(native_stack_path(source, stack_yaml))
            .current_directory(self.stack_command_directory(source))
    }

    pub(crate) fn stack_ghc_version(&self, source: &Path) -> CommandSpec {
        let stack_yaml = self.stack_yaml_path();
        self.apply(native_stack_ghc_version(source, stack_yaml))
            .current_directory(self.stack_command_directory(source))
    }

    fn stack_command_directory(&self, source: &Path) -> PathBuf {
        match self.stack_yaml.as_deref() {
            Some(configured) => configured.parent().unwrap_or(source).to_path_buf(),
            None => source.to_path_buf(),
        }
    }

    pub(crate) fn stack_provenance(&self, source: &Path) -> Result<NativeStackProvenance, String> {
        let source = fs::canonicalize(source)
            .map_err(|error| format!("cannot canonicalize native oracle source: {error}"))?;
        let stack_yaml = source.join("stack.yaml");
        let stack_lock = source.join("stack.yaml.lock");
        let configured_stack_yaml = self.stack_yaml_path();
        let effective_stack_yaml = if configured_stack_yaml.is_absolute() {
            configured_stack_yaml.to_path_buf()
        } else {
            source.join(configured_stack_yaml)
        };
        let effective_stack_yaml = effective_stack_yaml.canonicalize().map_err(|error| {
            format!("cannot canonicalize effective native Stack configuration: {error}")
        })?;
        #[cfg(target_os = "macos")]
        if let Some(llvm_ar) = &self.llvm_ar {
            llvm_ar.revalidate()?;
        }
        let llvm_ar = self
            .llvm_ar
            .as_ref()
            .map(|llvm_ar| llvm_ar.canonical.clone());
        let llvm_ar_sha256 = self.llvm_ar.as_ref().map(|llvm_ar| llvm_ar.sha256);
        Ok(NativeStackProvenance {
            stack_yaml_sha256: sha256_file(&stack_yaml)
                .map_err(|error| format!("cannot hash pinned Stack configuration: {error}"))?,
            stack_lock_sha256: sha256_file(&stack_lock)
                .map_err(|error| format!("cannot hash pinned Stack lock: {error}"))?,
            effective_stack_yaml_sha256: sha256_file(&effective_stack_yaml).map_err(|error| {
                format!("cannot hash effective native Stack configuration: {error}")
            })?,
            source,
            source_commit: PINNED_ORACLE_SOURCE_COMMIT,
            effective_stack_yaml,
            llvm_ar,
            llvm_ar_sha256,
            llvm_ar_version: self.llvm_ar_version.clone(),
        })
    }

    fn stack_yaml_path(&self) -> &Path {
        self.stack_yaml
            .as_deref()
            .unwrap_or_else(|| Path::new("stack.yaml"))
    }
}

pub(crate) const PINNED_ORACLE_SOURCE_COMMIT: &str = "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff";

#[cfg(unix)]
fn native_archive_feature_probe(bound_llvm_ar: &Path, work_directory: &Path) -> CommandSpec {
    CommandSpec::new(bound_llvm_ar.as_os_str(), Duration::from_secs(30))
        .arguments(["qL", "outer.a", "@response.rsp"])
        .current_directory(work_directory)
}

#[cfg(unix)]
fn verify_native_archive_feature_probe_policy() -> Result<(), String> {
    let adapter_root = Path::new("/adapter");
    let authority = adapter_root.join(".authority");
    let work = adapter_root.join(".stack-work");
    #[cfg(target_os = "macos")]
    let archiver = authority.join("llvm").join("bin").join("llvm-ar");
    #[cfg(not(target_os = "macos"))]
    let archiver = authority.join("llvm-ar");
    let probe = native_archive_feature_probe(&archiver, &work);
    if probe.program != archiver.into_os_string()
        || probe.arguments
            != [
                OsString::from("qL"),
                OsString::from("outer.a"),
                OsString::from("@response.rsp"),
            ]
        || probe.current_directory.as_deref() != Some(work.as_path())
        || probe.timeout != Duration::from_secs(30)
    {
        return Err(
            "native archive preflight does not use bound authority and exact feature argv"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_native_archive_identity_policy() -> Result<(), String> {
    use std::os::unix::process::ExitStatusExt as _;

    if !accepted_llvm_ar_version("Homebrew LLVM version 18.1.8\n  Optimized build.\n")
        || !accepted_llvm_ar_version("Homebrew LLVM version 22.1.8\n  Optimized build.\n")
        || accepted_llvm_ar_version("LLVM version 22.1.8\n")
        || accepted_llvm_ar_version("Homebrew LLVM version 22.1.9\n")
    {
        return Err("native archive identity acceptance differs from policy".to_owned());
    }
    let stdout = b"Homebrew LLVM version 22.1.8\n  Optimized build.\n".to_vec();
    let truncated = CommandResult {
        status: ExitStatus::from_raw(0),
        duration: Duration::ZERO,
        timed_out: false,
        stdout_bytes: stdout.len() as u64 + 1,
        stdout_sha256: sha256_bytes(&stdout),
        stdout,
        stderr: Vec::new(),
        stdout_truncated: true,
        stderr_truncated: false,
        stderr_bytes: 0,
        stderr_sha256: sha256_bytes(&[]),
        cleanup_id: None,
        termination_forced: false,
        termination_reaped: false,
        candidate_quiescence_complete: false,
    };
    let truncated_error =
        require_complete_native_archiver_stdout("truncated-identity-verifier", &truncated)
            .expect_err("truncated native archive identity must fail closed");
    if !truncated_error.contains("stdout_truncated=true") {
        return Err("truncated native archive identity satisfied policy".to_owned());
    }
    let restricted = NativeArchiverOwnerAuthority::RestrictedConsumer {
        uid: 61_001,
        groups: vec![20, 61_002],
    };
    if restricted.admits_owner(61_001)
        || !restricted.admits_owner(61_003)
        || restricted.permits_file_mode(61_003, 61_002, 0o660)
        || !restricted.permits_file_mode(61_003, 61_004, 0o660)
        || !restricted.permits_ancestor_mode(0, 0, 0o1777, true)
        || restricted.permits_ancestor_mode(0, 0, 0o0777, true)
        || restricted.permits_ancestor_mode(61_001, 61_002, 0o700, true)
    {
        return Err(
            "restricted native archiver ownership policy differs from effective access".to_owned(),
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_restricted_native_archiver_launch(
    adapter: &Path,
    transaction: &NativeArchiverTransaction,
) -> Result<(), String> {
    transaction.require_execution("restricted archiver launch")?;
    let sudo = resolve_absolute_standard_executable(Path::new("/usr/bin/sudo"))?;
    sudo.revalidate()?;
    let mut command =
        CommandSpec::new(sudo.invocation_path(), Duration::from_secs(30)).arguments([
            OsString::from("-n"),
            OsString::from("-u"),
            OsString::from("nobody"),
            OsString::from("--"),
            adapter.join("ar").into_os_string(),
            OsString::from("--version"),
        ]);
    command.canonical_executable_identity = Some(sudo.canonical_identity().to_owned());
    command.invocation_name = Some(OsString::from("sudo"));
    let result = transaction
        .run(command.current_directory(Path::new("/private/tmp")))
        .map_err(|error| format!("cannot launch restricted staged archiver: {error}"))?;
    require_complete_native_archiver_stdout("restricted-native-archiver-identity", &result)?;
    let version = std::str::from_utf8(&result.stdout)
        .map_err(|_| "restricted staged archiver identity is not UTF-8".to_owned())?;
    if !accepted_llvm_ar_version(version) {
        return Err("restricted staged archiver identity differs from policy".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
const NATIVE_ARCHIVER_VERIFIER_RECEIPT_LIMIT: usize = 64;
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVER_VERIFIER_DETAIL_LIMIT: usize = 512;

#[cfg(target_os = "macos")]
struct NativeArchiverVerifierEnvelope {
    primary_deadline: Instant,
    command_completion_deadline: Instant,
    adapter_cleanup_deadline: Instant,
    root_cleanup_deadline: Instant,
}

#[cfg(target_os = "macos")]
impl NativeArchiverVerifierEnvelope {
    fn new() -> Result<Self, String> {
        let started = Instant::now();
        let primary_deadline = started
            .checked_add(Duration::from_secs(5 * 60))
            .ok_or_else(|| "native archiver verifier primary deadline overflowed".to_owned())?;
        let command_completion_deadline = primary_deadline
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| "native archiver verifier command deadline overflowed".to_owned())?;
        let adapter_cleanup_deadline = command_completion_deadline
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| "native archiver verifier adapter cleanup overflowed".to_owned())?;
        let root_cleanup_deadline = adapter_cleanup_deadline
            .checked_add(Duration::from_secs(60))
            .ok_or_else(|| "native archiver verifier root cleanup overflowed".to_owned())?;
        Ok(Self {
            primary_deadline,
            command_completion_deadline,
            adapter_cleanup_deadline,
            root_cleanup_deadline,
        })
    }

    fn transaction(&self, phase: &str) -> Result<NativeArchiverTransaction, String> {
        let started = Instant::now();
        let execution_deadline = started
            .checked_add(NATIVE_ARCHIVER_EXECUTION_BUDGET)
            .unwrap_or(self.primary_deadline)
            .min(self.primary_deadline);
        let completion_deadline = started
            .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
            .unwrap_or(self.command_completion_deadline)
            .min(self.command_completion_deadline);
        if started >= execution_deadline || execution_deadline >= completion_deadline {
            return Err(format!(
                "native archiver verifier envelope expired before {phase}"
            ));
        }
        Ok(NativeArchiverTransaction {
            execution_deadline,
            completion_deadline,
        })
    }
}

#[cfg(target_os = "macos")]
struct NativeArchiverVerifierEvidence {
    file: fs::File,
    started: Instant,
    sequence: usize,
    target: &'static str,
    case: &'static str,
}

#[cfg(target_os = "macos")]
impl NativeArchiverVerifierEvidence {
    fn create(path: &Path, case: &'static str) -> Result<Self, String> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| format!("cannot create native archiver verifier receipt: {error}"))?;
        Ok(Self {
            file,
            started: Instant::now(),
            sequence: 0,
            target: "macos-native-archiver-acquisition",
            case,
        })
    }

    fn record(
        &mut self,
        phase: &str,
        state: &str,
        cleanup_owner: &str,
        cleanup_result: &str,
        detail: &str,
    ) -> Result<(), String> {
        if self.sequence >= NATIVE_ARCHIVER_VERIFIER_RECEIPT_LIMIT {
            return Err("native archiver verifier receipt count exceeded its bound".to_owned());
        }
        self.sequence += 1;
        let mut bounded_detail = String::new();
        for character in detail.chars() {
            let character = if character.is_control() {
                ' '
            } else {
                character
            };
            if bounded_detail.len() + character.len_utf8() > NATIVE_ARCHIVER_VERIFIER_DETAIL_LIMIT {
                break;
            }
            bounded_detail.push(character);
        }
        writeln!(
            self.file,
            "native-archiver-verifier-v1 sequence={} target={} case={} phase={} state={} elapsedMillis={} cleanupOwner={} cleanupResult={} detail={}",
            self.sequence,
            self.target,
            self.case,
            phase,
            state,
            self.started.elapsed().as_millis(),
            cleanup_owner,
            cleanup_result,
            bounded_detail,
        )
        .and_then(|()| self.file.flush())
        .map_err(|error| format!("cannot persist native archiver verifier receipt: {error}"))?;
        eprintln!("hell-progress-target={}", self.target);
        eprintln!("hell-progress-case={}", self.case);
        eprintln!("hell-progress-subphase={phase}");
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn run_native_archiver_verifier_phase<T>(
    evidence: &mut NativeArchiverVerifierEvidence,
    phase: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    evidence.record(phase, "active", "none", "not-applicable", "started")?;
    match operation() {
        Ok(value) => {
            evidence.record(phase, "passed", "none", "not-applicable", "completed")?;
            Ok(value)
        }
        Err(error) => {
            let receipt = evidence.record(phase, "failed", "none", "not-applicable", &error);
            match receipt {
                Ok(()) => Err(error),
                Err(receipt) => Err(format!(
                    "{error}; additionally, phase receipt persistence failed: {receipt}"
                )),
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn verify_native_archiver_graph_receipts(
    graph: &NativeArchiverLoadGraph,
    source_prefix: &Path,
    staged_members: &[PathBuf],
    external_members: &[PathBuf],
) -> Result<(), String> {
    for edge in &graph.edges {
        match &edge.target {
            NativeArchiverLoadTarget::Staged(relative) => {
                if relative
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
                    || staged_members
                        .iter()
                        .filter(|member| *member == relative)
                        .count()
                        != 1
                {
                    return Err(
                        "staged archiver graph target lacks one normalized manifest member"
                            .to_owned(),
                    );
                }
            }
            NativeArchiverLoadTarget::External(canonical) => {
                if canonical.starts_with(source_prefix)
                    || external_members
                        .iter()
                        .filter(|member| *member == canonical)
                        .count()
                        != 1
                {
                    return Err(
                        "staged archiver graph external target lacks one closed receipt".to_owned(),
                    );
                }
            }
            NativeArchiverLoadTarget::System(_) => {}
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_macos_native_archiver_acquisition_for_integration(
    receipt_path: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let envelope = NativeArchiverVerifierEnvelope::new()?;
    let mut evidence = NativeArchiverVerifierEvidence::create(
        receipt_path,
        "homebrew-real-positive-acquire-stage-execute-cleanup",
    )?;
    let mut verifier_root =
        run_native_archiver_verifier_phase(&mut evidence, "verifier-root-creation", || {
            create_adapter_directory(Path::new("/private/tmp"))
        })?;
    let root = verifier_root.path().to_owned();
    let launcher = root.join("confined-launcher");
    let mut launcher_receipt = None;
    let mut directory = None;
    let result = (|| {
        run_native_archiver_verifier_phase(&mut evidence, "root-setup", || {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
                .map_err(|error| format!("cannot open native archiver verifier root: {error}"))
        })?;
        let acquisition_transaction = envelope.transaction("Homebrew source acquisition")?;
        let acquired = run_native_archiver_verifier_phase(
            &mut evidence,
            "homebrew-source-acquisition",
            || acquire_native_archiver_source(&acquisition_transaction),
        )?;
        run_native_archiver_verifier_phase(&mut evidence, "confined-launcher-staging", || {
            let current_executable = std::env::current_exe()
                .map_err(|error| format!("cannot locate confined verifier launcher: {error}"))?;
            fs::copy(&current_executable, &launcher)
                .map_err(|error| format!("cannot stage confined verifier launcher: {error}"))?;
            fs::set_permissions(&launcher, fs::Permissions::from_mode(0o555))
                .map_err(|error| format!("cannot freeze confined verifier launcher: {error}"))?;
            launcher_receipt = Some(BoundNativeCleanupFile::bind(
                &launcher,
                acquisition_transaction.execution_deadline,
            )?);
            Ok(())
        })?;
        let (positive_directory, staged) =
            run_native_archiver_verifier_phase(&mut evidence, "positive-closure-staging", || {
                directory = Some(create_adapter_directory(&root)?);
                let retained = directory.as_ref().ok_or_else(|| {
                    "native archiver verifier directory was not retained".to_owned()
                })?;
                let path = retained.path().to_owned();
                let stage_transaction = envelope.transaction("positive closure staging")?;
                prepare_adapter_work_directory(&path)?;
                let staged = install_staged_native_archive_adapter(
                    &path,
                    &launcher,
                    &acquired,
                    &stage_transaction,
                )?;
                Ok((path, staged))
            })?;
        let validation_transaction = envelope.transaction("positive graph validation")?;
        run_native_archiver_verifier_phase(&mut evidence, "positive-graph-validation", || {
            staged.revalidate_until(
                validation_transaction.execution_deadline,
                validation_transaction.completion_deadline,
            )
        })?;
        run_native_archiver_verifier_phase(&mut evidence, "positive-graph-receipts", || {
            let staged_members = staged
                .distribution
                .entries
                .iter()
                .map(|entry| entry.relative.clone())
                .collect::<Vec<_>>();
            let external_members = staged
                .external_dependencies
                .iter()
                .map(|dependency| dependency.canonical.clone())
                .collect::<Vec<_>>();
            verify_native_archiver_graph_receipts(
                &staged.load_graph,
                &acquired.source_prefix,
                &staged_members,
                &external_members,
            )
        })?;
        let identity_transaction = envelope.transaction("staged identity execution")?;
        run_native_archiver_verifier_phase(&mut evidence, "staged-identity-execution", || {
            let identity = identity_transaction
                .run(staged.command(Duration::from_secs(30), ["--version"]))
                .map_err(|error| format!("cannot execute staged archiver identity: {error}"))?;
            require_complete_native_archiver_stdout("native-archiver-staged-execution", &identity)?;
            let version = std::str::from_utf8(&identity.stdout)
                .map_err(|_| "staged archiver verifier identity is not UTF-8".to_owned())?;
            if !accepted_llvm_ar_version(version) {
                return Err("staged archiver verifier identity differs from policy".to_owned());
            }
            Ok(())
        })?;
        let restricted_transaction = envelope.transaction("restricted staged identity")?;
        run_native_archiver_verifier_phase(&mut evidence, "restricted-staged-execution", || {
            verify_restricted_native_archiver_launch(&positive_directory, &restricted_transaction)
        })?;
        let work = positive_directory.join(".stack-work");
        run_native_archiver_verifier_phase(&mut evidence, "archive-input", || {
            fs::write(work.join("member.o"), b"native-archive-adapter\n")
                .map_err(|error| format!("cannot write staged archiver verifier member: {error}"))
        })?;
        let inner_transaction = envelope.transaction("inner archive execution")?;
        run_native_archiver_verifier_phase(&mut evidence, "archive-inner", || {
            let inner = inner_transaction
                .run(
                    staged
                        .command(Duration::from_secs(30), ["qcls", "inner.a", "member.o"])
                        .current_directory(&work),
                )
                .map_err(|error| format!("cannot run staged archiver inner probe: {error}"))?;
            if inner.timed_out || !inner.status.success() {
                return Err(command_result_failure("staged-archiver-inner", &inner));
            }
            Ok(())
        })?;
        fs::write(work.join("response.rsp"), b"inner.a\n")
            .map_err(|error| format!("cannot write staged archiver verifier response: {error}"))?;
        let response_transaction = envelope.transaction("response archive execution")?;
        run_native_archiver_verifier_phase(&mut evidence, "archive-response", || {
            let response = response_transaction
                .run(
                    staged
                        .command(Duration::from_secs(30), ["qL", "outer.a", "@response.rsp"])
                        .current_directory(&work),
                )
                .map_err(|error| format!("cannot run staged archiver response probe: {error}"))?;
            if response.timed_out || !response.status.success() {
                return Err(command_result_failure(
                    "staged-archiver-response",
                    &response,
                ));
            }
            Ok(())
        })?;
        let table_transaction = envelope.transaction("archive table execution")?;
        run_native_archiver_verifier_phase(&mut evidence, "archive-table", || {
            let table = table_transaction
                .run(
                    staged
                        .command(Duration::from_secs(30), ["t", "outer.a"])
                        .current_directory(&work),
                )
                .map_err(|error| {
                    format!("cannot inspect staged archiver verifier table: {error}")
                })?;
            if table.timed_out || !table.status.success() || table.stdout != b"member.o\n" {
                return Err(command_result_failure("staged-archiver-table", &table));
            }
            Ok(())
        })?;
        run_native_archiver_verifier_phase(&mut evidence, "validation-pass-receipt", || {
            let passes = staged.validation_passes.counts();
            if passes
                != (NativeArchiverValidationPassCounts {
                    full_closure: 1,
                    load_graph: 1,
                    spawn_preflight: 4,
                })
            {
                return Err(format!(
                    "staged archiver validation pass receipt differs from policy: {passes:?}"
                ));
            }
            Ok(())
        })?;

        Ok(())
    })();
    let mut failures = Vec::new();
    if let Err(error) = result {
        failures.push(error);
    }
    let adapter_cleanup = directory.as_mut().map_or(Ok(()), |directory| {
        directory.close_until(envelope.adapter_cleanup_deadline)
    });
    let adapter_cleanup_detail = match &adapter_cleanup {
        Ok(()) => "completed".to_owned(),
        Err(error) => error.clone(),
    };
    if let Err(error) = evidence.record(
        "cleanup-adapter",
        if adapter_cleanup.is_ok() {
            "passed"
        } else {
            "failed"
        },
        "adapter-directory",
        if adapter_cleanup.is_ok() {
            "absent"
        } else {
            "retained"
        },
        &adapter_cleanup_detail,
    ) {
        failures.push(error);
    }
    if let Err(error) = adapter_cleanup {
        failures.push(format!("adapter-directory cleanup: {error}"));
    }
    let launcher_cleanup = launcher_receipt.as_ref().map_or(Ok(()), |receipt| {
        receipt.remove_until(envelope.root_cleanup_deadline)
    });
    let launcher_cleanup_detail = match &launcher_cleanup {
        Ok(()) => "completed".to_owned(),
        Err(error) => error.clone(),
    };
    if let Err(error) = evidence.record(
        "cleanup-launcher",
        if launcher_cleanup.is_ok() {
            "passed"
        } else {
            "failed"
        },
        "confined-launcher",
        if launcher_cleanup.is_ok() {
            "absent"
        } else {
            "retained"
        },
        &launcher_cleanup_detail,
    ) {
        failures.push(error);
    }
    if let Err(error) = launcher_cleanup {
        failures.push(format!("confined-launcher cleanup: {error}"));
    }
    let root_cleanup = verifier_root.close_until(envelope.root_cleanup_deadline);
    let root_cleanup_detail = match &root_cleanup {
        Ok(()) => "completed".to_owned(),
        Err(error) => error.clone(),
    };
    if let Err(error) = evidence.record(
        "cleanup-root",
        if root_cleanup.is_ok() {
            "passed"
        } else {
            "failed"
        },
        "verifier-root",
        if root_cleanup.is_ok() {
            "absent"
        } else {
            "retained"
        },
        &root_cleanup_detail,
    ) {
        failures.push(error);
    }
    if let Err(error) = root_cleanup {
        failures.push(format!("verifier-root cleanup: {error}"));
    }
    let terminal_state = if failures.is_empty() {
        "passed"
    } else {
        "failed"
    };
    let terminal_detail = if failures.is_empty() {
        "completed".to_owned()
    } else {
        failures.join("; ")
    };
    if let Err(error) = evidence.record(
        "terminal",
        terminal_state,
        "all",
        if failures.is_empty() {
            "absent"
        } else {
            "failed"
        },
        &terminal_detail,
    ) {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_macos_native_archiver_topology_for_integration(
    receipt_path: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let envelope = NativeArchiverVerifierEnvelope::new()?;
    let mut evidence = NativeArchiverVerifierEvidence::create(
        receipt_path,
        "synthetic-system-topology-parser-and-mutation-negatives",
    )?;
    let mut directory =
        run_native_archiver_verifier_phase(&mut evidence, "verifier-root-creation", || {
            create_adapter_directory(Path::new("/private/tmp"))
        })?;
    let root = directory.path().to_owned();
    let result = (|| {
        run_native_archiver_verifier_phase(&mut evidence, "system-only-topology", || {
            let system = PathBuf::from("/usr/lib/libSystem.B.dylib");
            let graph = NativeArchiverLoadGraph {
                edges: vec![NativeArchiverLoadEdge {
                    source: PathBuf::from("bin/llvm-ar"),
                    load_name: system.to_string_lossy().into_owned(),
                    target: NativeArchiverLoadTarget::System(system),
                }],
            };
            verify_native_archiver_graph_receipts(
                &graph,
                &root.join("synthetic-prefix"),
                &[PathBuf::from("bin/llvm-ar")],
                &[],
            )
        })?;
        let work = root.join(".stack-work");
        run_native_archiver_verifier_phase(&mut evidence, "synthetic-work-setup", || {
            prepare_adapter_work_directory(&root)
        })?;
        let escape = work.join("tmp").join("escape");
        let prefix = escape.join("prefix");
        let bin = prefix.join("bin");
        let outside = escape.join("outside");
        run_native_archiver_verifier_phase(&mut evidence, "load-command-parser", || {
            let parsed = parse_macho_load_commands(
                "cmd LC_ID_DYLIB\nname @rpath/self.dylib (offset 24)\ncmd LC_RPATH\npath first (offset 12)\ncmd LC_RPATH\npath second (offset 12)\ncmd LC_LOAD_DYLIB\nname @rpath/load.dylib (offset 24)\n",
            )?;
            if parsed.load_names != ["@rpath/load.dylib"]
                || parsed.rpaths != ["first", "second"]
                || parse_macho_load_commands("cmd LC_LOAD_DYLIB\ncmd LC_RPATH\n").is_ok()
                || parse_macho_load_commands("cmd LC_RPATH\n").is_ok()
            {
                return Err("Mach-O load-command parser differs from exact policy".to_owned());
            }
            Ok(())
        })?;
        run_native_archiver_verifier_phase(&mut evidence, "ordered-rpath-and-escape", || {
            fs::create_dir_all(&bin)
                .and_then(|()| fs::create_dir_all(&outside))
                .map_err(|error| format!("cannot create loader escape fixture: {error}"))?;
            let fixture_archiver = bin.join("llvm-ar");
            let escaped_library = outside.join("libescape.dylib");
            fs::write(&fixture_archiver, b"fixture\n")
                .and_then(|()| fs::write(&escaped_library, b"fixture\n"))
                .map_err(|error| format!("cannot write loader escape fixture: {error}"))?;
            let first = escape.join("first");
            let second = escape.join("second");
            fs::create_dir(&first)
                .and_then(|()| fs::create_dir(&second))
                .and_then(|()| fs::write(first.join("ordered.dylib"), b"first\n"))
                .and_then(|()| fs::write(second.join("ordered.dylib"), b"second\n"))
                .map_err(|error| format!("cannot create ordered run-path fixture: {error}"))?;
            let ordered = resolve_macho_load_name(
                "@rpath/ordered.dylib",
                &fixture_archiver,
                &bin,
                &[first.clone(), second],
            )?;
            if ordered.canonical
                != fs::canonicalize(first.join("ordered.dylib")).map_err(|error| {
                    format!("cannot canonicalize ordered run-path fixture: {error}")
                })?
            {
                return Err(
                    "Mach-O run-path resolution did not preserve first-existing order".to_owned(),
                );
            }
            let escape_rpaths = resolve_macho_rpath_roots(
                &fixture_archiver,
                &bin,
                &["@loader_path/../../outside".to_owned()],
                &[],
            )?;
            let resolved = resolve_macho_load_name(
                "@rpath/libescape.dylib",
                &fixture_archiver,
                &bin,
                &escape_rpaths,
            )?;
            let canonical_prefix = fs::canonicalize(&prefix)
                .map_err(|error| format!("cannot canonicalize loader escape prefix: {error}"))?;
            if normalized_staged_load_path(
                &resolved.logical,
                &canonical_prefix,
                &resolved.canonical,
            )
            .is_ok()
            {
                return Err("loader-relative escape satisfied staged boundary policy".to_owned());
            }
            Ok(())
        })?;
        run_native_archiver_verifier_phase(&mut evidence, "same-size-leaf-mutation", || {
            let leaf = work.join("tmp/mutation/bin/dependency");
            create_native_archiver_dependency_fixture(&leaf, b"original-bytes\n")?;
            let transaction = envelope.transaction("synthetic dependency mutation")?;
            let authority = NativeArchiverOwnerAuthority::TrustedPublisher {
                uid: nix::unistd::geteuid().as_raw(),
            };
            let dependency =
                BoundNativeArchiverDependency::bind_until(&leaf, transaction, &authority)?;
            fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755))
                .and_then(|()| fs::write(&leaf, b"mutated!-bytes\n"))
                .map_err(|error| format!("cannot mutate synthetic dependency: {error}"))?;
            if dependency.revalidate_full_until(transaction).is_ok() {
                return Err("same-size synthetic dependency mutation satisfied receipt".to_owned());
            }
            Ok(())
        })?;
        Ok(())
    })();
    let mut failures = result.err().into_iter().collect::<Vec<_>>();
    let cleanup = directory.close_until(envelope.root_cleanup_deadline);
    let cleanup_detail = cleanup
        .as_ref()
        .map_or_else(|error| error.clone(), |()| "completed".to_owned());
    if let Err(error) = evidence.record(
        "cleanup-root",
        if cleanup.is_ok() { "passed" } else { "failed" },
        "synthetic-verifier-root",
        if cleanup.is_ok() {
            "absent"
        } else {
            "retained"
        },
        &cleanup_detail,
    ) {
        failures.push(error);
    }
    if let Err(error) = cleanup {
        failures.push(format!("synthetic verifier cleanup: {error}"));
    }
    let passed = failures.is_empty();
    let terminal_detail = if passed {
        "completed".to_owned()
    } else {
        failures.join("; ")
    };
    if let Err(error) = evidence.record(
        "terminal",
        if passed { "passed" } else { "failed" },
        "all",
        if passed { "absent" } else { "failed" },
        &terminal_detail,
    ) {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_macos_native_archiver_dependency_receipt_for_integration() -> Result<(), String>
{
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let mut directory = create_adapter_directory(Path::new("/private/tmp"))?;
    let root = directory.path().to_owned();
    let started = Instant::now();
    let transaction = NativeArchiverTransaction {
        execution_deadline: started
            .checked_add(Duration::from_secs(45))
            .ok_or_else(|| "native archiver dependency verifier deadline overflowed".to_owned())?,
        completion_deadline: started
            .checked_add(Duration::from_secs(60))
            .ok_or_else(|| {
                "native archiver dependency verifier completion deadline overflowed".to_owned()
            })?,
    };
    let authority = NativeArchiverOwnerAuthority::TrustedPublisher {
        uid: nix::unistd::geteuid().as_raw(),
    };
    let result = (|| {
        let sibling_parent = root.join("sibling-parent");
        let sibling_leaf = sibling_parent.join("bin/dependency");
        create_native_archiver_dependency_fixture(&sibling_leaf, b"sibling-receipt\n")?;
        let sibling =
            BoundNativeArchiverDependency::bind_until(&sibling_leaf, transaction, &authority)?;
        let unrelated = sibling_parent.join("unrelated");
        fs::create_dir(&unrelated)
            .map_err(|error| format!("cannot create dependency sibling churn: {error}"))?;
        sibling
            .revalidate_full_until(transaction)
            .map_err(|error| {
                format!("unrelated dependency sibling invalidated its authority: {error}")
            })?;
        fs::remove_dir(&unrelated)
            .map_err(|error| format!("cannot remove dependency sibling churn: {error}"))?;
        sibling
            .revalidate_full_until(transaction)
            .map_err(|error| {
                format!("removed dependency sibling invalidated its authority: {error}")
            })?;

        let intermediate = root.join("intermediate-parent/bound");
        let intermediate_leaf = intermediate.join("dependency");
        create_native_archiver_dependency_fixture(&intermediate_leaf, b"intermediate\n")?;
        let intermediate_receipt =
            BoundNativeArchiverDependency::bind_until(&intermediate_leaf, transaction, &authority)?;
        let displaced = intermediate.with_file_name("displaced");
        fs::rename(&intermediate, &displaced)
            .map_err(|error| format!("cannot displace dependency ancestor: {error}"))?;
        fs::create_dir(&intermediate)
            .map_err(|error| format!("cannot replace dependency ancestor: {error}"))?;
        fs::hard_link(displaced.join("dependency"), &intermediate_leaf).map_err(|error| {
            format!("cannot retain dependency leaf across substitution: {error}")
        })?;
        let intermediate_error = intermediate_receipt
            .revalidate_full_until(transaction)
            .expect_err("a replaced dependency ancestor must fail");
        if !matches!(
            intermediate_error.as_str(),
            "Mach-O dependency identity changed before use"
                | "Mach-O dependency ancestor identity changed before use"
        ) {
            return Err(format!(
                "dependency ancestor substitution diagnostic differs: {intermediate_error}"
            ));
        }

        let symlink_parent = root.join("symlink-parent");
        let first_target = symlink_parent.join("first");
        let second_target = symlink_parent.join("second");
        let first_leaf = first_target.join("dependency");
        create_native_archiver_dependency_fixture(&first_leaf, b"symlink-target\n")?;
        fs::create_dir(&second_target)
            .map_err(|error| format!("cannot create alternate dependency target: {error}"))?;
        fs::hard_link(&first_leaf, second_target.join("dependency")).map_err(|error| {
            format!("cannot retain dependency across symlink retarget: {error}")
        })?;
        let alias = symlink_parent.join("alias");
        symlink(&first_target, &alias)
            .map_err(|error| format!("cannot create dependency ancestor symlink: {error}"))?;
        let alias_leaf = alias.join("dependency");
        let symlink_receipt =
            BoundNativeArchiverDependency::bind_until(&alias_leaf, transaction, &authority)?;
        fs::remove_file(&alias)
            .map_err(|error| format!("cannot remove dependency ancestor symlink: {error}"))?;
        symlink(&second_target, &alias)
            .map_err(|error| format!("cannot retarget dependency ancestor symlink: {error}"))?;
        if symlink_receipt.revalidate_full_until(transaction).is_ok() {
            return Err("retargeted dependency ancestor retained its authority".to_owned());
        }

        let mode_parent = root.join("mode-parent");
        let mode_leaf = mode_parent.join("dependency");
        create_native_archiver_dependency_fixture(&mode_leaf, b"mode-receipt\n")?;
        let mode_receipt =
            BoundNativeArchiverDependency::bind_until(&mode_leaf, transaction, &authority)?;
        fs::set_permissions(&mode_parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot mutate dependency ancestor mode: {error}"))?;
        let mode_error = mode_receipt
            .revalidate_full_until(transaction)
            .expect_err("a dependency ancestor mode mutation must fail");
        if mode_error != "Mach-O dependency ancestor identity changed before use" {
            return Err(format!(
                "dependency ancestor mode diagnostic differs: {mode_error}"
            ));
        }

        let acl_parent = root.join("acl-parent");
        let acl_leaf = acl_parent.join("dependency");
        create_native_archiver_dependency_fixture(&acl_leaf, b"acl-receipt\n")?;
        let acl_receipt =
            BoundNativeArchiverDependency::bind_until(&acl_leaf, transaction, &authority)?;
        run_fixed_macos_chmod(
            [
                OsStr::new("+a"),
                OsStr::new("everyone allow write"),
                acl_parent.as_os_str(),
            ],
            "seed the dependency ancestor ACL mutation",
        )?;
        let acl_error = acl_receipt
            .revalidate_full_until(transaction)
            .expect_err("a dependency ancestor ACL mutation must fail");
        if acl_error != "Mach-O dependency authority retains a macOS access-control list" {
            return Err(format!(
                "dependency ancestor ACL diagnostic differs: {acl_error}"
            ));
        }

        let leaf_parent = root.join("leaf-parent");
        let leaf = leaf_parent.join("dependency");
        create_native_archiver_dependency_fixture(&leaf, b"first-leaf\n")?;
        let leaf_receipt =
            BoundNativeArchiverDependency::bind_until(&leaf, transaction, &authority)?;
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot open dependency leaf for mutation: {error}"))?;
        fs::write(&leaf, b"other-leaf\n")
            .map_err(|error| format!("cannot mutate dependency leaf bytes: {error}"))?;
        fs::set_permissions(&leaf, fs::Permissions::from_mode(0o555))
            .map_err(|error| format!("cannot refreeze mutated dependency leaf: {error}"))?;
        let leaf_error = leaf_receipt
            .revalidate_full_until(transaction)
            .expect_err("a dependency leaf byte mutation must fail");
        if !matches!(
            leaf_error.as_str(),
            "Mach-O dependency identity changed before use"
                | "Mach-O dependency content changed before use"
        ) {
            return Err(format!(
                "dependency leaf mutation diagnostic differs: {leaf_error}"
            ));
        }
        Ok(())
    })();
    let cleanup = directory.close_until(transaction.completion_deadline);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; native archiver dependency verifier cleanup also failed: {cleanup}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn create_native_archiver_dependency_fixture(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = path
        .parent()
        .ok_or_else(|| "native archiver dependency fixture has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create native archiver dependency fixture: {error}"))?;
    fs::write(path, bytes)
        .map_err(|error| format!("cannot write native archiver dependency fixture: {error}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o555))
        .map_err(|error| format!("cannot freeze native archiver dependency fixture: {error}"))
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_macos_native_archiver_receipt_for_integration() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut source_directory = create_adapter_directory(Path::new("/private/tmp"))?;
    let mut directory = create_adapter_directory(Path::new("/private/tmp"))?;
    let source_root = source_directory.path().to_owned();
    let root = directory.path().to_owned();
    let started = Instant::now();
    let construction_envelope = NativeArchiveAdapterConstructionEnvelope {
        execution_deadline: started
            .checked_add(Duration::from_secs(60))
            .ok_or_else(|| {
                "native archiver construction verifier deadline overflowed".to_owned()
            })?,
        completion_deadline: started
            .checked_add(Duration::from_secs(3 * 60))
            .ok_or_else(|| {
                "native archiver construction verifier cleanup deadline overflowed".to_owned()
            })?,
        archiver_execution_deadline: started
            .checked_add(Duration::from_secs(45))
            .ok_or_else(|| "native archiver receipt deadline overflowed".to_owned())?,
        archiver_completion_deadline: started
            .checked_add(Duration::from_secs(60))
            .ok_or_else(|| "native archiver receipt completion deadline overflowed".to_owned())?,
    };
    let transaction = NativeArchiverTransaction {
        execution_deadline: started
            .checked_add(Duration::from_secs(45))
            .ok_or_else(|| "native archiver receipt deadline overflowed".to_owned())?,
        completion_deadline: started
            .checked_add(Duration::from_secs(60))
            .ok_or_else(|| "native archiver receipt completion deadline overflowed".to_owned())?,
    };
    let mut brokers = Vec::<NativeArchiveInputBroker>::new();
    let result = (|| {
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot open native archiver receipt root: {error}"))?;
        prepare_adapter_work_directory(&root)?;
        let source_prefix = source_root.join("llvm-source");
        let source_bin = source_prefix.join("bin");
        fs::create_dir_all(&source_bin)
            .map_err(|error| format!("cannot create native archiver receipt source: {error}"))?;
        let source_archiver = source_bin.join("llvm-ar");
        let current_executable = std::env::current_exe()
            .map_err(|error| format!("cannot locate native archiver receipt program: {error}"))?;
        fs::copy(&current_executable, &source_archiver)
            .map_err(|error| format!("cannot copy native archiver receipt program: {error}"))?;
        fs::set_permissions(&source_archiver, fs::Permissions::from_mode(0o555))
            .and_then(|()| fs::set_permissions(&source_bin, fs::Permissions::from_mode(0o555)))
            .and_then(|()| fs::set_permissions(&source_prefix, fs::Permissions::from_mode(0o555)))
            .map_err(|error| format!("cannot freeze native archiver receipt source: {error}"))?;
        strip_staged_native_acls_until(&source_prefix, Some(transaction.execution_deadline))?;
        let otool = resolve_absolute_standard_executable(Path::new("/usr/bin/otool"))?;
        let (files, load_graph, external_dependencies) = acquire_native_archiver_load_graph(
            &source_archiver,
            &source_prefix,
            &otool,
            &transaction,
            &NativeArchiverOwnerAuthority::TrustedPublisher {
                uid: nix::unistd::geteuid().as_raw(),
            },
        )?;
        let acquired = AcquiredNativeArchiverSource {
            source_prefix: fs::canonicalize(&source_prefix).map_err(|error| {
                format!("cannot canonicalize native archiver receipt source: {error}")
            })?,
            files,
            load_graph,
            external_dependencies,
            otool,
        };
        let staged = install_staged_native_archive_adapter(
            &root,
            &current_executable,
            &acquired,
            &transaction,
        )?;
        if staged.validation_passes.counts()
            != (NativeArchiverValidationPassCounts {
                full_closure: 1,
                load_graph: 1,
                spawn_preflight: 0,
            })
        {
            return Err("initial native archiver pass receipt differs from policy".to_owned());
        }
        let stale_archiver_transaction = NativeArchiverTransaction {
            execution_deadline: Instant::now(),
            completion_deadline: transaction.completion_deadline,
        };
        let stale_error = staged
            .revalidate_until(
                stale_archiver_transaction.execution_deadline,
                stale_archiver_transaction.completion_deadline,
            )
            .expect_err("stale archiver acquisition deadline must reject revalidation");
        if !stale_error.contains(
            "staged native toolchain absolute deadline expired before staged LLVM archiver revalidation",
        ) {
            return Err(format!(
                "stale archiver deadline diagnostic differs: {stale_error}"
            ));
        }
        let archiver_subtransaction = construction_envelope.archiver_transaction()?;
        if archiver_subtransaction.execution_deadline > construction_envelope.execution_deadline
            || archiver_subtransaction.completion_deadline
                > construction_envelope.completion_deadline
        {
            return Err("native archiver sub-budget escaped its construction envelope".to_owned());
        }
        let toolchain_subtransaction = construction_envelope.toolchain_transaction()?;
        if toolchain_subtransaction.execution_deadline != construction_envelope.execution_deadline
            || toolchain_subtransaction.completion_deadline
                != construction_envelope.completion_deadline
        {
            return Err(
                "native toolchain sub-budget differs from its construction envelope".to_owned(),
            );
        }
        staged.revalidate_until(
            construction_envelope.execution_deadline,
            construction_envelope.completion_deadline,
        )?;
        if staged.validation_passes.counts()
            != (NativeArchiverValidationPassCounts {
                full_closure: 1,
                load_graph: 1,
                spawn_preflight: 0,
            })
        {
            return Err("final native archiver receipt rescanned its sealed closure".to_owned());
        }
        let staging_root = root.join(".authority/inputs");
        let work = root.join(".stack-work");
        brokers.push(NativeArchiveInputBroker::start(
            &staging_root,
            nix::unistd::geteuid().as_raw(),
            staged.clone(),
            construction_envelope.execution_deadline,
        )?);
        let broker = brokers
            .last_mut()
            .ok_or_else(|| "native archiver verifier broker owner is absent".to_owned())?;
        let trusted_group = nix::unistd::getegid().as_raw();
        let authority_root = root.join(".authority");
        for directory in [&root, &authority_root, &staging_root] {
            std::os::unix::fs::chown(directory, None, Some(trusted_group)).map_err(|error| {
                format!("cannot bind brokered archiver verifier group: {error}")
            })?;
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o2755))
            .and_then(|()| fs::set_permissions(&authority_root, fs::Permissions::from_mode(0o555)))
            .and_then(|()| fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o2710)))
            .map_err(|error| format!("cannot seal brokered archiver verifier: {error}"))?;
        let capability = NativeArchiveInputBrokerCapability::bind(
            &root,
            construction_envelope.execution_deadline,
        )
        .map_err(|error| format!("cannot bind brokered archiver verifier: {error}"))?;
        for expected_authorizations in 1..=3 {
            let arguments = vec![OsString::from("__native-archiver-receipt-child")];
            let authorized = capability
                .authorize_archiver(&arguments, &work, construction_envelope.execution_deadline)
                .map_err(|error| format!("cannot authorize brokered archiver verifier: {error}"))?;
            let result = transaction
                .run(authorized.command(arguments, &work))
                .map_err(|error| format!("cannot run broker-authorized archiver: {error}"))?;
            if result.timed_out
                || !result.status.success()
                || result.stdout != b"member.o\n"
                || broker.authorization_count() != expected_authorizations
                || staged.validation_passes.counts()
                    != (NativeArchiverValidationPassCounts {
                        full_closure: 1,
                        load_graph: 1,
                        spawn_preflight: expected_authorizations,
                    })
            {
                return Err(
                    "brokered archiver authorization rescanned or did not execute exactly"
                        .to_owned(),
                );
            }
        }
        let authorizations_before_expiry = broker.authorization_count();
        if capability
            .authorize_archiver(
                &[OsString::from("__native-archiver-receipt-child")],
                &work,
                Instant::now(),
            )
            .is_ok()
            || broker.authorization_count() != authorizations_before_expiry
        {
            return Err("expired brokered archiver request reached authority binding".to_owned());
        }
        broker.close_until(construction_envelope.completion_deadline)?;

        let before_mid_authorization_expiry = staged.validation_passes.counts();
        brokers.push(
            NativeArchiveInputBroker::start_with_expired_authorization_for_integration(
                &staging_root,
                nix::unistd::geteuid().as_raw(),
                staged.clone(),
                construction_envelope.completion_deadline,
            )?,
        );
        let expiring_broker = brokers
            .last_mut()
            .ok_or_else(|| "expiring archiver verifier broker owner is absent".to_owned())?;
        let expiring_capability = NativeArchiveInputBrokerCapability::bind(
            &root,
            construction_envelope.completion_deadline,
        )
        .map_err(|error| format!("cannot bind expiring archiver verifier: {error}"))?;
        let mid_authorization_error = match expiring_capability.authorize_archiver(
            &[OsString::from("__native-archiver-receipt-child")],
            &work,
            construction_envelope.completion_deadline,
        ) {
            Ok(_) => {
                return Err(
                    "an authorization expiring after request receipt unexpectedly succeeded"
                        .to_owned(),
                );
            }
            Err(error) => error,
        };
        if !mid_authorization_error
            .to_string()
            .contains("closed during authorization state")
            || expiring_broker.authorization_count() != 0
            || staged.validation_passes.counts() != before_mid_authorization_expiry
        {
            return Err(format!(
                "mid-authorization expiry performed late authority work: {mid_authorization_error}"
            ));
        }
        expiring_broker.close_until(construction_envelope.completion_deadline)?;

        let before_drip_expiry = staged.validation_passes.counts();
        brokers.push(
            NativeArchiveInputBroker::start_with_drip_expiry_for_integration(
                &staging_root,
                nix::unistd::geteuid().as_raw(),
                staged.clone(),
                construction_envelope.completion_deadline,
            )?,
        );
        let drip_broker = brokers
            .last_mut()
            .ok_or_else(|| "drip-expiry broker owner is absent".to_owned())?;
        let mut drip_stream = std::os::unix::net::UnixStream::connect(&drip_broker.socket)
            .map_err(|error| format!("cannot connect drip-expiry verifier: {error}"))?;
        configure_native_archive_broker_stream(
            &drip_stream,
            construction_envelope.completion_deadline,
        )?;
        drip_stream
            .write_all(NATIVE_ARCHIVE_AUTH_BROKER_MAGIC)
            .map_err(|error| format!("cannot write drip-expiry verifier magic: {error}"))?;
        let mut readiness = [0_u8; 1];
        read_native_archive_broker_exact_until(
            &mut drip_stream,
            &mut readiness,
            construction_envelope.completion_deadline,
            "drip-expiry readiness",
            false,
        )?;
        if readiness != [NATIVE_ARCHIVE_AUTH_BROKER_READY] {
            return Err("drip-expiry broker readiness differs".to_owned());
        }
        let remaining_millis = u64::try_from(
            construction_envelope
                .completion_deadline
                .saturating_duration_since(Instant::now())
                .min(NATIVE_ARCHIVE_AUTHORIZATION_BUDGET)
                .as_millis(),
        )
        .map_err(|_| "drip-expiry authorization cutoff overflowed".to_owned())?;
        drip_stream
            .write_all(&remaining_millis.to_le_bytes())
            .map_err(|error| format!("cannot write drip-expiry cutoff: {error}"))?;
        write_native_archive_broker_u32(&mut drip_stream, 1)?;
        write_native_archive_broker_u32(&mut drip_stream, 2)?;
        drip_stream
            .write_all(b"x")
            .map_err(|error| format!("cannot write drip-expiry argument prefix: {error}"))?;
        let mut state = [0_u8; 1];
        let drip_error = read_native_archive_broker_exact_until(
            &mut drip_stream,
            &mut state,
            construction_envelope.completion_deadline,
            "drip-expiry authorization state",
            false,
        )
        .expect_err("a drip-fed authorization crossing its cutoff must close without a response");
        if !drip_error.contains("closed during drip-expiry authorization state")
            || drip_broker.authorization_count() != 0
            || staged.validation_passes.counts() != before_drip_expiry
        {
            return Err(format!(
                "drip-fed authorization expiry performed late authority work: {drip_error}"
            ));
        }
        drip_broker.close_until(construction_envelope.completion_deadline)?;

        let before_magic_expiry = staged.validation_passes.counts();
        brokers.push(
            NativeArchiveInputBroker::start_with_magic_drip_expiry_for_integration(
                &staging_root,
                nix::unistd::geteuid().as_raw(),
                staged.clone(),
                construction_envelope.completion_deadline,
            )?,
        );
        let magic_broker = brokers
            .last_mut()
            .ok_or_else(|| "magic-expiry broker owner is absent".to_owned())?;
        let mut magic_stream = std::os::unix::net::UnixStream::connect(&magic_broker.socket)
            .map_err(|error| format!("cannot connect magic-expiry verifier: {error}"))?;
        configure_native_archive_broker_stream(
            &magic_stream,
            construction_envelope.completion_deadline,
        )?;
        magic_stream
            .write_all(&NATIVE_ARCHIVE_AUTH_BROKER_MAGIC[..1])
            .map_err(|error| format!("cannot write magic-expiry prefix: {error}"))?;
        let mut readiness = [0_u8; 1];
        let magic_error = read_native_archive_broker_exact_until(
            &mut magic_stream,
            &mut readiness,
            construction_envelope.completion_deadline,
            "magic-expiry readiness",
            false,
        )
        .expect_err("a drip-fed broker magic crossing its cutoff must close without readiness");
        if !magic_error.contains("closed during magic-expiry readiness")
            || magic_broker.authorization_count() != 0
            || staged.validation_passes.counts() != before_magic_expiry
        {
            return Err(format!(
                "drip-fed broker magic expiry performed late authority work: {magic_error}"
            ));
        }
        magic_broker.close_until(construction_envelope.completion_deadline)?;

        let before_input_expiry = staged.validation_passes.counts();
        brokers.push(
            NativeArchiveInputBroker::start_with_input_drip_expiry_for_integration(
                &staging_root,
                nix::unistd::geteuid().as_raw(),
            )?,
        );
        let input_broker = brokers
            .last_mut()
            .ok_or_else(|| "input-expiry broker owner is absent".to_owned())?;
        let mut input_stream = std::os::unix::net::UnixStream::connect(&input_broker.socket)
            .map_err(|error| format!("cannot connect input-expiry verifier: {error}"))?;
        configure_native_archive_broker_stream(
            &input_stream,
            construction_envelope.completion_deadline,
        )?;
        input_stream
            .write_all(NATIVE_ARCHIVE_INPUT_BROKER_MAGIC)
            .map_err(|error| format!("cannot write input-expiry magic: {error}"))?;
        write_native_archive_broker_u32(&mut input_stream, 1)?;
        write_native_archive_broker_u32(&mut input_stream, 2)?;
        input_stream
            .write_all(b"x")
            .map_err(|error| format!("cannot write input-expiry path prefix: {error}"))?;
        let mut state = [0_u8; 1];
        let input_error = read_native_archive_broker_exact_until(
            &mut input_stream,
            &mut state,
            construction_envelope.completion_deadline,
            "input-expiry response state",
            false,
        )
        .expect_err("a drip-fed input request crossing its cutoff must close without a response");
        if !input_error.contains("closed during input-expiry response state")
            || input_broker.authorization_count() != 0
            || staged.validation_passes.counts() != before_input_expiry
            || staging_root.join("request-0").exists()
            || staging_root.join("request-0/member-0").exists()
        {
            return Err(format!(
                "drip-fed input expiry performed late copy or authority work: {input_error}"
            ));
        }
        input_broker.close_until(construction_envelope.completion_deadline)?;
        if fs::read_dir(&staging_root)
            .map_err(|error| format!("cannot inspect input-expiry cleanup: {error}"))?
            .next()
            .is_some()
        {
            return Err("drip-fed input expiry staging remains after cleanup".to_owned());
        }

        let before_expired = staged.validation_passes.counts();
        let expired = NativeArchiverTransaction {
            execution_deadline: Instant::now(),
            completion_deadline: transaction.completion_deadline,
        };
        if expired
            .run(staged.command(Duration::from_secs(5), ["__native-archiver-receipt-child"]))
            .is_ok()
            || staged.validation_passes.counts() != before_expired
        {
            return Err("expired native archiver receipt reached preflight or spawn".to_owned());
        }

        fs::set_permissions(&staged.distribution.root, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot open native archiver receipt prefix: {error}"))?;
        fs::write(staged.distribution.root.join("unexpected"), b"unexpected\n")
            .map_err(|error| format!("cannot mutate native archiver receipt prefix: {error}"))?;
        if transaction
            .run(staged.command(Duration::from_secs(5), ["__native-archiver-receipt-child"]))
            .is_ok()
            || staged.validation_passes.counts() != before_expired
        {
            return Err("mutated native archiver closure reached spawn".to_owned());
        }
        brokers.push(NativeArchiveInputBroker::start_for_integration(
            &staging_root,
            nix::unistd::geteuid().as_raw(),
            1,
            1,
        )?);
        let finalizer_probe: Result<(), String> =
            Err("injected native archiver verifier failure after broker start".to_owned());
        match finalizer_probe {
            Err(error)
                if error == "injected native archiver verifier failure after broker start" => {}
            Err(error) => {
                return Err(format!(
                    "native archiver verifier finalizer injection differs: {error}"
                ));
            }
            Ok(()) => {
                return Err(
                    "native archiver verifier finalizer injection unexpectedly succeeded"
                        .to_owned(),
                );
            }
        }
        let ordered_failure = compose_native_archiver_verifier_completion(
            Err("injected verifier primary".to_owned()),
            Err("injected broker cleanup".to_owned()),
            Err("injected directory cleanup".to_owned()),
        )
        .expect_err("verifier failure composition must retain every cause");
        if ordered_failure
            != "injected verifier primary; native archiver broker cleanup failed: injected broker cleanup; native archiver receipt cleanup failed: injected directory cleanup"
        {
            return Err(format!(
                "native archiver verifier failure order differs: {ordered_failure}"
            ));
        }
        Ok(())
    })();
    let mut broker_cleanup_failures = Vec::new();
    for broker in brokers.iter_mut().rev() {
        if let Err(error) = broker.close_until(construction_envelope.completion_deadline) {
            broker_cleanup_failures.push(error);
        }
        if broker.socket_root.exists() || broker.socket.exists() || broker.capability.exists() {
            broker_cleanup_failures
                .push("native archiver verifier broker authority remains after cleanup".to_owned());
        }
    }
    let verifier_staging = root.join(".authority/inputs");
    match fs::read_dir(&verifier_staging) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                broker_cleanup_failures
                    .push("native archiver verifier staging remains after cleanup".to_owned());
            }
        }
        Err(error) => broker_cleanup_failures.push(format!(
            "cannot attest native archiver verifier staging cleanup: {error}"
        )),
    }
    let broker_cleanup = if broker_cleanup_failures.is_empty() {
        Ok(())
    } else {
        Err(broker_cleanup_failures.join("; "))
    };
    let mut cleanup_failures = Vec::new();
    if let Err(error) = directory.close_until(construction_envelope.completion_deadline) {
        cleanup_failures.push(error);
    }
    if let Err(error) = source_directory.close_until(construction_envelope.completion_deadline) {
        cleanup_failures.push(error);
    }
    let cleanup = if cleanup_failures.is_empty() {
        Ok(())
    } else {
        Err(cleanup_failures.join("; "))
    };
    compose_native_archiver_verifier_completion(result, broker_cleanup, cleanup)
}

#[cfg(target_os = "macos")]
fn compose_native_archiver_verifier_completion(
    primary: Result<(), String>,
    broker_cleanup: Result<(), String>,
    directory_cleanup: Result<(), String>,
) -> Result<(), String> {
    let mut failures = Vec::new();
    if let Err(primary) = primary {
        failures.push(primary);
    }
    if let Err(broker_cleanup) = broker_cleanup {
        failures.push(format!(
            "native archiver broker cleanup failed: {broker_cleanup}"
        ));
    }
    if let Err(directory_cleanup) = directory_cleanup {
        failures.push(format!(
            "native archiver receipt cleanup failed: {directory_cleanup}"
        ));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(unix)]
fn prepare_adapter_work_directory(adapter_root: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let work_directory = adapter_root.join(".stack-work");
    fs::create_dir(&work_directory)
        .map_err(|error| format!("cannot create candidate Stack work directory: {error}"))?;
    fs::set_permissions(&work_directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot confine candidate Stack work directory: {error}"))?;
    let temporary_directory = work_directory.join("tmp");
    fs::create_dir(&temporary_directory)
        .map_err(|error| format!("cannot create candidate Stack temporary directory: {error}"))?;
    strip_staged_native_acls(adapter_root)?;
    fs::set_permissions(adapter_root, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("cannot confine macOS archive adapter directory: {error}"))?;
    fs::set_permissions(&work_directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot confine candidate Stack work directory: {error}"))?;
    fs::set_permissions(&temporary_directory, fs::Permissions::from_mode(0o770))
        .map_err(|error| format!("cannot confine candidate Stack temporary directory: {error}"))
}

#[cfg(target_os = "macos")]
fn clean_native_archive_probe(work_directory: &Path) -> Result<(), String> {
    for name in ["inner.a", "member.o", "outer.a", "response.rsp"] {
        let path = work_directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                fs::remove_file(&path).map_err(|error| {
                    format!("cannot remove native archive probe output {name:?}: {error}")
                })?;
            }
            Ok(_) => {
                return Err(format!(
                    "native archive probe output {name:?} is not regular"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect native archive probe output {name:?}: {error}"
                ));
            }
        }
    }
    Ok(())
}

fn yaml_single_quoted_path(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "native Stack source path is not UTF-8".to_owned())?;
    if value.chars().any(char::is_control) {
        return Err("native Stack source path contains a control character".to_owned());
    }
    Ok(yaml_single_quoted(value))
}

fn yaml_single_quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn write_native_stack_overlay(
    directory: &Path,
    source: &Path,
    ghc_bin: &Path,
) -> Result<PathBuf, String> {
    const PINNED_STACK_YAML: &[u8] =
        include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml");
    const PINNED_STACK_LOCK: &[u8] =
        include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock");
    let stack_yaml = fs::read(source.join("stack.yaml"))
        .map_err(|error| format!("cannot read pinned Stack configuration: {error}"))?;
    if stack_yaml != PINNED_STACK_YAML {
        return Err("pinned Stack configuration differs from native CI policy".to_owned());
    }
    let stack_lock = fs::read(source.join("stack.yaml.lock"))
        .map_err(|error| format!("cannot read pinned Stack lock: {error}"))?;
    if stack_lock != PINNED_STACK_LOCK {
        return Err("pinned Stack lock differs from native CI policy".to_owned());
    }
    let canonical_source = fs::canonicalize(source)
        .map_err(|error| format!("cannot canonicalize native Stack source: {error}"))?;
    let package = yaml_single_quoted_path(&canonical_source)?;
    let canonical_adapter = fs::canonicalize(directory)
        .map_err(|error| format!("cannot canonicalize native archive adapter: {error}"))?;
    let adapter = yaml_single_quoted_path(&canonical_adapter)?;
    let canonical_ghc_bin = fs::canonicalize(ghc_bin)
        .map_err(|error| format!("cannot canonicalize staged GHC bin directory: {error}"))?;
    if !canonical_ghc_bin.starts_with(canonical_adapter.join(".toolchain/system-ghc-9.8.2")) {
        return Err("staged GHC bin directory escapes the native adapter".to_owned());
    }
    let ghc_bin = yaml_single_quoted_path(&canonical_ghc_bin)?;
    let ar = canonical_adapter.join("ar");
    let ar_value = ar
        .to_str()
        .ok_or_else(|| "native archive adapter path is not UTF-8".to_owned())?;
    if ar_value.chars().any(char::is_control) {
        return Err("native archive adapter path contains a control character".to_owned());
    }
    let configure_ar = yaml_single_quoted(&format!("--with-ar={ar_value}"));
    let overlay = format!(
        "resolver: nightly-2024-10-21\npackages:\n  - {package}\nsystem-ghc: true\ninstall-ghc: false\ncompiler-check: match-exact\nallow-different-user: true\nextra-path:\n  - {adapter}\n  - {ghc_bin}\nconfigure-options:\n  \"$everything\":\n    - {configure_ar}\nghc-options:\n  \"$everything\": \"-split-sections -j\"\n  unix-time: \"-optl-all_load\"\n  network-control: \"-fforce-recomp\"\n"
    );
    let overlay_path = directory.join("stack.yaml");
    fs::write(&overlay_path, overlay)
        .map_err(|error| format!("cannot write native Stack overlay: {error}"))?;
    fs::write(directory.join("stack.yaml.lock"), stack_lock)
        .map_err(|error| format!("cannot copy pinned native Stack lock: {error}"))?;
    Ok(overlay_path)
}

fn native_archive_path(
    adapter_root: &Path,
    stack_bin: &Path,
    ghc_bin: &Path,
) -> Result<OsString, String> {
    std::env::join_paths([
        adapter_root,
        stack_bin,
        ghc_bin,
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .map_err(|error| format!("cannot construct archive adapter PATH: {error}"))
}

const SENSITIVE_ENVIRONMENT: [&str; 9] = [
    "GITHUB_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "GITHUB_OUTPUT",
    "GITHUB_ENV",
    "GITHUB_PATH",
    "GITHUB_STEP_SUMMARY",
    "GH_TOKEN",
];

#[derive(Clone)]
struct ReleaseCandidateEnvironment {
    target: OsString,
    isolated: OsString,
    source_date_epoch: OsString,
}

thread_local! {
    static RELEASE_CANDIDATE_ENVIRONMENT: RefCell<Option<ReleaseCandidateEnvironment>> = const { RefCell::new(None) };
}

pub(crate) fn with_release_candidate_environment<T>(
    target: &std::path::Path,
    isolated: &std::path::Path,
    source_date_epoch: u64,
    launch_policy: &hell_testkit::CandidateLaunchPolicy,
    operation: impl FnOnce() -> T,
) -> T {
    let environment = ReleaseCandidateEnvironment {
        target: target.as_os_str().to_owned(),
        isolated: isolated.as_os_str().to_owned(),
        source_date_epoch: source_date_epoch.to_string().into(),
    };
    RELEASE_CANDIDATE_ENVIRONMENT.with(|slot| {
        struct Restore<'a> {
            slot: &'a RefCell<Option<ReleaseCandidateEnvironment>>,
            previous: Option<ReleaseCandidateEnvironment>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.slot.replace(self.previous.take());
            }
        }
        let previous = slot.replace(Some(environment));
        let _restore = Restore { slot, previous };
        hell_testkit::with_candidate_launch_policy(launch_policy, operation)
    })
}

pub(crate) fn release_candidate_target() -> Option<PathBuf> {
    RELEASE_CANDIDATE_ENVIRONMENT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|environment| PathBuf::from(environment.target.clone()))
    })
}

#[derive(Debug)]
pub struct CommandResult {
    pub status: ExitStatus,
    pub duration: Duration,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: Digest,
    pub stderr_sha256: Digest,
    pub cleanup_id: Option<u64>,
    pub termination_forced: bool,
    pub termination_reaped: bool,
    pub candidate_quiescence_complete: bool,
    #[cfg(windows)]
    pub windows_launch_control: Option<hell_testkit::WindowsLaunchControlReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandRunPhase {
    ProgramResolution,
    SupervisedExecution,
    StdoutRelay,
    StderrRelay,
}

impl CommandRunPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProgramResolution => "program-resolution",
            Self::SupervisedExecution => "supervised-execution",
            Self::StdoutRelay => "stdout-relay",
            Self::StderrRelay => "stderr-relay",
        }
    }
}

#[derive(Debug)]
pub struct CommandRunError {
    phase: CommandRunPhase,
    source: std::io::Error,
    completed: Option<Box<CommandResult>>,
}

impl CommandRunError {
    fn new(phase: CommandRunPhase, source: std::io::Error) -> Self {
        Self {
            phase,
            source,
            completed: None,
        }
    }

    fn after_completion(
        phase: CommandRunPhase,
        source: std::io::Error,
        completed: CommandResult,
    ) -> Self {
        Self {
            phase,
            source,
            completed: Some(Box::new(completed)),
        }
    }

    pub fn phase(&self) -> CommandRunPhase {
        self.phase
    }

    pub fn kind(&self) -> std::io::ErrorKind {
        self.source.kind()
    }

    pub fn raw_os_error(&self) -> Option<i32> {
        self.source.raw_os_error()
    }

    pub fn message(&self) -> String {
        self.source.to_string()
    }

    pub fn completed(&self) -> Option<&CommandResult> {
        self.completed.as_deref()
    }

    pub fn retained_cleanup_receipt(&self) -> Option<hell_testkit::RetainedTerminationReceipt> {
        hell_testkit::retained_termination_receipt(&self.source)
    }

    pub fn candidate_quiescence_receipt(&self) -> Option<hell_testkit::CandidateQuiescenceReceipt> {
        hell_testkit::candidate_quiescence_receipt(&self.source)
    }

    pub fn supervised_io_receipt(&self) -> Option<hell_testkit::SupervisedIoReceipt> {
        hell_testkit::supervised_io_receipt(&self.source)
    }
}

impl std::fmt::Display for CommandRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.phase.as_str(), self.source)
    }
}

impl std::error::Error for CommandRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl CommandSpec {
    pub fn new(program: impl Into<OsString>, timeout: Duration) -> Self {
        let mut spec = Self {
            program: program.into(),
            arguments: Vec::new(),
            current_directory: None,
            environment: Vec::new(),
            clear_environment: false,
            process_scope: ProcessScope::IsolatedTree,
            timeout,
            canonical_executable_identity: None,
            invocation_name: None,
            program_resolution_error: None,
            native_toolchain: None,
            #[cfg(target_os = "macos")]
            native_toolchain_query_deadline: None,
            #[cfg(target_os = "macos")]
            native_archiver: None,
            #[cfg(target_os = "macos")]
            native_archiver_deadlines: None,
        };
        if let Some(release) = RELEASE_CANDIDATE_ENVIRONMENT.with(|slot| slot.borrow().clone()) {
            let isolated = PathBuf::from(&release.isolated);
            spec = spec
                .release_candidate_environment()
                .environment("CARGO_TARGET_DIR", release.target.clone())
                .environment("CARGO_INCREMENTAL", "0")
                .environment("SOURCE_DATE_EPOCH", release.source_date_epoch.clone())
                .environment("HOME", isolated.join("home"))
                .environment("USERPROFILE", isolated.join("home"))
                .environment("CARGO_HOME", isolated.join("cargo"))
                .environment("SCCACHE_DIR", isolated.join("sccache"))
                .environment("TEMP", isolated.join("tmp"))
                .environment("TMP", isolated.join("tmp"))
                .environment("TMPDIR", isolated.join("tmp"));
        }
        spec
    }

    pub fn cargo(timeout: Duration) -> Self {
        Self::cargo_from_resolution(timeout, resolve_cargo_executable())
    }

    #[cfg(windows)]
    pub(crate) fn trusted_absolute(program: PathBuf, timeout: Duration) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(&program)
            .map_err(|error| format!("cannot inspect trusted Windows executable: {error}"))?;
        let canonical = fs::canonicalize(&program)
            .map_err(|error| format!("cannot canonicalize trusted Windows executable: {error}"))?;
        if !program.is_absolute()
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || canonical != program
        {
            return Err("trusted Windows executable is not one canonical regular file".to_owned());
        }
        let mut spec = Self::new(program, timeout);
        spec.canonical_executable_identity = Some(canonical);
        Ok(spec)
    }

    #[cfg(unix)]
    pub fn cargo_deny(timeout: Duration) -> Self {
        let mut spec = Self::new(OsString::from("cargo-deny"), timeout);
        spec.invocation_name = Some(OsString::from("cargo-deny"));
        match resolve_standard_path_executable(OsStr::new("cargo-deny")) {
            Ok(resolved) => {
                spec.program = resolved.invocation_path.into_os_string();
                spec.canonical_executable_identity = Some(resolved.canonical_identity);
            }
            Err(error) => spec.program_resolution_error = Some(error),
        }
        spec
    }

    fn cargo_from_resolution(
        timeout: Duration,
        resolution: Result<ResolvedCargoExecutable, String>,
    ) -> Self {
        let mut spec = Self::new(OsString::from("cargo"), timeout);
        spec.invocation_name = Some(OsString::from("cargo"));
        match resolution {
            Ok(resolved) => {
                spec.program = resolved.invocation_path.into_os_string();
                spec.canonical_executable_identity = Some(resolved.canonical_identity);
                spec.invocation_name = Some(resolved.invocation_name);
            }
            Err(error) => spec.program_resolution_error = Some(error),
        }
        spec
    }

    pub(crate) fn trusted_cargo(timeout: Duration, resolved: &ResolvedCargoExecutable) -> Self {
        let mut spec = Self::new(resolved.invocation_path.clone().into_os_string(), timeout);
        spec.canonical_executable_identity = Some(resolved.canonical_identity.clone());
        spec.invocation_name = Some(resolved.invocation_name.clone());
        spec
    }

    #[cfg(test)]
    pub(crate) fn cargo_resolution_failure(timeout: Duration, error: &str) -> Self {
        Self::cargo_from_resolution(timeout, Err(error.to_owned()))
    }

    #[cfg(test)]
    pub(crate) fn cargo_resolution_success(
        timeout: Duration,
        invocation_path: PathBuf,
        canonical_identity: PathBuf,
    ) -> Self {
        Self::cargo_from_resolution(
            timeout,
            Ok(ResolvedCargoExecutable {
                invocation_path,
                canonical_identity,
                invocation_name: OsString::from("cargo"),
            }),
        )
    }

    pub fn argument(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    pub fn arguments<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn current_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.current_directory = Some(path.into());
        self
    }

    pub fn release_candidate_environment(mut self) -> Self {
        self.environment = hell_testkit::RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.into(), value)))
            .collect();
        self.clear_environment = true;
        self
    }

    pub fn environment(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        let name = name.into();
        assert!(
            !is_sensitive_environment(&name),
            "sensitive environment variables cannot be added to a supervised command"
        );
        self.environment.push((name, value.into()));
        self
    }

    pub fn git_safe_directory(self, path: &Path) -> Self {
        const GIT_CONFIG_NAMES: [&str; 3] =
            ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"];
        assert_eq!(
            Path::new(&self.program).file_name(),
            Some(OsStr::new("git")),
            "safe.directory configuration is restricted to Git commands"
        );
        assert!(
            self.environment.iter().all(|(name, _)| !GIT_CONFIG_NAMES
                .iter()
                .any(|reserved| name == OsStr::new(reserved))),
            "Git safe.directory configuration must be unique"
        );
        self.environment("GIT_CONFIG_COUNT", "1")
            .environment("GIT_CONFIG_KEY_0", "safe.directory")
            .environment("GIT_CONFIG_VALUE_0", path.as_os_str())
    }

    #[cfg(test)]
    pub fn environment_names(&self) -> Vec<String> {
        self.environment
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect()
    }

    pub fn display_program(&self) -> String {
        self.program.to_string_lossy().into_owned()
    }

    pub fn display_invocation_name(&self) -> Option<String> {
        self.invocation_name
            .as_deref()
            .map(|name| name.to_string_lossy().into_owned())
    }

    pub fn display_canonical_executable_identity(&self) -> Option<String> {
        self.canonical_executable_identity
            .as_deref()
            .map(|path| path.to_string_lossy().into_owned())
    }

    pub fn display_arguments(&self) -> Vec<String> {
        self.arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    pub fn run(&self) -> Result<CommandResult, CommandRunError> {
        self.run_inner(None, None)
    }

    pub(crate) fn run_until(
        &self,
        execution_deadline: Instant,
        completion_deadline: Instant,
        progress: SupervisedProgressObserver,
    ) -> Result<CommandResult, CommandRunError> {
        self.run_inner(
            Some((execution_deadline, completion_deadline)),
            Some(progress),
        )
    }

    fn run_inner(
        &self,
        deadlines: Option<(Instant, Instant)>,
        progress: Option<SupervisedProgressObserver>,
    ) -> Result<CommandResult, CommandRunError> {
        let started = Instant::now();
        let live_relay = progress.is_some();
        if let Some((execution_deadline, completion_deadline)) = deadlines
            && (execution_deadline > completion_deadline || Instant::now() >= execution_deadline)
        {
            return Err(CommandRunError::new(
                CommandRunPhase::ProgramResolution,
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "command absolute deadline expired before program resolution",
                ),
            ));
        }
        if let Some(error) = &self.program_resolution_error {
            return Err(CommandRunError::new(
                CommandRunPhase::ProgramResolution,
                std::io::Error::new(std::io::ErrorKind::NotFound, error.clone()),
            ));
        }
        if let Some(native_toolchain) = &self.native_toolchain {
            #[cfg(target_os = "macos")]
            let validation = if let Some(deadline) = self.native_toolchain_query_deadline {
                native_toolchain.revalidate_ghc_query_authority(deadline)
            } else {
                native_toolchain.revalidate()
            };
            #[cfg(not(target_os = "macos"))]
            let validation = native_toolchain.revalidate();
            validation.map_err(|error| {
                CommandRunError::new(
                    CommandRunPhase::ProgramResolution,
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, error),
                )
            })?;
        }
        #[cfg(target_os = "macos")]
        if let Some(native_archiver) = &self.native_archiver {
            let archiver_deadlines = self.native_archiver_deadlines.or(deadlines);
            let validation = match archiver_deadlines {
                Some((execution_deadline, completion_deadline)) => native_archiver
                    .revalidate_for_spawn_until(execution_deadline, completion_deadline),
                None => native_archiver.revalidate_for_spawn(),
            };
            validation.map_err(|error| {
                CommandRunError::new(
                    CommandRunPhase::ProgramResolution,
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, error),
                )
            })?;
        }
        if let Some(expected) = &self.canonical_executable_identity {
            revalidate_resolved_cargo(Path::new(&self.program), expected)
                .map_err(|error| CommandRunError::new(CommandRunPhase::ProgramResolution, error))?;
        }
        let mut command = Command::new(&self.program);
        #[cfg(unix)]
        if let Some(invocation_name) = &self.invocation_name {
            use std::os::unix::process::CommandExt as _;

            let invocation_path = Path::new(invocation_name);
            if invocation_name.is_empty()
                || invocation_path.file_name() != Some(invocation_name.as_os_str())
                || invocation_path.parent() != Some(Path::new(""))
            {
                return Err(CommandRunError::new(
                    CommandRunPhase::ProgramResolution,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "resolved invocation name is not one canonical component",
                    ),
                ));
            }
            command.arg0(invocation_name);
        }
        command.args(&self.arguments);
        if self.clear_environment {
            command.env_clear();
        }
        for name in SENSITIVE_ENVIRONMENT {
            command.env_remove(name);
        }
        command.envs(self.environment.iter().cloned());
        for name in SENSITIVE_ENVIRONMENT {
            command.env_remove(name);
        }
        if let Some(directory) = &self.current_directory {
            command.current_dir(directory);
        }

        debug_assert_eq!(self.process_scope, ProcessScope::IsolatedTree);

        let output = if let Some(expected) = &self.canonical_executable_identity {
            let identity =
                BoundProgramInvocation::new(PathBuf::from(&self.program), expected.clone())
                    .map_err(|error| {
                        CommandRunError::new(CommandRunPhase::ProgramResolution, error)
                    })?;
            if let Some((execution_deadline, completion_deadline)) = deadlines {
                run_supervised_command_with_bound_program_until(
                    &mut command,
                    &[],
                    execution_deadline,
                    completion_deadline,
                    &identity,
                    progress,
                )
            } else {
                run_supervised_command_with_bound_program(
                    &mut command,
                    &[],
                    self.timeout,
                    &identity,
                )
            }
        } else if let Some((execution_deadline, completion_deadline)) = deadlines {
            run_supervised_command_until(
                &mut command,
                &[],
                execution_deadline,
                completion_deadline,
                progress,
            )
        } else {
            run_supervised_command(&mut command, &[], self.timeout)
        }
        .map_err(|error| CommandRunError::new(CommandRunPhase::SupervisedExecution, error))?;
        let stdout = output.stdout.retained_bytes();
        let stderr = output.stderr.retained_bytes();
        let result = CommandResult {
            status: output.status,
            duration: started.elapsed(),
            timed_out: output.timed_out,
            stdout,
            stderr,
            stdout_truncated: output.stdout.truncated,
            stderr_truncated: output.stderr.truncated,
            stdout_bytes: output.stdout.total_bytes,
            stderr_bytes: output.stderr.total_bytes,
            stdout_sha256: output.stdout.sha256,
            stderr_sha256: output.stderr.sha256,
            cleanup_id: output.termination.map(|report| report.cleanup_id),
            termination_forced: output.termination.is_some_and(|report| report.forced),
            termination_reaped: output.termination.is_some_and(|report| report.reaped),
            candidate_quiescence_complete: output.candidate_quiescence_complete,
            #[cfg(windows)]
            windows_launch_control: output.windows_launch_control,
        };
        if !live_relay && let Err(error) = std::io::stdout().write_all(&result.stdout) {
            return Err(CommandRunError::after_completion(
                CommandRunPhase::StdoutRelay,
                error,
                result,
            ));
        }
        if !live_relay && let Err(error) = std::io::stderr().write_all(&result.stderr) {
            return Err(CommandRunError::after_completion(
                CommandRunPhase::StderrRelay,
                error,
                result,
            ));
        }
        Ok(result)
    }
}

fn is_sensitive_environment(name: &OsString) -> bool {
    SENSITIVE_ENVIRONMENT
        .iter()
        .any(|sensitive| name == sensitive)
}

#[cfg(unix)]
pub(crate) fn resolve_standard_path_executable(
    name: &OsStr,
) -> Result<ResolvedStandardExecutable, String> {
    let path = std::env::var_os("PATH").ok_or_else(|| {
        format!(
            "cannot resolve {} without standard PATH",
            name.to_string_lossy()
        )
    })?;
    let search = std::env::split_paths(&path).collect::<Vec<_>>();
    resolve_standard_path_executable_from(name, &search)
}

#[cfg(unix)]
pub(crate) fn resolve_standard_cargo_executable() -> Result<ResolvedCargoExecutable, String> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| "cannot resolve standard Cargo without standard PATH".to_owned())?;
    let search = std::env::split_paths(&path).collect::<Vec<_>>();
    resolve_standard_cargo_executable_from(&search)
}

#[cfg(unix)]
pub(crate) fn resolve_standard_cargo_executable_from(
    search: &[PathBuf],
) -> Result<ResolvedCargoExecutable, String> {
    let resolved = resolve_standard_path_executable_from(OsStr::new("cargo"), search)?;
    Ok(ResolvedCargoExecutable {
        invocation_path: resolved.invocation_path,
        canonical_identity: resolved.canonical_identity,
        invocation_name: OsString::from("cargo"),
    })
}

#[cfg(unix)]
pub(crate) fn resolve_absolute_standard_executable(
    path: &Path,
) -> Result<ResolvedStandardExecutable, String> {
    if !path.is_absolute() {
        return Err("standard tool path must be absolute".to_owned());
    }
    resolved_standard_candidate(path).ok_or_else(|| {
        format!(
            "cannot bind absolute standard executable {}",
            path.display()
        )
    })
}

#[cfg(unix)]
pub(crate) fn resolve_standard_path_executable_from(
    name: &OsStr,
    search: &[PathBuf],
) -> Result<ResolvedStandardExecutable, String> {
    let name_path = Path::new(name);
    if name.is_empty() || name_path.is_absolute() || name_path.components().count() != 1 {
        return Err("standard tool name must be one relative path component".to_owned());
    }
    for directory in search.iter().filter(|directory| directory.is_absolute()) {
        if let Some(resolved) = resolved_standard_candidate(&directory.join(name)) {
            return Ok(resolved);
        }
    }
    Err(format!(
        "cannot resolve {} from standard PATH",
        name.to_string_lossy()
    ))
}

#[cfg(unix)]
fn resolved_standard_candidate(path: &Path) -> Option<ResolvedStandardExecutable> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use nix::fcntl::AtFlags;
        use nix::unistd::{AccessFlags, faccessat};

        if faccessat(None, path, AccessFlags::X_OK, AtFlags::AT_EACCESS).is_err() {
            return None;
        }
    }
    let canonical_identity = fs::canonicalize(path).ok()?;
    let file_name = path.file_name()?;
    let canonical_parent = fs::canonicalize(path.parent()?).ok()?;
    let parent_before = fs::metadata(&canonical_parent).ok()?;
    let before = fs::metadata(&canonical_identity).ok()?;
    let after = fs::metadata(&canonical_identity).ok()?;
    let parent_after = fs::metadata(&canonical_parent).ok()?;
    let trusted_owner =
        parent_before.uid() == 0 || parent_before.uid() == nix::unistd::geteuid().as_raw();
    if !before.is_file()
        || !parent_before.is_dir()
        || !trusted_owner
        || parent_before.mode() & 0o022 != 0
        || parent_before.dev() != parent_after.dev()
        || parent_before.ino() != parent_after.ino()
        || parent_before.uid() != parent_after.uid()
        || parent_before.gid() != parent_after.gid()
        || parent_before.mode() != parent_after.mode()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
        || before.len() != after.len()
        || fs::canonicalize(path).ok()? != canonical_identity
    {
        return None;
    }
    Some(ResolvedStandardExecutable {
        invocation_path: canonical_parent.join(file_name),
        canonical_identity,
        parent_device: parent_before.dev(),
        parent_inode: parent_before.ino(),
        parent_owner: parent_before.uid(),
        parent_group: parent_before.gid(),
        parent_mode: parent_before.mode(),
        device: before.dev(),
        inode: before.ino(),
        owner: before.uid(),
        group: before.gid(),
        mode: before.mode(),
        bytes: before.len(),
    })
}

pub(crate) fn resolve_cargo_executable() -> Result<ResolvedCargoExecutable, String> {
    let configured = std::env::var_os("CARGO");
    let search = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default();
    let extensions = if cfg!(windows) {
        std::env::var_os("PATHEXT")
            .map(|value| windows_executable_extensions(&value))
            .unwrap_or_else(|| vec![OsString::from(".COM"), OsString::from(".EXE")])
    } else {
        Vec::new()
    };
    resolve_cargo_from(
        configured.as_deref(),
        &search,
        &extensions,
        cfg!(unix),
        cfg!(windows),
    )
}

#[cfg(windows)]
fn resolve_windows_named_executable(name: &str) -> Result<ResolvedCargoExecutable, String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("Windows tool name is not one canonical component".to_owned());
    }
    let search = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .ok_or_else(|| "standard PATH is unavailable".to_owned())?;
    let extensions = std::env::var_os("PATHEXT")
        .map(|value| windows_executable_extensions(&value))
        .unwrap_or_else(|| vec![OsString::from(".COM"), OsString::from(".EXE")]);
    let mut resolved =
        resolve_cargo_from(Some(OsStr::new(name)), &search, &extensions, false, true)?;
    resolved.invocation_name = OsString::from(name);
    Ok(resolved)
}

#[cfg(windows)]
pub(crate) fn resolve_windows_rustup_authority(
    cargo: &ResolvedCargoExecutable,
    candidate_root: &Path,
) -> Result<ResolvedWindowsRustupAuthority, String> {
    let cargo_source = ResolvedWindowsExecutableIdentity::bind(cargo, "cargo")?;
    let rustup_resolved = resolve_windows_named_executable("rustup")?;
    let rustup = ResolvedWindowsExecutableIdentity::bind(&rustup_resolved, "rustup")?;
    let rustc_source_resolved = resolve_windows_named_executable("rustc")?;
    let rustc_source = ResolvedWindowsExecutableIdentity::bind(&rustc_source_resolved, "rustc")?;
    let home = parse_rustup_home_output(&run_bound_windows_rustup_probe(
        &rustup,
        candidate_root,
        &["show", "home"],
    )?)?;
    let home = fs::canonicalize(home)
        .map_err(|error| format!("cannot canonicalize standard RUSTUP_HOME: {error}"))?;
    let configured_toolchain = windows_configured_cargo_toolchain(&cargo_source, &home)?;
    let (toolchain, toolchain_root) = if let Some(configured) = configured_toolchain {
        configured
    } else {
        let toolchain = parse_active_rustup_toolchain(&run_bound_windows_rustup_probe(
            &rustup,
            candidate_root,
            &["show", "active-toolchain"],
        )?)?;
        let toolchain_root = home.join("toolchains").join(&toolchain);
        (toolchain, toolchain_root)
    };
    if fs::canonicalize(&toolchain_root).ok().as_deref() != Some(toolchain_root.as_path()) {
        return Err("selected Windows Rust toolchain path is redirected".to_owned());
    }
    let cargo = bind_windows_absolute_executable(&toolchain_root.join("bin/cargo.exe"), "cargo")?;
    let rustc = bind_windows_absolute_executable(&toolchain_root.join("bin/rustc.exe"), "rustc")?;
    let cargo_source = classify_windows_tool_source(cargo_source, &rustup, &cargo, "cargo")?;
    let rustc_source = classify_windows_tool_source(rustc_source, &rustup, &rustc, "rustc")?;
    let authority = ResolvedWindowsRustupAuthority {
        cargo_source,
        rustc_source,
        rustup,
        home,
        toolchain,
        toolchain_root,
        cargo,
        rustc,
    };
    authority.revalidate()?;
    Ok(authority)
}

#[cfg(windows)]
fn windows_configured_cargo_toolchain(
    cargo_source: &ResolvedWindowsExecutableIdentity,
    home: &Path,
) -> Result<Option<(OsString, PathBuf)>, String> {
    let toolchains = home.join("toolchains");
    let Ok(relative) = cargo_source.canonical().strip_prefix(&toolchains) else {
        return Ok(None);
    };
    let mut components = relative.components();
    let toolchain = match components.next() {
        Some(std::path::Component::Normal(toolchain)) => toolchain,
        _ => {
            return Err(
                "configured Windows Cargo has no canonical Rustup toolchain name".to_owned(),
            );
        }
    };
    let canonical_toolchain = toolchain.to_str().is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    });
    if !canonical_toolchain
        || components.next() != Some(std::path::Component::Normal(OsStr::new("bin")))
        || components.next() != Some(std::path::Component::Normal(OsStr::new("cargo.exe")))
        || components.next().is_some()
    {
        return Err("configured Windows Cargo has a noncanonical Rustup toolchain path".to_owned());
    }
    let root = toolchains.join(toolchain);
    if fs::canonicalize(&root).ok().as_deref() != Some(root.as_path())
        || root.join("bin/cargo.exe") != cargo_source.canonical()
    {
        return Err("configured Windows Cargo toolchain identity is redirected".to_owned());
    }
    Ok(Some((toolchain.to_owned(), root)))
}

#[cfg(windows)]
fn classify_windows_tool_source(
    resolved: ResolvedWindowsExecutableIdentity,
    rustup: &ResolvedWindowsExecutableIdentity,
    selected: &ResolvedWindowsExecutableIdentity,
    logical_name: &str,
) -> Result<ResolvedWindowsToolSourceAuthority, String> {
    let authority = if resolved.file.same_file(&rustup.file) {
        ResolvedWindowsToolSourceAuthority::RustupProxy(resolved)
    } else {
        match windows_standard_copied_proxy_matches(&resolved, rustup) {
            Ok(true) => ResolvedWindowsToolSourceAuthority::CopiedRustupProxy(resolved),
            Ok(false)
                if resolved.file.same_file(&selected.file)
                    && resolved.canonical == selected.canonical =>
            {
                ResolvedWindowsToolSourceAuthority::SelectedToolchain(resolved)
            }
            copied_proxy => {
                let diagnostic = WindowsToolClassificationDiagnostic::capture(
                    &resolved,
                    rustup,
                    selected,
                    logical_name,
                    copied_proxy,
                );
                return Err(format!(
                    "Windows {logical_name} is neither a standard Rustup proxy nor the selected toolchain executable; {diagnostic}"
                ));
            }
        }
    };
    authority.revalidate(logical_name, rustup, selected)?;
    Ok(authority)
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsPeImageIdentity {
    machine: u16,
    section_count: u16,
    timestamp: u32,
    optional_header_size: u16,
    characteristics: u16,
    optional_header_magic: u16,
    subsystem: u16,
    dll_characteristics: u16,
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsToolClassificationDiagnostic {
    source_invocation: PathBuf,
    source_canonical: PathBuf,
    rustup_invocation: PathBuf,
    rustup_canonical: PathBuf,
    selected_invocation: PathBuf,
    selected_canonical: PathBuf,
    source_revalidation: Result<(), String>,
    rustup_revalidation: Result<(), String>,
    selected_revalidation: Result<(), String>,
    source_file_identity: String,
    rustup_file_identity: String,
    selected_file_identity: String,
    source_same_file_rustup: bool,
    source_same_file_selected: bool,
    source_direct: bool,
    rustup_direct: bool,
    canonical_paths_distinct: bool,
    canonical_parent_same: bool,
    invocation_parent_same: bool,
    source_size: u64,
    rustup_size: u64,
    selected_size: u64,
    size_equal: bool,
    source_sha256: String,
    rustup_sha256: String,
    selected_sha256: String,
    sha256_equal: bool,
    source_pe: Result<WindowsPeImageIdentity, String>,
    rustup_pe: Result<WindowsPeImageIdentity, String>,
    pe_identity_equal: Option<bool>,
    copied_proxy_result: Result<bool, String>,
    selected_canonical_exact: bool,
}

#[cfg(windows)]
impl WindowsToolClassificationDiagnostic {
    fn capture(
        source: &ResolvedWindowsExecutableIdentity,
        rustup: &ResolvedWindowsExecutableIdentity,
        selected: &ResolvedWindowsExecutableIdentity,
        logical_name: &str,
        copied_proxy_result: Result<bool, String>,
    ) -> Self {
        let source_pe = windows_pe_image_identity(&source.canonical);
        let rustup_pe = windows_pe_image_identity(&rustup.canonical);
        Self {
            source_invocation: source.invocation.clone(),
            source_canonical: source.canonical.clone(),
            rustup_invocation: rustup.invocation.clone(),
            rustup_canonical: rustup.canonical.clone(),
            selected_invocation: selected.invocation.clone(),
            selected_canonical: selected.canonical.clone(),
            source_revalidation: source.revalidate(logical_name),
            rustup_revalidation: rustup.revalidate("rustup"),
            selected_revalidation: selected.revalidate(logical_name),
            source_file_identity: format!("{:?}", source.file),
            rustup_file_identity: format!("{:?}", rustup.file),
            selected_file_identity: format!("{:?}", selected.file),
            source_same_file_rustup: source.file.same_file(&rustup.file),
            source_same_file_selected: source.file.same_file(&selected.file),
            source_direct: windows_direct_spelling_matches(&source.invocation, &source.canonical),
            rustup_direct: windows_direct_spelling_matches(&rustup.invocation, &rustup.canonical),
            canonical_paths_distinct: source.canonical != rustup.canonical,
            canonical_parent_same: source.canonical.parent() == rustup.canonical.parent(),
            invocation_parent_same: source.invocation.parent() == rustup.invocation.parent(),
            source_size: source.file.size(),
            rustup_size: rustup.file.size(),
            selected_size: selected.file.size(),
            size_equal: source.file.size() == rustup.file.size(),
            source_sha256: source.file.sha256().hex(),
            rustup_sha256: rustup.file.sha256().hex(),
            selected_sha256: selected.file.sha256().hex(),
            sha256_equal: source.file.sha256() == rustup.file.sha256(),
            pe_identity_equal: source_pe
                .as_ref()
                .ok()
                .zip(rustup_pe.as_ref().ok())
                .map(|(source, rustup)| source == rustup),
            source_pe,
            rustup_pe,
            copied_proxy_result,
            selected_canonical_exact: source.canonical == selected.canonical,
        }
    }
}

#[cfg(any(windows, test))]
impl std::fmt::Display for WindowsToolClassificationDiagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "sourceInvocation={:?}; sourceCanonical={:?}; rustupInvocation={:?}; rustupCanonical={:?}; selectedInvocation={:?}; selectedCanonical={:?}; sourceRevalidation={:?}; rustupRevalidation={:?}; selectedRevalidation={:?}; sourceFileIdentity={}; rustupFileIdentity={}; selectedFileIdentity={}; sourceSameFileRustup={}; sourceSameFileSelected={}; sourceDirect={}; rustupDirect={}; canonicalPathsDistinct={}; canonicalParentSame={}; invocationParentSame={}; sourceSize={}; rustupSize={}; selectedSize={}; sizeEqual={}; sourceSha256={}; rustupSha256={}; selectedSha256={}; sha256Equal={}; sourcePe={:?}; rustupPe={:?}; peIdentityEqual={:?}; copiedProxyResult={:?}; selectedCanonicalExact={}",
            self.source_invocation,
            self.source_canonical,
            self.rustup_invocation,
            self.rustup_canonical,
            self.selected_invocation,
            self.selected_canonical,
            self.source_revalidation,
            self.rustup_revalidation,
            self.selected_revalidation,
            self.source_file_identity,
            self.rustup_file_identity,
            self.selected_file_identity,
            self.source_same_file_rustup,
            self.source_same_file_selected,
            self.source_direct,
            self.rustup_direct,
            self.canonical_paths_distinct,
            self.canonical_parent_same,
            self.invocation_parent_same,
            self.source_size,
            self.rustup_size,
            self.selected_size,
            self.size_equal,
            self.source_sha256,
            self.rustup_sha256,
            self.selected_sha256,
            self.sha256_equal,
            self.source_pe,
            self.rustup_pe,
            self.pe_identity_equal,
            self.copied_proxy_result,
            self.selected_canonical_exact,
        )
    }
}

#[cfg(any(windows, test))]
fn windows_pe_image_identity(path: &Path) -> Result<WindowsPeImageIdentity, String> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file =
        fs::File::open(path).map_err(|error| format!("cannot open Windows PE image: {error}"))?;
    let length = file
        .metadata()
        .map_err(|error| format!("cannot inspect Windows PE image: {error}"))?
        .len();
    let mut dos_header = [0_u8; 64];
    file.read_exact(&mut dos_header)
        .map_err(|error| format!("cannot read Windows DOS header: {error}"))?;
    if &dos_header[..2] != b"MZ" {
        return Err("Windows executable lacks an MZ header".to_owned());
    }
    let pe_offset = u64::from(u32::from_le_bytes(
        dos_header[60..64]
            .try_into()
            .map_err(|_| "Windows DOS header has no PE offset".to_owned())?,
    ));
    const PE_HEADER_BYTES: u64 = 24 + 72;
    if pe_offset < 64 || pe_offset > length.saturating_sub(PE_HEADER_BYTES) {
        return Err("Windows executable PE header offset is invalid".to_owned());
    }
    file.seek(SeekFrom::Start(pe_offset))
        .map_err(|error| format!("cannot seek to Windows PE header: {error}"))?;
    let mut header = [0_u8; PE_HEADER_BYTES as usize];
    file.read_exact(&mut header)
        .map_err(|error| format!("cannot read Windows PE header: {error}"))?;
    if &header[..4] != b"PE\0\0" {
        return Err("Windows executable lacks a PE signature".to_owned());
    }
    let read_u16 = |offset: usize| u16::from_le_bytes([header[offset], header[offset + 1]]);
    let read_u32 = |offset: usize| {
        u32::from_le_bytes([
            header[offset],
            header[offset + 1],
            header[offset + 2],
            header[offset + 3],
        ])
    };
    let optional_header_size = read_u16(20);
    if optional_header_size < 72 {
        return Err("Windows executable PE optional header is truncated".to_owned());
    }
    let optional_header_magic = read_u16(24);
    if !matches!(optional_header_magic, 0x010b | 0x020b) {
        return Err("Windows executable has an unsupported PE optional header".to_owned());
    }
    Ok(WindowsPeImageIdentity {
        machine: read_u16(4),
        section_count: read_u16(6),
        timestamp: read_u32(8),
        optional_header_size,
        characteristics: read_u16(22),
        optional_header_magic,
        subsystem: read_u16(92),
        dll_characteristics: read_u16(94),
    })
}

#[cfg(any(windows, test))]
fn windows_pe_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| "Windows PE field is truncated".to_owned())?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

#[cfg(any(windows, test))]
fn windows_pe_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| "Windows PE field is truncated".to_owned())?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(any(windows, test))]
struct WindowsPeImportSection {
    virtual_address: u32,
    span: u32,
    raw_start: u32,
}

#[cfg(any(windows, test))]
struct WindowsPeImportLayout {
    import_rva: u32,
    import_size: u32,
    sections: Vec<WindowsPeImportSection>,
}

#[cfg(any(windows, test))]
fn windows_pe_import_layout(bytes: &[u8]) -> Result<WindowsPeImportLayout, String> {
    const MAX_SECTIONS: usize = 96;

    if bytes.len() < 64 || &bytes[..2] != b"MZ" {
        return Err("Windows executable lacks a bounded DOS header".to_owned());
    }
    let pe = usize::try_from(windows_pe_u32(bytes, 60)?)
        .map_err(|_| "Windows PE offset is not representable".to_owned())?;
    if bytes.get(pe..pe.saturating_add(4)) != Some(b"PE\0\0") {
        return Err("Windows executable lacks a PE signature".to_owned());
    }
    let section_count = usize::from(windows_pe_u16(bytes, pe + 6)?);
    if section_count == 0 || section_count > MAX_SECTIONS {
        return Err("Windows PE section inventory exceeds its bound".to_owned());
    }
    let optional_size = usize::from(windows_pe_u16(bytes, pe + 20)?);
    let optional = pe
        .checked_add(24)
        .ok_or_else(|| "Windows PE optional-header offset overflowed".to_owned())?;
    let optional_end = optional
        .checked_add(optional_size)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| "Windows PE optional header is truncated".to_owned())?;
    let data_directory = match windows_pe_u16(bytes, optional)? {
        0x010b => 96,
        0x020b => 112,
        _ => return Err("Windows executable has an unsupported PE optional header".to_owned()),
    };
    if optional_size < data_directory + 16 {
        return Err("Windows PE import directory is truncated".to_owned());
    }
    let import_rva = windows_pe_u32(bytes, optional + data_directory + 8)?;
    let import_size = windows_pe_u32(bytes, optional + data_directory + 12)?;
    let section_bytes = section_count
        .checked_mul(40)
        .and_then(|length| optional_end.checked_add(length))
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| "Windows PE section table is truncated".to_owned())?;
    let mut sections = Vec::with_capacity(section_count);
    for offset in (optional_end..section_bytes).step_by(40) {
        let virtual_size = windows_pe_u32(bytes, offset + 8)?;
        let virtual_address = windows_pe_u32(bytes, offset + 12)?;
        let raw_size = windows_pe_u32(bytes, offset + 16)?;
        let raw_start = windows_pe_u32(bytes, offset + 20)?;
        let raw_end = u64::from(raw_start) + u64::from(raw_size);
        if raw_end > bytes.len() as u64 {
            return Err("Windows PE section extends beyond the image".to_owned());
        }
        sections.push(WindowsPeImportSection {
            virtual_address,
            span: virtual_size.max(raw_size),
            raw_start,
        });
    }
    Ok(WindowsPeImportLayout {
        import_rva,
        import_size,
        sections,
    })
}

#[cfg(any(windows, test))]
fn windows_pe_rva_offset(rva: u32, sections: &[WindowsPeImportSection]) -> Result<usize, String> {
    sections
        .iter()
        .find_map(|section| {
            let delta = rva.checked_sub(section.virtual_address)?;
            (delta < section.span)
                .then(|| section.raw_start.checked_add(delta))
                .flatten()
                .and_then(|offset| usize::try_from(offset).ok())
        })
        .ok_or_else(|| "Windows PE RVA is outside its closed section inventory".to_owned())
}

#[cfg(any(windows, test))]
fn windows_pe_imports(path: &Path) -> Result<Vec<String>, String> {
    const MAX_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_IMPORTS: usize = 128;
    const MAX_IMPORT_NAME_BYTES: usize = 260;

    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot inspect PE image: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_IMAGE_BYTES {
        return Err("Windows PE image is not one bounded file".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| format!("cannot read PE image: {error}"))?;
    let layout = windows_pe_import_layout(&bytes)?;
    let import_rva = layout.import_rva;
    let import_size = layout.import_size;
    if import_rva == 0 && import_size == 0 {
        return Ok(Vec::new());
    }
    if import_rva == 0 || import_size < 20 {
        return Err("Windows PE import directory has an invalid extent".to_owned());
    }
    let mut imports = Vec::new();
    let descriptor_count = usize::try_from(import_size / 20)
        .map_err(|_| "Windows PE import count is not representable".to_owned())?
        .min(MAX_IMPORTS + 1);
    for index in 0..descriptor_count {
        let descriptor_rva = import_rva
            .checked_add(u32::try_from(index * 20).expect("bounded import index"))
            .ok_or_else(|| "Windows PE import descriptor overflowed".to_owned())?;
        let descriptor = windows_pe_rva_offset(descriptor_rva, &layout.sections)?;
        let fields = bytes
            .get(descriptor..descriptor.saturating_add(20))
            .ok_or_else(|| "Windows PE import descriptor is truncated".to_owned())?;
        if fields.iter().all(|byte| *byte == 0) {
            return Ok(imports);
        }
        if index == MAX_IMPORTS {
            return Err("Windows PE import inventory exceeds its bound".to_owned());
        }
        let name_rva = windows_pe_u32(&bytes, descriptor + 12)?;
        let name = windows_pe_rva_offset(name_rva, &layout.sections)?;
        let available = bytes
            .get(name..name.saturating_add(MAX_IMPORT_NAME_BYTES).min(bytes.len()))
            .ok_or_else(|| "Windows PE import name is outside the image".to_owned())?;
        let end = available
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| "Windows PE import name is not bounded".to_owned())?;
        let import = std::str::from_utf8(&available[..end])
            .map_err(|_| "Windows PE import name is not UTF-8".to_owned())?;
        if import.is_empty()
            || !import
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err("Windows PE import name has invalid syntax".to_owned());
        }
        imports.push(import.to_owned());
    }
    Err("Windows PE import inventory is not terminated within its bound".to_owned())
}

#[cfg(any(windows, test))]
fn bounded_windows_prelaunch_value(value: &OsStr) -> String {
    const LIMIT: usize = 4_096;

    let rendered = format!("\"{}\"", value.to_string_lossy().escape_debug());
    if rendered.len() <= LIMIT {
        return rendered;
    }
    let split = (0..=LIMIT)
        .rev()
        .find(|index| rendered.is_char_boundary(*index))
        .expect("zero is a UTF-8 boundary");
    format!("{}<truncated:{}>", &rendered[..split], rendered.len())
}

#[cfg(any(windows, test))]
fn windows_parent_prelaunch_diagnostic(target_arguments: &[OsString]) -> String {
    let program = target_arguments
        .first()
        .map_or_else(|| OsStr::new("<absent>"), OsString::as_os_str);
    let imports = windows_pe_imports(Path::new(program))
        .map(|imports| format!("{imports:?}"))
        .unwrap_or_else(|error| format!("<unavailable:{error}>"));
    let system_root = std::env::var_os("SystemRoot").map_or_else(
        || "<absent>".to_owned(),
        |value| bounded_windows_prelaunch_value(&value),
    );
    let path = std::env::var_os("PATH").map_or_else(
        || "<absent>".to_owned(),
        |value| bounded_windows_prelaunch_value(&value),
    );
    let cwd = std::env::current_dir()
        .map(|value| bounded_windows_prelaunch_value(value.as_os_str()))
        .unwrap_or_else(|error| format!("<unavailable:{error}>"));
    format!(
        "restricted Windows target prelaunch evidence: program={},graphicalBinding=inherited-default,imports={imports},SystemRoot={system_root},PATH={path},cwd={cwd}",
        bounded_windows_prelaunch_value(program),
    )
}

#[cfg(windows)]
fn windows_standard_copied_proxy_matches(
    executable: &ResolvedWindowsExecutableIdentity,
    rustup: &ResolvedWindowsExecutableIdentity,
) -> Result<bool, String> {
    if executable.file.same_file(&rustup.file)
        || !windows_direct_spelling_matches(&executable.invocation, &executable.canonical)
        || !windows_direct_spelling_matches(&rustup.invocation, &rustup.canonical)
        || executable.canonical == rustup.canonical
        || executable.canonical.parent() != rustup.canonical.parent()
        || executable.invocation.parent() != rustup.invocation.parent()
        || executable.file.size() != rustup.file.size()
        || executable.file.sha256() != rustup.file.sha256()
    {
        return Ok(false);
    }
    Ok(windows_pe_image_identity(&executable.canonical)?
        == windows_pe_image_identity(&rustup.canonical)?)
}

#[cfg(windows)]
fn windows_direct_spelling_matches(invocation: &Path, canonical: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt as _;

    if !invocation.is_absolute() || !canonical.is_absolute() {
        return false;
    }
    let invocation = invocation.as_os_str().encode_wide().collect::<Vec<_>>();
    let canonical = canonical.as_os_str().encode_wide().collect::<Vec<_>>();
    windows_case_only_direct_spelling_units(&invocation, &canonical)
}

#[cfg(any(windows, test))]
fn windows_case_only_direct_spelling_units(invocation: &[u16], canonical: &[u16]) -> bool {
    fn is_separator(unit: u16) -> bool {
        unit == u16::from(b'\\') || unit == u16::from(b'/')
    }

    fn has_dot_component(path: &[u16]) -> bool {
        path.split(|unit| is_separator(*unit))
            .any(|component| component == [b'.' as u16] || component == [b'.' as u16; 2])
    }

    fn case_only_unit_matches(left: u16, right: u16) -> bool {
        if is_separator(left) || is_separator(right) {
            return left == right;
        }
        if left <= u16::from(u8::MAX) && right <= u16::from(u8::MAX) {
            return (left as u8).eq_ignore_ascii_case(&(right as u8));
        }
        left == right
    }

    invocation.len() == canonical.len()
        && !has_dot_component(invocation)
        && !has_dot_component(canonical)
        && invocation
            .iter()
            .copied()
            .zip(canonical.iter().copied())
            .all(|(left, right)| case_only_unit_matches(left, right))
}

#[cfg(windows)]
pub(crate) fn bind_windows_absolute_executable(
    path: &Path,
    logical_name: &str,
) -> Result<ResolvedWindowsExecutableIdentity, String> {
    if !path.is_absolute() || !windows_executable_stem_is(path, logical_name) {
        return Err(format!(
            "staged Windows {logical_name} path is not canonical"
        ));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize staged Windows {logical_name}: {error}"))?;
    if canonical != path {
        return Err(format!("staged Windows {logical_name} path is redirected"));
    }
    ResolvedWindowsExecutableIdentity::bind(
        &ResolvedCargoExecutable {
            invocation_path: path.to_path_buf(),
            canonical_identity: canonical,
            invocation_name: OsString::from(logical_name),
        },
        logical_name,
    )
}

#[cfg(windows)]
fn run_bound_windows_rustup_probe(
    rustup: &ResolvedWindowsExecutableIdentity,
    candidate_root: &Path,
    arguments: &[&str],
) -> Result<Vec<u8>, String> {
    rustup.revalidate("rustup")?;
    let identity = BoundProgramInvocation::new(rustup.invocation.clone(), rustup.canonical.clone())
        .map_err(|error| format!("cannot bind standard rustup identity: {error}"))?;
    let mut command = Command::new(&rustup.invocation);
    command.args(arguments).current_dir(candidate_root);
    hell_testkit::configure_release_child_environment(&mut command);
    let output = run_supervised_command_with_bound_program(
        &mut command,
        &[],
        Duration::from_secs(10),
        &identity,
    )
    .map_err(|error| format!("cannot inspect standard rustup configuration: {error}"))?;
    if output.timed_out || !output.status.success() {
        return Err(format!(
            "standard rustup configuration probe failed with status {:?}, timedOut={}, stderr={:?}",
            output.status.code(),
            output.timed_out,
            String::from_utf8_lossy(&output.stderr.retained_bytes())
        ));
    }
    output
        .stdout
        .complete
        .ok_or_else(|| "standard rustup configuration probe exceeded capture bound".to_owned())
}

#[cfg(unix)]
pub(crate) fn resolve_posix_cargo_authority(
    cargo: &ResolvedCargoExecutable,
    candidate_root: &Path,
) -> Result<ResolvedPosixCargoAuthority, String> {
    use std::os::unix::fs::MetadataExt as _;

    if cargo.invocation_name.as_os_str() != OsStr::new("cargo")
        || cargo.invocation_path.file_name() != Some(OsStr::new("cargo"))
    {
        return Err("logical Cargo invocation must be named cargo".to_owned());
    }
    let rustup = match resolve_standard_path_executable(OsStr::new("rustup")) {
        Ok(rustup) => rustup,
        Err(error) => {
            return Err(format!(
                "cannot classify Cargo without the independently resolved standard Rustup: {error}"
            ));
        }
    };
    let standard_rustup = ResolvedPosixStandardExecutableIdentity::bind(&rustup)?;
    let cargo_identity = ResolvedPosixCanonicalExecutableIdentity::bind(&cargo.canonical_identity)?;
    let cargo_metadata = fs::metadata(&cargo.canonical_identity)
        .map_err(|error| format!("cannot inspect resolved Cargo identity: {error}"))?;
    let same_as_rustup = cargo_metadata.dev() == standard_rustup.device
        && cargo_metadata.ino() == standard_rustup.inode;
    if !same_as_rustup {
        return Ok(ResolvedPosixCargoAuthority::Native {
            cargo: cargo_identity,
            standard_rustup,
        });
    }
    let rustc = resolve_standard_path_executable(OsStr::new("rustc"))?;
    let Some(proxy_identity) = ResolvedPosixRustupProxyIdentity::bind(cargo, &rustup)? else {
        return Err("Cargo matches Rustup but its exact proxy identity differs".to_owned());
    };
    let home = parse_rustup_home_output(&run_bound_rustup_probe(
        &rustup,
        candidate_root,
        &["show", "home"],
    )?)?;
    let home = fs::canonicalize(&home)
        .map_err(|error| format!("cannot canonicalize standard RUSTUP_HOME: {error}"))?;
    let toolchain = parse_active_rustup_toolchain(&run_bound_rustup_probe(
        &rustup,
        candidate_root,
        &["show", "active-toolchain"],
    )?)?;
    let toolchain_root = home.join("toolchains").join(&toolchain);
    let canonical_toolchain = fs::canonicalize(&toolchain_root)
        .map_err(|error| format!("cannot canonicalize active Rust toolchain: {error}"))?;
    if canonical_toolchain != toolchain_root {
        return Err("active Rust toolchain path is redirected".to_owned());
    }
    let rustc_authority = ResolvedPosixRustcAuthority::bind(
        &rustc,
        &proxy_identity,
        &toolchain_root.join("bin").join("rustc"),
    )?;
    proxy_identity.revalidate()?;
    rustc_authority.revalidate(&proxy_identity)?;
    Ok(ResolvedPosixCargoAuthority::Rustup(
        ResolvedPosixRustupAuthority {
            proxy_identity,
            rustc_authority,
            home,
            toolchain,
        },
    ))
}

#[cfg(unix)]
fn run_bound_rustup_probe(
    rustup: &ResolvedStandardExecutable,
    candidate_root: &Path,
    arguments: &[&str],
) -> Result<Vec<u8>, String> {
    let identity = BoundProgramInvocation::new(
        rustup.invocation_path.clone(),
        rustup.canonical_identity.clone(),
    )
    .map_err(|error| format!("cannot bind standard rustup identity: {error}"))?;
    let mut command = Command::new(&rustup.invocation_path);
    command.args(arguments).current_dir(candidate_root);
    hell_testkit::configure_release_child_environment(&mut command);
    let output = run_supervised_command_with_bound_program(
        &mut command,
        &[],
        Duration::from_secs(10),
        &identity,
    )
    .map_err(|error| format!("cannot inspect standard rustup configuration: {error}"))?;
    if output.timed_out || !output.status.success() {
        return Err(format!(
            "standard rustup configuration probe failed with status {:?}, timedOut={}, stderr={:?}",
            output.status.code(),
            output.timed_out,
            String::from_utf8_lossy(&output.stderr.retained_bytes())
        ));
    }
    output
        .stdout
        .complete
        .ok_or_else(|| "standard rustup configuration probe exceeded capture bound".to_owned())
}

#[cfg(any(unix, windows, test))]
fn parse_rustup_home_output(output: &[u8]) -> Result<PathBuf, String> {
    let text = std::str::from_utf8(output)
        .map_err(|_| "standard rustup home output is not UTF-8".to_owned())?;
    let mut lines = text.lines();
    let home = lines
        .next()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| "standard rustup home output is empty".to_owned())?;
    if lines.next().is_some() {
        return Err("standard rustup home output has multiple lines".to_owned());
    }
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err("standard rustup home is not absolute".to_owned());
    }
    Ok(home)
}

#[cfg(any(unix, windows, test))]
fn parse_active_rustup_toolchain(output: &[u8]) -> Result<OsString, String> {
    let text = std::str::from_utf8(output)
        .map_err(|_| "active Rust toolchain output is not UTF-8".to_owned())?;
    let mut lines = text.lines();
    let line = lines
        .next()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| "active Rust toolchain output is empty".to_owned())?;
    if lines.next().is_some() {
        return Err("active Rust toolchain output has multiple lines".to_owned());
    }
    if line == "no active toolchain" {
        return Err("standard rustup has no active toolchain".to_owned());
    }
    let toolchain = line
        .split_ascii_whitespace()
        .next()
        .filter(|toolchain| {
            !toolchain.is_empty()
                && toolchain
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .ok_or_else(|| "active Rust toolchain name is not canonical".to_owned())?;
    Ok(OsString::from(toolchain))
}

pub(crate) fn resolve_cargo_from(
    configured: Option<&OsStr>,
    search: &[PathBuf],
    windows_extensions: &[OsString],
    require_unix_executable: bool,
    windows: bool,
) -> Result<ResolvedCargoExecutable, String> {
    let program = configured.unwrap_or_else(|| OsStr::new("cargo"));
    if program.is_empty() {
        return Err("CARGO names an empty executable".to_owned());
    }
    let path = Path::new(program);
    if path.is_absolute() {
        if windows && !has_native_windows_extension(path) {
            return Err("CARGO absolute path is not a native COM/EXE executable".to_owned());
        }
        return resolved_tool_candidate(path, require_unix_executable, windows)
            .ok_or_else(|| "CARGO does not name an executable file".to_owned());
    }
    if path.components().count() > 1 {
        return Err("CARGO relative component paths are not allowed".to_owned());
    }
    let names = executable_names(program, windows_extensions, windows)?;
    for directory in search.iter().filter(|directory| directory.is_absolute()) {
        for name in &names {
            let candidate = directory.join(name);
            if let Some(candidate) =
                resolved_tool_candidate(&candidate, require_unix_executable, windows)
            {
                return Ok(candidate);
            }
        }
    }
    Err("cannot resolve Cargo executable from standard CARGO or PATH".to_owned())
}

fn executable_names(
    program: &OsStr,
    windows_extensions: &[OsString],
    windows: bool,
) -> Result<Vec<OsString>, String> {
    if !windows {
        return Ok(vec![program.to_owned()]);
    }
    if Path::new(program).extension().is_some() {
        return has_native_windows_extension(Path::new(program))
            .then(|| vec![program.to_owned()])
            .ok_or_else(|| "CARGO name is not a native COM/EXE executable".to_owned());
    }
    if windows_extensions.is_empty() {
        return Err("PATHEXT contains no native COM/EXE extensions".to_owned());
    }
    Ok(windows_extensions
        .iter()
        .map(|extension| {
            let mut name = program.to_owned();
            name.push(extension);
            name
        })
        .collect())
}

pub(crate) fn windows_executable_extensions(value: &OsStr) -> Vec<OsString> {
    value
        .to_string_lossy()
        .split(';')
        .filter(|extension| !extension.is_empty())
        .filter(|extension| {
            extension.eq_ignore_ascii_case(".com") || extension.eq_ignore_ascii_case(".exe")
        })
        .map(OsString::from)
        .collect()
}

fn has_native_windows_extension(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        let extension = extension.to_string_lossy();
        extension.eq_ignore_ascii_case("com") || extension.eq_ignore_ascii_case("exe")
    })
}

fn resolved_tool_candidate(
    path: &Path,
    require_unix_executable: bool,
    windows: bool,
) -> Option<ResolvedCargoExecutable> {
    let Ok(metadata) = fs::metadata(path) else {
        return None;
    };
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    if require_unix_executable {
        use nix::fcntl::AtFlags;
        use nix::unistd::{AccessFlags, faccessat};

        if faccessat(None, path, AccessFlags::X_OK, AtFlags::AT_EACCESS).is_err() {
            return None;
        }
    }
    let _ = require_unix_executable;
    let canonical_identity = fs::canonicalize(path).ok()?;
    if windows && !has_native_windows_extension(&canonical_identity) {
        return None;
    }
    let file_name = path.file_name()?;
    let canonical_parent = fs::canonicalize(path.parent()?).ok()?;
    let invocation_path = canonical_parent.join(file_name);
    Some(ResolvedCargoExecutable {
        invocation_path,
        canonical_identity,
        invocation_name: OsString::from("cargo"),
    })
}

fn revalidate_resolved_cargo(invocation: &Path, expected: &Path) -> std::io::Result<()> {
    let resolved =
        resolved_tool_candidate(invocation, cfg!(unix), cfg!(windows)).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "resolved Cargo invocation is no longer an executable file",
            )
        })?;
    if resolved.canonical_identity != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "resolved Cargo executable identity changed before spawn",
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn verify_cargo_multicall_argv_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let sequence = CARGO_MULTICALL_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "hell-ci-cargo-multicall-verifier-{}-{sequence}",
        std::process::id()
    ));
    if root.exists() {
        return Err("Cargo multicall verifier root already exists".to_owned());
    }
    fs::create_dir(&root)
        .map_err(|error| format!("cannot create Cargo multicall verifier root: {error}"))?;
    let result = (|| {
        let cargo_root = root.join("cargo-bin");
        let standard_root = root.join("standard-bin");
        fs::create_dir(&cargo_root)
            .map_err(|error| format!("cannot create Cargo multicall directory: {error}"))?;
        fs::create_dir(&standard_root)
            .map_err(|error| format!("cannot create standard multicall directory: {error}"))?;

        let target = fs::canonicalize(std::env::current_exe().map_err(|error| {
            format!("cannot identify Cargo multicall verifier executable: {error}")
        })?)
        .map_err(|error| format!("cannot canonicalize Cargo multicall verifier: {error}"))?;
        let alias = cargo_root.join("cargo");
        let rustup = standard_root.join("rustup");
        let rustc = standard_root.join("rustc");
        symlink(&target, &alias)
            .map_err(|error| format!("cannot create Cargo multicall alias: {error}"))?;
        symlink(&target, &rustup)
            .map_err(|error| format!("cannot create Rustup multicall alias: {error}"))?;
        symlink(&target, &rustc)
            .map_err(|error| format!("cannot create Rustc multicall alias: {error}"))?;
        let child_arguments = ["__verify-cargo-multicall-argv-child"];

        let direct = CommandSpec::new(&target, Duration::from_secs(5))
            .arguments(child_arguments)
            .run()
            .map_err(|error| format!("cannot execute direct Cargo multicall control: {error}"))?;
        if direct.status.success() {
            return Err(
                "direct Cargo multicall control unexpectedly received Cargo argv[0]".to_owned(),
            );
        }

        let resolved = resolve_cargo_from(Some(alias.as_os_str()), &[], &[], true, false)?;
        let standard_rustup = resolved_standard_candidate(&rustup)
            .ok_or_else(|| "cannot bind Cargo multicall Rustup alias".to_owned())?;
        let identity = ResolvedPosixRustupProxyIdentity::bind(&resolved, &standard_rustup)?
            .ok_or_else(|| "Cargo multicall aliases do not share one identity".to_owned())?;
        let canonical_cargo_root = fs::canonicalize(&cargo_root)
            .map_err(|error| format!("cannot canonicalize Cargo multicall directory: {error}"))?;
        if identity.cargo_invocation() != canonical_cargo_root.join("cargo")
            || identity.cargo() != target
            || identity.cargo().file_name() != target.file_name()
        {
            return Err("Cargo multicall identity differs from its bound paths".to_owned());
        }
        identity.revalidate()?;

        let replacement = root.join("replacement-engine");
        fs::copy(&target, &replacement)
            .map_err(|error| format!("cannot copy Cargo multicall replacement: {error}"))?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).map_err(|error| {
            format!("cannot make Cargo multicall replacement executable: {error}")
        })?;
        fs::remove_file(&alias)
            .map_err(|error| format!("cannot remove Cargo multicall alias: {error}"))?;
        symlink(&replacement, &alias)
            .map_err(|error| format!("cannot substitute Cargo multicall alias: {error}"))?;
        if identity.revalidate().is_ok() {
            return Err("substituted Cargo multicall identity was accepted".to_owned());
        }
        fs::remove_file(&alias)
            .map_err(|error| format!("cannot remove substituted Cargo alias: {error}"))?;
        symlink(&target, &alias)
            .map_err(|error| format!("cannot restore Cargo multicall alias: {error}"))?;
        identity.revalidate()?;

        let mut forged_invocation_name = resolved.clone();
        forged_invocation_name.invocation_name = OsString::from("rustup");
        if ResolvedPosixRustupProxyIdentity::bind(&forged_invocation_name, &standard_rustup)?
            .is_some()
        {
            return Err("forged Cargo multicall invocation name was accepted".to_owned());
        }

        let spec = CommandSpec::cargo_from_resolution(Duration::from_secs(5), Ok(resolved));
        if spec.display_invocation_name().as_deref() != Some("cargo") {
            return Err("Cargo multicall invocation name was not retained".to_owned());
        }
        let executed = spec
            .arguments(child_arguments)
            .run()
            .map_err(|error| format!("cannot execute bound Cargo multicall alias: {error}"))?;
        if !executed.status.success()
            || std::str::from_utf8(&executed.stdout)
                .ok()
                .is_none_or(|stdout| !stdout.contains("cargo-multicall-argv-child"))
        {
            return Err("bound Cargo multicall alias did not preserve exact argv[0]".to_owned());
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&root)
        .map_err(|error| format!("cannot remove Cargo multicall verifier root: {error}"));
    result.and(cleanup)
}

#[cfg(unix)]
pub(crate) fn verify_cargo_multicall_argv_child_for_integration() -> Result<(), String> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments
        .first()
        .and_then(|value| Path::new(value).file_name())
        != Some(OsStr::new("cargo"))
    {
        return Err("Cargo multicall child did not receive the exact logical argv[0]".to_owned());
    }
    if arguments.len() != 2
        || arguments.get(1).map(OsString::as_os_str)
            != Some(OsStr::new("__verify-cargo-multicall-argv-child"))
    {
        return Err("Cargo multicall child arguments differ from the typed request".to_owned());
    }
    println!("cargo-multicall-argv-child");
    Ok(())
}

fn native_stack_build(source: &Path, stack_yaml: &Path, timeout: Duration) -> CommandSpec {
    CommandSpec::new("stack", timeout)
        .arguments(["--lock-file", "error-on-write", "--stack-yaml"])
        .argument(stack_yaml)
        .argument("build")
        .current_directory(source)
}

fn native_stack_path(source: &Path, stack_yaml: &Path) -> CommandSpec {
    CommandSpec::new("stack", Duration::from_mins(5))
        .arguments(["--lock-file", "error-on-write", "--stack-yaml"])
        .argument(stack_yaml)
        .arguments(["path", "--local-install-root"])
        .current_directory(source)
}

fn native_stack_ghc_version(source: &Path, stack_yaml: &Path) -> CommandSpec {
    CommandSpec::new("stack", Duration::from_mins(5))
        .arguments(["--lock-file", "error-on-write", "--stack-yaml"])
        .argument(stack_yaml)
        .arguments(["exec", "--", "ghc", "--numeric-version"])
        .current_directory(source)
}

pub(crate) fn verify_pinned_oracle_checkout(source: &Path) -> Result<(), String> {
    verify_tracked_checkout(source, PINNED_ORACLE_SOURCE_COMMIT)
}

fn verify_tracked_checkout(source: &Path, expected: &str) -> Result<(), String> {
    let head = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(["rev-parse", "HEAD"])
        .current_directory(source)
        .run()
        .map_err(|error| format!("cannot identify oracle checkout: {error}"))?;
    if !head.status.success()
        || head.timed_out
        || std::str::from_utf8(&head.stdout)
            .map_err(|_| "oracle checkout identity is not UTF-8".to_owned())?
            .trim()
            != expected
    {
        return Err("oracle source checkout differs from pinned commit".to_owned());
    }
    let status = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_directory(source)
        .run()
        .map_err(|error| format!("cannot inspect oracle checkout: {error}"))?;
    if !status.status.success() || status.timed_out || !status.stdout.is_empty() {
        return Err("oracle source has tracked or staged changes".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_native_archive_arguments(
    arguments: &[OsString],
    argument_offset: usize,
    current_directory: &Path,
    authority: &mut NativeArchiveWorkAuthority,
    input_groups: &mut Vec<NativeArchiveInputGroup>,
    deadline: Instant,
) -> std::io::Result<()> {
    let mut positional_only = false;
    let mut members = 0usize;
    for (position, argument) in arguments.iter().enumerate() {
        require_native_archive_deadline(deadline, "archive member validation")?;
        if argument == OsStr::new("--") {
            positional_only = true;
            continue;
        }
        let Some(value) = argument.to_str() else {
            return Err(std::io::Error::other(
                "archive adapter arguments must be UTF-8",
            ));
        };
        if let Some(response) = value.strip_prefix('@') {
            validate_native_archive_response(
                response,
                argument_offset + position,
                current_directory,
                authority,
                input_groups,
                &mut members,
                deadline,
            )?;
        } else if !positional_only && value.starts_with('-') {
            return Err(std::io::Error::other(format!(
                "archive adapter received unsupported argument {value:?}"
            )));
        } else {
            let input_index = validate_native_archive_member(
                Path::new(value),
                current_directory,
                authority,
                &mut members,
                deadline,
            )?;
            input_groups.push(NativeArchiveInputGroup {
                argument_index: argument_offset + position,
                input_indices: vec![input_index],
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_native_archive_member(
    member: &Path,
    current_directory: &Path,
    authority: &mut NativeArchiveWorkAuthority,
    members: &mut usize,
    deadline: Instant,
) -> std::io::Result<usize> {
    *members = members
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("archive member count overflowed its bound"))?;
    if *members > NATIVE_ARCHIVE_MEMBER_LIMIT {
        return Err(std::io::Error::other(
            "archive member count exceeds its bound",
        ));
    }
    require_native_archive_deadline(deadline, "archive member binding")?;
    if member.is_absolute() {
        return Err(std::io::Error::other(
            "archive member must be relative to its bound work directory",
        ));
    }
    let member = current_directory.join(member);
    let canonical = fs::canonicalize(&member)
        .map_err(|error| std::io::Error::other(format!("cannot bind archive member: {error}")))?;
    if !canonical.starts_with(&authority.read_root) {
        return Err(std::io::Error::other(
            "archive member escapes its bound work directory",
        ));
    }
    let input_index = authority.inputs.len();
    authority.inputs.push(NativeArchiveFileReceipt::bind(
        "archive member",
        &canonical,
        deadline,
    )?);
    Ok(input_index)
}

#[cfg(unix)]
fn validate_native_archive_response(
    response: &str,
    argument_index: usize,
    current_directory: &Path,
    authority: &mut NativeArchiveWorkAuthority,
    input_groups: &mut Vec<NativeArchiveInputGroup>,
    members: &mut usize,
    deadline: Instant,
) -> std::io::Result<()> {
    require_native_archive_deadline(deadline, "archive response binding")?;
    let response = Path::new(response);
    let response = if response.is_absolute() {
        response.to_path_buf()
    } else {
        current_directory.join(response)
    };
    let canonical = fs::canonicalize(&response).map_err(|error| {
        std::io::Error::other(format!("cannot bind archive response file: {error}"))
    })?;
    if !canonical.starts_with(&authority.read_root) {
        return Err(std::io::Error::other(
            "archive response file escapes its bound work directory",
        ));
    }
    let receipt = NativeArchiveFileReceipt::bind("archive response file", &canonical, deadline)?;
    if receipt.size > NATIVE_ARCHIVE_RESPONSE_BYTE_LIMIT {
        return Err(std::io::Error::other(
            "archive response file exceeds its byte bound",
        ));
    }
    let read_limit = NATIVE_ARCHIVE_RESPONSE_BYTE_LIMIT
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("archive response byte bound overflowed"))?;
    let mut contents = Vec::new();
    let mut response_file = receipt.guard.try_clone().map_err(|error| {
        std::io::Error::other(format!("cannot clone archive response receipt: {error}"))
    })?;
    response_file.seek(SeekFrom::Start(0)).map_err(|error| {
        std::io::Error::other(format!("cannot rewind archive response receipt: {error}"))
    })?;
    response_file
        .take(read_limit)
        .read_to_end(&mut contents)
        .map_err(|error| {
            std::io::Error::other(format!("cannot read archive response file: {error}"))
        })?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > NATIVE_ARCHIVE_RESPONSE_BYTE_LIMIT {
        return Err(std::io::Error::other(
            "archive response file exceeds its byte bound",
        ));
    }
    let contents = std::str::from_utf8(&contents)
        .map_err(|_| std::io::Error::other("archive response file is not UTF-8"))?;
    require_native_archive_deadline(deadline, "archive response read")?;
    let mut input_indices = Vec::new();
    for member in contents.lines() {
        if member.is_empty()
            || member != member.trim()
            || member.contains([' ', '"', '\''])
            || member.contains('\\')
            || member.chars().any(char::is_control)
            || member.starts_with('-')
            || member.starts_with('@')
        {
            return Err(std::io::Error::other(
                "archive response file contains an unsupported argument",
            ));
        }
        input_indices.push(validate_native_archive_member(
            Path::new(member),
            current_directory,
            authority,
            members,
            deadline,
        )?);
    }
    authority.inputs.push(receipt);
    input_groups.push(NativeArchiveInputGroup {
        argument_index,
        input_indices,
    });
    Ok(())
}

#[cfg(unix)]
fn native_archive_configure_probe(
    arguments: &[OsString],
    current_directory: &Path,
) -> Option<std::io::Result<Vec<OsString>>> {
    if arguments
        != [
            OsStr::new("clqs"),
            OsStr::new("conftest.a"),
            OsStr::new("conftest.o"),
        ]
    {
        return None;
    }
    let configure = current_directory.join("configure");
    let member = current_directory.join("conftest.o");
    let archive = current_directory.join("conftest.a");
    let regular_real_file = |path: &Path| {
        fs::symlink_metadata(path)
            .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
    };
    if !regular_real_file(&configure) || !regular_real_file(&member) {
        return Some(Err(std::io::Error::other(
            "GHC configure archive probe fixture is not a regular real file",
        )));
    }
    match fs::symlink_metadata(&archive) {
        Ok(_) => {
            return Some(Err(std::io::Error::other(
                "GHC configure archive probe target already exists",
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Some(Err(std::io::Error::other(format!(
                "cannot inspect GHC configure archive probe target: {error}"
            ))));
        }
    }
    Some(Ok(vec![
        OsString::from("qclsL"),
        OsString::from("conftest.a"),
        OsString::from("conftest.o"),
    ]))
}

#[cfg(unix)]
fn archive_adapter_directory(invoked: &OsStr) -> std::io::Result<PathBuf> {
    let invoked = Path::new(invoked);
    let invoked_parent = invoked
        .parent()
        .ok_or_else(|| std::io::Error::other("archive adapter directory is missing"))?;
    if !invoked_parent.as_os_str().is_empty() {
        return fs::canonicalize(invoked_parent);
    }

    let current_executable = fs::canonicalize(std::env::current_exe()?)?;
    let current_metadata = fs::symlink_metadata(&current_executable)?;
    let path = std::env::var_os("PATH")
        .ok_or_else(|| std::io::Error::other("archive adapter PATH is missing"))?;
    let current_directory = std::env::current_dir()?;
    for entry in std::env::split_paths(&path) {
        let entry = if entry.is_absolute() {
            entry
        } else {
            current_directory.join(entry)
        };
        let candidate = entry.join("ar");
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        use std::os::unix::fs::MetadataExt as _;
        if metadata.dev() == current_metadata.dev() && metadata.ino() == current_metadata.ino() {
            return fs::canonicalize(entry);
        }
    }
    Err(std::io::Error::other(
        "archive adapter invocation authority is missing",
    ))
}

#[cfg(unix)]
const NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET: Duration = Duration::from_secs(30);
#[cfg(unix)]
const NATIVE_ARCHIVE_ADAPTER_CLEANUP_RESERVE: Duration = Duration::from_secs(5);
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVE_AUTHORIZATION_BUDGET: Duration = Duration::from_secs(25);
#[cfg(unix)]
const NATIVE_ARCHIVE_RESPONSE_BYTE_LIMIT: u64 = 1024 * 1024;
#[cfg(unix)]
const NATIVE_ARCHIVE_MEMBER_LIMIT: usize = 100_000;
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVE_INPUT_BROKER_MAGIC: &[u8; 24] = b"hell-archive-input-v1\0\0\0";
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVE_AUTH_BROKER_MAGIC: &[u8; 24] = b"hell-archive-auth-v1\0\0\0\0";
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVE_AUTH_BROKER_READY: u8 = 0xa5;
#[cfg(target_os = "macos")]
pub(crate) const NATIVE_ARCHIVE_FAKE_BROKER_CONNECTIVITY_MARKER: &[u8; 32] =
    b"hell-fake-broker-connectable-v1\n";
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVE_INPUT_PATH_BYTE_LIMIT: usize = 16 * 1024;
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVE_INPUT_STAGE_BYTE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;
#[cfg(target_os = "macos")]
const NATIVE_ARCHIVE_INPUT_REQUEST_ROOT_LIMIT: usize = NATIVE_ARCHIVE_MEMBER_LIMIT;
#[cfg(target_os = "macos")]
static NATIVE_ARCHIVE_INPUT_BROKER_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "macos")]
pub(crate) struct NativeArchiveInputBroker {
    socket: PathBuf,
    socket_root: PathBuf,
    capability: PathBuf,
    staging_root: PathBuf,
    stop: Arc<std::sync::atomic::AtomicBool>,
    completion: std::sync::mpsc::Receiver<Result<(), String>>,
    thread: Option<std::thread::JoinHandle<()>>,
    terminal: bool,
    closed: bool,
    authorizations: Arc<AtomicU64>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct NativeArchiveInputBrokerLimits {
    request_roots: usize,
    staged_entries: usize,
    staged_bytes: u64,
    append_after_metadata_for_integration: bool,
    expire_authorization_after_request_for_integration: bool,
    expire_authorization_during_argument_read_for_integration: bool,
    expire_during_magic_read_for_integration: bool,
    expire_input_during_path_read_for_integration: bool,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct NativeArchiveAuthorizationIntegrationFaults {
    expire_after_request: bool,
    expire_during_argument_read: bool,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Default)]
struct NativeArchiveInputBrokerAccounting {
    request_sequence: u64,
    request_roots: usize,
    staged_entries: usize,
    staged_bytes: u64,
}

#[cfg(target_os = "macos")]
struct NativeArchiveInputBrokerWorker {
    staging_root: PathBuf,
    candidate_uid: u32,
    limits: NativeArchiveInputBrokerLimits,
    archiver: Option<BoundNativeArchiver>,
    authorization_deadline: Option<Instant>,
    authorizations: Arc<AtomicU64>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(target_os = "macos")]
impl NativeArchiveInputBrokerLimits {
    const PRODUCTION: Self = Self {
        request_roots: NATIVE_ARCHIVE_INPUT_REQUEST_ROOT_LIMIT,
        staged_entries: NATIVE_ARCHIVE_MEMBER_LIMIT,
        staged_bytes: NATIVE_ARCHIVE_INPUT_STAGE_BYTE_LIMIT,
        append_after_metadata_for_integration: false,
        expire_authorization_after_request_for_integration: false,
        expire_authorization_during_argument_read_for_integration: false,
        expire_during_magic_read_for_integration: false,
        expire_input_during_path_read_for_integration: false,
    };
}

#[cfg(target_os = "macos")]
impl NativeArchiveInputBroker {
    fn start(
        staging_root: &Path,
        candidate_uid: u32,
        archiver: BoundNativeArchiver,
        authorization_deadline: Instant,
    ) -> Result<Self, String> {
        Self::start_with_limits(
            staging_root,
            candidate_uid,
            NativeArchiveInputBrokerLimits::PRODUCTION,
            Some(archiver),
            Some(authorization_deadline),
        )
    }

    fn start_with_expired_authorization_for_integration(
        staging_root: &Path,
        candidate_uid: u32,
        archiver: BoundNativeArchiver,
        authorization_deadline: Instant,
    ) -> Result<Self, String> {
        Self::start_with_limits(
            staging_root,
            candidate_uid,
            NativeArchiveInputBrokerLimits {
                expire_authorization_after_request_for_integration: true,
                ..NativeArchiveInputBrokerLimits::PRODUCTION
            },
            Some(archiver),
            Some(authorization_deadline),
        )
    }

    fn start_with_drip_expiry_for_integration(
        staging_root: &Path,
        candidate_uid: u32,
        archiver: BoundNativeArchiver,
        authorization_deadline: Instant,
    ) -> Result<Self, String> {
        Self::start_with_limits(
            staging_root,
            candidate_uid,
            NativeArchiveInputBrokerLimits {
                expire_authorization_during_argument_read_for_integration: true,
                ..NativeArchiveInputBrokerLimits::PRODUCTION
            },
            Some(archiver),
            Some(authorization_deadline),
        )
    }

    fn start_with_magic_drip_expiry_for_integration(
        staging_root: &Path,
        candidate_uid: u32,
        archiver: BoundNativeArchiver,
        authorization_deadline: Instant,
    ) -> Result<Self, String> {
        Self::start_with_limits(
            staging_root,
            candidate_uid,
            NativeArchiveInputBrokerLimits {
                expire_during_magic_read_for_integration: true,
                ..NativeArchiveInputBrokerLimits::PRODUCTION
            },
            Some(archiver),
            Some(authorization_deadline),
        )
    }

    fn start_with_input_drip_expiry_for_integration(
        staging_root: &Path,
        candidate_uid: u32,
    ) -> Result<Self, String> {
        Self::start_with_limits(
            staging_root,
            candidate_uid,
            NativeArchiveInputBrokerLimits {
                expire_input_during_path_read_for_integration: true,
                ..NativeArchiveInputBrokerLimits::PRODUCTION
            },
            None,
            None,
        )
    }

    pub(crate) fn start_for_integration(
        staging_root: &Path,
        candidate_uid: u32,
        request_root_limit: usize,
        staged_byte_limit: u64,
    ) -> Result<Self, String> {
        if request_root_limit == 0 || staged_byte_limit == 0 {
            return Err("native archive broker integration limits must be positive".to_owned());
        }
        Self::start_with_limits(
            staging_root,
            candidate_uid,
            NativeArchiveInputBrokerLimits {
                request_roots: request_root_limit,
                staged_entries: NATIVE_ARCHIVE_MEMBER_LIMIT,
                staged_bytes: staged_byte_limit,
                append_after_metadata_for_integration: true,
                expire_authorization_after_request_for_integration: false,
                expire_authorization_during_argument_read_for_integration: false,
                expire_during_magic_read_for_integration: false,
                expire_input_during_path_read_for_integration: false,
            },
            None,
            None,
        )
    }

    fn start_with_limits(
        staging_root: &Path,
        candidate_uid: u32,
        limits: NativeArchiveInputBrokerLimits,
        archiver: Option<BoundNativeArchiver>,
        authorization_deadline: Option<Instant>,
    ) -> Result<Self, String> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::os::unix::net::UnixListener;

        let socket_base = fs::canonicalize("/tmp").map_err(|error| {
            format!("cannot bind native archive broker base authority: {error}")
        })?;
        let mut socket_root = None;
        for _ in 0..16 {
            let sequence = NATIVE_ARCHIVE_INPUT_BROKER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let candidate = socket_base.join(format!("hell-ai-{}-{sequence}", std::process::id()));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    socket_root = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "cannot create native archive broker authority: {error}"
                    ));
                }
            }
        }
        let socket_root = socket_root
            .ok_or_else(|| "native archive broker authority allocation exhausted".to_owned())?;
        let socket = socket_root.join("s");
        let capability = staging_root.join(".broker-v1");
        let setup = (|| {
            fs::set_permissions(&socket_root, fs::Permissions::from_mode(0o711)).map_err(
                |error| format!("cannot confine native archive broker authority: {error}"),
            )?;
            let listener = UnixListener::bind(&socket)
                .map_err(|error| format!("cannot bind native archive input broker: {error}"))?;
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o622))
                .map_err(|error| format!("cannot confine native archive input broker: {error}"))?;
            symlink(&socket, &capability).map_err(|error| {
                format!("cannot publish sealed native archive broker capability: {error}")
            })?;
            Ok::<_, String>(listener)
        })();
        let listener = match setup {
            Ok(listener) => listener,
            Err(primary) => {
                return native_archive_input_broker_start_failure(
                    primary,
                    &socket_root,
                    &socket,
                    &capability,
                );
            }
        };
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let authorizations = Arc::new(AtomicU64::new(0));
        let worker_authorizations = Arc::clone(&authorizations);
        let worker_root = staging_root.to_path_buf();
        let (completion_sender, completion) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("native-archive-input-broker".to_owned())
            .spawn(move || {
                let result = run_native_archive_input_broker(
                    listener,
                    NativeArchiveInputBrokerWorker {
                        staging_root: worker_root,
                        candidate_uid,
                        limits,
                        archiver,
                        authorization_deadline,
                        authorizations: worker_authorizations,
                        stop: worker_stop,
                    },
                );
                let _ = completion_sender.send(result);
            });
        let thread = match thread {
            Ok(thread) => thread,
            Err(error) => {
                return native_archive_input_broker_start_failure(
                    format!("cannot launch native archive input broker: {error}"),
                    &socket_root,
                    &socket,
                    &capability,
                );
            }
        };
        Ok(Self {
            socket,
            socket_root,
            capability,
            staging_root: staging_root.to_path_buf(),
            stop,
            completion,
            thread: Some(thread),
            terminal: false,
            closed: false,
            authorizations,
        })
    }

    fn authorization_count(&self) -> u64 {
        self.authorizations.load(Ordering::Acquire)
    }

    pub(crate) fn close_until(&mut self, deadline: Instant) -> Result<(), String> {
        use std::os::unix::net::UnixStream;

        if self.closed {
            return Ok(());
        }
        self.stop.store(true, Ordering::Release);
        if let Ok(mut wake) = UnixStream::connect(&self.socket) {
            let _ = wake.write_all(b"stop");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (broker, broker_terminal) = if self.terminal {
            (Ok(()), true)
        } else if remaining.is_zero() {
            (
                Err("native archive input broker cleanup deadline expired".to_owned()),
                false,
            )
        } else {
            match self.completion.recv_timeout(remaining) {
                Ok(result) => (result, true),
                Err(error) => (
                    Err(format!(
                        "native archive input broker did not terminate before cleanup: {error}"
                    )),
                    false,
                ),
            }
        };
        self.terminal |= broker_terminal;
        let joined = if broker_terminal {
            self.thread.take().map_or(Ok(()), |thread| {
                thread
                    .join()
                    .map_err(|_| "native archive input broker panicked during cleanup".to_owned())
            })
        } else {
            Err("native archive input broker thread remains owned".to_owned())
        };
        let cleanup = if broker_terminal {
            cleanup_native_archive_input_staging_until(
                &self.staging_root,
                &self.capability,
                deadline,
            )
        } else {
            Err("native archive input staging cleanup retained by broker".to_owned())
        };
        let mut failures = Vec::new();
        if let Err(error) = broker {
            failures.push(format!("broker: {error}"));
        }
        if let Err(error) = joined {
            failures.push(format!("broker-thread: {error}"));
        }
        let cleanup_succeeded = cleanup.is_ok();
        if let Err(error) = cleanup {
            failures.push(format!("staging-cleanup: {error}"));
        }
        let socket_cleanup = if broker_terminal {
            remove_native_archive_broker_socket(&self.socket_root, &self.socket)
        } else {
            Err("native archive broker socket cleanup retained by broker".to_owned())
        };
        let socket_cleanup_succeeded = socket_cleanup.is_ok();
        if let Err(error) = socket_cleanup {
            failures.push(format!("broker-authority-cleanup: {error}"));
        }
        self.closed = broker_terminal && cleanup_succeeded && socket_cleanup_succeeded;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

#[cfg(target_os = "macos")]
fn native_archive_input_broker_start_failure<T>(
    primary: String,
    socket_root: &Path,
    socket: &Path,
    capability: &Path,
) -> Result<T, String> {
    let mut failures = vec![primary];
    match fs::remove_file(capability) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => failures.push(format!("broker capability cleanup: {error}")),
    }
    if let Err(error) = remove_native_archive_broker_socket(socket_root, socket) {
        failures.push(error);
    }
    Err(failures.join("; "))
}

#[cfg(target_os = "macos")]
fn remove_native_archive_broker_socket(socket_root: &Path, socket: &Path) -> Result<(), String> {
    let mut failures = Vec::new();
    match fs::remove_file(socket) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => failures.push(format!("broker socket cleanup: {error}")),
    }
    match fs::remove_dir(socket_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => failures.push(format!("broker root cleanup: {error}")),
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(target_os = "macos")]
fn run_native_archive_input_broker(
    listener: std::os::unix::net::UnixListener,
    worker: NativeArchiveInputBrokerWorker,
) -> Result<(), String> {
    let mut accounting = NativeArchiveInputBrokerAccounting::default();
    loop {
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| format!("cannot accept native archive input request: {error}"))?;
        if worker.stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let request_started = Instant::now();
        let request_completion_deadline = request_started
            .checked_add(NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET)
            .ok_or_else(|| "native archive input request deadline overflowed".to_owned())?;
        let mut request_deadline = request_completion_deadline
            .checked_sub(NATIVE_ARCHIVE_ADAPTER_CLEANUP_RESERVE)
            .ok_or_else(|| "native archive input request cleanup reserve underflowed".to_owned())?;
        if let Some(authorization_deadline) = worker.authorization_deadline {
            request_deadline = request_deadline.min(authorization_deadline);
        }
        let mut magic = [0_u8; NATIVE_ARCHIVE_INPUT_BROKER_MAGIC.len()];
        let response = read_native_archive_broker_exact_until(
            &mut stream,
            &mut magic,
            request_deadline,
            "request magic",
            worker.limits.expire_during_magic_read_for_integration,
        )
        .and_then(|()| {
            if magic == *NATIVE_ARCHIVE_INPUT_BROKER_MAGIC {
                stage_native_archive_input_request(
                    &mut stream,
                    &worker.staging_root,
                    worker.candidate_uid,
                    &mut accounting,
                    worker.limits,
                    request_deadline,
                    request_completion_deadline,
                )
            } else if magic == *NATIVE_ARCHIVE_AUTH_BROKER_MAGIC {
                serve_native_archive_authorization_request(
                    &mut stream,
                    worker.archiver.as_ref().ok_or_else(|| {
                        "native archive broker lacks its retained archiver authority".to_owned()
                    })?,
                    worker.authorizations.as_ref(),
                    request_started,
                    worker.authorization_deadline.ok_or_else(|| {
                        "native archive broker parent authorization deadline is absent".to_owned()
                    })?,
                    NativeArchiveAuthorizationIntegrationFaults {
                        expire_after_request: worker
                            .limits
                            .expire_authorization_after_request_for_integration,
                        expire_during_argument_read: worker
                            .limits
                            .expire_authorization_during_argument_read_for_integration,
                    },
                )
            } else {
                Err("native archive broker request magic differs".to_owned())
            }
        });
        accounting.request_sequence = accounting
            .request_sequence
            .checked_add(1)
            .ok_or_else(|| "native archive input request sequence overflowed".to_owned())?;
        if let Err(error) = response {
            if magic == *NATIVE_ARCHIVE_AUTH_BROKER_MAGIC
                || worker.limits.expire_during_magic_read_for_integration
                || worker.limits.expire_input_during_path_read_for_integration
            {
                continue;
            }
            let detail = error.as_bytes();
            let bounded = &detail[..detail.len().min(4096)];
            let _ = write_native_archive_broker_exact_until(
                &mut stream,
                &[1],
                request_deadline,
                "input error state",
            )
            .and_then(|()| {
                write_native_archive_broker_u32_until(
                    &mut stream,
                    bounded.len(),
                    request_deadline,
                    "input error length",
                )
            })
            .and_then(|()| {
                write_native_archive_broker_exact_until(
                    &mut stream,
                    bounded,
                    request_deadline,
                    "input error detail",
                )
            });
        }
    }
}

#[cfg(target_os = "macos")]
fn configure_native_archive_broker_stream(
    stream: &std::os::unix::net::UnixStream,
    deadline: Instant,
) -> Result<(), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("native archive input broker deadline expired".to_owned());
    }
    let socket_timeout = remaining.min(NATIVE_ARCHIVE_ADAPTER_CLEANUP_RESERVE);
    stream.set_read_timeout(Some(socket_timeout)).map_err(|error| {
        format!(
            "cannot bound native archive input broker read with {socket_timeout:?} syscall quantum and {remaining:?} remaining: {error}"
        )
    })?;
    stream.set_write_timeout(Some(socket_timeout)).map_err(|error| {
        format!(
            "cannot bound native archive input broker write with {socket_timeout:?} syscall quantum and {remaining:?} remaining: {error}"
        )
    })
}

#[cfg(target_os = "macos")]
fn stage_native_archive_input_request(
    stream: &mut std::os::unix::net::UnixStream,
    staging_root: &Path,
    candidate_uid: u32,
    accounting: &mut NativeArchiveInputBrokerAccounting,
    limits: NativeArchiveInputBrokerLimits,
    deadline: Instant,
    cleanup_deadline: Instant,
) -> Result<(), String> {
    let accounting_before = *accounting;
    let request_root = staging_root.join(format!("request-{}", accounting.request_sequence));
    let result = stage_native_archive_input_request_inner(
        stream,
        staging_root,
        candidate_uid,
        accounting,
        limits,
        deadline,
        &request_root,
    );
    if result.is_ok() {
        return result;
    }
    let cleanup = match fs::symlink_metadata(&request_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect failed native archive request root: {error}"
        )),
        Ok(_) => {
            let mut removed = 0_usize;
            remove_native_archive_input_entry_until(&request_root, cleanup_deadline, &mut removed)
        }
    };
    match (result, cleanup) {
        (Err(primary), Ok(())) => {
            *accounting = accounting_before;
            Err(primary)
        }
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; failed native archive request cleanup also failed: {cleanup}"
        )),
        (Ok(()), _) => unreachable!("successful archive staging returned through failure cleanup"),
    }
}

#[cfg(target_os = "macos")]
fn stage_native_archive_input_request_inner(
    stream: &mut std::os::unix::net::UnixStream,
    staging_root: &Path,
    candidate_uid: u32,
    accounting: &mut NativeArchiveInputBrokerAccounting,
    limits: NativeArchiveInputBrokerLimits,
    deadline: Instant,
    request_root: &Path,
) -> Result<(), String> {
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let count = read_native_archive_broker_u32_until(stream, deadline, "input request count")?;
    if count == 0 {
        return Err("native archive input request does not contain members".to_owned());
    }
    if count > limits.staged_entries {
        return Err("native archive input request exceeds its member bound".to_owned());
    }
    let admitted_request_roots = accounting
        .request_roots
        .checked_add(1)
        .ok_or_else(|| "native archive input request root count overflowed".to_owned())?;
    if admitted_request_roots > limits.request_roots {
        return Err("native archive input request root count exceeds its bound".to_owned());
    }
    accounting.request_roots = admitted_request_roots;
    if let Err(error) = fs::create_dir(request_root) {
        accounting.request_roots = accounting
            .request_roots
            .checked_sub(1)
            .ok_or_else(|| "native archive input request root rollback underflowed".to_owned())?;
        return Err(format!(
            "cannot create native archive input request root: {error}"
        ));
    }
    fs::set_permissions(request_root, fs::Permissions::from_mode(0o2750))
        .map_err(|error| format!("cannot confine native archive input request root: {error}"))?;
    let mut staged = Vec::with_capacity(count);
    for position in 0..count {
        require_native_archive_deadline(deadline, "trusted archive input staging")
            .map_err(|error| error.to_string())?;
        accounting.staged_entries = accounting
            .staged_entries
            .checked_add(1)
            .ok_or_else(|| "native archive staged entry count overflowed".to_owned())?;
        if accounting.staged_entries > limits.staged_entries {
            return Err("native archive staged entry count exceeds its bound".to_owned());
        }
        let path_len = read_native_archive_broker_u32_until(stream, deadline, "input path length")?;
        if path_len == 0 || path_len > NATIVE_ARCHIVE_INPUT_PATH_BYTE_LIMIT {
            return Err("native archive input path length is outside its bound".to_owned());
        }
        let mut path = vec![0_u8; path_len];
        read_native_archive_broker_exact_until(
            stream,
            &mut path,
            deadline,
            "input path",
            limits.expire_input_during_path_read_for_integration && position == 0,
        )?;
        let mut expected_sha256 = [0_u8; 32];
        read_native_archive_broker_exact_until(
            stream,
            &mut expected_sha256,
            deadline,
            "input digest",
            false,
        )?;
        let source = PathBuf::from(OsString::from_vec(path));
        let name = source
            .file_name()
            .ok_or_else(|| "native archive input name is absent".to_owned())?;
        let member_root = request_root.join(format!("member-{position}"));
        fs::create_dir(&member_root)
            .map_err(|error| format!("cannot create native archive member root: {error}"))?;
        fs::set_permissions(&member_root, fs::Permissions::from_mode(0o2750))
            .map_err(|error| format!("cannot confine native archive member root: {error}"))?;
        let destination = member_root.join(name);
        let mut input = fs::File::open(&source)
            .map_err(|error| format!("cannot open retained native archive input: {error}"))?;
        let metadata = input
            .metadata()
            .map_err(|error| format!("cannot inspect retained native archive input: {error}"))?;
        if !metadata.is_file() {
            return Err("retained native archive input is not regular".to_owned());
        }
        if metadata.uid() != candidate_uid {
            return Err("native archive input is not owned by the candidate principal".to_owned());
        }
        accounting.staged_bytes = accounting
            .staged_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| "native archive staged byte count overflowed".to_owned())?;
        if accounting.staged_bytes > limits.staged_bytes {
            return Err("native archive staged byte count exceeds its bound".to_owned());
        }
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o440)
            .open(&destination)
            .map_err(|error| format!("cannot create trusted native archive input: {error}"))?;
        if limits.append_after_metadata_for_integration
            && name == OsStr::new("append-during-copy.o")
        {
            let mut mutation = fs::OpenOptions::new()
                .append(true)
                .open(&source)
                .map_err(|error| format!("cannot inject native archive input growth: {error}"))?;
            mutation
                .write_all(b"x")
                .and_then(|()| mutation.sync_all())
                .map_err(|error| format!("cannot inject native archive input growth: {error}"))?;
        }
        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        let buffer_len = u64::try_from(buffer.len())
            .map_err(|_| "native archive copy buffer length does not fit u64".to_owned())?;
        while copied < metadata.len() {
            require_native_archive_deadline(deadline, "trusted archive input copy")
                .map_err(|error| error.to_string())?;
            let remaining = usize::try_from((metadata.len() - copied).min(buffer_len))
                .map_err(|_| "native archive copy remainder does not fit usize".to_owned())?;
            let read = input
                .read(&mut buffer[..remaining])
                .map_err(|error| format!("cannot read native archive input: {error}"))?;
            if read == 0 {
                break;
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| format!("cannot write trusted native archive input: {error}"))?;
            digest.update(&buffer[..read]);
            copied = copied
                .checked_add(
                    u64::try_from(read)
                        .map_err(|_| "native archive copy length does not fit u64".to_owned())?,
                )
                .ok_or_else(|| "native archive copy length overflowed".to_owned())?;
        }
        let mut growth = [0_u8; 1];
        let grew = input
            .read(&mut growth)
            .map_err(|error| format!("cannot probe native archive input growth: {error}"))?
            != 0;
        output
            .sync_all()
            .map_err(|error| format!("cannot sync trusted native archive input: {error}"))?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o440))
            .map_err(|error| format!("cannot freeze trusted native archive input: {error}"))?;
        if copied != metadata.len() || grew || digest.finish() != Digest(expected_sha256) {
            return Err("native archive input changed while it was staged".to_owned());
        }
        staged.push(
            destination
                .strip_prefix(staging_root)
                .map_err(|_| "trusted native archive input escaped staging root".to_owned())?
                .to_path_buf(),
        );
    }
    write_native_archive_broker_exact_until(stream, &[0], deadline, "input response state")?;
    write_native_archive_broker_u32_until(stream, staged.len(), deadline, "input response count")?;
    for path in staged {
        use std::os::unix::ffi::OsStrExt as _;
        let path = path.as_os_str().as_bytes();
        if path.len() > NATIVE_ARCHIVE_INPUT_PATH_BYTE_LIMIT {
            return Err("trusted native archive input path exceeds its bound".to_owned());
        }
        write_native_archive_broker_u32_until(
            stream,
            path.len(),
            deadline,
            "input response path length",
        )?;
        write_native_archive_broker_exact_until(stream, path, deadline, "input response path")?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
const NATIVE_ARCHIVE_AUTHORIZATION_BYTE_LIMIT: usize = 4 * 1024 * 1024;

#[cfg(target_os = "macos")]
struct NativeArchiveAuthorizedProgram {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    sha256: Digest,
}

#[cfg(target_os = "macos")]
impl NativeArchiveAuthorizedProgram {
    fn command(&self, arguments: Vec<OsString>, current_directory: &Path) -> CommandSpec {
        let mut command = CommandSpec::new(&self.path, NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET)
            .arguments(arguments)
            .current_directory(current_directory);
        command.canonical_executable_identity = Some(self.path.clone());
        command.invocation_name = Some(OsString::from("llvm-ar"));
        command
    }

    fn revalidate(&self, deadline: Instant) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        require_native_archive_deadline(deadline, "brokered archiver receipt revalidation")?;
        let metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            std::io::Error::other(format!("cannot inspect brokered archiver receipt: {error}"))
        })?;
        let canonical = fs::canonicalize(&self.path).map_err(|error| {
            std::io::Error::other(format!(
                "cannot canonicalize brokered archiver receipt: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || canonical != self.path
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.gid() != self.gid
            || metadata.mode() & 0o7777 != self.mode
            || metadata.len() != self.size
            || sha256_file_until_with_label(
                &self.path,
                deadline,
                "brokered archiver receipt program hash",
            )
            .map_err(std::io::Error::other)?
                != self.sha256
        {
            return Err(std::io::Error::other(
                "brokered archiver receipt identity changed before spawn",
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn native_archive_authorization_digest(
    arguments: &[OsString],
    current_directory: &Path,
    remaining_millis: u64,
) -> Result<Digest, String> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut digest = Sha256::new();
    digest.update(&remaining_millis.to_le_bytes());
    digest.update(
        &u64::try_from(arguments.len())
            .map_err(|_| "native archive authorization argument count overflowed".to_owned())?
            .to_le_bytes(),
    );
    let mut bytes = 0usize;
    for argument in arguments {
        let argument = argument.as_os_str().as_bytes();
        bytes = bytes
            .checked_add(argument.len())
            .filter(|value| *value <= NATIVE_ARCHIVE_AUTHORIZATION_BYTE_LIMIT)
            .ok_or_else(|| "native archive authorization exceeds its byte bound".to_owned())?;
        digest.update(
            &u64::try_from(argument.len())
                .map_err(|_| "native archive authorization field overflowed".to_owned())?
                .to_le_bytes(),
        );
        digest.update(argument);
    }
    let current_directory = current_directory.as_os_str().as_bytes();
    let _total_bytes = bytes
        .checked_add(current_directory.len())
        .filter(|value| *value <= NATIVE_ARCHIVE_AUTHORIZATION_BYTE_LIMIT)
        .ok_or_else(|| "native archive authorization exceeds its byte bound".to_owned())?;
    digest.update(
        &u64::try_from(current_directory.len())
            .map_err(|_| "native archive authorization directory length overflowed".to_owned())?
            .to_le_bytes(),
    );
    digest.update(current_directory);
    Ok(digest.finish())
}

#[cfg(target_os = "macos")]
fn serve_native_archive_authorization_request(
    stream: &mut std::os::unix::net::UnixStream,
    archiver: &BoundNativeArchiver,
    authorizations: &AtomicU64,
    request_started: Instant,
    parent_deadline: Instant,
    integration_faults: NativeArchiveAuthorizationIntegrationFaults,
) -> Result<(), String> {
    let maximum_deadline = request_started
        .checked_add(NATIVE_ARCHIVE_AUTHORIZATION_BUDGET)
        .ok_or_else(|| "native archive authorization deadline overflowed".to_owned())?
        .min(parent_deadline);
    write_native_archive_broker_exact_until(
        stream,
        &[NATIVE_ARCHIVE_AUTH_BROKER_READY],
        maximum_deadline,
        "authorization readiness",
    )?;
    let remaining_millis =
        read_native_archive_broker_u64_until(stream, maximum_deadline, "authorization cutoff")?;
    let remaining = Duration::from_millis(remaining_millis);
    if remaining.is_zero() || remaining > NATIVE_ARCHIVE_AUTHORIZATION_BUDGET {
        return write_native_archive_authorization_error(
            stream,
            "native archive authorization cutoff is outside its bound",
            maximum_deadline,
        );
    }
    let mut request_deadline = request_started
        .checked_add(remaining)
        .ok_or_else(|| "native archive authorization cutoff overflowed".to_owned())?
        .min(parent_deadline);
    let result = authorize_native_archive_request(
        stream,
        archiver,
        authorizations,
        remaining_millis,
        &mut request_deadline,
        request_started,
        integration_faults,
    );
    match result {
        Ok(()) => Ok(()),
        Err(_) if Instant::now() >= request_deadline => Ok(()),
        Err(error) => write_native_archive_authorization_error(stream, &error, request_deadline),
    }
}

#[cfg(target_os = "macos")]
fn write_native_archive_authorization_error(
    stream: &mut std::os::unix::net::UnixStream,
    error: &str,
    deadline: Instant,
) -> Result<(), String> {
    require_native_archive_deadline(deadline, "authorization error delivery")
        .map_err(|error| error.to_string())?;
    let detail = error.as_bytes();
    let bounded = &detail[..detail.len().min(4096)];
    write_native_archive_broker_exact_until(stream, &[1], deadline, "authorization error state")?;
    write_native_archive_broker_u32_until(
        stream,
        bounded.len(),
        deadline,
        "authorization error length",
    )?;
    write_native_archive_broker_exact_until(stream, bounded, deadline, "authorization error detail")
}

#[cfg(target_os = "macos")]
fn authorize_native_archive_request(
    stream: &mut std::os::unix::net::UnixStream,
    archiver: &BoundNativeArchiver,
    authorizations: &AtomicU64,
    remaining_millis: u64,
    deadline: &mut Instant,
    request_started: Instant,
    integration_faults: NativeArchiveAuthorizationIntegrationFaults,
) -> Result<(), String> {
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::MetadataExt as _;

    require_native_archive_deadline(*deadline, "authorization argument count")
        .map_err(|error| error.to_string())?;
    let count =
        read_native_archive_broker_u32_until(stream, *deadline, "authorization argument count")?;
    if count == 0 || count > NATIVE_ARCHIVE_MEMBER_LIMIT {
        return Err("native archive authorization argument count is outside its bound".to_owned());
    }
    let mut arguments = Vec::with_capacity(count);
    let mut bytes = 0usize;
    for index in 0..count {
        require_native_archive_deadline(*deadline, "authorization argument read")
            .map_err(|error| error.to_string())?;
        let length = read_native_archive_broker_u32_until(
            stream,
            *deadline,
            "authorization argument length",
        )?;
        bytes = bytes
            .checked_add(length)
            .filter(|value| *value <= NATIVE_ARCHIVE_AUTHORIZATION_BYTE_LIMIT)
            .ok_or_else(|| "native archive authorization exceeds its byte bound".to_owned())?;
        let mut argument = vec![0_u8; length];
        let argument_read = read_native_archive_broker_exact_until(
            stream,
            &mut argument,
            *deadline,
            "authorization argument",
            integration_faults.expire_during_argument_read && index == 0,
        );
        if integration_faults.expire_during_argument_read && index == 0 && argument_read.is_err() {
            *deadline = request_started;
        }
        argument_read?;
        arguments.push(OsString::from_vec(argument));
    }
    let directory_length =
        read_native_archive_broker_u32_until(stream, *deadline, "authorization directory length")?;
    let _total_bytes = bytes
        .checked_add(directory_length)
        .filter(|value| *value <= NATIVE_ARCHIVE_AUTHORIZATION_BYTE_LIMIT)
        .ok_or_else(|| "native archive authorization exceeds its byte bound".to_owned())?;
    let mut directory = vec![0_u8; directory_length];
    read_native_archive_broker_exact_until(
        stream,
        &mut directory,
        *deadline,
        "authorization directory",
        false,
    )?;
    let directory = PathBuf::from(OsString::from_vec(directory));
    if !directory.is_absolute() {
        return Err("native archive authorization directory is not absolute".to_owned());
    }
    let request_digest =
        native_archive_authorization_digest(&arguments, &directory, remaining_millis)?;
    if integration_faults.expire_after_request {
        *deadline = request_started;
    }
    require_native_archive_deadline(*deadline, "authorization preflight")
        .map_err(|error| error.to_string())?;
    archiver.revalidate_for_brokered_spawn_until(*deadline)?;
    let metadata = fs::symlink_metadata(&archiver.path)
        .map_err(|error| format!("cannot bind brokered archiver receipt: {error}"))?;
    require_native_archive_deadline(*deadline, "authorization receipt delivery")
        .map_err(|error| error.to_string())?;
    let mut receipt = Vec::with_capacity(1 + 32 + 32 + 8 + 8 + 4 + 4 + 4 + 8);
    receipt.push(0);
    receipt.extend_from_slice(&request_digest.0);
    receipt.extend_from_slice(&archiver.sha256.0);
    receipt.extend_from_slice(&metadata.dev().to_le_bytes());
    receipt.extend_from_slice(&metadata.ino().to_le_bytes());
    receipt.extend_from_slice(&metadata.uid().to_le_bytes());
    receipt.extend_from_slice(&metadata.gid().to_le_bytes());
    receipt.extend_from_slice(&(metadata.mode() & 0o7777).to_le_bytes());
    receipt.extend_from_slice(&metadata.len().to_le_bytes());
    write_native_archive_broker_exact_until(stream, &receipt, *deadline, "authorization receipt")?;
    require_native_archive_deadline(*deadline, "authorization receipt completion")
        .map_err(|error| error.to_string())?;
    authorizations.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_native_archive_broker_u32(
    stream: &mut impl std::io::Write,
    value: usize,
) -> Result<(), String> {
    let value =
        u32::try_from(value).map_err(|_| "native archive broker field exceeds u32".to_owned())?;
    stream
        .write_all(&value.to_le_bytes())
        .map_err(|error| format!("cannot write native archive broker field: {error}"))
}

#[cfg(target_os = "macos")]
fn read_native_archive_broker_exact_until(
    stream: &mut std::os::unix::net::UnixStream,
    mut buffer: &mut [u8],
    deadline: Instant,
    phase: &str,
    expire_after_first_read_for_integration: bool,
) -> Result<(), String> {
    stream.set_nonblocking(true).map_err(|error| {
        format!("cannot make native archive broker {phase} nonblocking: {error}")
    })?;
    let mut read_deadline = deadline;
    let mut completed_read = false;
    while !buffer.is_empty() {
        require_native_archive_deadline(read_deadline, phase).map_err(|error| error.to_string())?;
        let remaining = read_deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut descriptors = [nix::poll::PollFd::new(
            &*stream,
            nix::poll::PollFlags::POLLIN | nix::poll::PollFlags::POLLHUP,
        )];
        if nix::poll::poll(&mut descriptors, timeout)
            .map_err(|error| format!("cannot poll native archive broker {phase}: {error}"))?
            == 0
        {
            return Err(format!(
                "native archive adapter deadline expired during {phase}"
            ));
        }
        match stream.read(buffer) {
            Ok(0) => return Err(format!("native archive broker closed during {phase}")),
            Ok(read) => {
                buffer = &mut buffer[read..];
                if expire_after_first_read_for_integration && !completed_read {
                    read_deadline = Instant::now();
                }
                completed_read = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(format!(
                    "cannot read native archive broker {phase}: {error}"
                ));
            }
        }
    }
    require_native_archive_deadline(read_deadline, phase).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn write_native_archive_broker_exact_until(
    stream: &mut std::os::unix::net::UnixStream,
    mut buffer: &[u8],
    deadline: Instant,
    phase: &str,
) -> Result<(), String> {
    stream.set_nonblocking(true).map_err(|error| {
        format!("cannot make native archive broker {phase} nonblocking: {error}")
    })?;
    while !buffer.is_empty() {
        require_native_archive_deadline(deadline, phase).map_err(|error| error.to_string())?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut descriptors = [nix::poll::PollFd::new(
            &*stream,
            nix::poll::PollFlags::POLLOUT | nix::poll::PollFlags::POLLHUP,
        )];
        if nix::poll::poll(&mut descriptors, timeout)
            .map_err(|error| format!("cannot poll native archive broker {phase}: {error}"))?
            == 0
        {
            return Err(format!(
                "native archive adapter deadline expired during {phase}"
            ));
        }
        match stream.write(buffer) {
            Ok(0) => return Err(format!("native archive broker closed during {phase}")),
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(format!(
                    "cannot write native archive broker {phase}: {error}"
                ));
            }
        }
    }
    require_native_archive_deadline(deadline, phase).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn write_native_archive_broker_u32_until(
    stream: &mut std::os::unix::net::UnixStream,
    value: usize,
    deadline: Instant,
    phase: &str,
) -> Result<(), String> {
    let value =
        u32::try_from(value).map_err(|_| "native archive broker field exceeds u32".to_owned())?;
    write_native_archive_broker_exact_until(stream, &value.to_le_bytes(), deadline, phase)
}

#[cfg(target_os = "macos")]
fn read_native_archive_broker_u32_until(
    stream: &mut std::os::unix::net::UnixStream,
    deadline: Instant,
    phase: &str,
) -> Result<usize, String> {
    let mut value = [0_u8; 4];
    read_native_archive_broker_exact_until(stream, &mut value, deadline, phase, false)?;
    usize::try_from(u32::from_le_bytes(value))
        .map_err(|_| "native archive broker field does not fit usize".to_owned())
}

#[cfg(target_os = "macos")]
fn read_native_archive_broker_u64_until(
    stream: &mut std::os::unix::net::UnixStream,
    deadline: Instant,
    phase: &str,
) -> Result<u64, String> {
    let mut value = [0_u8; 8];
    read_native_archive_broker_exact_until(stream, &mut value, deadline, phase, false)?;
    Ok(u64::from_le_bytes(value))
}

#[cfg(target_os = "macos")]
fn count_native_archive_request_roots(
    staging_root: &Path,
    deadline: Instant,
) -> Result<usize, String> {
    let mut request_roots = 0_usize;
    let mut topology_entries = 0_usize;
    for entry in fs::read_dir(staging_root)
        .map_err(|error| format!("cannot enumerate native archive staging: {error}"))?
    {
        require_native_archive_deadline(deadline, "native archive staging inventory")
            .map_err(|error| error.to_string())?;
        let entry =
            entry.map_err(|error| format!("cannot inspect native archive staging: {error}"))?;
        topology_entries = topology_entries
            .checked_add(1)
            .ok_or_else(|| "native archive staging inventory overflowed".to_owned())?;
        if topology_entries > NATIVE_ARCHIVE_INPUT_REQUEST_ROOT_LIMIT.saturating_add(1) {
            return Err("native archive staging inventory exceeds its bound".to_owned());
        }
        if entry.file_name().to_string_lossy().starts_with("request-") {
            request_roots = request_roots
                .checked_add(1)
                .ok_or_else(|| "native archive request-root inventory overflowed".to_owned())?;
        }
    }
    Ok(request_roots)
}

#[cfg(target_os = "macos")]
fn cleanup_native_archive_input_staging_until(
    staging_root: &Path,
    socket: &Path,
    deadline: Instant,
) -> Result<(), String> {
    if fs::symlink_metadata(socket).is_ok() {
        fs::remove_file(socket)
            .map_err(|error| format!("cannot remove native archive input broker: {error}"))?;
    }
    let mut count = 0_usize;
    let children = fs::read_dir(staging_root)
        .map_err(|error| format!("cannot enumerate native archive input staging: {error}"))?;
    for child in children {
        require_native_archive_deadline(deadline, "trusted archive input cleanup")
            .map_err(|error| error.to_string())?;
        let child = child
            .map_err(|error| format!("cannot inspect native archive staged entry: {error}"))?;
        remove_native_archive_input_entry_until(&child.path(), deadline, &mut count)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_native_archive_input_entry_until(
    path: &Path,
    deadline: Instant,
    count: &mut usize,
) -> Result<(), String> {
    require_native_archive_deadline(deadline, "trusted archive input cleanup")
        .map_err(|error| error.to_string())?;
    *count = count
        .checked_add(1)
        .ok_or_else(|| "native archive input cleanup count overflowed".to_owned())?;
    if *count > NATIVE_ARCHIVE_MEMBER_LIMIT.saturating_mul(3) {
        return Err("native archive input cleanup count exceeds its bound".to_owned());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect native archive staged entry: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("native archive staged entry is redirected".to_owned());
    }
    if metadata.is_dir() {
        for child in fs::read_dir(path)
            .map_err(|error| format!("cannot enumerate native archive staged directory: {error}"))?
        {
            let child = child
                .map_err(|error| format!("cannot inspect native archive staged child: {error}"))?;
            remove_native_archive_input_entry_until(&child.path(), deadline, count)?;
        }
        fs::remove_dir(path)
            .map_err(|error| format!("cannot remove native archive staged directory: {error}"))
    } else if metadata.is_file() {
        fs::remove_file(path)
            .map_err(|error| format!("cannot remove native archive staged input: {error}"))
    } else {
        Err("native archive staged entry has an unsupported type".to_owned())
    }
}

#[cfg(unix)]
struct NativeArchiveDirectoryReceipt {
    label: &'static str,
    path: PathBuf,
    guard: fs::File,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
impl NativeArchiveDirectoryReceipt {
    fn bind(label: &'static str, path: &Path, deadline: Instant) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;

        require_native_archive_deadline(deadline, label)?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| std::io::Error::other(format!("cannot inspect {label}: {error}")))?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| std::io::Error::other(format!("cannot bind {label}: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || canonical != path {
            return Err(std::io::Error::other(format!("{label} is redirected")));
        }
        let guard = fs::File::open(path)
            .map_err(|error| std::io::Error::other(format!("cannot retain {label}: {error}")))?;
        let retained = guard.metadata().map_err(|error| {
            std::io::Error::other(format!("cannot retain {label} identity: {error}"))
        })?;
        if !retained.is_dir()
            || retained.dev() != metadata.dev()
            || retained.ino() != metadata.ino()
        {
            return Err(std::io::Error::other(format!(
                "{label} changed while it was retained"
            )));
        }
        require_native_archive_deadline(deadline, label)?;
        Ok(Self {
            label,
            path: canonical,
            guard,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
        })
    }

    fn revalidate(&self, deadline: Instant) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        require_native_archive_deadline(deadline, self.label)?;
        let retained = self.guard.metadata().map_err(|error| {
            std::io::Error::other(format!(
                "cannot revalidate retained {}: {error}",
                self.label
            ))
        })?;
        let current = fs::symlink_metadata(&self.path).map_err(|error| {
            std::io::Error::other(format!("cannot revalidate {}: {error}", self.label))
        })?;
        if !retained.is_dir()
            || retained.dev() != self.device
            || retained.ino() != self.inode
            || retained.uid() != self.uid
            || retained.gid() != self.gid
            || retained.mode() & 0o7777 != self.mode
            || current.file_type().is_symlink()
            || !current.is_dir()
            || current.dev() != self.device
            || current.ino() != self.inode
            || current.uid() != self.uid
            || current.gid() != self.gid
            || current.mode() & 0o7777 != self.mode
        {
            return Err(std::io::Error::other(format!(
                "{} identity changed",
                self.label
            )));
        }
        require_native_archive_deadline(deadline, self.label)
    }
}

#[cfg(target_os = "macos")]
struct NativeArchiveInputBrokerCapability {
    adapter_root: NativeArchiveDirectoryReceipt,
    authority_root: NativeArchiveDirectoryReceipt,
    staging_root: NativeArchiveDirectoryReceipt,
    socket_root: NativeArchiveDirectoryReceipt,
    capability: PathBuf,
    capability_target: PathBuf,
    capability_device: u64,
    capability_inode: u64,
    capability_uid: u32,
    capability_gid: u32,
    socket: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    socket_uid: u32,
    socket_gid: u32,
    socket_mode: u32,
}

#[cfg(target_os = "macos")]
impl NativeArchiveInputBrokerCapability {
    fn bind(adapter_root: &Path, deadline: Instant) -> std::io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        let adapter_root = NativeArchiveDirectoryReceipt::bind(
            "sealed archive adapter root",
            adapter_root,
            deadline,
        )?;
        let authority_path = adapter_root.path.join(".authority");
        let authority_root = NativeArchiveDirectoryReceipt::bind(
            "sealed archive adapter authority",
            &authority_path,
            deadline,
        )?;
        let staging_path = authority_path.join("inputs");
        let staging_root = NativeArchiveDirectoryReceipt::bind(
            "sealed archive input staging root",
            &staging_path,
            deadline,
        )?;
        let capability = staging_path.join(".broker-v1");
        let capability_metadata = fs::symlink_metadata(&capability).map_err(|error| {
            std::io::Error::other(format!(
                "cannot inspect sealed archive input broker capability: {error}"
            ))
        })?;
        let socket = fs::read_link(&capability).map_err(|error| {
            std::io::Error::other(format!(
                "cannot read sealed archive input broker capability: {error}"
            ))
        })?;
        let socket_root_path = socket.parent().ok_or_else(|| {
            std::io::Error::other("sealed archive input broker has no socket authority")
        })?;
        let socket_root = NativeArchiveDirectoryReceipt::bind(
            "sealed archive input broker socket root",
            socket_root_path,
            deadline,
        )?;
        let socket_metadata = fs::symlink_metadata(&socket).map_err(|error| {
            std::io::Error::other(format!(
                "cannot inspect sealed archive input broker: {error}"
            ))
        })?;
        if adapter_root.mode != 0o2755
            || authority_root.mode != 0o555
            || staging_root.mode != 0o2710
            || authority_root.uid != adapter_root.uid
            || staging_root.uid != adapter_root.uid
            || !capability_metadata.file_type().is_symlink()
            || capability_metadata.uid() != adapter_root.uid
            || !socket.is_absolute()
            || socket.file_name() != Some(OsStr::new("s"))
            || socket_root.mode != 0o711
            || socket_root.uid != adapter_root.uid
            || socket_metadata.file_type().is_symlink()
            || !socket_metadata.file_type().is_socket()
            || socket_metadata.uid() != adapter_root.uid
            || socket_metadata.mode() & 0o7777 != 0o622
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "sealed archive input broker authority differs from policy: adapterMode={:o}, authorityMode={:o}, stagingMode={:o}, adapterUid={}, authorityUid={}, stagingUid={}, capabilitySymlink={}, capabilityUid={}, socketAbsolute={}, socketName={:?}, socketRootMode={:o}, socketRootUid={}, socketSymlink={}, socketTypeSocket={}, socketUid={}, socketMode={:o}",
                    adapter_root.mode,
                    authority_root.mode,
                    staging_root.mode,
                    adapter_root.uid,
                    authority_root.uid,
                    staging_root.uid,
                    capability_metadata.file_type().is_symlink(),
                    capability_metadata.uid(),
                    socket.is_absolute(),
                    socket.file_name(),
                    socket_root.mode,
                    socket_root.uid,
                    socket_metadata.file_type().is_symlink(),
                    socket_metadata.file_type().is_socket(),
                    socket_metadata.uid(),
                    socket_metadata.mode() & 0o7777,
                ),
            ));
        }
        require_native_archive_deadline(deadline, "archive input broker binding")?;
        Ok(Self {
            adapter_root,
            authority_root,
            staging_root,
            socket_root,
            capability,
            capability_target: socket.clone(),
            capability_device: capability_metadata.dev(),
            capability_inode: capability_metadata.ino(),
            capability_uid: capability_metadata.uid(),
            capability_gid: capability_metadata.gid(),
            socket,
            socket_device: socket_metadata.dev(),
            socket_inode: socket_metadata.ino(),
            socket_uid: socket_metadata.uid(),
            socket_gid: socket_metadata.gid(),
            socket_mode: socket_metadata.mode() & 0o7777,
        })
    }

    fn revalidate(&self, deadline: Instant) -> std::io::Result<()> {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        self.adapter_root.revalidate(deadline)?;
        self.authority_root.revalidate(deadline)?;
        self.staging_root.revalidate(deadline)?;
        self.socket_root.revalidate(deadline)?;
        let capability = fs::symlink_metadata(&self.capability).map_err(|error| {
            std::io::Error::other(format!(
                "cannot revalidate sealed archive input broker capability: {error}"
            ))
        })?;
        let socket = fs::symlink_metadata(&self.socket).map_err(|error| {
            std::io::Error::other(format!(
                "cannot revalidate sealed archive input broker: {error}"
            ))
        })?;
        if !capability.file_type().is_symlink()
            || capability.dev() != self.capability_device
            || capability.ino() != self.capability_inode
            || capability.uid() != self.capability_uid
            || capability.gid() != self.capability_gid
            || fs::read_link(&self.capability)? != self.capability_target
            || socket.file_type().is_symlink()
            || !socket.file_type().is_socket()
            || socket.dev() != self.socket_device
            || socket.ino() != self.socket_inode
            || socket.uid() != self.socket_uid
            || socket.gid() != self.socket_gid
            || socket.mode() & 0o7777 != self.socket_mode
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "sealed archive input broker identity changed",
            ));
        }
        require_native_archive_deadline(deadline, "archive input broker revalidation")
    }

    fn bind_staged_input(
        &self,
        relative: &Path,
        deadline: Instant,
    ) -> std::io::Result<NativeArchiveFileReceipt> {
        use std::path::Component;

        let components = relative.components().collect::<Vec<_>>();
        if relative.is_absolute()
            || components.len() != 3
            || !matches!(components[0], Component::Normal(name) if canonical_native_archive_staging_component(name, "request-"))
            || !matches!(components[1], Component::Normal(name) if canonical_native_archive_staging_component(name, "member-"))
            || !matches!(components[2], Component::Normal(_))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted archive input relative topology differs",
            ));
        }
        self.revalidate(deadline)?;
        let request_root = NativeArchiveDirectoryReceipt::bind(
            "trusted archive request root",
            &self.staging_root.path.join(components[0].as_os_str()),
            deadline,
        )?;
        let member_root = NativeArchiveDirectoryReceipt::bind(
            "trusted archive member root",
            &request_root.path.join(components[1].as_os_str()),
            deadline,
        )?;
        if request_root.uid != self.staging_root.uid
            || request_root.gid != self.staging_root.gid
            || request_root.mode != 0o2750
            || member_root.uid != self.staging_root.uid
            || member_root.gid != self.staging_root.gid
            || member_root.mode != 0o2750
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "trusted archive input directory authority differs",
            ));
        }
        let path = self.staging_root.path.join(relative);
        let receipt = NativeArchiveFileReceipt::bind("trusted archive input", &path, deadline)?;
        if receipt
            .path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            != Some(self.staging_root.path.as_path())
            || receipt.uid != self.staging_root.uid
            || receipt.gid != self.staging_root.gid
            || receipt.mode != 0o440
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "trusted archive input escaped its sealed staging authority",
            ));
        }
        self.revalidate(deadline)?;
        Ok(receipt)
    }

    fn authorize_archiver(
        &self,
        arguments: &[OsString],
        current_directory: &Path,
        deadline: Instant,
    ) -> std::io::Result<NativeArchiveAuthorizedProgram> {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::net::UnixStream;

        self.revalidate(deadline)?;
        let mut stream = UnixStream::connect(&self.socket).map_err(|error| {
            std::io::Error::other(format!(
                "cannot connect to native archive authorization broker: {error}"
            ))
        })?;
        write_native_archive_broker_exact_until(
            &mut stream,
            NATIVE_ARCHIVE_AUTH_BROKER_MAGIC,
            deadline,
            "authorization request magic",
        )
        .map_err(std::io::Error::other)?;
        let mut readiness = [0_u8; 1];
        read_native_archive_broker_exact_until(
            &mut stream,
            &mut readiness,
            deadline,
            "authorization readiness",
            false,
        )
        .map_err(std::io::Error::other)?;
        if readiness != [NATIVE_ARCHIVE_AUTH_BROKER_READY] {
            return Err(std::io::Error::other(
                "native archive broker readiness differs",
            ));
        }
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(NATIVE_ARCHIVE_AUTHORIZATION_BUDGET);
        let remaining_millis = u64::try_from(remaining.as_millis())
            .map_err(|_| std::io::Error::other("native archive authorization cutoff overflowed"))?;
        if remaining_millis == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "native archive authorization deadline expired before request",
            ));
        }
        let expected_request =
            native_archive_authorization_digest(arguments, current_directory, remaining_millis)
                .map_err(std::io::Error::other)?;
        write_native_archive_broker_exact_until(
            &mut stream,
            &remaining_millis.to_le_bytes(),
            deadline,
            "authorization cutoff",
        )
        .map_err(std::io::Error::other)?;
        write_native_archive_broker_u32_until(
            &mut stream,
            arguments.len(),
            deadline,
            "authorization argument count",
        )
        .map_err(std::io::Error::other)?;
        for argument in arguments {
            let bytes = argument.as_os_str().as_bytes();
            write_native_archive_broker_u32_until(
                &mut stream,
                bytes.len(),
                deadline,
                "authorization argument length",
            )
            .map_err(std::io::Error::other)?;
            write_native_archive_broker_exact_until(
                &mut stream,
                bytes,
                deadline,
                "authorization argument",
            )
            .map_err(std::io::Error::other)?;
        }
        let directory = current_directory.as_os_str().as_bytes();
        write_native_archive_broker_u32_until(
            &mut stream,
            directory.len(),
            deadline,
            "authorization directory length",
        )
        .map_err(std::io::Error::other)?;
        write_native_archive_broker_exact_until(
            &mut stream,
            directory,
            deadline,
            "authorization directory",
        )
        .map_err(std::io::Error::other)?;
        let mut state = [0_u8; 1];
        read_native_archive_broker_exact_until(
            &mut stream,
            &mut state,
            deadline,
            "authorization state",
            false,
        )
        .map_err(std::io::Error::other)?;
        if state[0] == 1 {
            let detail_len = read_native_archive_broker_u32_until(
                &mut stream,
                deadline,
                "authorization error length",
            )
            .map_err(std::io::Error::other)?;
            if detail_len > 4096 {
                return Err(std::io::Error::other(
                    "native archive authorization error exceeds its bound",
                ));
            }
            let mut detail = vec![0_u8; detail_len];
            read_native_archive_broker_exact_until(
                &mut stream,
                &mut detail,
                deadline,
                "authorization error",
                false,
            )
            .map_err(std::io::Error::other)?;
            return Err(std::io::Error::other(format!(
                "native archive authorization rejected: {}",
                String::from_utf8_lossy(&detail)
            )));
        }
        if state != [0] {
            return Err(std::io::Error::other(
                "native archive authorization state is invalid",
            ));
        }
        let mut request = [0_u8; 32];
        let mut sha256 = [0_u8; 32];
        read_native_archive_broker_exact_until(
            &mut stream,
            &mut request,
            deadline,
            "authorization request digest",
            false,
        )
        .and_then(|()| {
            read_native_archive_broker_exact_until(
                &mut stream,
                &mut sha256,
                deadline,
                "authorization program digest",
                false,
            )
        })
        .map_err(std::io::Error::other)?;
        if Digest(request) != expected_request {
            return Err(std::io::Error::other(
                "native archive authorization request receipt differs",
            ));
        }
        let device = read_native_archive_broker_u64_until(
            &mut stream,
            deadline,
            "authorization device receipt",
        )
        .map_err(std::io::Error::other)?;
        let inode = read_native_archive_broker_u64_until(
            &mut stream,
            deadline,
            "authorization inode receipt",
        )
        .map_err(std::io::Error::other)?;
        let uid = read_native_archive_broker_u32_until(
            &mut stream,
            deadline,
            "authorization uid receipt",
        )
        .map_err(std::io::Error::other)?;
        let gid = read_native_archive_broker_u32_until(
            &mut stream,
            deadline,
            "authorization gid receipt",
        )
        .map_err(std::io::Error::other)?;
        let mode = read_native_archive_broker_u32_until(
            &mut stream,
            deadline,
            "authorization mode receipt",
        )
        .map_err(std::io::Error::other)?;
        let size = read_native_archive_broker_u64_until(
            &mut stream,
            deadline,
            "authorization size receipt",
        )
        .map_err(std::io::Error::other)?;
        let receipt = NativeArchiveAuthorizedProgram {
            path: self.authority_root.path.join("llvm/bin/llvm-ar"),
            device,
            inode,
            uid: u32::try_from(uid).map_err(|_| {
                std::io::Error::other("native archive authorization uid does not fit u32")
            })?,
            gid: u32::try_from(gid).map_err(|_| {
                std::io::Error::other("native archive authorization gid does not fit u32")
            })?,
            mode: u32::try_from(mode).map_err(|_| {
                std::io::Error::other("native archive authorization mode does not fit u32")
            })?,
            size,
            sha256: Digest(sha256),
        };
        receipt.revalidate(deadline)?;
        self.revalidate(deadline)?;
        Ok(receipt)
    }
}

#[cfg(target_os = "macos")]
fn canonical_native_archive_staging_component(value: &OsStr, prefix: &str) -> bool {
    let Some(value) = value.to_str() else {
        return false;
    };
    let Some(sequence) = value.strip_prefix(prefix) else {
        return false;
    };
    !sequence.is_empty()
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && sequence
            .parse::<u64>()
            .is_ok_and(|number| number.to_string() == sequence)
}

#[cfg(unix)]
struct NativeArchiveFileReceipt {
    label: &'static str,
    path: PathBuf,
    guard: fs::File,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    sha256: Digest,
}

#[cfg(unix)]
impl NativeArchiveFileReceipt {
    fn bind(label: &'static str, path: &Path, deadline: Instant) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;

        require_native_archive_deadline(deadline, label)?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| std::io::Error::other(format!("cannot inspect {label}: {error}")))?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| std::io::Error::other(format!("cannot bind {label}: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || canonical != path {
            return Err(std::io::Error::other(format!(
                "{label} is not a regular real file"
            )));
        }
        let guard = fs::File::open(path)
            .map_err(|error| std::io::Error::other(format!("cannot retain {label}: {error}")))?;
        let retained = guard.metadata().map_err(|error| {
            std::io::Error::other(format!("cannot retain {label} identity: {error}"))
        })?;
        if !retained.is_file()
            || retained.dev() != metadata.dev()
            || retained.ino() != metadata.ino()
        {
            return Err(std::io::Error::other(format!(
                "{label} changed while it was retained"
            )));
        }
        let sha256 = sha256_retained_native_archive_file(&guard, deadline, label)?;
        require_native_archive_deadline(deadline, label)?;
        Ok(Self {
            label,
            path: canonical,
            guard,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            size: metadata.len(),
            sha256,
        })
    }

    fn revalidate(&self, deadline: Instant) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        require_native_archive_deadline(deadline, self.label)?;
        let retained = self.guard.metadata().map_err(|error| {
            std::io::Error::other(format!(
                "cannot revalidate retained {}: {error}",
                self.label
            ))
        })?;
        let current = fs::symlink_metadata(&self.path).map_err(|error| {
            std::io::Error::other(format!("cannot revalidate {}: {error}", self.label))
        })?;
        let sha256 = sha256_retained_native_archive_file(&self.guard, deadline, self.label)?;
        if !retained.is_file()
            || retained.dev() != self.device
            || retained.ino() != self.inode
            || retained.uid() != self.uid
            || retained.gid() != self.gid
            || retained.mode() & 0o7777 != self.mode
            || retained.len() != self.size
            || current.file_type().is_symlink()
            || !current.is_file()
            || current.dev() != self.device
            || current.ino() != self.inode
            || current.uid() != self.uid
            || current.gid() != self.gid
            || current.mode() & 0o7777 != self.mode
            || current.len() != self.size
            || sha256 != self.sha256
        {
            return Err(std::io::Error::other(format!(
                "{} identity changed",
                self.label
            )));
        }
        require_native_archive_deadline(deadline, self.label)
    }
}

#[cfg(unix)]
fn sha256_retained_native_archive_file(
    file: &fs::File,
    deadline: Instant,
    label: &str,
) -> std::io::Result<Digest> {
    let mut retained = file.try_clone().map_err(|error| {
        std::io::Error::other(format!("cannot clone retained {label}: {error}"))
    })?;
    retained.seek(SeekFrom::Start(0)).map_err(|error| {
        std::io::Error::other(format!("cannot rewind retained {label}: {error}"))
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        require_native_archive_deadline(deadline, label)?;
        let read = retained.read(&mut buffer).map_err(|error| {
            std::io::Error::other(format!("cannot hash retained {label}: {error}"))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    require_native_archive_deadline(deadline, label)?;
    Ok(digest.finish())
}

#[cfg(unix)]
struct NativeArchiveTargetReceipt {
    path: PathBuf,
    guard: fs::File,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
impl NativeArchiveTargetReceipt {
    fn bind(path: &Path, deadline: Instant) -> std::io::Result<Self> {
        require_native_archive_deadline(deadline, "archive target binding")?;
        let receipt = NativeArchiveFileReceipt::bind("archive target", path, deadline)?;
        Ok(Self {
            path: receipt.path,
            guard: receipt.guard,
            device: receipt.device,
            inode: receipt.inode,
            uid: receipt.uid,
            gid: receipt.gid,
            mode: receipt.mode,
        })
    }

    fn revalidate(&self, deadline: Instant) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        require_native_archive_deadline(deadline, "archive target revalidation")?;
        let retained = self.guard.metadata().map_err(|error| {
            std::io::Error::other(format!(
                "cannot revalidate retained archive target: {error}"
            ))
        })?;
        let current = fs::symlink_metadata(&self.path).map_err(|error| {
            std::io::Error::other(format!("cannot revalidate archive target: {error}"))
        })?;
        if !retained.is_file()
            || retained.dev() != self.device
            || retained.ino() != self.inode
            || retained.uid() != self.uid
            || retained.gid() != self.gid
            || retained.mode() & 0o7777 != self.mode
            || current.file_type().is_symlink()
            || !current.is_file()
            || current.dev() != self.device
            || current.ino() != self.inode
            || current.uid() != self.uid
            || current.gid() != self.gid
            || current.mode() & 0o7777 != self.mode
        {
            return Err(std::io::Error::other(
                "archive target identity changed during invocation",
            ));
        }
        require_native_archive_deadline(deadline, "archive target revalidation")
    }
}

#[cfg(unix)]
struct NativeArchiveWorkAuthority {
    read_root: PathBuf,
    write_root: PathBuf,
    directories: Vec<NativeArchiveDirectoryReceipt>,
    inputs: Vec<NativeArchiveFileReceipt>,
    targets: Vec<NativeArchiveTargetReceipt>,
    pending_targets: Vec<PathBuf>,
}

#[cfg(unix)]
struct NativeArchiveInputGroup {
    argument_index: usize,
    input_indices: Vec<usize>,
}

#[cfg(unix)]
impl NativeArchiveWorkAuthority {
    fn revalidate_before_launch(&self, deadline: Instant) -> std::io::Result<()> {
        for directory in &self.directories {
            directory.revalidate(deadline)?;
        }
        for input in &self.inputs {
            input.revalidate(deadline)?;
        }
        for target in &self.targets {
            target.revalidate(deadline)?;
        }
        for target in &self.pending_targets {
            match fs::symlink_metadata(target) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(std::io::Error::other(
                        "fresh archive target appeared before launch",
                    ));
                }
                Err(error) => {
                    return Err(std::io::Error::other(format!(
                        "cannot attest fresh archive target absence: {error}"
                    )));
                }
            }
        }
        require_native_archive_deadline(deadline, "prelaunch authority revalidation")
    }

    fn revalidate_after_launch(&self, deadline: Instant) -> std::io::Result<()> {
        for directory in &self.directories {
            directory.revalidate(deadline)?;
        }
        for input in &self.inputs {
            input.revalidate(deadline)?;
        }
        for target in &self.targets {
            target.revalidate(deadline)?;
        }
        for target in &self.pending_targets {
            let metadata = fs::symlink_metadata(target).map_err(|error| {
                std::io::Error::other(format!("cannot inspect fresh archive target: {error}"))
            })?;
            let canonical = fs::canonicalize(target).map_err(|error| {
                std::io::Error::other(format!("cannot bind fresh archive target: {error}"))
            })?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || canonical != *target
                || !canonical.starts_with(&self.write_root)
            {
                return Err(std::io::Error::other(
                    "fresh archive target differs after invocation",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
struct NativeArchiveInvocation {
    arguments: Vec<OsString>,
    authority: Option<NativeArchiveWorkAuthority>,
    input_groups: Vec<NativeArchiveInputGroup>,
}

#[cfg(unix)]
impl NativeArchiveInvocation {
    fn require_input_group_topology(&self) -> std::io::Result<()> {
        let Some(authority) = &self.authority else {
            return if self.input_groups.is_empty() {
                Ok(())
            } else {
                Err(std::io::Error::other(
                    "native archive input groups lack an authority",
                ))
            };
        };
        let mut prior = None;
        for group in &self.input_groups {
            if group.argument_index >= self.arguments.len()
                || prior.is_some_and(|position| position >= group.argument_index)
                || group
                    .input_indices
                    .iter()
                    .any(|position| *position >= authority.inputs.len())
            {
                return Err(std::io::Error::other(
                    "native archive input group topology is invalid",
                ));
            }
            prior = Some(group.argument_index);
        }
        Ok(())
    }

    fn revalidate_before_launch(&self, deadline: Instant) -> std::io::Result<()> {
        if let Some(authority) = &self.authority {
            authority.revalidate_before_launch(deadline)?;
        }
        Ok(())
    }

    fn revalidate_after_launch(&self, deadline: Instant) -> std::io::Result<()> {
        if let Some(authority) = &self.authority {
            authority.revalidate_after_launch(deadline)?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn stage_inputs_with_broker(
        &mut self,
        adapter_root: &Path,
        deadline: Instant,
    ) -> std::io::Result<()> {
        use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
        use std::os::unix::net::UnixStream;

        let broker = NativeArchiveInputBrokerCapability::bind(adapter_root, deadline)?;
        let flattened = self
            .input_groups
            .iter()
            .flat_map(|group| group.input_indices.iter().copied())
            .collect::<Vec<_>>();
        if flattened.len() > NATIVE_ARCHIVE_MEMBER_LIMIT {
            return Err(std::io::Error::other(
                "native archive staged input count exceeds its bound",
            ));
        }
        if flattened.is_empty() {
            broker.revalidate(deadline)?;
            return Ok(());
        }
        let authority = self.authority.as_mut().ok_or_else(|| {
            std::io::Error::other("native archive input staging authority is absent")
        })?;
        let mut stream = UnixStream::connect(&broker.socket).map_err(|error| {
            std::io::Error::other(format!(
                "cannot connect to native archive input broker: {error}"
            ))
        })?;
        broker.revalidate(deadline)?;
        write_native_archive_broker_exact_until(
            &mut stream,
            NATIVE_ARCHIVE_INPUT_BROKER_MAGIC,
            deadline,
            "input request magic",
        )
        .map_err(std::io::Error::other)?;
        write_native_archive_broker_u32_until(
            &mut stream,
            flattened.len(),
            deadline,
            "input request count",
        )
        .map_err(std::io::Error::other)?;
        for input_index in &flattened {
            let input = authority.inputs.get(*input_index).ok_or_else(|| {
                std::io::Error::other("native archive input receipt index is invalid")
            })?;
            let path = input.path.as_os_str().as_bytes();
            if path.is_empty() || path.len() > NATIVE_ARCHIVE_INPUT_PATH_BYTE_LIMIT {
                return Err(std::io::Error::other(
                    "native archive input path length is outside its bound",
                ));
            }
            write_native_archive_broker_u32_until(
                &mut stream,
                path.len(),
                deadline,
                "input request path length",
            )
            .map_err(std::io::Error::other)?;
            write_native_archive_broker_exact_until(
                &mut stream,
                path,
                deadline,
                "input request path",
            )
            .map_err(std::io::Error::other)?;
            write_native_archive_broker_exact_until(
                &mut stream,
                &input.sha256.0,
                deadline,
                "input request digest",
            )
            .map_err(std::io::Error::other)?;
        }
        let mut state = [0_u8; 1];
        read_native_archive_broker_exact_until(
            &mut stream,
            &mut state,
            deadline,
            "input response state",
            false,
        )
        .map_err(std::io::Error::other)?;
        if state[0] == 1 {
            let detail_len =
                read_native_archive_broker_u32_until(&mut stream, deadline, "input error length")
                    .map_err(std::io::Error::other)?;
            if detail_len > 4096 {
                return Err(std::io::Error::other(
                    "native archive input broker error exceeds its bound",
                ));
            }
            let mut detail = vec![0_u8; detail_len];
            read_native_archive_broker_exact_until(
                &mut stream,
                &mut detail,
                deadline,
                "input error detail",
                false,
            )
            .map_err(std::io::Error::other)?;
            return Err(std::io::Error::other(format!(
                "native archive input broker rejected staging: {}",
                String::from_utf8_lossy(&detail)
            )));
        }
        if state[0] != 0 {
            return Err(std::io::Error::other(
                "native archive input broker state is invalid",
            ));
        }
        let staged_count =
            read_native_archive_broker_u32_until(&mut stream, deadline, "input response count")
                .map_err(std::io::Error::other)?;
        if staged_count != flattened.len() {
            return Err(std::io::Error::other(
                "native archive input broker response count differs",
            ));
        }
        let mut staged_paths = Vec::with_capacity(staged_count);
        let mut staged_receipts = Vec::with_capacity(staged_count);
        for input_index in &flattened {
            let path_len = read_native_archive_broker_u32_until(
                &mut stream,
                deadline,
                "input response path length",
            )
            .map_err(std::io::Error::other)?;
            if path_len == 0 || path_len > NATIVE_ARCHIVE_INPUT_PATH_BYTE_LIMIT {
                return Err(std::io::Error::other(
                    "trusted native archive input path length is outside its bound",
                ));
            }
            let mut path = vec![0_u8; path_len];
            read_native_archive_broker_exact_until(
                &mut stream,
                &mut path,
                deadline,
                "input response path",
                false,
            )
            .map_err(std::io::Error::other)?;
            let relative = PathBuf::from(OsString::from_vec(path));
            let receipt = broker.bind_staged_input(&relative, deadline)?;
            let expected = authority.inputs.get(*input_index).ok_or_else(|| {
                std::io::Error::other("native archive input receipt index is invalid")
            })?;
            if receipt.sha256 != expected.sha256 || receipt.size != expected.size {
                return Err(std::io::Error::other(
                    "trusted archive input differs from its candidate receipt",
                ));
            }
            staged_paths.push(receipt.path.as_os_str().to_owned());
            staged_receipts.push(receipt);
        }
        let mut replacements = BTreeMap::<usize, Vec<OsString>>::new();
        let mut staged_position = 0_usize;
        for group in &self.input_groups {
            let end = staged_position
                .checked_add(group.input_indices.len())
                .ok_or_else(|| std::io::Error::other("staged argv position overflowed"))?;
            let replacement = staged_paths
                .get(staged_position..end)
                .ok_or_else(|| std::io::Error::other("staged argv topology is incomplete"))?
                .to_vec();
            if replacements
                .insert(group.argument_index, replacement)
                .is_some()
            {
                return Err(std::io::Error::other(
                    "native archive input argv position is repeated",
                ));
            }
            staged_position = end;
        }
        let mut staged_arguments = Vec::new();
        for (position, argument) in self.arguments.iter().enumerate() {
            if let Some(replacement) = replacements.remove(&position) {
                staged_arguments.extend(replacement);
            } else {
                staged_arguments.push(argument.clone());
            }
        }
        if staged_position != staged_paths.len() || !replacements.is_empty() {
            return Err(std::io::Error::other(
                "native archive staged argv topology differs",
            ));
        }
        authority.inputs.extend(staged_receipts);
        self.arguments = staged_arguments;
        self.input_groups.clear();
        Ok(())
    }
}

#[cfg(unix)]
fn require_native_archive_deadline(deadline: Instant, phase: &str) -> std::io::Result<()> {
    if Instant::now() >= deadline {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("native archive adapter deadline expired during {phase}"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
pub(crate) fn run_native_archive_adapter(arguments: &[OsString]) -> std::process::ExitCode {
    let result: std::io::Result<ExitStatus> = (|| {
        let completion_deadline = Instant::now()
            .checked_add(NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET)
            .ok_or_else(|| std::io::Error::other("native archive adapter deadline overflowed"))?;
        let execution_deadline = completion_deadline
            .checked_sub(NATIVE_ARCHIVE_ADAPTER_CLEANUP_RESERVE)
            .ok_or_else(|| {
                std::io::Error::other("native archive adapter cleanup reserve underflowed")
            })?;
        let invoked = std::env::args_os()
            .next()
            .ok_or_else(|| std::io::Error::other("archive adapter argv[0] is missing"))?;
        let directory = archive_adapter_directory(&invoked)?;
        let current_directory = std::env::current_dir()?;
        #[cfg(all(unix, not(target_os = "macos")))]
        let bound_llvm_ar = directory.join(".authority").join("llvm-ar");
        let invocation = if native_archive_identity_request(arguments) {
            NativeArchiveInvocation {
                arguments: vec![OsString::from("--version")],
                authority: None,
                input_groups: Vec::new(),
            }
        } else {
            bind_native_archive_invocation(
                arguments,
                &directory,
                &current_directory,
                std::env::var_os("TMPDIR").as_deref().map(Path::new),
                execution_deadline,
            )?
        };
        #[cfg(target_os = "macos")]
        let mut invocation = invocation;
        #[cfg(target_os = "macos")]
        if invocation.authority.is_some() {
            invocation.stage_inputs_with_broker(&directory, execution_deadline)?;
        }
        invocation.require_input_group_topology()?;
        invocation.revalidate_before_launch(execution_deadline)?;
        #[cfg(target_os = "macos")]
        {
            let broker = NativeArchiveInputBrokerCapability::bind(&directory, execution_deadline)?;
            let authorized = broker.authorize_archiver(
                &invocation.arguments,
                &current_directory,
                execution_deadline,
            )?;
            invocation.revalidate_before_launch(execution_deadline)?;
            let (progress, _progress_receiver) = SupervisedProgressObserver::bounded(1);
            let result = authorized
                .command(invocation.arguments.clone(), &current_directory)
                .run_until(execution_deadline, completion_deadline, progress)
                .map_err(std::io::Error::other)?;
            if result.status.success() {
                invocation.revalidate_after_launch(completion_deadline)?;
            } else {
                invocation.revalidate_before_launch(completion_deadline)?;
            }
            Ok(result.status)
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        let status = Command::new(&bound_llvm_ar)
            .args(&invocation.arguments)
            .current_dir(&current_directory)
            .status()?;
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            if status.success() {
                invocation.revalidate_after_launch(completion_deadline)?;
            } else {
                invocation.revalidate_before_launch(completion_deadline)?;
            }
            Ok(status)
        }
    })();
    match result {
        Ok(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or(
                std::process::ExitCode::FAILURE,
                std::process::ExitCode::from,
            ),
        Err(error) => {
            eprintln!("native archive adapter failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn native_archive_identity_request(arguments: &[OsString]) -> bool {
    arguments.len() == 1 && arguments[0] == OsStr::new("--version")
}

#[cfg(unix)]
fn normalize_native_archive_arguments(
    arguments: &[OsString],
    adapter_root: &Path,
    current_directory: &Path,
) -> std::io::Result<Vec<OsString>> {
    let temporary_directory = std::env::var_os("TMPDIR").map(PathBuf::from);
    normalize_native_archive_arguments_with_temporary_directory(
        arguments,
        adapter_root,
        current_directory,
        temporary_directory.as_deref(),
    )
}

#[cfg(unix)]
fn normalize_native_archive_arguments_with_temporary_directory(
    arguments: &[OsString],
    adapter_root: &Path,
    current_directory: &Path,
    temporary_directory: Option<&Path>,
) -> std::io::Result<Vec<OsString>> {
    let deadline = Instant::now()
        .checked_add(NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET)
        .ok_or_else(|| std::io::Error::other("native archive adapter deadline overflowed"))?;
    bind_native_archive_invocation(
        arguments,
        adapter_root,
        current_directory,
        temporary_directory,
        deadline,
    )
    .map(|invocation| invocation.arguments)
}

#[cfg(unix)]
fn bind_native_archive_invocation(
    arguments: &[OsString],
    adapter_root: &Path,
    current_directory: &Path,
    temporary_directory: Option<&Path>,
    deadline: Instant,
) -> std::io::Result<NativeArchiveInvocation> {
    require_native_archive_deadline(deadline, "argument binding")?;
    let Some(first) = arguments.first() else {
        return Err(std::io::Error::other(
            "archive adapter arguments are missing",
        ));
    };
    let configure_probe =
        native_archive_configure_probe(arguments, current_directory).transpose()?;
    let is_configure_probe = configure_probe.is_some();
    let arguments = configure_probe.as_deref().unwrap_or(arguments);
    let mut target_index = 1;
    let (mut saw_symbol_table, mut saw_create_quietly) = (false, false);
    while let Some(argument) = arguments.get(target_index) {
        match argument.to_str() {
            Some("s" | "-s") if !saw_symbol_table => {
                saw_symbol_table = true;
                target_index += 1;
                continue;
            }
            Some("c" | "-c") if !saw_create_quietly => {
                saw_create_quietly = true;
                target_index += 1;
                continue;
            }
            Some("s" | "-s" | "c" | "-c") => {
                return Err(std::io::Error::other(
                    "archive adapter modifier is repeated",
                ));
            }
            _ => {}
        }
        break;
    }
    let Some(target) = arguments.get(target_index) else {
        return Err(std::io::Error::other("archive adapter target is missing"));
    };
    if target.to_str().is_some_and(|value| value.starts_with('-')) {
        return Err(std::io::Error::other(
            "archive adapter target is an unsupported option",
        ));
    }
    let target = Path::new(target);
    let target_path = if target.is_absolute() {
        target.to_path_buf()
    } else {
        current_directory.join(target)
    };
    let mut authority = if is_configure_probe {
        let current = fs::canonicalize(current_directory).map_err(|error| {
            std::io::Error::other(format!(
                "cannot bind configure archive current directory: {error}"
            ))
        })?;
        native_archive_direct_work_authority(&current, &target_path, &current, deadline)?
    } else {
        native_archive_work_authority_until(
            adapter_root,
            current_directory,
            &target_path,
            temporary_directory,
            deadline,
        )?
    };
    if fs::symlink_metadata(&target_path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(std::io::Error::other(
            "archive adapter target may not be a symbolic link",
        ));
    }
    let canonical_target = match fs::canonicalize(&target_path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = target_path
                .parent()
                .ok_or_else(|| std::io::Error::other("archive adapter target parent is missing"))?;
            let canonical_parent = fs::canonicalize(parent).map_err(|error| {
                std::io::Error::other(format!("cannot bind archive target parent: {error}"))
            })?;
            let name = target_path
                .file_name()
                .ok_or_else(|| std::io::Error::other("archive adapter target name is missing"))?;
            canonical_parent.join(name)
        }
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "cannot inspect archive target: {error}"
            )));
        }
    };
    if !canonical_target.starts_with(&authority.write_root) {
        return Err(std::io::Error::other(
            "archive adapter target escapes its bound work directory",
        ));
    }
    let mut input_groups = Vec::new();
    validate_native_archive_arguments(
        &arguments[target_index + 1..],
        target_index + 1,
        current_directory,
        &mut authority,
        &mut input_groups,
        deadline,
    )?;
    let replacement = match first.to_str() {
        Some("r") | Some("-r") => {
            if target_path.exists() {
                return Err(std::io::Error::other(
                    "replace-to-append conversion requires a fresh archive target",
                ));
            }
            Some(if first == "r" { "qL" } else { "-qL" })
        }
        Some("q") => Some("qL"),
        Some("-q") => Some("-qL"),
        Some("qc") => Some("qLc"),
        Some("-qc") => Some("-qLc"),
        Some("qcls") => Some("qclsL"),
        Some("-qcls") => Some("-qclsL"),
        Some("clqs") => Some("qclsL"),
        Some("-clqs") => Some("-qclsL"),
        Some("qL" | "-qL" | "qLc" | "-qLc" | "qcL" | "-qcL" | "qclsL" | "-qclsL") => None,
        Some("t") | Some("-t") => None,
        Some(value) => {
            return Err(std::io::Error::other(format!(
                "archive adapter received unsupported operation {value:?}"
            )));
        }
        None => {
            return Err(std::io::Error::other(
                "archive adapter operation must be UTF-8",
            ));
        }
    };
    let mut normalized = arguments.to_vec();
    if let Some(replacement) = replacement {
        normalized[0] = replacement.into();
    }
    authority.revalidate_before_launch(deadline)?;
    Ok(NativeArchiveInvocation {
        arguments: normalized,
        authority: Some(authority),
        input_groups,
    })
}

#[cfg(unix)]
fn native_archive_work_authority(
    adapter_root: &Path,
    current_directory: &Path,
    target: &Path,
    temporary_directory: Option<&Path>,
) -> std::io::Result<NativeArchiveWorkAuthority> {
    let deadline = Instant::now()
        .checked_add(NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET)
        .ok_or_else(|| std::io::Error::other("native archive adapter deadline overflowed"))?;
    native_archive_work_authority_until(
        adapter_root,
        current_directory,
        target,
        temporary_directory,
        deadline,
    )
}

#[cfg(unix)]
fn native_archive_work_authority_until(
    adapter_root: &Path,
    current_directory: &Path,
    target: &Path,
    temporary_directory: Option<&Path>,
    deadline: Instant,
) -> std::io::Result<NativeArchiveWorkAuthority> {
    require_native_archive_deadline(deadline, "work authority binding")?;
    let adapter_work = fs::canonicalize(adapter_root.join(".stack-work")).map_err(|error| {
        std::io::Error::other(format!("cannot bind archive work directory: {error}"))
    })?;
    let current = fs::canonicalize(current_directory).map_err(|error| {
        std::io::Error::other(format!("cannot bind archive current directory: {error}"))
    })?;
    let adapter_temporary = adapter_work.join("tmp");
    if current.starts_with(&adapter_work) {
        if current.starts_with(&adapter_temporary) {
            return native_stack_temporary_work_authority_until(
                &current,
                target,
                &adapter_temporary,
                deadline,
            );
        }
        return native_archive_direct_work_authority(&current, target, &adapter_work, deadline);
    }
    let temporary = temporary_directory
        .ok_or_else(|| std::io::Error::other("archive adapter temporary authority is absent"))?;
    let temporary_metadata = fs::symlink_metadata(temporary).map_err(|error| {
        std::io::Error::other(format!(
            "cannot inspect archive temporary authority: {error}"
        ))
    })?;
    if temporary != adapter_temporary
        || temporary_metadata.file_type().is_symlink()
        || !temporary_metadata.is_dir()
    {
        return Err(std::io::Error::other(
            "archive adapter temporary authority differs from its bound directory",
        ));
    }
    let temporary = fs::canonicalize(temporary).map_err(|error| {
        std::io::Error::other(format!("cannot bind archive temporary authority: {error}"))
    })?;
    if temporary != adapter_temporary {
        return Err(std::io::Error::other(
            "archive adapter temporary authority differs from its bound directory",
        ));
    }
    native_stack_temporary_work_authority_until(&current, target, &temporary, deadline)
}

#[cfg(unix)]
fn native_stack_temporary_work_authority_until(
    current: &Path,
    target: &Path,
    temporary: &Path,
    deadline: Instant,
) -> std::io::Result<NativeArchiveWorkAuthority> {
    require_native_archive_deadline(deadline, "Stack temporary authority binding")?;
    let relative = current.strip_prefix(temporary).map_err(|_| {
        std::io::Error::other("archive adapter current directory escapes its temporary authority")
    })?;
    let mut components = relative.components();
    let (Some(std::path::Component::Normal(stack)), Some(std::path::Component::Normal(package))) =
        (components.next(), components.next())
    else {
        return Err(std::io::Error::other(
            "archive adapter current directory is outside a Stack package tree",
        ));
    };
    let stack_is_canonical = stack
        .to_str()
        .and_then(|name| name.strip_prefix("stack-"))
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
    if !stack_is_canonical {
        return Err(std::io::Error::other(
            "archive adapter Stack temporary name is invalid",
        ));
    }
    let package_is_canonical = package.to_str().is_some_and(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    });
    if !package_is_canonical {
        return Err(std::io::Error::other(
            "archive adapter current directory is outside a Stack package source tree",
        ));
    }
    let session = temporary.join(stack);
    let package_root = session.join(package);
    let write_root = package_root.join(".stack-work");
    let temporary_receipt =
        NativeArchiveDirectoryReceipt::bind("archive temporary authority", temporary, deadline)?;
    let session_receipt =
        NativeArchiveDirectoryReceipt::bind("Stack session authority", &session, deadline)?;
    let package_receipt =
        NativeArchiveDirectoryReceipt::bind("Stack package authority", &package_root, deadline)?;
    let current_receipt = NativeArchiveDirectoryReceipt::bind(
        "archive invocation current directory",
        current,
        deadline,
    )?;
    let write_receipt = NativeArchiveDirectoryReceipt::bind(
        "Stack package archive write authority",
        &write_root,
        deadline,
    )?;
    if !current.starts_with(&package_root) {
        return Err(std::io::Error::other(
            "archive adapter current directory escapes its Stack package authority",
        ));
    }
    let mut authority = NativeArchiveWorkAuthority {
        read_root: package_root,
        write_root,
        directories: vec![
            temporary_receipt,
            session_receipt,
            package_receipt,
            current_receipt,
            write_receipt,
        ],
        inputs: Vec::new(),
        targets: Vec::new(),
        pending_targets: Vec::new(),
    };
    bind_native_archive_target(&mut authority, target, deadline)?;
    Ok(authority)
}

#[cfg(unix)]
fn native_archive_direct_work_authority(
    current: &Path,
    target: &Path,
    work: &Path,
    deadline: Instant,
) -> std::io::Result<NativeArchiveWorkAuthority> {
    let work_receipt =
        NativeArchiveDirectoryReceipt::bind("archive work authority", work, deadline)?;
    let current_receipt = NativeArchiveDirectoryReceipt::bind(
        "archive invocation current directory",
        current,
        deadline,
    )?;
    if !current.starts_with(work) {
        return Err(std::io::Error::other(
            "archive adapter current directory escapes its work authority",
        ));
    }
    let mut authority = NativeArchiveWorkAuthority {
        read_root: work.to_path_buf(),
        write_root: work.to_path_buf(),
        directories: vec![work_receipt, current_receipt],
        inputs: Vec::new(),
        targets: Vec::new(),
        pending_targets: Vec::new(),
    };
    bind_native_archive_target(&mut authority, target, deadline)?;
    Ok(authority)
}

#[cfg(unix)]
fn bind_native_archive_target(
    authority: &mut NativeArchiveWorkAuthority,
    target: &Path,
    deadline: Instant,
) -> std::io::Result<()> {
    require_native_archive_deadline(deadline, "archive target binding")?;
    match fs::symlink_metadata(target) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(std::io::Error::other(
                    "archive adapter target is not a regular real file",
                ));
            }
            let canonical = fs::canonicalize(target).map_err(|error| {
                std::io::Error::other(format!("cannot bind archive target: {error}"))
            })?;
            let receipt = NativeArchiveTargetReceipt::bind(&canonical, deadline)?;
            if !receipt.path.starts_with(&authority.write_root) {
                return Err(std::io::Error::other(
                    "archive adapter target escapes its bound work directory",
                ));
            }
            authority.targets.push(receipt);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = target
                .parent()
                .ok_or_else(|| std::io::Error::other("archive adapter target parent is missing"))?;
            let canonical_parent = fs::canonicalize(parent).map_err(|error| {
                std::io::Error::other(format!("cannot bind archive target parent: {error}"))
            })?;
            let receipt = NativeArchiveDirectoryReceipt::bind(
                "archive target parent authority",
                &canonical_parent,
                deadline,
            )?;
            if !receipt.path.starts_with(&authority.write_root) {
                return Err(std::io::Error::other(
                    "archive adapter target escapes its bound work directory",
                ));
            }
            authority.directories.push(receipt);
            authority.pending_targets.push(canonical_parent.join(
                target.file_name().ok_or_else(|| {
                    std::io::Error::other("archive adapter target name is missing")
                })?,
            ));
        }
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "cannot inspect archive target: {error}"
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn run_posix_release_child(arguments: &[OsString]) -> std::process::ExitCode {
    let error = exec_posix_release_child(arguments);
    eprintln!("POSIX release child launcher failed: {error}");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_native_archive_broker_descendant_launcher(
    arguments: &[OsString],
) -> Result<(), String> {
    let [adapter_root, fake_broker, writable_root] = arguments else {
        return Err(
            "native archive broker descendant launcher requires adapter, fake endpoint, and writable root"
                .to_owned(),
        );
    };
    use std::os::unix::fs::PermissionsExt as _;

    let source = Path::new(writable_root).join("broker-budget-input.o");
    let growing = Path::new(writable_root).join("append-during-copy.o");
    let oversize = Path::new(writable_root).join("broker-oversize-input.o");
    for (path, contents) in [
        (&source, b"data".as_slice()),
        (&growing, b"grow".as_slice()),
        (&oversize, &[b'o'; 53]),
    ] {
        fs::write(path, contents)
            .and_then(|()| fs::set_permissions(path, fs::Permissions::from_mode(0o666)))
            .map_err(|error| format!("cannot create broker budget input: {error}"))?;
    }
    {
        use std::os::unix::net::UnixStream;

        let control_deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| "fake broker connectivity deadline overflowed".to_owned())?;
        let mut control = UnixStream::connect(fake_broker)
            .map_err(|error| format!("candidate cannot connect to fake broker: {error}"))?;
        configure_native_archive_broker_stream(&control, control_deadline)?;
        control
            .write_all(NATIVE_ARCHIVE_FAKE_BROKER_CONNECTIVITY_MARKER)
            .map_err(|error| format!("cannot write fake broker connectivity marker: {error}"))?;
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot bind broker descendant executable: {error}"))?;
    let result = CommandSpec::new(executable, Duration::from_secs(10))
        .argument("__verify-native-archive-broker-descendant-consumer")
        .argument(adapter_root)
        .argument(fake_broker)
        .argument(&source)
        .argument(&growing)
        .argument(&oversize)
        .run()
        .map_err(|error| format!("cannot execute broker descendant consumer: {error}"))?;
    if result.timed_out || !result.status.success() {
        return Err(format!(
            "broker descendant consumer failed: status={:?}; stderr={}",
            result.status.code(),
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_native_archive_broker_descendant_consumer(
    arguments: &[OsString],
) -> Result<(), String> {
    let [adapter_root, fake_broker, source, growing, oversize] = arguments else {
        return Err(
            "native archive broker descendant consumer requires adapter, typed decoy, and input paths"
                .to_owned(),
        );
    };
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or_else(|| "broker descendant deadline overflowed".to_owned())?;
    let capability = NativeArchiveInputBrokerCapability::bind(Path::new(adapter_root), deadline)
        .map_err(|error| format!("cannot bind descendant broker capability: {error}"))?;
    use std::os::unix::fs::MetadataExt as _;
    let decoy = fs::symlink_metadata(fake_broker)
        .map_err(|error| format!("cannot bind typed decoy broker receipt: {error}"))?;
    if capability.socket == Path::new(fake_broker)
        || (capability.socket_device, capability.socket_inode) == (decoy.dev(), decoy.ino())
    {
        return Err("sealed broker capability resolved to the typed decoy endpoint".to_owned());
    }
    capability
        .revalidate(deadline)
        .map_err(|error| format!("cannot revalidate descendant broker capability: {error}"))?;
    for _ in 0..3 {
        require_native_archive_broker_test_rejection(
            &capability.socket,
            None,
            "native archive input request does not contain members",
            deadline,
        )?;
    }
    for _ in 0..2 {
        require_native_archive_broker_test_success(
            &capability.socket,
            Path::new(source),
            deadline,
        )?;
    }
    require_native_archive_broker_test_rejection(
        &capability.socket,
        Some(Path::new(growing)),
        "native archive input changed while it was staged",
        deadline,
    )?;
    require_native_archive_broker_test_rejection(
        &capability.socket,
        Some(Path::new(oversize)),
        "native archive staged byte count exceeds its bound",
        deadline,
    )?;
    require_native_archive_broker_test_rejection(
        &capability.socket,
        Some(Path::new(source)),
        "native archive input request root count exceeds its bound",
        deadline,
    )?;
    let staging_root = Path::new(adapter_root).join(".authority/inputs");
    let mut request_roots = 0_usize;
    for entry in fs::read_dir(&staging_root)
        .map_err(|error| format!("cannot enumerate descendant broker staging: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("cannot inspect descendant broker staging: {error}"))?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("request-") {
            request_roots = request_roots
                .checked_add(1)
                .ok_or_else(|| "descendant broker request count overflowed".to_owned())?;
        } else if name != OsStr::new(".broker-v1") {
            return Err("descendant broker staging contains an unexpected entry".to_owned());
        }
    }
    if request_roots != 4 || staging_root.join("request-7").exists() {
        return Err("descendant broker request-root admission differs from its bound".to_owned());
    }
    let bounded_growth = fs::read(
        staging_root
            .join("request-5/member-0")
            .join("append-during-copy.o"),
    )
    .map_err(|error| format!("cannot inspect bounded growing input staging: {error}"))?;
    if bounded_growth != b"grow" {
        return Err("growing native archive input exceeded its admitted copy length".to_owned());
    }
    if fs::read_dir(staging_root.join("request-6/member-0"))
        .map_err(|error| format!("cannot inspect rejected oversized staging: {error}"))?
        .next()
        .is_some()
    {
        return Err("oversized native archive input wrote beyond its admitted budget".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_native_archive_broker_test_success(
    socket: &Path,
    source: &Path,
    deadline: Instant,
) -> Result<(), String> {
    let mut stream = write_native_archive_broker_test_request(socket, Some(source), deadline)?;
    let mut state = [0_u8; 1];
    read_native_archive_broker_exact_until(
        &mut stream,
        &mut state,
        deadline,
        "descendant response state",
        false,
    )?;
    if state != [0]
        || read_native_archive_broker_u32_until(&mut stream, deadline, "descendant response count")?
            != 1
    {
        return Err("descendant broker did not accept the admitted request".to_owned());
    }
    let path_len = read_native_archive_broker_u32_until(
        &mut stream,
        deadline,
        "descendant response path length",
    )?;
    if path_len == 0 || path_len > NATIVE_ARCHIVE_INPUT_PATH_BYTE_LIMIT {
        return Err("descendant broker staged path length is outside its bound".to_owned());
    }
    let mut path = vec![0_u8; path_len];
    read_native_archive_broker_exact_until(
        &mut stream,
        &mut path,
        deadline,
        "descendant response path",
        false,
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn require_native_archive_broker_test_rejection(
    socket: &Path,
    source: Option<&Path>,
    expected: &str,
    deadline: Instant,
) -> Result<(), String> {
    let mut stream = write_native_archive_broker_test_request(socket, source, deadline)?;
    let mut state = [0_u8; 1];
    read_native_archive_broker_exact_until(
        &mut stream,
        &mut state,
        deadline,
        "descendant rejection state",
        false,
    )?;
    if state != [1] {
        return Err("descendant broker did not reject the bounded request".to_owned());
    }
    let detail_len =
        read_native_archive_broker_u32_until(&mut stream, deadline, "descendant rejection length")?;
    if detail_len == 0 || detail_len > 4096 {
        return Err("descendant broker rejection detail is outside its bound".to_owned());
    }
    let mut detail = vec![0_u8; detail_len];
    read_native_archive_broker_exact_until(
        &mut stream,
        &mut detail,
        deadline,
        "descendant rejection detail",
        false,
    )?;
    if String::from_utf8_lossy(&detail) != expected {
        return Err(format!(
            "descendant broker rejection differs: {}",
            String::from_utf8_lossy(&detail)
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn write_native_archive_broker_test_request(
    socket: &Path,
    source: Option<&Path>,
    deadline: Instant,
) -> Result<std::os::unix::net::UnixStream, String> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket)
        .map_err(|error| format!("cannot connect descendant broker capability: {error}"))?;
    configure_native_archive_broker_stream(&stream, deadline)?;
    stream
        .write_all(NATIVE_ARCHIVE_INPUT_BROKER_MAGIC)
        .map_err(|error| format!("cannot write descendant broker magic: {error}"))?;
    write_native_archive_broker_u32(&mut stream, usize::from(source.is_some()))?;
    if let Some(source) = source {
        let path = source.as_os_str().as_bytes();
        write_native_archive_broker_u32(&mut stream, path.len())?;
        stream
            .write_all(path)
            .map_err(|error| format!("cannot write descendant broker path: {error}"))?;
        let contents = fs::read(source)
            .map_err(|error| format!("cannot read descendant broker input: {error}"))?;
        let mut digest = Sha256::new();
        digest.update(&contents);
        stream
            .write_all(&digest.finish().0)
            .map_err(|error| format!("cannot write descendant broker digest: {error}"))?;
    }
    Ok(stream)
}

#[cfg(unix)]
fn exec_posix_release_child(arguments: &[OsString]) -> std::io::Error {
    use std::os::unix::process::CommandExt as _;

    match posix_release_child_command(arguments) {
        Ok(mut command) => command.exec(),
        Err(error) => error,
    }
}

#[cfg(unix)]
fn posix_release_child_command(arguments: &[OsString]) -> std::io::Result<Command> {
    use std::os::unix::process::CommandExt as _;

    let (count, framed) = arguments
        .split_first()
        .ok_or_else(|| std::io::Error::other("POSIX release child envelope is missing"))?;
    let count_text = count.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child environment count is not UTF-8",
        )
    })?;
    let count = count_text.parse::<usize>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child environment count is invalid",
        )
    })?;
    if count_text != count.to_string()
        || count > hell_testkit::POSIX_RELEASE_CHILD_ENVIRONMENT_ALLOWLIST.len()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child environment count is not canonical or exceeds its bound",
        ));
    }
    let pair_arguments = count.checked_mul(2).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child environment framing overflowed",
        )
    })?;
    if framed.len() <= pair_arguments + 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child environment framing is incomplete",
        ));
    }
    let (encoded_environment, command_arguments) = framed.split_at(pair_arguments);
    let (invocation_name, command_arguments) = command_arguments
        .split_first()
        .expect("framing check retained the invocation name");
    let (program, child_arguments) = command_arguments
        .split_first()
        .expect("framing check retained the program");
    let invocation_path = Path::new(invocation_name);
    if invocation_path.file_name() != Some(invocation_name.as_os_str())
        || invocation_path.parent() != Some(Path::new(""))
        || invocation_name.is_empty()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child invocation name is not canonical",
        ));
    }
    if !Path::new(program).is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child program is not absolute",
        ));
    }
    if Path::new(program).file_name() != Some(invocation_name.as_os_str()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child invocation name differs from its bound program",
        ));
    }
    let mut environment = BTreeMap::new();
    for pair in encoded_environment.chunks_exact(2) {
        let name = pair[0].to_str().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX release child environment name is not UTF-8",
            )
        })?;
        if !hell_testkit::POSIX_RELEASE_CHILD_ENVIRONMENT_ALLOWLIST.contains(&name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX release child environment name is not allowed",
            ));
        }
        if environment
            .insert(pair[0].clone(), pair[1].clone())
            .is_some()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX release child environment name is duplicated",
            ));
        }
    }
    let mut command = Command::new(program);
    command
        .arg0(invocation_name)
        .args(child_arguments)
        .env_clear()
        .envs(environment);
    Ok(command)
}

#[cfg(windows)]
pub(crate) fn run_windows_restricted_child(arguments: &[OsString]) -> std::process::ExitCode {
    run_windows_restricted_child_with_token(arguments, false)
}

#[cfg(windows)]
pub(crate) fn run_windows_write_restricted_child(arguments: &[OsString]) -> std::process::ExitCode {
    run_windows_restricted_child_with_token(arguments, true)
}

#[cfg(windows)]
fn run_windows_restricted_child_with_token(
    arguments: &[OsString],
    write_restricted: bool,
) -> std::process::ExitCode {
    match windows_restricted_child(arguments, write_restricted) {
        Ok((code, evidence)) => {
            let outcome = windows_restricted_child_outcome(code, &evidence);
            std::process::ExitCode::from(outcome.exit_code)
        }
        Err(error) => {
            eprintln!("restricted child launcher failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
struct WindowsRestrictedChildOutcome {
    exit_code: u8,
    diagnostic: Option<String>,
}

#[cfg(any(windows, test))]
fn windows_restricted_child_outcome(
    code: u32,
    prelaunch_evidence: &str,
) -> WindowsRestrictedChildOutcome {
    if let Some(raw_status) = windows_raw_status_diagnostic(code) {
        return WindowsRestrictedChildOutcome {
            exit_code: u8::MAX,
            diagnostic: Some(format!("{raw_status}\n{prelaunch_evidence}")),
        };
    }
    let exit_code = u8::try_from(code).expect("representable Windows child status");
    WindowsRestrictedChildOutcome {
        exit_code,
        diagnostic: (exit_code != 0).then(|| prelaunch_evidence.to_owned()),
    }
}

#[cfg(any(windows, test))]
fn windows_raw_status_diagnostic(code: u32) -> Option<String> {
    u8::try_from(code)
        .err()
        .map(|_| format!("restricted child exited with raw Windows status {code} (0x{code:08x})"))
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsRestrictedLaunchRequest {
    adapter: PathBuf,
    adapter_sha256: Digest,
    target_arguments: Vec<OsString>,
    #[cfg(windows)]
    child_request: Option<hell_testkit::WindowsReleaseChildRequest>,
}

#[cfg(any(windows, test))]
fn parse_windows_restricted_launch_request(
    decoded: Vec<OsString>,
) -> std::io::Result<WindowsRestrictedLaunchRequest> {
    let mut decoded = decoded.into_iter();
    let adapter = PathBuf::from(
        decoded
            .next()
            .ok_or_else(|| std::io::Error::other("restricted argv adapter path is absent"))?,
    );
    let digest = decoded
        .next()
        .ok_or_else(|| std::io::Error::other("restricted argv adapter digest is absent"))?
        .into_string()
        .map_err(|_| std::io::Error::other("restricted argv adapter digest is not UTF-8"))?;
    let adapter_sha256 = Digest::from_hex(&digest)
        .map_err(|error| std::io::Error::other(format!("invalid adapter digest: {error}")))?;
    if digest != adapter_sha256.hex() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restricted argv adapter digest is not canonical lowercase",
        ));
    }
    let remaining = decoded.collect::<Vec<_>>();
    #[cfg(all(windows, test))]
    let (target_arguments, child_request) = {
        if remaining.first().is_some_and(|field| {
            Path::new(field)
                .file_name()
                .is_some_and(|name| name.eq_ignore_ascii_case(OsStr::new("cargo.exe")))
        }) {
            (remaining, None)
        } else {
            let child = hell_testkit::parse_windows_release_child_request(remaining)?;
            (child.target_arguments().to_vec(), Some(child))
        }
    };
    #[cfg(all(windows, not(test)))]
    let (target_arguments, child_request) = {
        let child = hell_testkit::parse_windows_release_child_request(remaining)?;
        (child.target_arguments().to_vec(), Some(child))
    };
    #[cfg(not(windows))]
    let target_arguments = remaining;
    if !adapter.is_absolute()
        || adapter.file_name() != Some(OsStr::new("hell-test-helper.exe"))
        || target_arguments.is_empty()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restricted launch request differs from its adapter contract",
        ));
    }
    Ok(WindowsRestrictedLaunchRequest {
        adapter,
        adapter_sha256,
        target_arguments,
        #[cfg(windows)]
        child_request,
    })
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsLaunchTokenConstraint {
    DuplicatedCurrentPrimary,
}

#[cfg(any(windows, test))]
const WINDOWS_LAUNCH_TOKEN_CONSTRAINTS: [WindowsLaunchTokenConstraint; 1] =
    [WindowsLaunchTokenConstraint::DuplicatedCurrentPrimary];

#[cfg(any(windows, test))]
fn windows_launch_token_contract(
    constraints: &[WindowsLaunchTokenConstraint],
) -> std::io::Result<()> {
    if constraints != WINDOWS_LAUNCH_TOKEN_CONSTRAINTS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows child launcher must duplicate the current normal primary token",
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsRestrictedGraphicalBinding {
    InheritedDefault,
}

#[cfg(any(windows, test))]
const WINDOWS_RESTRICTED_GRAPHICAL_BINDING: WindowsRestrictedGraphicalBinding =
    WindowsRestrictedGraphicalBinding::InheritedDefault;

#[cfg(any(windows, test))]
const WINDOWS_SUPPORTED_LAUNCH_CANARY: [(&str, [&str; 4]); 1] =
    [("cmd.exe", ["/d", "/c", "exit", "0"])];

// The canary validates actual process initialization under the supported
// normal-user token. It intentionally does not gate on a literal PE import
// name: Windows API-set forwarding makes direct `kernel32.dll` spelling an
// invalid launchability predicate.

#[cfg(any(windows, test))]
fn windows_restricted_graphical_binding_contract(
    binding: WindowsRestrictedGraphicalBinding,
) -> std::io::Result<()> {
    match binding {
        WindowsRestrictedGraphicalBinding::InheritedDefault => Ok(()),
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsRestrictedStdioHandle {
    EofStandardInput,
    CapturedStandardOutput,
    CapturedStandardError,
}

#[cfg(any(windows, test))]
const WINDOWS_RESTRICTED_STDIO_HANDLES: [WindowsRestrictedStdioHandle; 3] = [
    WindowsRestrictedStdioHandle::EofStandardInput,
    WindowsRestrictedStdioHandle::CapturedStandardOutput,
    WindowsRestrictedStdioHandle::CapturedStandardError,
];

#[cfg(any(windows, test))]
const WINDOWS_STARTF_USE_STD_HANDLES: u32 = 0x0000_0100;

#[cfg(any(windows, test))]
fn windows_restricted_stdio_contract(
    handles: &[WindowsRestrictedStdioHandle],
) -> std::io::Result<()> {
    if handles != WINDOWS_RESTRICTED_STDIO_HANDLES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restricted child must inherit exactly EOF stdin, captured stdout, and captured stderr",
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn relay_windows_restricted_diagnostic(
    mut source: impl std::io::Read,
    mut destination: impl std::io::Write,
) -> std::io::Result<()> {
    if let Err(error) = std::io::copy(&mut source, &mut destination)
        && error.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(error);
    }
    destination.flush()
}

#[cfg(windows)]
fn windows_duplicate_current_primary_token(
    process_token: &firehazard::token::OwnedHandle,
) -> std::io::Result<firehazard::token::OwnedHandle> {
    windows_launch_token_contract(&WINDOWS_LAUNCH_TOKEN_CONSTRAINTS)?;
    Ok(firehazard::duplicate_token_ex(
        process_token,
        firehazard::token::ASSIGN_PRIMARY | firehazard::token::QUERY,
        None,
        firehazard::security::Identification,
        firehazard::token::Primary,
    )?)
}

#[cfg(windows)]
fn windows_write_restricted_primary_token(
    process_token: &firehazard::token::OwnedHandle,
) -> std::io::Result<firehazard::token::OwnedHandle> {
    let authenticated_users = firehazard::convert_string_sid_to_sid_a("S-1-5-11")?;
    let restricted_code = firehazard::convert_string_sid_to_sid_a("S-1-5-12")?;
    let restricted_sids = [
        firehazard::sid::AndAttributes::new(&authenticated_users, ()),
        firehazard::sid::AndAttributes::new(&restricted_code, ()),
    ];
    let restricted = firehazard::create_restricted_token(
        process_token,
        firehazard::token::WRITE_RESTRICTED | firehazard::token::DISABLE_MAX_PRIVILEGE,
        None,
        None,
        Some(&restricted_sids),
    )?;
    Ok(firehazard::duplicate_token_ex(
        &restricted,
        firehazard::token::ASSIGN_PRIMARY | firehazard::token::QUERY,
        None,
        firehazard::security::Identification,
        firehazard::token::Primary,
    )?)
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedWindowsRestrictedCanary {
    subsystem: &'static str,
    program: PathBuf,
    arguments: Vec<&'static str>,
    imports: Vec<String>,
}

#[cfg(any(windows, test))]
fn resolve_windows_supported_launch_canary(
    system_root: &Path,
) -> std::io::Result<ResolvedWindowsRestrictedCanary> {
    let (executable, arguments) = WINDOWS_SUPPORTED_LAUNCH_CANARY
        .first()
        .ok_or_else(|| std::io::Error::other("supported launch canary is absent"))?;
    let program = system_root.join(executable);
    let metadata = fs::symlink_metadata(&program)?;
    let canonical = fs::canonicalize(&program)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || canonical != program {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "supported launch canary is not one canonical System32 file",
        ));
    }
    let imports = windows_pe_imports(&program).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("cannot inspect supported launch canary: {error}"),
        )
    })?;
    Ok(ResolvedWindowsRestrictedCanary {
        subsystem: "supported-launch",
        program,
        arguments: arguments.to_vec(),
        imports,
    })
}

#[cfg(any(windows, test))]
fn resolve_windows_restricted_target_canary(
    program: &Path,
) -> std::io::Result<ResolvedWindowsRestrictedCanary> {
    let metadata = fs::symlink_metadata(program)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "restricted-token target canary is not one direct file",
        ));
    }
    let imports = windows_pe_imports(program).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("cannot inspect restricted-token target canary: {error}"),
        )
    })?;
    Ok(ResolvedWindowsRestrictedCanary {
        subsystem: "staged-target",
        program: program.to_path_buf(),
        arguments: vec!["--version"],
        imports,
    })
}

#[cfg(any(windows, test))]
fn windows_restricted_canary_diagnostic(
    canary: &ResolvedWindowsRestrictedCanary,
    status: u32,
) -> String {
    format!(
        "restricted Windows token canary evidence: subsystem={},program={},imports={:?},status={status} (0x{status:08x})",
        canary.subsystem,
        bounded_windows_prelaunch_value(canary.program.as_os_str()),
        canary.imports,
    )
}

#[cfg(any(windows, test))]
fn windows_restricted_canary_failure(
    canary: &ResolvedWindowsRestrictedCanary,
    status: u32,
) -> Option<String> {
    (status != 0).then(|| {
        format!(
            "{}; supported Windows launch canary must exit successfully",
            windows_restricted_canary_diagnostic(canary, status)
        )
    })
}

#[cfg(windows)]
fn windows_restricted_canary_command_line(program: &Path, arguments: &[&str]) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;

    let mut command_line = vec![u16::from(b'"')];
    command_line.extend(program.as_os_str().encode_wide());
    command_line.push(u16::from(b'"'));
    for argument in arguments {
        command_line.push(u16::from(b' '));
        command_line.extend(argument.encode_utf16());
    }
    command_line.push(0);
    command_line
}

#[cfg(windows)]
struct WindowsRestrictedLaunchPlan {
    application: PathBuf,
    command_line: Vec<u16>,
}

#[cfg(windows)]
fn windows_restricted_canary_launch_plan(
    program: &Path,
    arguments: &[&str],
) -> WindowsRestrictedLaunchPlan {
    WindowsRestrictedLaunchPlan {
        application: program.to_path_buf(),
        command_line: windows_restricted_canary_command_line(program, arguments),
    }
}

#[cfg(windows)]
fn windows_restricted_child_launch_plan(
    launcher: &Path,
    target_token: &OsStr,
) -> WindowsRestrictedLaunchPlan {
    use std::os::windows::ffi::OsStrExt as _;

    WindowsRestrictedLaunchPlan {
        application: launcher.to_path_buf(),
        command_line: "hell-test-helper __release-argv-child "
            .encode_utf16()
            .chain(target_token.encode_wide())
            .chain(std::iter::once(0))
            .collect(),
    }
}

#[cfg(windows)]
fn windows_restricted_child(
    arguments: &[OsString],
    write_restricted: bool,
) -> std::io::Result<(u32, String)> {
    let [encoded] = arguments else {
        return Err(std::io::Error::other(
            "restricted child requires one encoded argv token",
        ));
    };
    let request =
        parse_windows_restricted_launch_request(hell_testkit::decode_windows_argv(encoded)?)?;
    let prelaunch_evidence = windows_parent_prelaunch_diagnostic(&request.target_arguments);
    let launcher = fs::canonicalize(&request.adapter)?;
    let metadata = fs::symlink_metadata(&request.adapter)?;
    if launcher != request.adapter
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || sha256_file(&launcher)? != request.adapter_sha256
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "restricted argv adapter identity changed",
        ));
    }
    let child_request = request.child_request.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restricted launch request has no typed child environment",
        )
    })?;
    let target_token = hell_testkit::encode_windows_argv(&child_request.fields()?)?;
    let mut launcher_plan = windows_restricted_child_launch_plan(&launcher, &target_token);
    let process_token = firehazard::open_process_token(
        firehazard::get_current_process(),
        firehazard::token::ALL_ACCESS,
    )?;
    let token = if write_restricted {
        windows_write_restricted_primary_token(&process_token)?
    } else {
        // The release-platform path has a separately staged filesystem authority.
        windows_duplicate_current_primary_token(&process_token)?
    };

    let job = firehazard::create_job_object_w(None, ())?;
    let limits = firehazard::job::object::ExtendedLimitInformation {
        basic_limit_information: firehazard::job::object::BasicLimitInformation {
            limit_flags: firehazard::job::object::limit::KILL_ON_JOB_CLOSE,
            ..Default::default()
        },
        ..Default::default()
    };
    firehazard::set_information_job_object(&job, limits)?;

    windows_restricted_graphical_binding_contract(WINDOWS_RESTRICTED_GRAPHICAL_BINDING)?;
    windows_restricted_stdio_contract(&WINDOWS_RESTRICTED_STDIO_HANDLES)?;
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("SystemRoot is absent"))?
        .join("System32");
    let system_root = fs::canonicalize(&system_root)?;
    let target_program = request
        .target_arguments
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("restricted target program is absent"))?;
    if target_program
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(OsStr::new("cargo.exe")))
    {
        let target_canary = resolve_windows_restricted_target_canary(&target_program)?;
        let mut target_canary_plan =
            windows_restricted_canary_launch_plan(&target_canary.program, &target_canary.arguments);
        let target_canary_status = windows_create_restricted_process(
            &token,
            &job,
            &target_canary_plan.application,
            &mut target_canary_plan.command_line,
        )?;
        if let Some(error) = windows_restricted_canary_failure(&target_canary, target_canary_status)
        {
            return Err(std::io::Error::other(error));
        }
    }

    let canary = resolve_windows_supported_launch_canary(&system_root)?;
    let mut canary_plan = windows_restricted_canary_launch_plan(&canary.program, &canary.arguments);
    let status = windows_create_restricted_process(
        &token,
        &job,
        &canary_plan.application,
        &mut canary_plan.command_line,
    )?;
    if let Some(error) = windows_restricted_canary_failure(&canary, status) {
        return Err(std::io::Error::other(error));
    }

    let status = windows_create_restricted_process(
        &token,
        &job,
        &launcher_plan.application,
        &mut launcher_plan.command_line,
    )?;
    drop(job);
    Ok((status, prelaunch_evidence))
}

#[cfg(windows)]
fn windows_create_restricted_process(
    token: &firehazard::token::OwnedHandle,
    job: &firehazard::job::OwnedHandle,
    application: &Path,
    command_line: &mut [u16],
) -> std::io::Result<u32> {
    let application =
        widestring::U16CString::from_os_str(application.as_os_str()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("restricted child path contains NUL: {error}"),
            )
        })?;
    let administrators = firehazard::convert_string_sid_to_sid_a("S-1-5-32-544")?;
    let system = firehazard::convert_string_sid_to_sid_a("S-1-5-18")?;
    let restricted_code = firehazard::convert_string_sid_to_sid_a("S-1-5-12")?;
    let owner_rights = firehazard::convert_string_sid_to_sid_a("S-1-3-4")?;
    let mut process_acl = firehazard::acl::Builder::new(firehazard::acl::REVISION);
    process_acl.add_access_denied_ace(
        firehazard::acl::REVISION,
        firehazard::access::GENERIC_ALL.into(),
        &owner_rights,
    )?;
    process_acl.add_access_denied_ace(
        firehazard::acl::REVISION,
        firehazard::access::GENERIC_ALL.into(),
        &restricted_code,
    )?;
    process_acl.add_access_allowed_ace(
        firehazard::acl::REVISION,
        firehazard::access::GENERIC_ALL.into(),
        &administrators,
    )?;
    process_acl.add_access_allowed_ace(
        firehazard::acl::REVISION,
        firehazard::access::GENERIC_ALL.into(),
        &system,
    )?;
    process_acl.finish()?;
    let process_security = firehazard::security::DescriptorBuilder::new()
        .owner(&*administrators, false)?
        .dacl(true, process_acl.as_acl_ptr(), false)?
        .finish();
    let process_attributes = firehazard::security::Attributes::new(Some(&process_security), false);
    let inheritable = firehazard::security::Attributes::new(None, true);
    let (stdin_read, stdin_write) = firehazard::io::create_pipe(Some(&inheritable), 0)?;
    let (stdout_read, stdout_write) = firehazard::io::create_pipe(Some(&inheritable), 0)?;
    let (stderr_read, stderr_write) = firehazard::io::create_pipe(Some(&inheritable), 0)?;
    firehazard::handle::set_handle_information(&stdin_write, firehazard::handle::FLAG_INHERIT, ())?;
    firehazard::handle::set_handle_information(&stdout_read, firehazard::handle::FLAG_INHERIT, ())?;
    firehazard::handle::set_handle_information(&stderr_read, firehazard::handle::FLAG_INHERIT, ())?;
    let inherited_handles = [
        (&stdin_read).into(),
        (&stdout_write).into(),
        (&stderr_write).into(),
    ];
    let assigned_jobs = [job.into()];
    let attributes = [
        firehazard::process::ThreadAttributeRef::handle_list(&inherited_handles),
        firehazard::process::ThreadAttributeRef::job_list(&assigned_jobs),
    ];
    let mut startup = firehazard::process::StartupInfoExW::default();
    startup.startup_info.desktop = None;
    startup.startup_info.flags = WINDOWS_STARTF_USE_STD_HANDLES;
    startup.startup_info.std_input = Some((&stdin_read).into());
    startup.startup_info.std_output = Some((&stdout_write).into());
    startup.startup_info.std_error = Some((&stderr_write).into());
    startup.attribute_list = Some(firehazard::process::ThreadAttributeList::try_from(
        attributes.as_slice(),
    )?);
    let process = firehazard::create_process_as_user_w(
        token,
        application,
        Some(command_line),
        Some(&process_attributes),
        None,
        true,
        firehazard::process::CREATE_SUSPENDED | firehazard::process::EXTENDED_STARTUPINFO_PRESENT,
        firehazard::process::environment::Inherit,
        (),
        &startup,
    )?;
    drop(startup);
    drop(stdin_read);
    drop(stdin_write);
    drop(stdout_write);
    drop(stderr_write);
    let stdout_relay = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        relay_windows_restricted_diagnostic(stdout_read, stdout.lock())
    });
    let stderr_relay = std::thread::spawn(move || {
        let stderr = std::io::stderr();
        relay_windows_restricted_diagnostic(stderr_read, stderr)
    });
    firehazard::thread::resume_thread(&process.thread)?;
    let status = firehazard::process::wait_for_process(&process.process)?;
    stdout_relay
        .join()
        .map_err(|_| std::io::Error::other("restricted stdout relay panicked"))??;
    stderr_relay
        .join()
        .map_err(|_| std::io::Error::other("restricted stderr relay panicked"))??;
    Ok(status)
}

#[cfg(unix)]
fn verify_native_archive_stack_package_authority_for_integration(
    base: &Path,
) -> Result<(), String> {
    let mut directory = create_adapter_directory(base)?;
    let result = (|| {
        prepare_adapter_work_directory(directory.path())?;
        let temporary = directory.path().join(".stack-work/tmp");
        let package = temporary.join("stack-deadbeef/Only-0.1");
        let source = package.join("src/deeper");
        let write = package.join(".stack-work/dist/aarch64-osx/ghc-9.8.2/build");
        fs::create_dir_all(&source)
            .map_err(|error| format!("cannot create Stack source-cwd fixture: {error}"))?;
        fs::create_dir_all(&write)
            .map_err(|error| format!("cannot create Stack write-authority fixture: {error}"))?;
        fs::write(write.join("member.o"), b"object\n")
            .map_err(|error| format!("cannot write Stack member fixture: {error}"))?;
        let relative_member =
            Path::new("../..").join(".stack-work/dist/aarch64-osx/ghc-9.8.2/build/member.o");
        use std::os::unix::ffi::OsStrExt as _;
        let mut response = relative_member.as_os_str().as_bytes().to_vec();
        response.push(b'\n');
        fs::write(source.join("objects.rsp"), response)
            .map_err(|error| format!("cannot write Stack response fixture: {error}"))?;
        let relative_target =
            Path::new("../..").join(".stack-work/dist/aarch64-osx/ghc-9.8.2/build/archive.a");
        let arguments = [
            OsString::from("q"),
            relative_target.clone().into_os_string(),
            OsString::from("@objects.rsp"),
        ];
        let normalized = normalize_native_archive_arguments_with_temporary_directory(
            &arguments,
            directory.path(),
            &source,
            Some(&temporary),
        )
        .map_err(|error| format!("cannot bind real Stack package topology: {error}"))?;
        if normalized
            != [
                OsString::from("qL"),
                relative_target.clone().into_os_string(),
                OsString::from("@objects.rsp"),
            ]
        {
            return Err("real Stack package archive normalization differs".to_owned());
        }
        let authority = native_archive_work_authority(
            directory.path(),
            &source,
            &source.join(&relative_target),
            Some(&temporary),
        )
        .map_err(|error| format!("cannot retain real Stack package topology: {error}"))?;
        if authority.read_root
            != fs::canonicalize(&package)
                .map_err(|error| format!("cannot canonicalize Stack package fixture: {error}"))?
            || authority.write_root
                != fs::canonicalize(package.join(".stack-work")).map_err(|error| {
                    format!("cannot canonicalize Stack write-authority fixture: {error}")
                })?
        {
            return Err("Stack package read/write authorities were not separated".to_owned());
        }

        let outside = temporary.join("stack-deadbeef/outside");
        fs::create_dir(&outside)
            .map_err(|error| format!("cannot create Stack escape fixture: {error}"))?;
        let target_escape = normalize_native_archive_arguments_with_temporary_directory(
            &[
                OsString::from("q"),
                outside.join("archive.a").into_os_string(),
                relative_member.clone().into_os_string(),
            ],
            directory.path(),
            &source,
            Some(&temporary),
        )
        .expect_err("a Stack archive target outside the package write authority must fail");
        if target_escape.to_string() != "archive adapter target escapes its bound work directory" {
            return Err(format!(
                "Stack target escape diagnostic differs: {target_escape}"
            ));
        }

        let other_package = temporary.join("stack-deadbeef/StateVar-1.2.2");
        fs::create_dir(&other_package)
            .map_err(|error| format!("cannot create cross-package fixture: {error}"))?;
        fs::write(other_package.join("member.o"), b"cross-package\n")
            .map_err(|error| format!("cannot write cross-package fixture: {error}"))?;
        let cross_package_member = Path::new("../../..")
            .join("StateVar-1.2.2")
            .join("member.o");
        let member_escape = normalize_native_archive_arguments_with_temporary_directory(
            &[
                OsString::from("q"),
                relative_target.clone().into_os_string(),
                cross_package_member.into_os_string(),
            ],
            directory.path(),
            &source,
            Some(&temporary),
        )
        .expect_err("a member from another Stack package must fail");
        if member_escape.to_string() != "archive member escapes its bound work directory" {
            return Err(format!(
                "Stack cross-package member diagnostic differs: {member_escape}"
            ));
        }

        let deadline_error = match bind_native_archive_invocation(
            &arguments,
            directory.path(),
            &source,
            Some(&temporary),
            Instant::now(),
        ) {
            Err(error) => error,
            Ok(_) => return Err("an expired Stack archive authority was accepted".to_owned()),
        };
        if deadline_error.kind() != std::io::ErrorKind::TimedOut
            || fs::symlink_metadata(source.join(&relative_target)).is_ok()
        {
            return Err("expired Stack archive binding did not fail without a target".to_owned());
        }

        let receipt_deadline = Instant::now()
            .checked_add(NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET)
            .ok_or_else(|| "Stack receipt mutation deadline overflowed".to_owned())?;
        let response_path = source.join("objects.rsp");
        let member_path = write.join("member.o");
        let response_bytes = fs::read(&response_path)
            .map_err(|error| format!("cannot retain Stack response fixture bytes: {error}"))?;
        let member_bytes = fs::read(&member_path)
            .map_err(|error| format!("cannot retain Stack member fixture bytes: {error}"))?;
        let response_receipt = bind_native_archive_invocation(
            &arguments,
            directory.path(),
            &source,
            Some(&temporary),
            receipt_deadline,
        )
        .map_err(|error| format!("cannot retain same-size Stack response fixture: {error}"))?;
        let mut changed_response = response_bytes.clone();
        let response_byte = changed_response
            .iter_mut()
            .find(|byte| byte.is_ascii_alphanumeric())
            .ok_or_else(|| "Stack response fixture has no mutable byte".to_owned())?;
        *response_byte = if *response_byte == b'z' { b'y' } else { b'z' };
        fs::write(&response_path, &changed_response)
            .map_err(|error| format!("cannot mutate Stack response fixture in place: {error}"))?;
        let response_mutation = response_receipt
            .revalidate_before_launch(receipt_deadline)
            .expect_err("a same-size in-place response mutation must fail before launch");
        if response_mutation.to_string() != "archive response file identity changed" {
            return Err(format!(
                "same-size Stack response mutation diagnostic differs: {response_mutation}"
            ));
        }
        fs::write(&response_path, &response_bytes)
            .map_err(|error| format!("cannot restore Stack response fixture: {error}"))?;

        let member_receipt = bind_native_archive_invocation(
            &arguments,
            directory.path(),
            &source,
            Some(&temporary),
            receipt_deadline,
        )
        .map_err(|error| format!("cannot retain same-size Stack member fixture: {error}"))?;
        let canonical_member_path = fs::canonicalize(&member_path).map_err(|error| {
            format!("cannot canonicalize Stack member mutation fixture: {error}")
        })?;
        let bound_member = member_receipt.authority.as_ref().and_then(|authority| {
            authority
                .inputs
                .iter()
                .find(|input| input.label == "archive member")
        });
        if bound_member.is_none_or(|input| input.path != canonical_member_path) {
            return Err(format!(
                "Stack member mutation fixture bound a different input: expected={} observed={}",
                canonical_member_path.display(),
                bound_member.map_or_else(
                    || "<absent>".to_owned(),
                    |input| input.path.display().to_string()
                )
            ));
        }
        let mut changed_member = member_bytes.clone();
        let member_byte = changed_member
            .first_mut()
            .ok_or_else(|| "Stack member fixture is empty".to_owned())?;
        *member_byte ^= 1;
        fs::write(&member_path, &changed_member)
            .map_err(|error| format!("cannot mutate Stack member fixture in place: {error}"))?;
        let member_mutation = member_receipt
            .revalidate_before_launch(receipt_deadline)
            .expect_err("a same-size in-place member mutation must fail before launch");
        if member_mutation.to_string() != "archive member identity changed" {
            return Err(format!(
                "same-size Stack member mutation diagnostic differs: {member_mutation}"
            ));
        }
        fs::write(&member_path, &member_bytes)
            .map_err(|error| format!("cannot restore Stack member fixture: {error}"))?;

        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let broker_root = directory.path().join(".authority/inputs");
            fs::create_dir_all(&broker_root)
                .map_err(|error| format!("cannot create Stack input broker fixture: {error}"))?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o2755))
                .map_err(|error| format!("cannot seal Stack adapter fixture: {error}"))?;
            fs::set_permissions(
                directory.path().join(".authority"),
                fs::Permissions::from_mode(0o555),
            )
            .map_err(|error| format!("cannot seal Stack authority fixture: {error}"))?;
            fs::set_permissions(&broker_root, fs::Permissions::from_mode(0o2710))
                .map_err(|error| format!("cannot confine Stack input broker fixture: {error}"))?;
            use std::os::unix::fs::MetadataExt as _;
            let candidate_uid = fs::metadata(&member_path)
                .map_err(|error| format!("cannot inspect Stack broker member: {error}"))?
                .uid();
            let mut broker = NativeArchiveInputBroker::start_with_limits(
                &broker_root,
                candidate_uid,
                NativeArchiveInputBrokerLimits::PRODUCTION,
                None,
                None,
            )?;
            let mut staged = bind_native_archive_invocation(
                &arguments,
                directory.path(),
                &source,
                Some(&temporary),
                receipt_deadline,
            )
            .map_err(|error| format!("cannot bind trusted Stack input fixture: {error}"))?;
            staged
                .stage_inputs_with_broker(directory.path(), receipt_deadline)
                .map_err(|error| format!("cannot stage trusted Stack input fixture: {error}"))?;
            let canonical_member = fs::canonicalize(&member_path)
                .map_err(|error| format!("cannot canonicalize Stack member fixture: {error}"))?;
            if staged.arguments.iter().any(|argument| {
                argument == OsStr::new("@objects.rsp") || Path::new(argument) == canonical_member
            }) {
                return Err(
                    "trusted Stack input staging retained a candidate response/member path"
                        .to_owned(),
                );
            }
            if staged.arguments.len() != 3
                || staged.arguments[0] != OsStr::new("qL")
                || Path::new(&staged.arguments[1]) != relative_target
                || !Path::new(&staged.arguments[2]).is_absolute()
            {
                return Err(format!(
                    "trusted Stack input staging changed flag or argv order: {:?}",
                    staged.arguments
                ));
            }
            let executed = CommandSpec::new("/usr/bin/ar", Duration::from_secs(30))
                .arguments(staged.arguments.clone())
                .current_directory(&source)
                .run()
                .map_err(|error| {
                    format!("cannot execute transformed Stack archive argv: {error}")
                })?;
            if !executed.status.success() || executed.timed_out {
                return Err(format!(
                    "transformed Stack archive argv failed: status={:?}; stderr={}",
                    executed.status.code(),
                    String::from_utf8_lossy(&executed.stderr)
                ));
            }
            staged
                .revalidate_after_launch(receipt_deadline)
                .map_err(|error| format!("transformed Stack archive receipt failed: {error}"))?;
            let archive_path = source.join(&relative_target);
            let listed = CommandSpec::new("/usr/bin/ar", Duration::from_secs(30))
                .argument("t")
                .argument(&archive_path)
                .current_directory(&source)
                .run()
                .map_err(|error| format!("cannot inspect transformed Stack archive: {error}"))?;
            if !listed.status.success()
                || listed.timed_out
                || String::from_utf8_lossy(&listed.stdout)
                    .lines()
                    .collect::<Vec<_>>()
                    != ["member.o"]
            {
                return Err(format!(
                    "transformed Stack archive contents differ: status={:?}; stdout={}; stderr={}",
                    listed.status.code(),
                    String::from_utf8_lossy(&listed.stdout),
                    String::from_utf8_lossy(&listed.stderr)
                ));
            }
            let request_roots_before =
                count_native_archive_request_roots(&broker_root, receipt_deadline)?;
            let mut identity = bind_native_archive_invocation(
                &[OsString::from("t"), relative_target.as_os_str().to_owned()],
                directory.path(),
                &source,
                Some(&temporary),
                receipt_deadline,
            )
            .map_err(|error| format!("cannot bind Stack archive identity query: {error}"))?;
            identity
                .stage_inputs_with_broker(directory.path(), receipt_deadline)
                .map_err(|error| format!("cannot stage Stack archive identity query: {error}"))?;
            let request_roots_after =
                count_native_archive_request_roots(&broker_root, receipt_deadline)?;
            if request_roots_after != request_roots_before {
                return Err(
                    "member-free Stack archive query connected to the staging broker".to_owned(),
                );
            }
            fs::write(&response_path, &changed_response)
                .map_err(|error| format!("cannot mutate staged Stack response source: {error}"))?;
            fs::write(&member_path, &changed_member)
                .map_err(|error| format!("cannot mutate staged Stack member source: {error}"))?;
            if staged.revalidate_before_launch(receipt_deadline).is_ok() {
                return Err(
                    "trusted Stack input staging accepted a post-stage candidate mutation"
                        .to_owned(),
                );
            }
            fs::write(&response_path, &response_bytes)
                .map_err(|error| format!("cannot restore staged Stack response source: {error}"))?;
            fs::write(&member_path, &member_bytes)
                .map_err(|error| format!("cannot restore staged Stack member source: {error}"))?;
            broker.close_until(receipt_deadline)?;
        }

        let invocation = bind_native_archive_invocation(
            &arguments,
            directory.path(),
            &source,
            Some(&temporary),
            receipt_deadline,
        )
        .map_err(|error| format!("cannot retain Stack mutation fixture: {error}"))?;
        fs::remove_file(&response_path)
            .map_err(|error| format!("cannot replace Stack response fixture: {error}"))?;
        fs::write(&response_path, b"replacement\n")
            .map_err(|error| format!("cannot install Stack response substitution: {error}"))?;
        let substitution = invocation
            .revalidate_before_launch(receipt_deadline)
            .expect_err("a replaced Stack response receipt must fail before launch");
        if substitution.to_string() != "archive response file identity changed" {
            return Err(format!(
                "Stack response substitution diagnostic differs: {substitution}"
            ));
        }

        use std::os::unix::fs::symlink;
        let redirected_package = temporary.join("stack-cafebabe/StateVar-1.2.2");
        let redirected_source = redirected_package.join("src");
        let redirected_write = directory.path().join("redirected-write");
        fs::create_dir_all(&redirected_source)
            .map_err(|error| format!("cannot create redirected Stack source: {error}"))?;
        fs::create_dir(&redirected_write)
            .map_err(|error| format!("cannot create redirected Stack write root: {error}"))?;
        symlink(&redirected_write, redirected_package.join(".stack-work"))
            .map_err(|error| format!("cannot redirect Stack write authority: {error}"))?;
        let redirected = normalize_native_archive_arguments_with_temporary_directory(
            &[
                OsString::from("q"),
                OsString::from("../.stack-work/archive.a"),
            ],
            directory.path(),
            &redirected_source,
            Some(&temporary),
        )
        .expect_err("a redirected Stack write authority must fail before launch");
        if redirected.to_string() != "Stack package archive write authority is redirected" {
            return Err(format!(
                "redirected Stack write-authority diagnostic differs: {redirected}"
            ));
        }
        Ok(())
    })();
    let cleanup = directory.close();
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; Stack archive authority verifier cleanup also failed: {cleanup}"
        )),
    }
}

#[cfg(unix)]
#[cfg(target_os = "macos")]
fn verify_native_archive_ghc_configure_broker_for_integration(
    adapter_root: &Path,
    configure_root: &Path,
    arguments: &[OsString],
    execution_deadline: Instant,
    command_completion_deadline: Instant,
    cleanup_deadline: Instant,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if Instant::now() >= execution_deadline
        || execution_deadline >= command_completion_deadline
        || command_completion_deadline >= cleanup_deadline
    {
        return Err("GHC configure execution, command-completion, and broker-cleanup deadlines are not ordered".to_owned());
    }
    let authority_root = adapter_root.join(".authority");
    let staging_root = authority_root.join("inputs");
    fs::create_dir(&authority_root)
        .and_then(|()| fs::create_dir(&staging_root))
        .map_err(|error| format!("cannot create GHC configure broker authority: {error}"))?;
    fs::set_permissions(adapter_root, fs::Permissions::from_mode(0o2755))
        .and_then(|()| fs::set_permissions(&authority_root, fs::Permissions::from_mode(0o555)))
        .and_then(|()| fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o2710)))
        .map_err(|error| format!("cannot seal GHC configure broker authority: {error}"))?;
    let candidate_uid = fs::metadata(configure_root.join("conftest.o"))
        .map_err(|error| format!("cannot inspect GHC configure broker member: {error}"))?
        .uid();
    let mut broker = NativeArchiveInputBroker::start_with_limits(
        &staging_root,
        candidate_uid,
        NativeArchiveInputBrokerLimits::PRODUCTION,
        None,
        None,
    )?;
    let primary = (|| {
        let mut invocation = bind_native_archive_invocation(
            arguments,
            adapter_root,
            configure_root,
            Some(configure_root),
            execution_deadline,
        )
        .map_err(|error| format!("cannot bind sealed GHC configure probe: {error}"))?;
        let original = invocation
            .authority
            .as_ref()
            .and_then(|authority| authority.inputs.first())
            .map(|receipt| (receipt.sha256, receipt.size))
            .ok_or_else(|| "sealed GHC configure member receipt is absent".to_owned())?;
        invocation
            .stage_inputs_with_broker(adapter_root, execution_deadline)
            .map_err(|error| format!("cannot stage sealed GHC configure member: {error}"))?;
        let staged_member = Path::new(&invocation.arguments[2]);
        let staged_receipt = invocation
            .authority
            .as_ref()
            .and_then(|authority| authority.inputs.last())
            .ok_or_else(|| "trusted GHC configure member receipt is absent".to_owned())?;
        if invocation.arguments[0] != OsStr::new("qclsL")
            || invocation.arguments[1] != OsStr::new("conftest.a")
            || !staged_member.is_absolute()
            || !staged_member.starts_with(&staging_root)
            || (staged_receipt.sha256, staged_receipt.size) != original
        {
            return Err("sealed GHC configure probe argv or receipt differs".to_owned());
        }
        let executed = run_ghc_configure_archiver_until(
            CommandSpec::new("/usr/bin/ar", Duration::from_secs(30))
                .arguments(invocation.arguments.clone())
                .current_directory(configure_root),
            execution_deadline,
            command_completion_deadline,
            "execute sealed GHC configure probe",
        )?;
        if !executed.status.success() || executed.timed_out {
            return Err(format!(
                "sealed GHC configure probe failed: status={:?}; stderr={}",
                executed.status.code(),
                String::from_utf8_lossy(&executed.stderr)
            ));
        }
        invocation
            .revalidate_after_launch(execution_deadline)
            .map_err(|error| format!("sealed GHC configure postflight failed: {error}"))?;
        let listed = run_ghc_configure_archiver_until(
            CommandSpec::new("/usr/bin/ar", Duration::from_secs(30))
                .arguments(["t", "conftest.a"])
                .current_directory(configure_root),
            execution_deadline,
            command_completion_deadline,
            "inspect sealed GHC configure archive",
        )?;
        if !listed.status.success()
            || listed.timed_out
            || String::from_utf8_lossy(&listed.stdout)
                .lines()
                .collect::<Vec<_>>()
                != ["__.SYMDEF SORTED", "conftest.o"]
        {
            return Err(format!(
                "sealed GHC configure archive contents differ: status={:?}; stdout={}; stderr={}",
                listed.status.code(),
                String::from_utf8_lossy(&listed.stdout),
                String::from_utf8_lossy(&listed.stderr)
            ));
        }
        verify_ghc_configure_hung_archiver_cleanup(
            configure_root,
            execution_deadline,
            command_completion_deadline,
        )?;
        Ok(())
    })();
    let broker_cleanup = broker.close_until(cleanup_deadline);
    let authority_cleanup = if broker.closed {
        fs::set_permissions(&staging_root, fs::Permissions::from_mode(0o700))
            .and_then(|()| fs::set_permissions(&authority_root, fs::Permissions::from_mode(0o700)))
            .and_then(|()| fs::set_permissions(adapter_root, fs::Permissions::from_mode(0o700)))
            .map_err(|error| format!("cannot unseal GHC configure broker fixture: {error}"))
    } else {
        Err("GHC configure broker retains its sealed authority".to_owned())
    };
    let mut failures = Vec::new();
    if let Err(error) = primary {
        failures.push(error);
    }
    if let Err(error) = broker_cleanup {
        failures.push(format!("GHC configure broker cleanup: {error}"));
    }
    if let Err(error) = authority_cleanup {
        failures.push(error);
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(unix)]
#[cfg(target_os = "macos")]
fn verify_ghc_configure_hung_archiver_cleanup(
    configure_root: &Path,
    execution_deadline: Instant,
    command_completion_deadline: Instant,
) -> Result<(), String> {
    let receipt_path = configure_root.join("hung-archiver.pid");
    let started = Instant::now();
    let hung_execution_deadline = started
        .checked_add(Duration::from_secs(1))
        .map_or(execution_deadline, |deadline| {
            deadline.min(execution_deadline)
        });
    let hung_completion_deadline = started
        .checked_add(Duration::from_secs(3))
        .map_or(command_completion_deadline, |deadline| {
            deadline.min(command_completion_deadline)
        });
    let executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate hung GHC configure fixture: {error}"))?,
    )
    .map_err(|error| format!("cannot bind hung GHC configure fixture: {error}"))?;
    let result = run_ghc_configure_archiver_until(
        CommandSpec::new(executable, NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET)
            .arguments([
                "__native-archive-ghc-configure-hung-child",
                receipt_path
                    .to_str()
                    .ok_or_else(|| "hung GHC configure receipt path is not UTF-8".to_owned())?,
            ])
            .current_directory(configure_root),
        hung_execution_deadline,
        hung_completion_deadline,
        "execute hung GHC configure cleanup fixture",
    )?;
    if !result.timed_out {
        return Err("hung GHC configure fixture did not exhaust its execution cutoff".to_owned());
    }
    let pid = fs::read_to_string(&receipt_path)
        .map_err(|error| format!("cannot read hung GHC configure process receipt: {error}"))?
        .parse::<i32>()
        .map_err(|error| format!("hung GHC configure process receipt is invalid: {error}"))?;
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
        Err(nix::errno::Errno::ESRCH) => {}
        Ok(()) => return Err("hung GHC configure process remains live after cleanup".to_owned()),
        Err(error) => {
            return Err(format!(
                "cannot attest hung GHC configure process absence: {error}"
            ));
        }
    }
    fs::remove_file(&receipt_path)
        .map_err(|error| format!("cannot remove hung GHC configure process receipt: {error}"))
}

#[cfg(unix)]
#[cfg(target_os = "macos")]
fn run_ghc_configure_archiver_until(
    command: CommandSpec,
    execution_deadline: Instant,
    command_completion_deadline: Instant,
    phase: &str,
) -> Result<CommandResult, String> {
    if Instant::now() >= execution_deadline {
        return Err(format!(
            "cannot {phase}: GHC configure execution deadline expired before launch"
        ));
    }
    if execution_deadline >= command_completion_deadline {
        return Err(format!(
            "cannot {phase}: GHC configure execution and command-completion deadlines are not ordered"
        ));
    }
    let (progress, _receiver) = SupervisedProgressObserver::bounded(1);
    command
        .run_until(execution_deadline, command_completion_deadline, progress)
        .map_err(|error| format!("cannot {phase}: {error}"))
}

#[cfg(target_os = "macos")]
pub(crate) fn run_native_archive_ghc_configure_hung_child_for_integration(
    arguments: &[OsString],
) -> Result<(), String> {
    let [receipt_path] = arguments else {
        return Err("hung GHC configure fixture requires one process receipt".to_owned());
    };
    let mut receipt = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipt_path)
        .map_err(|error| format!("cannot create hung GHC configure process receipt: {error}"))?;
    receipt
        .write_all(std::process::id().to_string().as_bytes())
        .and_then(|()| receipt.sync_all())
        .map_err(|error| format!("cannot persist hung GHC configure process receipt: {error}"))?;
    loop {
        std::thread::yield_now();
    }
}

#[cfg(unix)]
pub(crate) fn verify_native_archive_ghc_configure_probe_for_integration(
    base: &Path,
) -> Result<(), String> {
    let base = fs::canonicalize(base)
        .map_err(|error| format!("cannot bind GHC configure fixture parent: {error}"))?;
    let fixture = base.join("ghc-configure-probe");
    if fs::symlink_metadata(&fixture).is_ok() {
        return Err("GHC configure probe fixture path is already occupied".to_owned());
    }
    fs::create_dir(&fixture)
        .map_err(|error| format!("cannot create GHC configure probe fixture: {error}"))?;
    let primary = (|| {
        let configure_root = fixture.join("configure-root");
        fs::create_dir(fixture.join(".stack-work"))
            .and_then(|()| fs::create_dir(&configure_root))
            .map_err(|error| format!("cannot create GHC configure probe root: {error}"))?;
        let configure = configure_root.join("configure");
        let member = configure_root.join("conftest.o");
        let target = configure_root.join("conftest.a");
        fs::write(&configure, b"configure marker\n")
            .map_err(|error| format!("cannot write GHC configure marker: {error}"))?;
        fs::write(&member, b"object marker\n")
            .map_err(|error| format!("cannot write GHC configure member: {error}"))?;
        let cleanup_deadline = Instant::now()
            .checked_add(NATIVE_ARCHIVE_ADAPTER_COMPLETION_BUDGET)
            .ok_or_else(|| "GHC configure probe deadline overflowed".to_owned())?;
        let command_completion_deadline = cleanup_deadline
            .checked_sub(NATIVE_ARCHIVE_ADAPTER_CLEANUP_RESERVE)
            .ok_or_else(|| "GHC configure probe cleanup reserve underflowed".to_owned())?;
        let execution_deadline = command_completion_deadline
            .checked_sub(NATIVE_ARCHIVE_ADAPTER_CLEANUP_RESERVE)
            .ok_or_else(|| {
                "GHC configure probe command-completion reserve underflowed".to_owned()
            })?;
        let arguments = [
            OsString::from("clqs"),
            OsString::from("conftest.a"),
            OsString::from("conftest.o"),
        ];
        let invocation = bind_native_archive_invocation(
            &arguments,
            &fixture,
            &configure_root,
            Some(&configure_root),
            execution_deadline,
        )
        .map_err(|error| format!("cannot bind exact GHC configure probe: {error}"))?;
        if invocation.arguments
            != [
                OsString::from("qclsL"),
                OsString::from("conftest.a"),
                OsString::from("conftest.o"),
            ]
            || invocation.input_groups.len() != 1
            || invocation.input_groups[0].argument_index != 2
            || invocation.input_groups[0].input_indices != [0]
        {
            return Err("GHC configure probe normalized argv topology differs".to_owned());
        }
        let authority = invocation
            .authority
            .as_ref()
            .ok_or_else(|| "GHC configure probe retained authority is absent".to_owned())?;
        let canonical_root = fs::canonicalize(&configure_root)
            .map_err(|error| format!("cannot bind GHC configure root: {error}"))?;
        let canonical_member = fs::canonicalize(&member)
            .map_err(|error| format!("cannot bind GHC configure member: {error}"))?;
        let pending_target = canonical_root.join("conftest.a");
        if authority.read_root != canonical_root
            || authority.write_root != canonical_root
            || authority.inputs.len() != 1
            || authority.inputs[0].label != "archive member"
            || authority.inputs[0].path != canonical_member
            || !authority.targets.is_empty()
            || authority.pending_targets != [pending_target]
        {
            return Err("GHC configure probe retained path authority differs".to_owned());
        }
        invocation
            .revalidate_before_launch(execution_deadline)
            .map_err(|error| format!("GHC configure probe receipt failed: {error}"))?;

        #[cfg(target_os = "macos")]
        verify_native_archive_ghc_configure_broker_for_integration(
            &fixture,
            &configure_root,
            &arguments,
            execution_deadline,
            command_completion_deadline,
            cleanup_deadline,
        )?;

        #[cfg(target_os = "macos")]
        {
            let expired_target = configure_root.join("expired.a");
            let expired = run_ghc_configure_archiver_until(
                CommandSpec::new("/usr/bin/ar", Duration::from_secs(30))
                    .arguments(["q", "expired.a", "conftest.o"])
                    .current_directory(&configure_root),
                Instant::now(),
                command_completion_deadline,
                "execute expired GHC configure probe",
            )
            .expect_err("expired GHC configure execution must fail before launch");
            if !expired.contains("deadline expired before launch") || expired_target.exists() {
                return Err("expired GHC configure probe launched late archiver work".to_owned());
            }
        }

        if !target.exists() {
            fs::write(&target, b"existing archive\n")
                .map_err(|error| format!("cannot create existing GHC probe target: {error}"))?;
        }
        let existing = match bind_native_archive_invocation(
            &arguments,
            &fixture,
            &configure_root,
            Some(&configure_root),
            execution_deadline,
        ) {
            Ok(_) => return Err("an existing GHC configure target was accepted".to_owned()),
            Err(error) => error.to_string(),
        };
        if existing != "GHC configure archive probe target already exists" {
            return Err(format!(
                "existing GHC probe target diagnostic differs: {existing}"
            ));
        }
        fs::remove_file(&target)
            .map_err(|error| format!("cannot remove existing GHC probe target: {error}"))?;

        fs::remove_file(&member)
            .map_err(|error| format!("cannot remove GHC configure member: {error}"))?;
        let missing = match bind_native_archive_invocation(
            &arguments,
            &fixture,
            &configure_root,
            Some(&configure_root),
            execution_deadline,
        ) {
            Ok(_) => return Err("a missing GHC configure member was accepted".to_owned()),
            Err(error) => error.to_string(),
        };
        if missing != "GHC configure archive probe fixture is not a regular real file" {
            return Err(format!(
                "missing GHC probe member diagnostic differs: {missing}"
            ));
        }
        fs::write(&member, b"object marker\n")
            .map_err(|error| format!("cannot restore GHC configure member: {error}"))?;

        let near_match = match bind_native_archive_invocation(
            &[
                OsString::from("clqs"),
                OsString::from("conftest.a"),
                OsString::from("member.o"),
            ],
            &fixture,
            &configure_root,
            Some(&configure_root),
            execution_deadline,
        ) {
            Ok(_) => {
                return Err("a near-match GHC configure probe gained direct authority".to_owned());
            }
            Err(error) => error.to_string(),
        };
        if near_match != "archive adapter temporary authority differs from its bound directory" {
            return Err(format!(
                "near-match GHC probe diagnostic differs: {near_match}"
            ));
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&fixture)
        .map_err(|error| format!("cannot clean GHC configure probe fixture: {error}"));
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; GHC configure probe cleanup also failed: {cleanup}"
        )),
    }
}

#[cfg(unix)]
pub(crate) fn verify_native_archive_policy_for_integration() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    verify_native_archive_feature_probe_policy()?;
    #[cfg(target_os = "macos")]
    verify_native_archive_identity_policy()?;

    let source = Path::new("oracle-source");
    let stack_yaml = Path::new("stack.yaml");
    let build = native_stack_build(source, stack_yaml, Duration::from_secs(1));
    if build.display_arguments()
        != [
            "--lock-file",
            "error-on-write",
            "--stack-yaml",
            "stack.yaml",
            "build",
        ]
        || build.current_directory.as_deref() != Some(source)
    {
        return Err(
            "native Stack build command does not retain its exact global options".to_owned(),
        );
    }
    let path = native_stack_path(source, stack_yaml);
    if path.display_arguments()
        != [
            "--lock-file",
            "error-on-write",
            "--stack-yaml",
            "stack.yaml",
            "path",
            "--local-install-root",
        ]
        || path.current_directory.as_deref() != Some(source)
    {
        return Err(
            "native Stack path command does not retain its exact global options".to_owned(),
        );
    }
    let ghc = native_stack_ghc_version(source, stack_yaml);
    if ghc.display_arguments()
        != [
            "--lock-file",
            "error-on-write",
            "--stack-yaml",
            "stack.yaml",
            "exec",
            "--",
            "ghc",
            "--numeric-version",
        ]
        || ghc.current_directory.as_deref() != Some(source)
    {
        return Err("native Stack GHC command does not retain its exact global options".to_owned());
    }
    let adapter_root = Path::new("/fixed/adapter");
    let adapter = NativeArchiveAdapter {
        _directory: None,
        bound_toolchain: None,
        llvm_ar: None,
        llvm_ar_version: None,
        path: None,
        stack_yaml: Some(adapter_root.join("stack.yaml")),
        temporary_directory: None,
        #[cfg(target_os = "macos")]
        input_broker: None,
    };
    if adapter
        .stack_build(source, Duration::from_secs(1))
        .current_directory
        .as_deref()
        != Some(adapter_root)
        || adapter.stack_path(source).current_directory.as_deref() != Some(adapter_root)
        || adapter
            .stack_ghc_version(source)
            .current_directory
            .as_deref()
            != Some(adapter_root)
    {
        return Err("native Stack adapter commands escaped the configured adapter root".to_owned());
    }

    let adapter = NativeArchiveAdapter {
        _directory: None,
        bound_toolchain: None,
        llvm_ar: None,
        llvm_ar_version: None,
        path: Some(OsString::from("/confined/path")),
        stack_yaml: None,
        temporary_directory: Some(PathBuf::from("/confined/tmp")),
        #[cfg(target_os = "macos")]
        input_broker: None,
    };
    let spec = adapter.apply(CommandSpec::new("program", Duration::from_secs(1)));
    if spec.environment
        != [
            (OsString::from("PATH"), OsString::from("/confined/path")),
            (OsString::from("TMPDIR"), OsString::from("/confined/tmp")),
        ]
        || spec
            .environment
            .iter()
            .any(|(name, _)| name == "AR" || name == "LD")
    {
        return Err("native archive adapter environment is not exactly confined".to_owned());
    }
    let clqs_root = std::env::temp_dir().join(format!(
        "hell-native-archive-policy-clqs-{}-{}",
        std::process::id(),
        ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let clqs_result = (|| {
        let work = clqs_root.join(".stack-work");
        fs::create_dir_all(&work)
            .map_err(|error| format!("cannot create CLQS verifier fixture: {error}"))?;
        fs::write(work.join("objects.rsp"), b"member.o\n")
            .map_err(|error| format!("cannot write CLQS response file: {error}"))?;
        fs::write(work.join("member.o"), b"object\n")
            .map_err(|error| format!("cannot write CLQS member: {error}"))?;
        let normalized = normalize_native_archive_arguments(
            &[
                OsString::from("clqs"),
                OsString::from("archive.a"),
                OsString::from("@objects.rsp"),
            ],
            &clqs_root,
            &work,
        )
        .map_err(|error| format!("cannot normalize CLQS archive arguments: {error}"))?;
        if normalized
            != [
                OsString::from("qclsL"),
                OsString::from("archive.a"),
                OsString::from("@objects.rsp"),
            ]
        {
            return Err("native archive CLQS normalization differs from policy".to_owned());
        }
        Ok(())
    })();
    let clqs_cleanup = fs::remove_dir_all(&clqs_root)
        .map_err(|error| format!("cannot remove CLQS verifier fixture: {error}"));
    clqs_result.and(clqs_cleanup)?;

    let provenance_root = std::env::temp_dir().join(format!(
        "hell-native-stack-policy-provenance-{}-{}",
        std::process::id(),
        ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let provenance_result = (|| {
        let source = provenance_root.join("oracle-source");
        fs::create_dir_all(&source)
            .map_err(|error| format!("cannot create Stack provenance fixture: {error}"))?;
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .map_err(|error| format!("cannot write Stack provenance configuration: {error}"))?;
        fs::write(
            source.join("stack.yaml.lock"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock"),
        )
        .map_err(|error| format!("cannot write Stack provenance lock: {error}"))?;
        let adapter = NativeArchiveAdapter {
            _directory: None,
            bound_toolchain: None,
            llvm_ar: None,
            llvm_ar_version: None,
            path: None,
            stack_yaml: None,
            temporary_directory: None,
            #[cfg(target_os = "macos")]
            input_broker: None,
        };
        let provenance = adapter.stack_provenance(&source)?;
        if provenance.effective_stack_yaml
            != fs::canonicalize(source.join("stack.yaml"))
                .map_err(|error| format!("cannot canonicalize Stack provenance fixture: {error}"))?
            || provenance.effective_stack_yaml_sha256
                != sha256_file(&source.join("stack.yaml"))
                    .map_err(|error| format!("cannot hash Stack provenance fixture: {error}"))?
        {
            return Err("relative Stack configuration provenance was not source-scoped".to_owned());
        }
        Ok(())
    })();
    let provenance_cleanup = fs::remove_dir_all(&provenance_root)
        .map_err(|error| format!("cannot remove Stack provenance fixture: {error}"));
    provenance_result.and(provenance_cleanup)?;

    let overlay_root = std::env::temp_dir().join(format!(
        "hell-native-stack-policy-overlay-{}-{}'s-base",
        std::process::id(),
        ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let overlay_result = (|| {
        let source = overlay_root.join("oracle's source");
        fs::create_dir_all(&source)
            .map_err(|error| format!("cannot create Stack overlay fixture: {error}"))?;
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .map_err(|error| format!("cannot write Stack overlay configuration: {error}"))?;
        fs::write(
            source.join("stack.yaml.lock"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock"),
        )
        .map_err(|error| format!("cannot write Stack overlay lock: {error}"))?;
        #[cfg(target_os = "macos")]
        let mut directory = create_adapter_directory(&overlay_root)?;
        #[cfg(not(target_os = "macos"))]
        let directory = create_adapter_directory(&overlay_root)?;
        let ghc_bin = directory.path().join(".toolchain/system-ghc-9.8.2/bin");
        fs::create_dir_all(&ghc_bin)
            .map_err(|error| format!("cannot create Stack overlay GHC bin: {error}"))?;
        let overlay = write_native_stack_overlay(directory.path(), &source, &ghc_bin)?;
        let content = fs::read_to_string(&overlay)
            .map_err(|error| format!("cannot read Stack overlay: {error}"))?;
        let canonical_adapter = fs::canonicalize(directory.path())
            .map_err(|error| format!("cannot canonicalize Stack overlay adapter: {error}"))?;
        let adapter_yaml = format!(
            "'{}'",
            canonical_adapter.display().to_string().replace('\'', "''")
        );
        let configure_ar = format!(
            "'--with-ar={}'",
            canonical_adapter
                .join("ar")
                .display()
                .to_string()
                .replace('\'', "''")
        );
        let ghc_bin_yaml = yaml_single_quoted_path(
            &fs::canonicalize(&ghc_bin)
                .map_err(|error| format!("cannot canonicalize Stack overlay GHC bin: {error}"))?,
        )?;
        if !content.starts_with("resolver: nightly-2024-10-21\npackages:\n")
            || !content.contains("oracle''s source'\n")
            || !content.contains(
                "system-ghc: true\ninstall-ghc: false\ncompiler-check: match-exact\nallow-different-user: true\n",
            )
            || !content.contains(&format!(
                "extra-path:\n  - {adapter_yaml}\n  - {ghc_bin_yaml}\nconfigure-options:\n  \"$everything\":\n    - {configure_ar}\nghc-options:\n"
            ))
            || content.contains("extra-prog-path")
            || !content.contains("  \"$everything\": \"-split-sections -j\"\n")
            || !content.contains("  unix-time: \"-optl-all_load\"\n")
            || !content.contains("  network-control: \"-fforce-recomp\"\n")
            || content.matches("all_load").count() != 1
            || content.matches("network-control").count() != 1
            || content.matches("-fforce-recomp").count() != 1
            || content.contains("apply-ghc-options")
            || fs::read(directory.path().join("stack.yaml.lock"))
                .map_err(|error| format!("cannot read copied Stack lock: {error}"))?
                != include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock")
        {
            return Err("native Stack overlay differs from its exact policy".to_owned());
        }
        fs::write(source.join("stack.yaml"), b"resolver: changed\n")
            .map_err(|error| format!("cannot mutate Stack overlay source: {error}"))?;
        if !write_native_stack_overlay(directory.path(), &source, &ghc_bin)
            .unwrap_err()
            .contains("configuration differs")
        {
            return Err("native Stack overlay accepted changed configuration".to_owned());
        }
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .map_err(|error| format!("cannot restore Stack overlay configuration: {error}"))?;
        fs::write(source.join("stack.yaml.lock"), b"snapshots: []\n")
            .map_err(|error| format!("cannot mutate Stack overlay lock: {error}"))?;
        if !write_native_stack_overlay(directory.path(), &source, &ghc_bin)
            .unwrap_err()
            .contains("lock differs")
        {
            return Err("native Stack overlay accepted changed lock".to_owned());
        }
        #[cfg(target_os = "macos")]
        {
            let cleanup_deadline = Instant::now()
                .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
                .ok_or_else(|| "Stack overlay cleanup deadline overflowed".to_owned())?;
            directory.close_until(cleanup_deadline)?;
        }
        #[cfg(not(target_os = "macos"))]
        drop(directory);
        if overlay.parent().is_some_and(Path::exists) {
            return Err("native Stack overlay fixture survived adapter cleanup".to_owned());
        }
        Ok(())
    })();
    let overlay_cleanup = fs::remove_dir_all(&overlay_root)
        .map_err(|error| format!("cannot remove Stack overlay fixture: {error}"));
    overlay_result.and(overlay_cleanup)?;

    let path_root = std::env::temp_dir().join(format!(
        "hell-native-archive-policy-path-{}-{}",
        std::process::id(),
        ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let path_result = (|| {
        let adapter = path_root.join("adapter");
        let stack_bin = path_root.join("stack/bin");
        let ghc_bin = path_root.join("ghc/bin");
        for directory in [&adapter, &stack_bin, &ghc_bin] {
            fs::create_dir_all(directory)
                .map_err(|error| format!("cannot create archive PATH fixture: {error}"))?;
        }
        let joined = native_archive_path(&adapter, &stack_bin, &ghc_bin)?;
        if std::env::split_paths(&joined).collect::<Vec<_>>()
            != [
                adapter,
                stack_bin,
                ghc_bin,
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin"),
            ]
        {
            return Err("native archive PATH inherited or reordered an entry".to_owned());
        }
        Ok(())
    })();
    let path_cleanup = fs::remove_dir_all(&path_root)
        .map_err(|error| format!("cannot remove archive PATH fixture: {error}"));
    path_result.and(path_cleanup)?;

    let inventory_root = std::env::temp_dir().join(format!(
        "hell-native-archive-policy-inventory-{}-{}",
        std::process::id(),
        ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let inventory_result = (|| {
        let source = inventory_root.join("source");
        fs::create_dir_all(&source)
            .map_err(|error| format!("cannot create archive inventory source: {error}"))?;
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .map_err(|error| format!("cannot write archive inventory configuration: {error}"))?;
        fs::write(
            source.join("stack.yaml.lock"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock"),
        )
        .map_err(|error| format!("cannot write archive inventory lock: {error}"))?;
        #[cfg(target_os = "macos")]
        let mut directory = create_adapter_directory(&inventory_root)?;
        #[cfg(not(target_os = "macos"))]
        let directory = create_adapter_directory(&inventory_root)?;
        let adapter = directory.path().to_owned();
        prepare_adapter_work_directory(&adapter)?;
        let confined_launcher = inventory_root.join("confined-launcher");
        fs::write(&confined_launcher, b"bound executable\n")
            .map_err(|error| format!("cannot write archive inventory executable: {error}"))?;
        fs::set_permissions(&confined_launcher, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot set archive inventory executable mode: {error}"))?;
        #[cfg(target_os = "macos")]
        let llvm_ar = {
            let bin = inventory_root.join("llvm-prefix").join("bin");
            fs::create_dir_all(&bin)
                .map_err(|error| format!("cannot create archive inventory LLVM bin: {error}"))?;
            let llvm_ar = bin.join("llvm-ar");
            fs::copy(
                std::env::current_exe().map_err(|error| {
                    format!("cannot locate archive inventory executable: {error}")
                })?,
                &llvm_ar,
            )
            .map_err(|error| format!("cannot copy archive inventory executable: {error}"))?;
            fs::set_permissions(&llvm_ar, fs::Permissions::from_mode(0o755)).map_err(|error| {
                format!("cannot set archive inventory executable mode: {error}")
            })?;
            llvm_ar
        };
        #[cfg(not(target_os = "macos"))]
        let llvm_ar = {
            let llvm_ar = inventory_root.join("reviewed-llvm-ar");
            fs::write(&llvm_ar, b"bound executable\n")
                .map_err(|error| format!("cannot write archive inventory executable: {error}"))?;
            fs::set_permissions(&llvm_ar, fs::Permissions::from_mode(0o755)).map_err(|error| {
                format!("cannot set archive inventory executable mode: {error}")
            })?;
            llvm_ar
        };
        #[cfg(target_os = "macos")]
        let staged_archiver = {
            let transaction = NativeArchiverTransaction::new()?;
            let acquired = acquire_native_archiver_candidate(&llvm_ar, &transaction)?;
            install_staged_native_archive_adapter(
                &adapter,
                &confined_launcher,
                &acquired,
                &transaction,
            )?
        };
        #[cfg(not(target_os = "macos"))]
        install_native_archive_adapter(&adapter, &confined_launcher, &llvm_ar)?;
        let ghc_bin = adapter.join(".toolchain/system-ghc-9.8.2/bin");
        fs::create_dir_all(&ghc_bin)
            .map_err(|error| format!("cannot create archive inventory GHC bin: {error}"))?;
        let overlay = write_native_stack_overlay(&adapter, &source, &ghc_bin)?;
        let mut entries = fs::read_dir(&adapter)
            .map_err(|error| format!("cannot enumerate archive adapter inventory: {error}"))?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot inspect archive adapter inventory: {error}"))?;
        entries.sort();
        let authority = adapter.join(".authority");
        let mut authority_entries = fs::read_dir(&authority)
            .map_err(|error| format!("cannot enumerate archive authority inventory: {error}"))?
            .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot inspect archive authority inventory: {error}"))?;
        authority_entries.sort();
        #[cfg(target_os = "macos")]
        let expected_authority_entries = ["inputs".to_owned(), "llvm".to_owned()];
        #[cfg(not(target_os = "macos"))]
        let expected_authority_entries = ["llvm-ar".to_owned()];
        let overlay_content = fs::read_to_string(&overlay)
            .map_err(|error| format!("cannot read archive inventory overlay: {error}"))?;
        if entries
            != [
                ".authority".to_owned(),
                ".stack-work".to_owned(),
                ".toolchain".to_owned(),
                "ar".to_owned(),
                "stack.yaml".to_owned(),
                "stack.yaml.lock".to_owned(),
            ]
            || fs::symlink_metadata(adapter.join("llvm-ar")).is_ok()
            || !fs::symlink_metadata(adapter.join("ar"))
                .map_err(|error| format!("cannot inspect archive launcher: {error}"))?
                .file_type()
                .is_symlink()
            || fs::canonicalize(adapter.join("ar"))
                .map_err(|error| format!("cannot canonicalize archive launcher: {error}"))?
                != fs::canonicalize(&confined_launcher)
                    .map_err(|error| format!("cannot canonicalize confined launcher: {error}"))?
            || fs::metadata(&authority)
                .map_err(|error| format!("cannot inspect archive authority: {error}"))?
                .permissions()
                .mode()
                & 0o7777
                != 0o555
            || authority_entries != expected_authority_entries
            || {
                #[cfg(target_os = "macos")]
                {
                    staged_archiver.revalidate().is_err()
                        || staged_archiver.path()
                            != authority.join("llvm").join("bin").join("llvm-ar")
                        || fs::symlink_metadata(staged_archiver.path())
                            .map_err(|error| {
                                format!("cannot inspect staged archive authority: {error}")
                            })?
                            .file_type()
                            .is_symlink()
                        || staged_archiver.sha256
                            != sha256_file(&llvm_ar).map_err(|error| {
                                format!("cannot hash reviewed archiver: {error}")
                            })?
                }
                #[cfg(not(target_os = "macos"))]
                {
                    fs::canonicalize(authority.join("llvm-ar")).map_err(|error| {
                        format!("cannot canonicalize archive authority: {error}")
                    })? != fs::canonicalize(&llvm_ar).map_err(|error| {
                        format!("cannot canonicalize reviewed archiver: {error}")
                    })?
                }
            }
            || !overlay_content.contains("extra-path:\n")
            || overlay_content.contains("extra-prog-path")
            || !overlay_content.contains("configure-options:\n")
            || !overlay_content.contains("--with-ar=")
        {
            return Err("native archive adapter inventory is not exactly closed".to_owned());
        }
        #[cfg(target_os = "macos")]
        {
            let cleanup_deadline = Instant::now()
                .checked_add(NATIVE_ARCHIVER_COMPLETION_BUDGET)
                .ok_or_else(|| "archive inventory cleanup deadline overflowed".to_owned())?;
            directory.close_until(cleanup_deadline)?;
        }
        #[cfg(not(target_os = "macos"))]
        drop(directory);
        if adapter.exists() {
            return Err("native archive adapter inventory survived cleanup".to_owned());
        }
        Ok(())
    })();
    let inventory_cleanup = fs::remove_dir_all(&inventory_root)
        .map_err(|error| format!("cannot remove archive inventory fixture: {error}"));
    inventory_result.and(inventory_cleanup)
}

#[cfg(unix)]
struct StandardResolverFixture(PathBuf);

#[cfg(unix)]
impl StandardResolverFixture {
    fn new(label: &str) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt as _;

        let path = std::env::temp_dir().join(format!(
            "hell-standard-resolver-verifier-{}-{}-{label}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)
            .map_err(|error| format!("cannot create standard resolver fixture: {error}"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot protect standard resolver fixture: {error}"))?;
        Ok(Self(path))
    }

    fn tool(&self, name: &str, executable: bool) -> Result<PathBuf, String> {
        use std::os::unix::fs::PermissionsExt as _;

        let path = self.0.join(name);
        fs::write(&path, b"tool\n")
            .map_err(|error| format!("cannot write standard resolver fixture tool: {error}"))?;
        let mode = if executable { 0o700 } else { 0o600 };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot set standard resolver tool mode: {error}"))?;
        Ok(path)
    }
}

#[cfg(unix)]
impl Drop for StandardResolverFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
pub(crate) fn verify_standard_tool_resolver_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let first = StandardResolverFixture::new("first")?;
    let second = StandardResolverFixture::new("second")?;
    let expected = first.tool("chmod", true)?;
    second.tool("chmod", true)?;
    let resolved = resolve_standard_path_executable_from(
        OsStr::new("chmod"),
        &[
            PathBuf::from("relative-path-is-not-authority"),
            first.0.clone(),
            second.0.clone(),
        ],
    )?;
    if resolved.invocation_path != fs::canonicalize(&expected).map_err(|error| error.to_string())?
        || resolved.canonical_identity
            != fs::canonicalize(&expected).map_err(|error| error.to_string())?
        || resolve_standard_path_executable_from(OsStr::new("bin/chmod"), &[]).is_ok()
    {
        return Err("standard executable search order is not exact".to_owned());
    }

    let absolute = StandardResolverFixture::new("absolute")?;
    let executable = absolute.tool("tool", true)?;
    let nonexecutable = absolute.tool("data", false)?;
    let resolved = resolve_absolute_standard_executable(&executable)?;
    resolved.revalidate()?;
    if resolve_absolute_standard_executable(Path::new("tool")).is_ok()
        || resolve_absolute_standard_executable(&nonexecutable).is_ok()
    {
        return Err("absolute standard executable policy accepted an invalid path".to_owned());
    }

    let writable = StandardResolverFixture::new("writable-parent")?;
    let writable_tool = writable.tool("chmod", true)?;
    fs::set_permissions(&writable.0, fs::Permissions::from_mode(0o770))
        .map_err(|error| format!("cannot open writable-parent negative fixture: {error}"))?;
    let writable_accepted = resolved_standard_candidate(&writable_tool).is_some();
    fs::set_permissions(&writable.0, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot restore writable-parent negative fixture: {error}"))?;
    if writable_accepted {
        return Err("standard resolver accepted a group-writable parent".to_owned());
    }

    let substitution = StandardResolverFixture::new("substitution")?;
    let original = substitution.tool("chmod-first", true)?;
    let replacement = substitution.tool("chmod-second", true)?;
    let alias = substitution.0.join("chmod");
    symlink(&original, &alias)
        .map_err(|error| format!("cannot create standard resolver alias: {error}"))?;
    let resolved = resolve_standard_path_executable_from(
        OsStr::new("chmod"),
        std::slice::from_ref(&substitution.0),
    )?;
    resolved.revalidate()?;
    fs::remove_file(&alias)
        .map_err(|error| format!("cannot remove standard resolver alias: {error}"))?;
    symlink(replacement, &alias)
        .map_err(|error| format!("cannot substitute standard resolver alias: {error}"))?;
    if resolved.revalidate().is_ok() {
        return Err("standard resolver accepted alias substitution".to_owned());
    }

    verify_standard_tool_parent_revalidation()?;
    verify_rustup_proxy_topology()
}

#[cfg(unix)]
fn verify_standard_tool_parent_revalidation() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let unusable = StandardResolverFixture::new("unusable")?;
    let unusable_tool = unusable.tool("chmod", false)?;
    fs::set_permissions(&unusable_tool, fs::Permissions::from_mode(0o001))
        .map_err(|error| format!("cannot set unusable-tool fixture mode: {error}"))?;
    let fallback = StandardResolverFixture::new("fallback")?;
    let expected = fallback.tool("chmod", true)?;
    let resolved = resolve_standard_path_executable_from(
        OsStr::new("chmod"),
        &[unusable.0.clone(), fallback.0.clone()],
    )?;
    if resolved.canonical_identity
        != fs::canonicalize(expected).map_err(|error| error.to_string())?
    {
        return Err("standard resolver did not skip an unusable candidate".to_owned());
    }

    let mode_drift = StandardResolverFixture::new("parent-mode-drift")?;
    let mode_tool = mode_drift.tool("chmod", true)?;
    let resolved = resolve_absolute_standard_executable(&mode_tool)?;
    fs::set_permissions(&mode_drift.0, fs::Permissions::from_mode(0o770))
        .map_err(|error| format!("cannot mutate standard-tool parent mode: {error}"))?;
    let writable_accepted = resolved.revalidate().is_ok();
    fs::set_permissions(&mode_drift.0, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot restore standard-tool parent mode: {error}"))?;
    if writable_accepted || resolved.revalidate().is_err() {
        return Err("standard resolver parent-mode revalidation is not exact".to_owned());
    }

    let substitution = StandardResolverFixture::new("parent-substitution")?;
    let substitution_tool = substitution.tool("chmod", true)?;
    let resolved = resolve_absolute_standard_executable(&substitution_tool)?;
    let displaced = substitution.0.with_extension("bound-parent");
    fs::rename(&substitution.0, &displaced)
        .map_err(|error| format!("cannot displace standard-tool parent: {error}"))?;
    let result = (|| {
        fs::create_dir(&substitution.0)
            .map_err(|error| format!("cannot replace standard-tool parent: {error}"))?;
        fs::set_permissions(&substitution.0, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot confine replacement standard-tool parent: {error}"))?;
        substitution.tool("chmod", true)?;
        if resolved.revalidate().is_ok() {
            return Err("standard resolver accepted a replaced parent identity".to_owned());
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&substitution.0)
        .and_then(|()| fs::rename(&displaced, &substitution.0))
        .map_err(|error| format!("cannot restore standard-tool parent fixture: {error}"));
    result.and(cleanup)
}

#[cfg(unix)]
fn verify_rustup_proxy_topology() -> Result<(), String> {
    let cargo_root = StandardResolverFixture::new("rustup-cargo")?;
    let standard_root = StandardResolverFixture::new("rustup-standard")?;
    let rustup = standard_root.tool("rustup", true)?;
    let cargo = cargo_root.0.join("cargo");
    let rustc = standard_root.0.join("rustc");
    fs::hard_link(&rustup, &cargo)
        .map_err(|error| format!("cannot link Cargo proxy fixture: {error}"))?;
    fs::hard_link(&rustup, &rustc)
        .map_err(|error| format!("cannot link rustc proxy fixture: {error}"))?;
    let resolved = resolve_cargo_from(Some(cargo.as_os_str()), &[], &[], true, false)?;
    let standard_rustup = resolved_standard_candidate(&rustup)
        .ok_or_else(|| "cannot bind standard Rustup fixture".to_owned())?;
    let standard_rustc = resolved_standard_candidate(&rustc)
        .ok_or_else(|| "cannot bind standard rustc fixture".to_owned())?;
    let identity = ResolvedPosixRustupProxyIdentity::bind(&resolved, &standard_rustup)?
        .ok_or_else(|| "hard-linked Cargo/Rustup fixture was not recognized".to_owned())?;
    let rustc_authority = ResolvedPosixRustcAuthority::bind(&standard_rustc, &identity, &rustc)?;
    if !matches!(
        rustc_authority,
        ResolvedPosixRustcAuthority::RustupProxy { .. }
    ) {
        return Err("hard-linked rustc fixture was not recognized as a Rustup proxy".to_owned());
    }
    identity.revalidate()?;

    let selected_root = StandardResolverFixture::new("selected-rustc")?;
    let selected_rustc = selected_root.tool("rustc", true)?;
    let selected_canonical = fs::canonicalize(&selected_rustc)
        .map_err(|error| format!("cannot canonicalize selected rustc fixture: {error}"))?;
    let selected_standard = resolved_standard_candidate(&selected_rustc)
        .ok_or_else(|| "cannot bind selected rustc fixture".to_owned())?;
    let selected_authority =
        ResolvedPosixRustcAuthority::bind(&selected_standard, &identity, &selected_canonical)?;
    if !matches!(
        selected_authority,
        ResolvedPosixRustcAuthority::SelectedToolchain { .. }
    ) {
        return Err("selected rustc fixture was classified as a proxy".to_owned());
    }
    selected_authority.revalidate(&identity)?;
    let copied_root = StandardResolverFixture::new("copied-rustc")?;
    let copied_rustc = copied_root.tool("rustc", true)?;
    let copied_standard = resolved_standard_candidate(&copied_rustc)
        .ok_or_else(|| "cannot bind copied rustc fixture".to_owned())?;
    if ResolvedPosixRustcAuthority::bind(&copied_standard, &identity, &selected_canonical).is_ok() {
        return Err("same-byte rustc outside the selected toolchain was accepted".to_owned());
    }

    let distinct_root = StandardResolverFixture::new("rustup-distinct")?;
    let distinct_cargo = distinct_root.tool("cargo", true)?;
    let distinct_rustup = distinct_root.tool("rustup", true)?;
    let native = resolve_cargo_from(Some(distinct_cargo.as_os_str()), &[], &[], true, false)?;
    let unrelated_rustup = resolved_standard_candidate(&distinct_rustup)
        .ok_or_else(|| "cannot bind unrelated Rustup fixture".to_owned())?;
    if ResolvedPosixRustupProxyIdentity::bind(&native, &unrelated_rustup)?.is_some() {
        return Err("same-byte distinct Cargo and Rustup files were treated as proxies".to_owned());
    }

    let forged_root = StandardResolverFixture::new("rustup-forged-name")?;
    let forged = forged_root.tool("rustup", true)?;
    let forged = resolve_cargo_from(Some(forged.as_os_str()), &[], &[], true, false)?;
    if ResolvedPosixRustupProxyIdentity::bind(&forged, &unrelated_rustup)?.is_some()
        || !matches!(
            resolve_posix_cargo_authority(&forged, &distinct_root.0),
            Err(error) if error == "logical Cargo invocation must be named cargo"
        )
    {
        return Err("forged logical Cargo name was accepted".to_owned());
    }

    fs::remove_file(&rustc).map_err(|error| format!("cannot remove rustc fixture: {error}"))?;
    standard_root.tool("rustc", true)?;
    if rustc_authority.revalidate(&identity).is_ok() {
        return Err("standard rustc proxy accepted a same-byte replacement".to_owned());
    }
    let selected_replacement = selected_root.tool("rustc-replacement", true)?;
    fs::remove_file(&selected_rustc)
        .and_then(|()| fs::rename(&selected_replacement, &selected_rustc))
        .map_err(|error| format!("cannot replace selected rustc fixture: {error}"))?;
    if selected_authority.revalidate(&identity).is_ok() {
        return Err("selected rustc accepted a same-byte replacement".to_owned());
    }

    fs::remove_file(&rustup).map_err(|error| format!("cannot remove Rustup fixture: {error}"))?;
    standard_root.tool("rustup", true)?;
    if identity.revalidate().is_ok() {
        return Err("Rustup proxy identity accepted a same-byte replacement".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ResolverDirectory(PathBuf);

    impl ResolverDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "hell-cargo-resolver-{}-{}-{label}",
                std::process::id(),
                ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn tool(&self, name: &str, executable: bool) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, b"tool\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;

                let mode = if executable { 0o700 } else { 0o600 };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            }
            let _ = executable;
            path
        }
    }

    impl Drop for ResolverDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cargo_resolver_requires_an_explicit_absolute_search_path() {
        assert!(resolve_cargo_from(None, &[], &[], cfg!(unix), false).is_err());
        assert!(resolve_cargo_from(Some(OsStr::new("")), &[], &[], cfg!(unix), false).is_err());

        let root = ResolverDirectory::new("relative-path");
        root.tool("hell-cargo-relative-only", true);
        assert!(
            resolve_cargo_from(
                Some(OsStr::new("hell-cargo-relative-only")),
                &[
                    PathBuf::new(),
                    PathBuf::from("."),
                    PathBuf::from("relative")
                ],
                &[],
                cfg!(unix),
                false,
            )
            .is_err()
        );
        assert!(
            resolve_cargo_from(
                Some(OsStr::new("relative/cargo")),
                std::slice::from_ref(&root.0),
                &[],
                cfg!(unix),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn rustup_configuration_parsers_bind_one_absolute_home_and_toolchain() {
        let (absolute_home, expected_home, two_absolute_homes): (&[u8], PathBuf, &[u8]) =
            if cfg!(windows) {
                (
                    b"C:\\rust-authority\n",
                    PathBuf::from("C:\\rust-authority"),
                    b"C:\\first\nD:\\second\n",
                )
            } else {
                (
                    b"/opt/rust-authority\n",
                    PathBuf::from("/opt/rust-authority"),
                    b"/first\n/second\n",
                )
            };
        assert_eq!(
            parse_rustup_home_output(absolute_home).unwrap(),
            expected_home
        );
        assert_eq!(
            parse_active_rustup_toolchain(
                b"1.97.1-x86_64-unknown-linux-gnu (overridden by '/checkout')\n"
            )
            .unwrap(),
            OsString::from("1.97.1-x86_64-unknown-linux-gnu")
        );
        for invalid in [
            b"relative/rustup\n".as_slice(),
            two_absolute_homes,
            b"\xff\n".as_slice(),
        ] {
            assert!(parse_rustup_home_output(invalid).is_err());
        }
        for invalid in [
            b"no active toolchain\n".as_slice(),
            b"stable/x86_64\n".as_slice(),
            b"stable\nnightly\n".as_slice(),
            b"\xff\n".as_slice(),
        ] {
            assert!(parse_active_rustup_toolchain(invalid).is_err());
        }
    }

    #[test]
    fn cargo_resolver_preserves_authority_order_and_fails_closed() {
        let first = ResolverDirectory::new("first");
        let second = ResolverDirectory::new("second");
        let first_cargo = first.tool("cargo", true);
        second.tool("cargo", true);
        let resolved = resolve_cargo_from(
            None,
            &[first.0.clone(), second.0.clone()],
            &[],
            cfg!(unix),
            false,
        )
        .unwrap();
        assert_eq!(
            resolved.invocation_path,
            fs::canonicalize(&first_cargo).unwrap()
        );
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(first_cargo).unwrap()
        );
        assert_eq!(resolved.invocation_name, "cargo");

        let proxy = second.tool("cargo-proxy", true);
        let resolved = resolve_cargo_from(
            Some(proxy.as_os_str()),
            std::slice::from_ref(&first.0),
            &[],
            cfg!(unix),
            false,
        )
        .unwrap();
        assert_eq!(resolved.invocation_path, fs::canonicalize(&proxy).unwrap());
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(proxy).unwrap()
        );

        let invalid_authority = second.path().join("missing-cargo");
        assert!(
            resolve_cargo_from(
                Some(invalid_authority.as_os_str()),
                std::slice::from_ref(&first.0),
                &[],
                cfg!(unix),
                false,
            )
            .is_err(),
            "an invalid authoritative CARGO path must not fall back to PATH"
        );
    }

    #[test]
    fn cargo_resolver_rejects_directories_and_non_executables() {
        let first = ResolverDirectory::new("invalid-candidate");
        let second = ResolverDirectory::new("valid-candidate");
        fs::create_dir(first.path().join("cargo")).unwrap();
        let expected = second.tool("cargo", true);
        let resolved = resolve_cargo_from(
            None,
            &[first.0.clone(), second.0.clone()],
            &[],
            cfg!(unix),
            false,
        )
        .unwrap();
        assert_eq!(
            resolved.invocation_path,
            fs::canonicalize(&expected).unwrap()
        );
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(expected).unwrap()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let non_executable = first.tool("cargo-nonexec", false);
            fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o001)).unwrap();
            assert!(
                resolve_cargo_from(Some(non_executable.as_os_str()), &[], &[], true, false,)
                    .is_err(),
                "another-user execute bit must not substitute for effective-user X_OK"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn cargo_resolver_retains_the_alias_and_binds_its_canonical_identity() {
        use std::os::unix::fs::symlink;

        let root = ResolverDirectory::new("symlink");
        let target = root.tool("cargo-target", true);
        let alias = root.path().join("cargo");
        symlink(&target, &alias).unwrap();
        let resolved =
            resolve_cargo_from(None, std::slice::from_ref(&root.0), &[], true, false).unwrap();
        assert_eq!(
            resolved.invocation_path,
            fs::canonicalize(root.path()).unwrap().join("cargo")
        );
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(target).unwrap()
        );
    }

    fn minimal_windows_pe(timestamp: u32) -> Vec<u8> {
        let mut image = vec![0_u8; 512];
        image[..2].copy_from_slice(b"MZ");
        image[60..64].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&3_u16.to_le_bytes());
        image[0x88..0x8c].copy_from_slice(&timestamp.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&0x00f0_u16.to_le_bytes());
        image[0x96..0x98].copy_from_slice(&0x0022_u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x020b_u16.to_le_bytes());
        image[0xdc..0xde].copy_from_slice(&3_u16.to_le_bytes());
        image[0xde..0xe0].copy_from_slice(&0x8160_u16.to_le_bytes());
        image
    }

    fn minimal_windows_pe_with_import(timestamp: u32, import: &[u8]) -> Vec<u8> {
        assert!(import.len() < 0x30 && !import.contains(&0));
        let mut image = minimal_windows_pe(timestamp);
        image.resize(1024, 0);
        image[0x86..0x88].copy_from_slice(&1_u16.to_le_bytes());
        image[0x110..0x114].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[0x114..0x118].copy_from_slice(&40_u32.to_le_bytes());
        image[0x190..0x194].copy_from_slice(&0x200_u32.to_le_bytes());
        image[0x194..0x198].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[0x198..0x19c].copy_from_slice(&0x200_u32.to_le_bytes());
        image[0x19c..0x1a0].copy_from_slice(&0x200_u32.to_le_bytes());
        image[0x20c..0x210].copy_from_slice(&0x1050_u32.to_le_bytes());
        image[0x250..0x250 + import.len()].copy_from_slice(import);
        image[0x250 + import.len()] = 0;
        image
    }

    #[test]
    fn windows_prelaunch_diagnostic_binds_pe_imports_environment_and_cwd() {
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let root = std::env::temp_dir().join(format!(
            "hell-windows-prelaunch-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let program = root.join("cargo.exe");
        fs::write(
            &program,
            minimal_windows_pe_with_import(17, b"KERNEL32.dll"),
        )
        .unwrap();
        assert_eq!(windows_pe_imports(&program).unwrap(), ["KERNEL32.dll"]);
        let diagnostic = windows_parent_prelaunch_diagnostic(&[
            program.clone().into_os_string(),
            OsString::from("--version"),
        ]);
        assert!(diagnostic.contains("imports=[\"KERNEL32.dll\"]"));
        assert!(diagnostic.contains("SystemRoot="));
        assert!(diagnostic.contains("PATH="));
        assert!(diagnostic.contains("cwd="));
        assert!(diagnostic.contains("graphicalBinding=inherited-default"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_pe_image_identity_binds_headers_and_rejects_non_images() {
        let root = ResolverDirectory::new("windows-pe-image");
        let first = root.path().join("first.exe");
        let equal = root.path().join("equal.exe");
        let changed = root.path().join("changed.exe");
        let invalid = root.path().join("invalid.exe");
        fs::write(&first, minimal_windows_pe(0x1234_5678)).unwrap();
        fs::write(&equal, minimal_windows_pe(0x1234_5678)).unwrap();
        fs::write(&changed, minimal_windows_pe(0x8765_4321)).unwrap();
        fs::write(&invalid, b"not a PE image").unwrap();

        assert_eq!(
            windows_pe_image_identity(&first).unwrap(),
            windows_pe_image_identity(&equal).unwrap()
        );
        assert_ne!(
            windows_pe_image_identity(&first).unwrap(),
            windows_pe_image_identity(&changed).unwrap()
        );
        assert!(windows_pe_image_identity(&invalid).is_err());
    }

    #[test]
    fn windows_tool_classification_diagnostic_names_every_closed_predicate() {
        let pe = WindowsPeImageIdentity {
            machine: 0x8664,
            section_count: 3,
            timestamp: 0x1234_5678,
            optional_header_size: 0x00f0,
            characteristics: 0x0022,
            optional_header_magic: 0x020b,
            subsystem: 3,
            dll_characteristics: 0x8160,
        };
        let diagnostic = WindowsToolClassificationDiagnostic {
            source_invocation: PathBuf::from(r"C:\standard\cargo.EXE"),
            source_canonical: PathBuf::from(r"C:\standard\cargo.exe"),
            rustup_invocation: PathBuf::from(r"C:\standard\rustup.EXE"),
            rustup_canonical: PathBuf::from(r"C:\standard\rustup.exe"),
            selected_invocation: PathBuf::from(r"C:\toolchain\bin\cargo.exe"),
            selected_canonical: PathBuf::from(r"C:\toolchain\bin\cargo.exe"),
            source_revalidation: Ok(()),
            rustup_revalidation: Ok(()),
            selected_revalidation: Err("selected-lock-failed".to_owned()),
            source_file_identity: "source-file-id".to_owned(),
            rustup_file_identity: "rustup-file-id".to_owned(),
            selected_file_identity: "selected-file-id".to_owned(),
            source_same_file_rustup: false,
            source_same_file_selected: false,
            source_direct: false,
            rustup_direct: false,
            canonical_paths_distinct: true,
            canonical_parent_same: true,
            invocation_parent_same: true,
            source_size: 17,
            rustup_size: 17,
            selected_size: 19,
            size_equal: true,
            source_sha256: "11".repeat(32),
            rustup_sha256: "11".repeat(32),
            selected_sha256: "22".repeat(32),
            sha256_equal: true,
            source_pe: Ok(pe),
            rustup_pe: Ok(pe),
            pe_identity_equal: Some(true),
            copied_proxy_result: Ok(false),
            selected_canonical_exact: false,
        };

        let rendered = diagnostic.to_string();
        for field in [
            "sourceInvocation=",
            "sourceCanonical=",
            "rustupInvocation=",
            "rustupCanonical=",
            "selectedInvocation=",
            "selectedCanonical=",
            "sourceRevalidation=",
            "rustupRevalidation=",
            "selectedRevalidation=",
            "sourceFileIdentity=",
            "rustupFileIdentity=",
            "selectedFileIdentity=",
            "sourceSameFileRustup=",
            "sourceSameFileSelected=",
            "sourceDirect=",
            "rustupDirect=",
            "canonicalPathsDistinct=",
            "canonicalParentSame=",
            "invocationParentSame=",
            "sourceSize=",
            "rustupSize=",
            "selectedSize=",
            "sizeEqual=",
            "sourceSha256=",
            "rustupSha256=",
            "selectedSha256=",
            "sha256Equal=",
            "sourcePe=",
            "rustupPe=",
            "peIdentityEqual=",
            "copiedProxyResult=",
            "selectedCanonicalExact=",
        ] {
            assert!(rendered.contains(field), "missing diagnostic field {field}");
        }
        assert!(rendered.contains(r#"sourceInvocation="C:\\standard\\cargo.EXE""#));
        assert!(rendered.contains("selected-lock-failed"));
        assert!(rendered.len() < 4_096);
    }

    #[test]
    fn windows_direct_spelling_accepts_only_component_exact_case_changes() {
        let matches = |invocation: &str, canonical: &str| {
            windows_case_only_direct_spelling_units(
                &invocation.encode_utf16().collect::<Vec<_>>(),
                &canonical.encode_utf16().collect::<Vec<_>>(),
            )
        };

        assert!(matches(
            r"\\?\C:\Users\runneradmin\.cargo\cargo.EXE",
            r"\\?\C:\Users\runneradmin\.cargo\cargo.exe"
        ));
        assert!(matches(
            r"\\server\share\Cargo.EXE",
            r"\\SERVER\SHARE\cargo.exe"
        ));
        assert!(!matches(
            r"\\?\C:\Users\runneradmin\.cargo\cargo.EXE",
            r"\\?\C:\Users\runneradmin\.cargo\rustc.exe"
        ));
        assert!(!matches(
            r"\\?\C:\Users\runneradmin\.cargo\cargo.EXE",
            r"\\?\D:\Users\runneradmin\.cargo\cargo.exe"
        ));
        assert!(!matches(
            r"\\server\share\cargo.EXE",
            r"\\server\other\cargo.exe"
        ));
        assert!(!matches(
            r"\\?\C:/Users/runneradmin/.cargo/cargo.EXE",
            r"\\?\C:\Users\runneradmin\.cargo\cargo.exe"
        ));
        assert!(!matches(
            r"\\?\C:\Users\runneradmin\.\cargo.EXE",
            r"\\?\C:\Users\runneradmin\.\cargo.exe"
        ));
        assert!(!matches(
            r"\\?\C:\Users\runneradmin\..\cargo.EXE",
            r"\\?\C:\Users\runneradmin\..\cargo.exe"
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_proxy_identity_distinguishes_hard_link_from_same_byte_copy() {
        let root = std::env::temp_dir().join(format!(
            "hell-windows-proxy-identity-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let rustup = root.join("rustup.exe");
        let cargo = root.join("cargo.exe");
        let copied = root.join("copied-rustup.exe");
        fs::write(&rustup, b"rustup proxy").unwrap();
        fs::hard_link(&rustup, &cargo).unwrap();
        fs::copy(&rustup, &copied).unwrap();

        let rustup_identity = WindowsBoundFileIdentity::bind(&rustup).unwrap();
        let cargo_identity = WindowsBoundFileIdentity::bind(&cargo).unwrap();
        let copied_identity = WindowsBoundFileIdentity::bind(&copied).unwrap();
        assert!(rustup_identity.same_file(&cargo_identity));
        assert!(!rustup_identity.same_file(&copied_identity));
        assert!(fs::write(&cargo, b"replacement").is_err());
        drop((rustup_identity, cargo_identity, copied_identity));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_tool_source_union_accepts_only_proxy_or_exact_selected_tool() {
        let proxy_root = ResolverDirectory::new("windows-tool-proxy");
        let selected_root = ResolverDirectory::new("windows-tool-selected");
        let copied_root = ResolverDirectory::new("windows-tool-copied");
        let proxy_directory = fs::canonicalize(proxy_root.path()).unwrap();
        let selected_directory = fs::canonicalize(selected_root.path()).unwrap();
        let copied_directory = fs::canonicalize(copied_root.path()).unwrap();
        let rustup_path = proxy_directory.join("rustup.exe");
        fs::write(&rustup_path, b"tool\n").unwrap();
        let cargo_proxy_path = proxy_directory.join("cargo.exe");
        fs::hard_link(&rustup_path, &cargo_proxy_path).unwrap();
        let selected_path = selected_directory.join("cargo.exe");
        let copied_path = copied_directory.join("cargo.exe");
        fs::write(&selected_path, b"tool\n").unwrap();
        fs::write(&copied_path, b"tool\n").unwrap();
        assert_eq!(
            fs::read(&selected_path).unwrap(),
            fs::read(&copied_path).unwrap()
        );

        let rustup = bind_windows_absolute_executable(&rustup_path, "rustup").unwrap();
        let proxy = bind_windows_absolute_executable(&cargo_proxy_path, "cargo").unwrap();
        let selected = bind_windows_absolute_executable(&selected_path, "cargo").unwrap();
        let copied = bind_windows_absolute_executable(&copied_path, "cargo").unwrap();
        assert!(matches!(
            classify_windows_tool_source(proxy, &rustup, &selected, "cargo").unwrap(),
            ResolvedWindowsToolSourceAuthority::RustupProxy(_)
        ));
        assert!(matches!(
            classify_windows_tool_source(selected.clone(), &rustup, &selected, "cargo").unwrap(),
            ResolvedWindowsToolSourceAuthority::SelectedToolchain(_)
        ));
        assert!(classify_windows_tool_source(copied, &rustup, &selected, "cargo").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn copied_rustup_proxy_binds_locked_cargo_and_rustc_siblings() {
        let copied_proxy_root = ResolverDirectory::new("windows-tool-copied-proxy");
        let selected_root = ResolverDirectory::new("windows-tool-selected-for-copy");
        let copied_proxy_directory = fs::canonicalize(copied_proxy_root.path()).unwrap();
        let selected_directory = fs::canonicalize(selected_root.path()).unwrap();
        let selected_path = selected_directory.join("cargo.exe");
        let selected_rustc_path = selected_directory.join("rustc.exe");
        fs::write(&selected_path, b"tool\n").unwrap();
        fs::write(&selected_rustc_path, b"tool\n").unwrap();
        let selected = bind_windows_absolute_executable(&selected_path, "cargo").unwrap();
        let selected_rustc =
            bind_windows_absolute_executable(&selected_rustc_path, "rustc").unwrap();
        let copied_proxy_bytes = minimal_windows_pe(0x1234_5678);
        let copied_rustup_path = copied_proxy_directory.join("rustup.exe");
        let copied_cargo_path = copied_proxy_directory.join("cargo.exe");
        let copied_rustc_path = copied_proxy_directory.join("rustc.exe");
        fs::write(&copied_rustup_path, &copied_proxy_bytes).unwrap();
        fs::write(&copied_cargo_path, &copied_proxy_bytes).unwrap();
        fs::write(&copied_rustc_path, &copied_proxy_bytes).unwrap();
        let bind_uppercase_extension = |path: &Path, logical_name: &str| {
            let canonical = fs::canonicalize(path).unwrap();
            ResolvedWindowsExecutableIdentity::bind(
                &ResolvedCargoExecutable {
                    invocation_path: canonical
                        .parent()
                        .unwrap()
                        .join(format!("{logical_name}.EXE")),
                    canonical_identity: canonical,
                    invocation_name: OsString::from(logical_name),
                },
                logical_name,
            )
            .unwrap()
        };
        let copied_rustup = bind_uppercase_extension(&copied_rustup_path, "rustup");
        let copied_cargo = bind_uppercase_extension(&copied_cargo_path, "cargo");
        let copied_rustc = bind_uppercase_extension(&copied_rustc_path, "rustc");
        let copied_cargo_authority =
            classify_windows_tool_source(copied_cargo.clone(), &copied_rustup, &selected, "cargo")
                .unwrap();
        assert!(matches!(
            &copied_cargo_authority,
            ResolvedWindowsToolSourceAuthority::CopiedRustupProxy(_)
        ));
        assert!(matches!(
            classify_windows_tool_source(copied_rustc, &copied_rustup, &selected_rustc, "rustc")
                .unwrap(),
            ResolvedWindowsToolSourceAuthority::CopiedRustupProxy(_)
        ));
        assert!(fs::write(&copied_cargo_path, &copied_proxy_bytes).is_err());
        assert!(fs::remove_file(&copied_cargo_path).is_err());
        assert!(
            fs::rename(
                &copied_cargo_path,
                copied_proxy_directory.join("renamed-cargo.exe")
            )
            .is_err()
        );
        copied_cargo_authority
            .revalidate("cargo", &copied_rustup, &selected)
            .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn copied_rustup_proxy_rejects_untrusted_changed_and_non_pe_copies() {
        let copied_proxy_root = ResolverDirectory::new("windows-tool-copied-proxy-negative");
        let untrusted_copy_root = ResolverDirectory::new("windows-tool-untrusted-copy");
        let altered_proxy_root = ResolverDirectory::new("windows-tool-altered-proxy");
        let invalid_proxy_root = ResolverDirectory::new("windows-tool-invalid-proxy");
        let selected_root = ResolverDirectory::new("windows-tool-selected-for-negative-copy");
        let copied_proxy_directory = fs::canonicalize(copied_proxy_root.path()).unwrap();
        let untrusted_copy_directory = fs::canonicalize(untrusted_copy_root.path()).unwrap();
        let altered_proxy_directory = fs::canonicalize(altered_proxy_root.path()).unwrap();
        let invalid_proxy_directory = fs::canonicalize(invalid_proxy_root.path()).unwrap();
        let selected_directory = fs::canonicalize(selected_root.path()).unwrap();
        let selected_path = selected_directory.join("cargo.exe");
        fs::write(&selected_path, b"tool\n").unwrap();
        let selected = bind_windows_absolute_executable(&selected_path, "cargo").unwrap();
        let copied_proxy_bytes = minimal_windows_pe(0x1234_5678);
        let copied_rustup_path = copied_proxy_directory.join("rustup.exe");
        fs::write(&copied_rustup_path, &copied_proxy_bytes).unwrap();
        let copied_rustup =
            bind_windows_absolute_executable(&copied_rustup_path, "rustup").unwrap();
        let untrusted_cargo_path = untrusted_copy_directory.join("cargo.exe");
        fs::write(&untrusted_cargo_path, &copied_proxy_bytes).unwrap();
        let untrusted_cargo =
            bind_windows_absolute_executable(&untrusted_cargo_path, "cargo").unwrap();
        assert!(
            classify_windows_tool_source(untrusted_cargo, &copied_rustup, &selected, "cargo")
                .is_err()
        );

        let altered_rustup_path = altered_proxy_directory.join("rustup.exe");
        let altered_cargo_path = altered_proxy_directory.join("cargo.exe");
        fs::write(&altered_rustup_path, &copied_proxy_bytes).unwrap();
        fs::write(&altered_cargo_path, minimal_windows_pe(0x8765_4321)).unwrap();
        let altered_rustup =
            bind_windows_absolute_executable(&altered_rustup_path, "rustup").unwrap();
        let altered_cargo = bind_windows_absolute_executable(&altered_cargo_path, "cargo").unwrap();
        assert!(
            classify_windows_tool_source(altered_cargo, &altered_rustup, &selected, "cargo")
                .is_err()
        );

        let invalid_rustup_path = invalid_proxy_directory.join("rustup.exe");
        let invalid_cargo_path = invalid_proxy_directory.join("cargo.exe");
        fs::write(&invalid_rustup_path, b"not a PE image").unwrap();
        fs::write(&invalid_cargo_path, b"not a PE image").unwrap();
        let invalid_rustup =
            bind_windows_absolute_executable(&invalid_rustup_path, "rustup").unwrap();
        let invalid_cargo = bind_windows_absolute_executable(&invalid_cargo_path, "cargo").unwrap();
        assert!(
            classify_windows_tool_source(invalid_cargo, &invalid_rustup, &selected, "cargo")
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn cargo_alias_identity_substitution_is_rejected_before_spawn() {
        use std::os::unix::fs::symlink;

        let root = ResolverDirectory::new("identity-substitution");
        let first = root.tool("first", true);
        let second = root.tool("second", true);
        let alias = root.path().join("cargo");
        symlink(first, &alias).unwrap();
        let resolved = resolve_cargo_from(Some(alias.as_os_str()), &[], &[], true, false).unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(second, &alias).unwrap();
        let error = CommandSpec::cargo_from_resolution(Duration::from_secs(1), Ok(resolved))
            .argument("--version")
            .run()
            .unwrap_err();
        assert_eq!(error.phase(), CommandRunPhase::ProgramResolution);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn windows_cargo_resolution_is_native_executable_only_and_ordered() {
        assert_eq!(
            windows_executable_extensions(OsStr::new(".BAT;.EXE;.com;.CMD;.exe")),
            [
                OsString::from(".EXE"),
                OsString::from(".com"),
                OsString::from(".exe")
            ]
        );
        let root = ResolverDirectory::new("windows-native");
        let exe = root.tool("cargo.EXE", false);
        root.tool("cargo.com", false);
        root.tool("cargo.BAT", false);
        root.tool("cargo.CMD", false);
        let extensions = windows_executable_extensions(OsStr::new(".BAT;.EXE;.com;.CMD"));
        let resolved = resolve_cargo_from(
            None,
            std::slice::from_ref(&root.0),
            &extensions,
            false,
            true,
        )
        .unwrap();
        assert_eq!(resolved.invocation_path, fs::canonicalize(&exe).unwrap());
        assert_eq!(resolved.canonical_identity, fs::canonicalize(exe).unwrap());
        assert!(
            resolve_cargo_from(
                Some(root.path().join("cargo.BAT").as_os_str()),
                &[],
                &extensions,
                false,
                true,
            )
            .is_err()
        );
        assert!(
            resolve_cargo_from(
                Some(OsStr::new("cargo.cmd")),
                std::slice::from_ref(&root.0),
                &extensions,
                false,
                true,
            )
            .is_err()
        );
        assert!(
            resolve_cargo_from(
                Some(root.path().join("cargo-without-extension").as_os_str()),
                &[],
                &extensions,
                false,
                true,
            )
            .is_err()
        );
        assert!(
            resolve_cargo_from(
                None,
                std::slice::from_ref(&root.0),
                &windows_executable_extensions(OsStr::new(".BAT;.CMD")),
                false,
                true,
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn windows_cargo_resolution_rechecks_the_canonical_target_extension() {
        use std::os::unix::fs::symlink;

        let root = ResolverDirectory::new("windows-reparse-target");
        let script = root.tool("actual.CMD", false);
        let alias = root.path().join("cargo.EXE");
        symlink(script, &alias).unwrap();
        assert!(
            resolve_cargo_from(
                Some(alias.as_os_str()),
                &[],
                &windows_executable_extensions(OsStr::new(".EXE;.COM")),
                false,
                true,
            )
            .is_err(),
            "an EXE alias must not authorize a canonical BAT/CMD target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn windows_cargo_resolution_keeps_a_native_alias_and_separate_identity() {
        use std::os::unix::fs::symlink;

        let root = ResolverDirectory::new("windows-native-alias");
        let target = root.tool("rustup.EXE", false);
        let alias = root.path().join("cargo.EXE");
        symlink(&target, &alias).unwrap();
        let resolved = resolve_cargo_from(
            Some(alias.as_os_str()),
            &[],
            &windows_executable_extensions(OsStr::new(".EXE;.COM")),
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            resolved.invocation_path,
            fs::canonicalize(root.path()).unwrap().join("cargo.EXE")
        );
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(target).unwrap()
        );
        assert_eq!(resolved.invocation_name, "cargo");
    }

    #[test]
    fn windows_restricted_child_retains_prelaunch_evidence_on_every_failure() {
        assert_eq!(windows_raw_status_diagnostic(0), None);
        assert_eq!(windows_raw_status_diagnostic(255), None);
        assert_eq!(
            windows_raw_status_diagnostic(0xc000_0135),
            Some(
                "restricted child exited with raw Windows status 3221225781 (0xc0000135)"
                    .to_owned()
            )
        );
        assert_eq!(
            windows_raw_status_diagnostic(0xc000_0142),
            Some(
                "restricted child exited with raw Windows status 3221225794 (0xc0000142)"
                    .to_owned()
            )
        );
        assert_eq!(
            windows_restricted_child_outcome(0, "parent prelaunch evidence"),
            WindowsRestrictedChildOutcome {
                exit_code: 0,
                diagnostic: None,
            }
        );
        assert_eq!(
            windows_restricted_child_outcome(1, "parent prelaunch evidence"),
            WindowsRestrictedChildOutcome {
                exit_code: 1,
                diagnostic: Some("parent prelaunch evidence".to_owned()),
            }
        );
        assert_eq!(
            windows_restricted_child_outcome(0xc000_0142, "parent prelaunch evidence"),
            WindowsRestrictedChildOutcome {
                exit_code: u8::MAX,
                diagnostic: Some(
                    "restricted child exited with raw Windows status 3221225794 \
                     (0xc0000142)\nparent prelaunch evidence"
                        .to_owned(),
                ),
            }
        );
    }

    #[test]
    fn windows_restricted_stdio_contract_rejects_missing_swapped_and_extra_handles() {
        assert!(windows_restricted_stdio_contract(&WINDOWS_RESTRICTED_STDIO_HANDLES).is_ok());
        assert!(windows_restricted_stdio_contract(&WINDOWS_RESTRICTED_STDIO_HANDLES[..2]).is_err());
        assert!(
            windows_restricted_stdio_contract(&[
                WindowsRestrictedStdioHandle::EofStandardInput,
                WindowsRestrictedStdioHandle::CapturedStandardError,
                WindowsRestrictedStdioHandle::CapturedStandardOutput,
            ])
            .is_err()
        );
        assert!(
            windows_restricted_stdio_contract(&[
                WindowsRestrictedStdioHandle::EofStandardInput,
                WindowsRestrictedStdioHandle::CapturedStandardOutput,
                WindowsRestrictedStdioHandle::CapturedStandardError,
                WindowsRestrictedStdioHandle::CapturedStandardError,
            ])
            .is_err()
        );
        assert_eq!(WINDOWS_STARTF_USE_STD_HANDLES, 0x0000_0100);
    }

    #[test]
    fn windows_restricted_diagnostic_relay_preserves_exact_bytes_and_accepts_pipe_eof() {
        struct BrokenPipeAfterPayload(std::io::Cursor<Vec<u8>>);
        struct FailingReader;

        impl std::io::Read for BrokenPipeAfterPayload {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let count = self.0.read(buffer)?;
                if count == 0 {
                    Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
                } else {
                    Ok(count)
                }
            }
        }

        impl std::io::Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("non-pipe relay failure"))
            }
        }

        let expected = b"cargo stdout\0\xff\r\ncargo stderr\n";
        let mut observed = Vec::new();
        relay_windows_restricted_diagnostic(
            BrokenPipeAfterPayload(std::io::Cursor::new(expected.to_vec())),
            &mut observed,
        )
        .unwrap();
        assert_eq!(observed, expected);
        assert!(relay_windows_restricted_diagnostic(FailingReader, Vec::new(),).is_err());
    }

    #[test]
    fn windows_restricted_request_requires_exact_adapter_shape_and_target() {
        let digest = Digest([0xa5; 32]);
        let adapter = if cfg!(windows) {
            "C:\\trusted\\hell-test-helper.exe"
        } else {
            "/trusted/hell-test-helper.exe"
        };
        let wrong_adapter = if cfg!(windows) {
            "C:\\trusted\\hell-ci.exe"
        } else {
            "/trusted/hell-ci.exe"
        };
        let baseline = vec![
            OsString::from(adapter),
            OsString::from(digest.hex()),
            OsString::from("C:\\trusted\\cargo.exe"),
            OsString::from("--version"),
        ];
        let parsed = parse_windows_restricted_launch_request(baseline.clone()).unwrap();
        assert_eq!(parsed.adapter, Path::new(adapter));
        assert_eq!(parsed.adapter_sha256, digest);
        assert_eq!(
            parsed.target_arguments,
            ["C:\\trusted\\cargo.exe", "--version"]
        );
        let mut wrong_name = baseline.clone();
        wrong_name[0] = OsString::from(wrong_adapter);
        assert!(parse_windows_restricted_launch_request(wrong_name).is_err());
        let mut relative = baseline.clone();
        relative[0] = OsString::from("hell-test-helper.exe");
        assert!(parse_windows_restricted_launch_request(relative).is_err());
        let mut wrong_digest = baseline.clone();
        wrong_digest[1] = OsString::from("00");
        assert!(parse_windows_restricted_launch_request(wrong_digest).is_err());
        let mut noncanonical_digest = baseline.clone();
        noncanonical_digest[1] = OsString::from(digest.hex().to_ascii_uppercase());
        assert!(parse_windows_restricted_launch_request(noncanonical_digest).is_err());
        assert!(parse_windows_restricted_launch_request(baseline[..2].to_vec()).is_err());
    }

    #[test]
    fn windows_launch_token_duplicates_the_current_normal_primary_token() {
        assert_eq!(
            WINDOWS_LAUNCH_TOKEN_CONSTRAINTS,
            [WindowsLaunchTokenConstraint::DuplicatedCurrentPrimary]
        );
        assert!(windows_launch_token_contract(&WINDOWS_LAUNCH_TOKEN_CONSTRAINTS).is_ok());
        assert!(windows_launch_token_contract(&[]).is_err());
        assert_eq!(
            WINDOWS_RESTRICTED_GRAPHICAL_BINDING,
            WindowsRestrictedGraphicalBinding::InheritedDefault
        );
    }

    #[test]
    fn windows_restricted_graphical_binding_is_exact() {
        assert_eq!(
            WINDOWS_RESTRICTED_GRAPHICAL_BINDING,
            WindowsRestrictedGraphicalBinding::InheritedDefault
        );
        assert!(
            windows_restricted_graphical_binding_contract(WINDOWS_RESTRICTED_GRAPHICAL_BINDING)
                .is_ok()
        );
    }

    #[test]
    fn windows_supported_launch_canary_is_pe_bound_and_must_succeed() {
        let root = ResolverDirectory::new("windows-supported-launch-canary");
        let program = root.path().join("cmd.exe");
        fs::write(
            &program,
            minimal_windows_pe_with_import(23, b"api-ms-win-core-console-l1-1-0.dll"),
        )
        .unwrap();
        let canonical_root = fs::canonicalize(root.path()).unwrap();
        let resolved = resolve_windows_supported_launch_canary(&canonical_root).unwrap();
        assert_eq!(resolved.program, canonical_root.join("cmd.exe"));
        assert_eq!(resolved.arguments, ["/d", "/c", "exit", "0"]);
        assert_eq!(resolved.imports, ["api-ms-win-core-console-l1-1-0.dll"]);
        let diagnostic = windows_restricted_canary_diagnostic(&resolved, 0xc000_0142);
        assert!(diagnostic.contains("subsystem=supported-launch"));
        assert!(diagnostic.contains("imports=[\"api-ms-win-core-console-l1-1-0.dll\"]"));
        assert!(diagnostic.contains("status=3221225794 (0xc0000142)"));
        assert_eq!(windows_restricted_canary_failure(&resolved, 0), None);
        let failure = windows_restricted_canary_failure(&resolved, 0xc000_0142).unwrap();
        assert!(failure.starts_with(&diagnostic));
        assert!(failure.ends_with("; supported Windows launch canary must exit successfully"));
        let target = root.path().join("cargo.exe");
        fs::write(&target, minimal_windows_pe_with_import(24, b"KERNEL32.dll")).unwrap();
        let target = resolve_windows_restricted_target_canary(&target).unwrap();
        assert_eq!(target.subsystem, "staged-target");
        assert_eq!(target.arguments, ["--version"]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_restricted_child_plan_is_coherent_and_separate_from_canary() {
        let launcher = Path::new(r"C:\staged\hell-test-helper.exe");
        let target_token = OsStr::new("encoded-target-argv");
        let child = windows_restricted_child_launch_plan(launcher, target_token);
        let canary = windows_restricted_canary_launch_plan(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            &["/d", "/c", "exit", "0"],
        );

        let decode = |plan: &WindowsRestrictedLaunchPlan| {
            String::from_utf16(&plan.command_line[..plan.command_line.len() - 1]).unwrap()
        };
        assert_eq!(child.application, launcher);
        assert_eq!(
            decode(&child),
            "hell-test-helper __release-argv-child encoded-target-argv"
        );
        assert_eq!(
            canary.application,
            Path::new(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            decode(&canary),
            r#""C:\Windows\System32\cmd.exe" /d /c exit 0"#
        );
        assert_ne!(child.application, canary.application);
        assert_ne!(child.command_line, canary.command_line);
    }

    #[test]
    fn environment_reporting_never_contains_values() {
        let spec = CommandSpec::new("program", Duration::from_secs(1))
            .environment("RUSTDOCFLAGS", "secret-value");
        assert_eq!(spec.environment_names(), ["RUSTDOCFLAGS"]);
        assert!(!format!("{:?}", spec.environment_names()).contains("secret-value"));
    }

    #[test]
    fn git_safe_directory_is_structured_environment_not_interpolated_argv() {
        let root = Path::new("/trusted/repository");
        let spec = CommandSpec::new("git", Duration::from_secs(1))
            .git_safe_directory(root)
            .arguments(["status", "--porcelain=v1"]);
        assert_eq!(spec.display_arguments(), ["status", "--porcelain=v1"]);
        assert!(
            spec.arguments
                .iter()
                .all(|argument| argument != OsStr::new("-c")
                    && !argument.to_string_lossy().starts_with("safe.directory="))
        );
        assert_eq!(
            spec.environment,
            [
                (OsString::from("GIT_CONFIG_COUNT"), OsString::from("1")),
                (
                    OsString::from("GIT_CONFIG_KEY_0"),
                    OsString::from("safe.directory")
                ),
                (
                    OsString::from("GIT_CONFIG_VALUE_0"),
                    root.as_os_str().to_os_string()
                ),
            ]
        );
    }

    #[test]
    fn release_commands_default_to_isolated_tree_scope() {
        let spec = CommandSpec::new("program", Duration::from_secs(1));
        assert_eq!(spec.process_scope, ProcessScope::IsolatedTree);
    }

    #[test]
    fn disabled_native_stack_commands_keep_the_source_directory() {
        let source = Path::new("/fixed/oracle-source");
        let adapter =
            NativeArchiveAdapter::for_macos(false, Path::new("/fixed/adapter-base"), source, None)
                .unwrap();

        for command in [
            adapter.stack_build(source, Duration::from_secs(1)),
            adapter.stack_path(source),
            adapter.stack_ghc_version(source),
        ] {
            assert_eq!(command.current_directory.as_deref(), Some(source));
        }

        let ghc = adapter.stack_ghc_version(source);
        assert_eq!(
            ghc.display_arguments(),
            [
                "--lock-file",
                "error-on-write",
                "--stack-yaml",
                "stack.yaml",
                "exec",
                "--",
                "ghc",
                "--numeric-version",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_stack_overlay_rejects_control_and_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt as _;

        assert!(yaml_single_quoted_path(Path::new("line\nbreak")).is_err());
        assert!(yaml_single_quoted_path(Path::new(&OsString::from_vec(vec![0xff, b'x']))).is_err());
    }

    #[test]
    #[should_panic(expected = "sensitive environment variables")]
    fn sensitive_environment_cannot_be_reintroduced() {
        let _ = CommandSpec::new("program", Duration::from_secs(1))
            .environment("GITHUB_TOKEN", "secret-value");
    }

    #[cfg(unix)]
    #[test]
    fn posix_adapter_builds_the_exact_exec_replacement() {
        let command = posix_release_child_command(&[
            OsString::from("2"),
            OsString::from("HOME"),
            OsString::from("/isolated/home"),
            OsString::from("RUSTUP_HOME"),
            OsString::from("/trusted/rustup"),
            OsString::from("cargo"),
            OsString::from("/trusted/cargo"),
            OsString::from("--version"),
        ])
        .unwrap();
        assert_eq!(command.get_program(), "/trusted/cargo");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["--version"]);
        assert!(
            command
                .get_envs()
                .any(|(name, value)| name == "HOME" && value == Some(OsStr::new("/isolated/home")))
        );
        assert!(
            command.get_envs().any(|(name, value)| name == "RUSTUP_HOME"
                && value == Some(OsStr::new("/trusted/rustup")))
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_adapter_rejects_malformed_or_forged_environment_envelopes() {
        for (arguments, expected) in [
            (vec![], "POSIX release child envelope is missing"),
            (
                vec!["01", "cargo", "/trusted/cargo"],
                "POSIX release child environment count is not canonical or exceeds its bound",
            ),
            (
                vec!["1", "HOME", "/isolated/home", "cargo"],
                "POSIX release child environment framing is incomplete",
            ),
            (
                vec!["1", "CUSTOM", "forbidden", "cargo", "/trusted/cargo"],
                "POSIX release child environment name is not allowed",
            ),
            (
                vec![
                    "2",
                    "HOME",
                    "/isolated/home",
                    "HOME",
                    "/other/home",
                    "cargo",
                    "/trusted/cargo",
                ],
                "POSIX release child environment name is duplicated",
            ),
            (
                vec!["0", "cargo", "relative-cargo"],
                "POSIX release child program is not absolute",
            ),
            (
                vec!["0", "rustc", "/trusted/cargo"],
                "POSIX release child invocation name differs from its bound program",
            ),
            (
                vec!["0", "path/cargo", "/trusted/cargo"],
                "POSIX release child invocation name is not canonical",
            ),
        ] {
            let arguments = arguments
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>();
            assert_eq!(
                posix_release_child_command(&arguments)
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_archive_identity_request_is_exact() {
        assert!(native_archive_identity_request(&[OsString::from(
            "--version"
        )]));
        for arguments in [
            vec![],
            vec!["--version", "archive.a"],
            vec!["-version"],
            vec!["--help"],
            vec!["q", "--version"],
        ] {
            let arguments = arguments
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>();
            assert!(
                !native_archive_identity_request(&arguments),
                "unexpected identity request accepted: {arguments:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_archive_adapter_uses_fixed_flattening_operations() {
        let root = std::env::temp_dir().join(format!(
            "hell-archive-adapter-arguments-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let work = root.join(".stack-work");
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("objects.rsp"), b"object.o\n").unwrap();
        fs::write(work.join("object.o"), b"object\n").unwrap();
        let fresh = work.join("fresh.a");
        for (input, expected, target) in [
            ("r", "qL", fresh.as_os_str()),
            ("-r", "-qL", fresh.as_os_str()),
            ("q", "qL", OsStr::new("archive.a")),
            ("-q", "-qL", OsStr::new("archive.a")),
            ("qc", "qLc", OsStr::new("archive.a")),
            ("-qc", "-qLc", OsStr::new("archive.a")),
            ("qcL", "qcL", OsStr::new("archive.a")),
            ("-qcL", "-qcL", OsStr::new("archive.a")),
            ("qcls", "qclsL", OsStr::new("archive.a")),
            ("-qcls", "-qclsL", OsStr::new("archive.a")),
            ("qclsL", "qclsL", OsStr::new("archive.a")),
            ("clqs", "qclsL", OsStr::new("archive.a")),
            ("-clqs", "-qclsL", OsStr::new("archive.a")),
        ] {
            let normalized = normalize_native_archive_arguments(
                &[
                    OsString::from(input),
                    OsString::from(target),
                    OsString::from("@objects.rsp"),
                ],
                &root,
                &work,
            )
            .unwrap();
            assert_eq!(normalized[0], expected);
            assert_eq!(normalized[1], target);
            assert_eq!(normalized[2], "@objects.rsp");
        }
        let macos = normalize_native_archive_arguments(
            &[
                OsString::from("-r"),
                OsString::from("-s"),
                OsString::from("-c"),
                fresh.as_os_str().to_owned(),
                OsString::from("@objects.rsp"),
            ],
            &root,
            &work,
        )
        .unwrap();
        assert_eq!(macos[0], "-qL");
        assert_eq!(macos[1], "-s");
        assert_eq!(macos[2], "-c");
        assert_eq!(macos[3], fresh.as_os_str());
        fs::write(&fresh, b"existing\n").unwrap();
        assert!(
            normalize_native_archive_arguments(
                &[
                    OsString::from("-q"),
                    OsString::from("-s"),
                    OsString::from("-s"),
                    fresh.as_os_str().to_owned(),
                    OsString::from("@objects.rsp"),
                ],
                &root,
                &work,
            )
            .is_err()
        );
        fs::write(&fresh, b"existing\n").unwrap();
        assert!(
            normalize_native_archive_arguments(
                &[
                    OsString::from("-r"),
                    fresh.as_os_str().to_owned(),
                    OsString::from("@objects.rsp"),
                ],
                &root,
                &work,
            )
            .is_err()
        );
        fs::remove_file(&fresh).unwrap();
        let unsupported = normalize_native_archive_arguments(
            &[
                OsString::from("qv"),
                OsString::from("archive.a"),
                OsString::from("@objects.rsp"),
            ],
            &root,
            &work,
        )
        .unwrap_err();
        assert_eq!(
            unsupported.to_string(),
            "archive adapter received unsupported operation \"qv\""
        );
        assert_eq!(
            normalize_native_archive_arguments(
                &[
                    OsString::from("t"),
                    OsString::from("archive.a"),
                    OsString::from("@objects.rsp"),
                ],
                &root,
                &work,
            )
            .unwrap()
            .into_iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
            ["t", "archive.a", "@objects.rsp"]
        );
        for operation in ["x", "s", "--version"] {
            assert!(
                normalize_native_archive_arguments(
                    &[
                        OsString::from(operation),
                        OsString::from("archive.a"),
                        OsString::from("@objects.rsp"),
                    ],
                    &root,
                    &work,
                )
                .is_err(),
                "unsupported operation {operation:?} was accepted"
            );
        }
        for argument in [
            "--thin",
            "--format=darwin",
            "--output=/outside",
            "--version",
            "-M",
        ] {
            assert!(
                normalize_native_archive_arguments(
                    &[
                        OsString::from("q"),
                        OsString::from("archive.a"),
                        OsString::from(argument),
                    ],
                    &root,
                    &work,
                )
                .is_err(),
                "unsupported argument {argument:?} was accepted"
            );
        }
        assert!(
            normalize_native_archive_arguments(
                &[
                    OsString::from("q"),
                    OsString::from("../archive.a"),
                    OsString::from("@objects.rsp"),
                ],
                &root,
                &work,
            )
            .is_err()
        );
        let outside = std::env::temp_dir().join(format!(
            "hell-archive-adapter-outside-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&outside, b"outside\n").unwrap();
        assert!(
            normalize_native_archive_arguments(
                &[OsString::from("t"), outside.as_os_str().to_owned(),],
                &root,
                &work,
            )
            .is_err()
        );
        fs::remove_file(&outside).unwrap();
        fs::write(work.join("unsafe.rsp"), b"--thin\n").unwrap();
        assert!(
            normalize_native_archive_arguments(
                &[
                    OsString::from("q"),
                    OsString::from("archive.a"),
                    OsString::from("@unsafe.rsp"),
                ],
                &root,
                &work,
            )
            .is_err()
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn tracked_oracle_checkout_rejects_modified_tracked_files() {
        let root = std::env::temp_dir().join(format!(
            "hell-oracle-checkout-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let source = fs::canonicalize(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .and_then(Path::parent)
                .unwrap(),
        )
        .unwrap();
        let clone = CommandSpec::new("git", Duration::from_secs(30))
            .arguments(["clone", "--quiet", "--shared"])
            .argument(&source)
            .argument(&root)
            .run()
            .unwrap();
        assert!(clone.status.success() && !clone.timed_out);
        let head = CommandSpec::new("git", Duration::from_secs(30))
            .arguments(["rev-parse", "HEAD"])
            .current_directory(&root)
            .run()
            .unwrap();
        assert!(head.status.success() && !head.timed_out);
        let head = std::str::from_utf8(&head.stdout).unwrap().trim();
        verify_tracked_checkout(&root, head).unwrap();
        fs::write(root.join("untracked"), b"rejected\n").unwrap();
        assert!(verify_tracked_checkout(&root, head).is_err());
        fs::remove_file(root.join("untracked")).unwrap();
        fs::write(root.join("Cargo.toml"), b"changed\n").unwrap();
        assert!(verify_tracked_checkout(&root, head).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
