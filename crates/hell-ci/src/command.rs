use std::cell::RefCell;
#[cfg(unix)]
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
#[cfg(windows)]
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hell_testkit::{
    BoundProgramInvocation, Digest, run_supervised_command,
    run_supervised_command_with_bound_program, sha256_file,
};

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
        use std::os::windows::fs::OpenOptionsExt as _;

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        let guard = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|error| format!("cannot lock Windows file identity: {error}"))?;
        let metadata = guard
            .metadata()
            .map_err(|error| format!("cannot inspect locked Windows file: {error}"))?;
        if !metadata.is_file() {
            return Err("Windows file identity is not regular".to_owned());
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot canonicalize locked Windows file: {error}"))?;
        Ok(Self {
            _guard: Arc::new(guard),
            handle: Arc::new(
                same_file::Handle::from_path(&canonical)
                    .map_err(|error| format!("cannot bind safe Windows file handle: {error}"))?,
            ),
            canonical,
            size: metadata.len(),
            sha256: sha256_file(path)
                .map_err(|error| format!("cannot hash locked Windows file: {error}"))?,
        })
    }

    pub(crate) fn revalidate(&self, path: &Path) -> Result<(), String> {
        if Self::bind(path)? != *self {
            return Err("Windows file identity changed before use".to_owned());
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
    pub(crate) fn canonical(&self) -> &Path {
        &self.canonical
    }

    pub(crate) fn device(&self) -> u64 {
        self.device
    }

    pub(crate) fn inode(&self) -> u64 {
        self.inode
    }

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
        if observed.canonical_identity != self.canonical_identity {
            return Err("resolved standard tool identity changed before spawn".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessScope {
    IsolatedTree,
}

pub(crate) struct NativeArchiveAdapter {
    _directory: Option<AdapterDirectory>,
    llvm_ar: Option<PathBuf>,
    llvm_ar_version: Option<String>,
    path: Option<OsString>,
    stack_yaml: Option<PathBuf>,
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
}

impl AdapterDirectory {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AdapterDirectory {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let authority = self.path.join(".authority");
            if fs::symlink_metadata(&authority).is_ok_and(|metadata| metadata.is_dir())
                && fs::set_permissions(&authority, fs::Permissions::from_mode(0o755)).is_err()
            {
                return;
            }
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

static ADAPTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn create_adapter_directory(base: &Path) -> Result<AdapterDirectory, String> {
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
    Err("cannot allocate a collision-free macOS archive adapter directory".to_owned())
}

fn accepted_llvm_ar_version(output: &str) -> bool {
    output.lines().any(|line| {
        matches!(
            line.trim(),
            "Homebrew LLVM version 18.1.8" | "Homebrew LLVM version 22.1.8"
        )
    })
}

#[cfg(unix)]
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
                llvm_ar: None,
                llvm_ar_version: None,
                path: None,
                stack_yaml: None,
            });
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (base, source, confined_launcher);
            return Err("the macOS native archive adapter requires a macOS host".to_owned());
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::symlink;

            let llvm_ar = resolve_path_executable(OsStr::new("llvm-ar"))?;
            let version = CommandSpec::new(llvm_ar.as_os_str(), Duration::from_secs(30))
                .argument("--version")
                .run()
                .map_err(|error| format!("cannot identify LLVM archiver: {error}"))?;
            if !version.status.success() || version.timed_out {
                return Err("LLVM archiver identity command failed".to_owned());
            }
            let version = std::str::from_utf8(&version.stdout)
                .map_err(|_| "LLVM archiver identity is not UTF-8".to_owned())?;
            if !accepted_llvm_ar_version(version) {
                return Err("LLVM archiver version differs from native CI policy".to_owned());
            }
            let llvm_ar_version = version.trim().to_owned();
            let inherited = std::env::var_os("PATH").ok_or_else(|| {
                "standard PATH is required for the macOS archive adapter".to_owned()
            })?;
            let current_directory = std::env::current_dir()
                .map_err(|error| format!("cannot resolve archive adapter PATH: {error}"))?;
            let directory = create_adapter_directory(base)?;
            let adapter_root = directory.path();
            prepare_adapter_work_directory(adapter_root)?;
            let executable = match confined_launcher {
                Some(path) => fs::canonicalize(path)
                    .map_err(|error| format!("cannot bind confined archive adapter: {error}"))?,
                None => std::env::current_exe()
                    .map_err(|error| format!("cannot locate CI driver executable: {error}"))?,
            };
            let authority = adapter_root.join(".authority");
            fs::create_dir(&authority)
                .map_err(|error| format!("cannot create macOS archive authority: {error}"))?;
            symlink(&executable, adapter_root.join("ar"))
                .map_err(|error| format!("cannot install macOS archive adapter: {error}"))?;
            bind_and_freeze_native_archive_authority(&authority, &llvm_ar)?;
            let work = adapter_root.join(".stack-work");
            fs::write(work.join("member.o"), b"native-archive-adapter\n")
                .map_err(|error| format!("cannot write archiver probe member: {error}"))?;
            let inner = CommandSpec::new(
                authority.join("llvm-ar").as_os_str(),
                Duration::from_secs(30),
            )
            .arguments(["qcls", "inner.a", "member.o"])
            .current_directory(&work)
            .run()
            .map_err(|error| format!("cannot build archiver probe input: {error}"))?;
            if !inner.status.success() || inner.timed_out {
                return Err("LLVM archiver cannot build the nested-archive probe".to_owned());
            }
            fs::write(work.join("response.rsp"), b"inner.a\n")
                .map_err(|error| format!("cannot write archiver response probe: {error}"))?;
            let bound_llvm_ar = authority.join("llvm-ar");
            let probe = native_archive_feature_probe(&bound_llvm_ar, &work)
                .run()
                .map_err(|error| format!("cannot probe LLVM archiver: {error}"))?;
            if !probe.status.success() || probe.timed_out {
                return Err(
                    "LLVM archiver lacks required response-file/flattening support".to_owned(),
                );
            }
            let table = CommandSpec::new(bound_llvm_ar.as_os_str(), Duration::from_secs(30))
                .arguments(["t", "outer.a"])
                .current_directory(&work)
                .run()
                .map_err(|error| format!("cannot inspect archiver flattening probe: {error}"))?;
            if !table.status.success() || table.timed_out || table.stdout != b"member.o\n" {
                return Err("LLVM archiver did not flatten the nested archive exactly".to_owned());
            }
            clean_native_archive_probe(&work)?;
            let path = native_archive_path(&inherited, adapter_root, &llvm_ar, &current_directory)?;
            let stack_yaml = write_native_stack_overlay(adapter_root, source)?;
            Ok(Self {
                _directory: Some(directory),
                llvm_ar: Some(llvm_ar),
                llvm_ar_version: Some(llvm_ar_version),
                path: Some(path),
                stack_yaml: Some(stack_yaml),
            })
        }
    }

    #[cfg(unix)]
    pub(crate) fn directory_path(&self) -> Option<&Path> {
        self._directory.as_ref().map(AdapterDirectory::path)
    }

    pub(crate) fn apply(&self, command: CommandSpec) -> CommandSpec {
        match &self.path {
            Some(path) => command.environment("PATH", path),
            None => command,
        }
    }

    pub(crate) fn identity_command(&self) -> Option<CommandSpec> {
        self.llvm_ar.as_ref().map(|llvm_ar| {
            CommandSpec::new(llvm_ar.as_os_str(), Duration::from_secs(30)).argument("--version")
        })
    }

    pub(crate) fn stack_build(&self, source: &Path, timeout: Duration) -> CommandSpec {
        let stack_yaml = self.stack_yaml_path();
        self.apply(native_stack_build(source, stack_yaml, timeout))
            .current_directory(stack_yaml.parent().unwrap_or(source))
    }

    pub(crate) fn stack_path(&self, source: &Path) -> CommandSpec {
        let stack_yaml = self.stack_yaml_path();
        self.apply(native_stack_path(source, stack_yaml))
            .current_directory(stack_yaml.parent().unwrap_or(source))
    }

    pub(crate) fn stack_ghc_version(&self, source: &Path) -> CommandSpec {
        let stack_yaml = self.stack_yaml_path();
        self.apply(native_stack_ghc_version(source, stack_yaml))
            .current_directory(stack_yaml.parent().unwrap_or(source))
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
        let llvm_ar = self
            .llvm_ar
            .as_deref()
            .map(fs::canonicalize)
            .transpose()
            .map_err(|error| format!("cannot canonicalize LLVM archiver: {error}"))?;
        let llvm_ar_sha256 = llvm_ar
            .as_deref()
            .map(sha256_file)
            .transpose()
            .map_err(|error| format!("cannot hash LLVM archiver: {error}"))?;
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
fn prepare_adapter_work_directory(adapter_root: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(adapter_root, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("cannot confine macOS archive adapter directory: {error}"))?;
    let work_directory = adapter_root.join(".stack-work");
    fs::create_dir(&work_directory)
        .map_err(|error| format!("cannot create candidate Stack work directory: {error}"))?;
    fs::set_permissions(&work_directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("cannot confine candidate Stack work directory: {error}"))
}

#[cfg(unix)]
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
    Ok(format!("'{}'", value.replace('\'', "''")))
}

fn write_native_stack_overlay(directory: &Path, source: &Path) -> Result<PathBuf, String> {
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
    let overlay = format!(
        "resolver: nightly-2024-10-21\npackages:\n  - {package}\nsystem-ghc: true\nallow-different-user: true\nghc-options:\n  \"$everything\": \"-split-sections -j\"\n  unix-time: \"-optl-all_load\"\n  network-control: \"-fforce-recomp\"\n"
    );
    let overlay_path = directory.join("stack.yaml");
    fs::write(&overlay_path, overlay)
        .map_err(|error| format!("cannot write native Stack overlay: {error}"))?;
    fs::write(directory.join("stack.yaml.lock"), stack_lock)
        .map_err(|error| format!("cannot copy pinned native Stack lock: {error}"))?;
    Ok(overlay_path)
}

fn native_archive_path(
    inherited: &OsStr,
    adapter_root: &Path,
    llvm_ar: &Path,
    current_directory: &Path,
) -> Result<OsString, String> {
    let llvm_ar = fs::canonicalize(llvm_ar)
        .map_err(|error| format!("cannot canonicalize LLVM archiver: {error}"))?;
    let provision_directory = llvm_ar
        .parent()
        .ok_or_else(|| "LLVM archiver has no provision directory".to_owned())?;
    let mut paths = vec![adapter_root.to_owned()];
    paths.extend(std::env::split_paths(inherited).filter(|entry| {
        let resolved = if entry.is_absolute() {
            entry.clone()
        } else {
            current_directory.join(entry)
        };
        let is_provision_directory =
            fs::canonicalize(&resolved).is_ok_and(|resolved| resolved == provision_directory);
        let exposes_selected_archiver =
            fs::canonicalize(resolved.join("llvm-ar")).is_ok_and(|candidate| candidate == llvm_ar);
        !is_provision_directory && !exposes_selected_archiver
    }));
    std::env::join_paths(paths)
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
    source_date_epoch: OsString,
}

thread_local! {
    static RELEASE_CANDIDATE_ENVIRONMENT: RefCell<Option<ReleaseCandidateEnvironment>> = const { RefCell::new(None) };
}

pub(crate) fn with_release_candidate_environment<T>(
    target: &std::path::Path,
    source_date_epoch: u64,
    launch_policy: &hell_testkit::CandidateLaunchPolicy,
    operation: impl FnOnce() -> T,
) -> T {
    let environment = ReleaseCandidateEnvironment {
        target: target.as_os_str().to_owned(),
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
        };
        if let Some(release) = RELEASE_CANDIDATE_ENVIRONMENT.with(|slot| slot.borrow().clone()) {
            let isolated = PathBuf::from(&release.target).join("release-child-environment");
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
        Self {
            program: resolved.invocation_path.clone().into_os_string(),
            arguments: Vec::new(),
            current_directory: None,
            environment: Vec::new(),
            clear_environment: false,
            process_scope: ProcessScope::IsolatedTree,
            timeout,
            canonical_executable_identity: Some(resolved.canonical_identity.clone()),
            invocation_name: Some(resolved.invocation_name.clone()),
            program_resolution_error: None,
        }
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
        if let Some(error) = &self.program_resolution_error {
            return Err(CommandRunError::new(
                CommandRunPhase::ProgramResolution,
                std::io::Error::new(std::io::ErrorKind::NotFound, error.clone()),
            ));
        }
        if let Some(expected) = &self.canonical_executable_identity {
            revalidate_resolved_cargo(Path::new(&self.program), expected)
                .map_err(|error| CommandRunError::new(CommandRunPhase::ProgramResolution, error))?;
        }
        let mut command = Command::new(&self.program);
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

        let started = Instant::now();
        let output = if let Some(expected) = &self.canonical_executable_identity {
            let identity =
                BoundProgramInvocation::new(PathBuf::from(&self.program), expected.clone())
                    .map_err(|error| {
                        CommandRunError::new(CommandRunPhase::ProgramResolution, error)
                    })?;
            run_supervised_command_with_bound_program(&mut command, &[], self.timeout, &identity)
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
        };
        if let Err(error) = std::io::stdout().write_all(&result.stdout) {
            return Err(CommandRunError::after_completion(
                CommandRunPhase::StdoutRelay,
                error,
                result,
            ));
        }
        if let Err(error) = std::io::stderr().write_all(&result.stderr) {
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
fn resolve_path_executable(name: &OsStr) -> Result<PathBuf, String> {
    Ok(resolve_standard_path_executable(name)?
        .invocation_path
        .clone())
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
    Some(ResolvedStandardExecutable {
        invocation_path: canonical_parent.join(file_name),
        canonical_identity,
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
    let toolchain = parse_active_rustup_toolchain(&run_bound_windows_rustup_probe(
        &rustup,
        candidate_root,
        &["show", "active-toolchain"],
    )?)?;
    let toolchain_root = home.join("toolchains").join(&toolchain);
    if fs::canonicalize(&toolchain_root).ok().as_deref() != Some(toolchain_root.as_path()) {
        return Err("active Windows Rust toolchain path is redirected".to_owned());
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
        "restricted Windows target prelaunch evidence: program={},imports={imports},SystemRoot={system_root},PATH={path},cwd={cwd}",
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
    current_directory: &Path,
    work_directory: &Path,
) -> std::io::Result<()> {
    let mut positional_only = false;
    for argument in arguments {
        if positional_only {
            continue;
        }
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
            validate_native_archive_response(response, current_directory, work_directory)?;
        } else if value.starts_with('-') {
            return Err(std::io::Error::other(format!(
                "archive adapter received unsupported argument {value:?}"
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_native_archive_response(
    response: &str,
    current_directory: &Path,
    work_directory: &Path,
) -> std::io::Result<()> {
    let response = Path::new(response);
    let response = if response.is_absolute() {
        response.to_path_buf()
    } else {
        current_directory.join(response)
    };
    let metadata = fs::symlink_metadata(&response).map_err(|error| {
        std::io::Error::other(format!("cannot inspect archive response file: {error}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::other(
            "archive response file is not a regular real file",
        ));
    }
    let canonical = fs::canonicalize(&response).map_err(|error| {
        std::io::Error::other(format!("cannot bind archive response file: {error}"))
    })?;
    if !canonical.starts_with(work_directory) {
        return Err(std::io::Error::other(
            "archive response file escapes its bound work directory",
        ));
    }
    let contents = fs::read_to_string(&canonical).map_err(|error| {
        std::io::Error::other(format!("cannot read archive response file: {error}"))
    })?;
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
    }
    Ok(())
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
pub(crate) fn run_native_archive_adapter(arguments: &[OsString]) -> std::process::ExitCode {
    let result = (|| {
        let invoked = std::env::args_os()
            .next()
            .ok_or_else(|| std::io::Error::other("archive adapter argv[0] is missing"))?;
        let directory = archive_adapter_directory(&invoked)?;
        let current_directory = std::env::current_dir()?;
        let normalized =
            normalize_native_archive_arguments(arguments, &directory, &current_directory)?;
        Command::new(directory.join(".authority").join("llvm-ar"))
            .args(normalized)
            .status()
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
fn normalize_native_archive_arguments(
    arguments: &[OsString],
    adapter_root: &Path,
    current_directory: &Path,
) -> std::io::Result<Vec<OsString>> {
    let Some(first) = arguments.first() else {
        return Err(std::io::Error::other(
            "archive adapter arguments are missing",
        ));
    };
    let work_directory = adapter_root.join(".stack-work");
    let bound_work_directory = fs::canonicalize(&work_directory).map_err(|error| {
        std::io::Error::other(format!("cannot bind archive work directory: {error}"))
    })?;
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
    if !canonical_target.starts_with(&bound_work_directory) {
        return Err(std::io::Error::other(
            "archive adapter target escapes its bound work directory",
        ));
    }
    validate_native_archive_arguments(
        &arguments[target_index + 1..],
        current_directory,
        &bound_work_directory,
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
    Ok(normalized)
}

#[cfg(unix)]
pub(crate) fn run_posix_release_child(arguments: &[OsString]) -> std::process::ExitCode {
    let error = exec_posix_release_child(arguments);
    eprintln!("POSIX release child launcher failed: {error}");
    std::process::ExitCode::FAILURE
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
    if framed.len() <= pair_arguments {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child environment framing is incomplete",
        ));
    }
    let (encoded_environment, command_arguments) = framed.split_at(pair_arguments);
    let (program, child_arguments) = command_arguments
        .split_first()
        .expect("framing check retained the program");
    if !Path::new(program).is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child program is not absolute",
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
    command.args(child_arguments).env_clear().envs(environment);
    Ok(command)
}

#[cfg(windows)]
pub(crate) fn run_windows_restricted_child(arguments: &[OsString]) -> std::process::ExitCode {
    match windows_restricted_child(arguments) {
        Ok((code, evidence)) => {
            let outcome = windows_restricted_child_outcome(code, &evidence);
            if let Some(diagnostic) = outcome.diagnostic {
                eprintln!("{diagnostic}");
            }
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
    let target_arguments = decoded.collect::<Vec<_>>();
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
    })
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsRestrictedTokenConstraint {
    DisableMaximumPrivileges,
    LuaToken,
    WriteRestricted,
}

#[cfg(any(windows, test))]
const WINDOWS_RESTRICTED_TOKEN_CONSTRAINTS: [WindowsRestrictedTokenConstraint; 3] = [
    WindowsRestrictedTokenConstraint::DisableMaximumPrivileges,
    WindowsRestrictedTokenConstraint::LuaToken,
    WindowsRestrictedTokenConstraint::WriteRestricted,
];

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsRestrictingSidConstraint {
    RestrictedCode,
    LogonSession,
}

#[cfg(any(windows, test))]
const WINDOWS_RESTRICTING_SID_CONSTRAINTS: [WindowsRestrictingSidConstraint; 2] = [
    WindowsRestrictingSidConstraint::RestrictedCode,
    WindowsRestrictingSidConstraint::LogonSession,
];

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsPrivateGraphicalAuthority {
    LocalSystem,
    LogonSession,
    RestrictedCode,
}

#[cfg(any(windows, test))]
const WINDOWS_PRIVATE_WINDOW_STATION_AUTHORITIES: [WindowsPrivateGraphicalAuthority; 3] = [
    WindowsPrivateGraphicalAuthority::LocalSystem,
    WindowsPrivateGraphicalAuthority::RestrictedCode,
    WindowsPrivateGraphicalAuthority::LogonSession,
];

#[cfg(any(windows, test))]
const WINDOWS_PRIVATE_DESKTOP_AUTHORITIES: [WindowsPrivateGraphicalAuthority; 3] = [
    WindowsPrivateGraphicalAuthority::LocalSystem,
    WindowsPrivateGraphicalAuthority::RestrictedCode,
    WindowsPrivateGraphicalAuthority::LogonSession,
];

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

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsPrivateWindowStationCreation {
    CreateOnly,
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsPrivateGraphicalSessionSpec {
    window_station_name: String,
    window_station_creation: WindowsPrivateWindowStationCreation,
    desktop_name: String,
    startup_binding: String,
    inherit_handle: bool,
    window_station_authorities: [WindowsPrivateGraphicalAuthority; 3],
    desktop_authorities: [WindowsPrivateGraphicalAuthority; 3],
}

#[cfg(any(windows, test))]
fn windows_private_graphical_session_spec(nonce: [u8; 16]) -> WindowsPrivateGraphicalSessionSpec {
    use std::fmt::Write as _;

    let mut window_station_name = String::from("hell-rs-release-");
    for byte in nonce {
        write!(&mut window_station_name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let desktop_name = "desktop".to_owned();
    let startup_binding = format!("{window_station_name}\\{desktop_name}");
    WindowsPrivateGraphicalSessionSpec {
        window_station_name,
        window_station_creation: WindowsPrivateWindowStationCreation::CreateOnly,
        desktop_name,
        startup_binding,
        inherit_handle: false,
        window_station_authorities: WINDOWS_PRIVATE_WINDOW_STATION_AUTHORITIES,
        desktop_authorities: WINDOWS_PRIVATE_DESKTOP_AUTHORITIES,
    }
}

#[cfg(windows)]
fn windows_restricted_token_flags() -> firehazard::token::RestrictedFlags {
    WINDOWS_RESTRICTED_TOKEN_CONSTRAINTS.into_iter().fold(
        Default::default(),
        |flags, constraint| {
            flags
                | match constraint {
                    WindowsRestrictedTokenConstraint::DisableMaximumPrivileges => {
                        firehazard::token::DISABLE_MAX_PRIVILEGE
                    }
                    WindowsRestrictedTokenConstraint::LuaToken => firehazard::token::LUA_TOKEN,
                    WindowsRestrictedTokenConstraint::WriteRestricted => {
                        firehazard::token::WRITE_RESTRICTED
                    }
                }
        },
    )
}

#[cfg(windows)]
fn windows_private_graphical_acl(
    logon_sid: firehazard::sid::Ptr<'_>,
    restricted_sid: firehazard::sid::Ptr<'_>,
    local_system_sid: firehazard::sid::Ptr<'_>,
    authorities: [WindowsPrivateGraphicalAuthority; 3],
) -> std::io::Result<firehazard::acl::Builder> {
    let mut acl = firehazard::acl::Builder::new(firehazard::acl::REVISION);
    for authority in authorities {
        let sid = match authority {
            WindowsPrivateGraphicalAuthority::LogonSession => logon_sid,
            WindowsPrivateGraphicalAuthority::RestrictedCode => restricted_sid,
            WindowsPrivateGraphicalAuthority::LocalSystem => local_system_sid,
        };
        acl.add_access_allowed_ace(
            firehazard::acl::REVISION,
            firehazard::access::GENERIC_ALL.into(),
            sid,
        )?;
    }
    acl.finish()?;
    Ok(acl)
}

#[cfg(any(windows, test))]
fn windows_private_graphical_authority_contract(
    authorities: &[WindowsPrivateGraphicalAuthority],
) -> std::io::Result<()> {
    let expected = [
        WindowsPrivateGraphicalAuthority::LocalSystem,
        WindowsPrivateGraphicalAuthority::RestrictedCode,
        WindowsPrivateGraphicalAuthority::LogonSession,
    ];
    if authorities.len() == expected.len()
        && expected
            .iter()
            .all(|authority| authorities.contains(authority))
    {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "private graphical objects must grant LocalSystem and both restricting SIDs GENERIC_ALL",
        ))
    }
}

#[cfg(windows)]
fn create_windows_private_graphical_session(
    logon_sid: firehazard::sid::Ptr<'_>,
    restricted_sid: firehazard::sid::Ptr<'_>,
    local_system_sid: firehazard::sid::Ptr<'_>,
) -> std::io::Result<(
    firehazard::winsta::OwnedHandle,
    firehazard::desktop::OwnedHandle,
    widestring::U16CString,
)> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|error| {
        std::io::Error::other(format!("cannot name private window station: {error}"))
    })?;
    let spec = windows_private_graphical_session_spec(nonce);
    windows_private_graphical_authority_contract(&spec.window_station_authorities)?;
    windows_private_graphical_authority_contract(&spec.desktop_authorities)?;

    let station_acl = windows_private_graphical_acl(
        logon_sid,
        restricted_sid,
        local_system_sid,
        spec.window_station_authorities,
    )?;
    let station_descriptor = firehazard::security::DescriptorBuilder::new()
        .dacl(true, Some(station_acl.as_acl_ptr()), false)?
        .finish();
    let station_attributes =
        firehazard::security::Attributes::new(Some(&station_descriptor), spec.inherit_handle);
    let station_name =
        widestring::U16CString::from_str(&spec.window_station_name).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("private window-station name contains NUL: {error}"),
            )
        })?;
    let station_creation = match spec.window_station_creation {
        WindowsPrivateWindowStationCreation::CreateOnly => firehazard::winsta::CWF_CREATE_ONLY,
    };
    let station = firehazard::create_window_station_w(
        station_name.as_ucstr(),
        station_creation,
        firehazard::winsta::ALL_ACCESS,
        Some(&station_attributes),
    )?;

    let original_station = firehazard::open_process_window_station()?;
    firehazard::set_process_window_station(&station)?;
    let desktop_acl = windows_private_graphical_acl(
        logon_sid,
        restricted_sid,
        local_system_sid,
        spec.desktop_authorities,
    )?;
    let desktop_descriptor = firehazard::security::DescriptorBuilder::new()
        .dacl(true, Some(desktop_acl.as_acl_ptr()), false)?
        .finish();
    let desktop_attributes =
        firehazard::security::Attributes::new(Some(&desktop_descriptor), spec.inherit_handle);
    let desktop_name = widestring::U16CString::from_str(&spec.desktop_name).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("private desktop name contains NUL: {error}"),
        )
    })?;
    let desktop_result = firehazard::create_desktop_w(
        desktop_name.as_ucstr(),
        (),
        None,
        None,
        firehazard::access::GENERIC_ALL,
        Some(&desktop_attributes),
    );
    if let Err(error) = firehazard::set_process_window_station(&original_station) {
        // This launcher is an ephemeral one-child process. If restoration
        // fails, retain both station handles until process exit rather than
        // closing a process-bound station and obscuring the original error.
        std::mem::forget(original_station);
        std::mem::forget(station);
        return Err(error.into());
    }
    // SetProcessWindowStation binds the duplicated handle itself. It cannot
    // be closed while it remains the process station, and this dedicated
    // launcher exits immediately after the child, so retain it until exit.
    std::mem::forget(original_station);
    let desktop = desktop_result?;
    let startup_binding =
        widestring::U16CString::from_str(spec.startup_binding).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("private desktop binding contains NUL: {error}"),
            )
        })?;
    Ok((station, desktop, startup_binding))
}

#[cfg(windows)]
fn windows_restricted_child(arguments: &[OsString]) -> std::io::Result<(u32, String)> {
    use std::os::windows::ffi::OsStrExt as _;

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
    let target_token = hell_testkit::encode_windows_argv(&request.target_arguments)?;
    let mut command_line = "hell-test-helper __release-argv-child "
        .encode_utf16()
        .chain(target_token.encode_wide())
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let application =
        widestring::U16CString::from_os_str(launcher.as_os_str()).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("restricted child launcher path contains NUL: {error}"),
            )
        })?;
    let process_token = firehazard::open_process_token(
        firehazard::get_current_process(),
        firehazard::token::ALL_ACCESS,
    )?;
    let restricted_sid = firehazard::convert_string_sid_to_sid_w(widestring::u16cstr!("S-1-5-12"))?;
    let local_system_sid =
        firehazard::convert_string_sid_to_sid_w(widestring::u16cstr!("S-1-5-18"))?;
    let logon_groups = process_token.logon_sid()?;
    let [logon_group] = logon_groups.groups() else {
        return Err(std::io::Error::other(
            "current Windows token must contain exactly one logon SID",
        ));
    };
    // WRITE_RESTRICTED applies this second SID set only to writes. Restricted
    // Code binds the explicitly prepared filesystem DACLs, while both restricting
    // SIDs bind the ephemeral private station and desktop. Cargo imports USER32
    // and COM DLLs whose initialization writes those graphical objects before
    // Rust entry, and a write check grants access only when every restricting
    // SID is admitted. CSRSS owns graphical-object setup in the LocalSystem
    // account, so it must retain authority on the same private objects.
    let restricted = WINDOWS_RESTRICTING_SID_CONSTRAINTS.map(|constraint| match constraint {
        WindowsRestrictingSidConstraint::RestrictedCode => {
            firehazard::sid::AndAttributes::new(&restricted_sid, ())
        }
        WindowsRestrictingSidConstraint::LogonSession => {
            firehazard::sid::AndAttributes::new(logon_group.sid, ())
        }
    });
    let token = firehazard::create_restricted_token(
        &process_token,
        windows_restricted_token_flags(),
        None,
        None,
        Some(&restricted),
    )?;

    let job = firehazard::create_job_object_w(None, ())?;
    let limits = firehazard::job::object::ExtendedLimitInformation {
        basic_limit_information: firehazard::job::object::BasicLimitInformation {
            limit_flags: firehazard::job::object::limit::KILL_ON_JOB_CLOSE,
            ..Default::default()
        },
        ..Default::default()
    };
    firehazard::set_information_job_object(&job, limits)?;

    let (private_window_station, private_desktop, private_desktop_name) =
        create_windows_private_graphical_session(
            logon_group.sid,
            restricted_sid.as_sid_ptr(),
            local_system_sid.as_sid_ptr(),
        )?;
    let desktop_name =
        abistr::CStrNonNull::<u16>::from_units_with_nul(private_desktop_name.as_slice_with_nul())
            .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("private desktop binding is not terminated: {error}"),
            )
        })?;
    windows_restricted_stdio_contract(&WINDOWS_RESTRICTED_STDIO_HANDLES)?;
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
    let attributes = [firehazard::process::ThreadAttributeRef::handle_list(
        &inherited_handles,
    )];
    let mut startup = firehazard::process::StartupInfoExW::default();
    startup.startup_info.desktop = Some(desktop_name);
    startup.startup_info.flags = WINDOWS_STARTF_USE_STD_HANDLES;
    startup.startup_info.std_input = Some((&stdin_read).into());
    startup.startup_info.std_output = Some((&stdout_write).into());
    startup.startup_info.std_error = Some((&stderr_write).into());
    startup.attribute_list = Some(firehazard::process::ThreadAttributeList::try_from(
        attributes.as_slice(),
    )?);
    let process = firehazard::create_process_as_user_w(
        &token,
        application,
        Some(&mut command_line),
        None,
        None,
        true,
        firehazard::process::CREATE_SUSPENDED | firehazard::process::EXTENDED_STARTUPINFO_PRESENT,
        firehazard::process::environment::Inherit,
        (),
        &startup,
    )?;
    firehazard::assign_process_to_job_object(&job, &process.process)?;
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
        relay_windows_restricted_diagnostic(stderr_read, stderr.lock())
    });
    firehazard::thread::resume_thread(&process.thread)?;
    let status = firehazard::process::wait_for_process(&process.process)?;
    drop(job);
    stdout_relay
        .join()
        .map_err(|_| std::io::Error::other("restricted stdout relay panicked"))??;
    stderr_relay
        .join()
        .map_err(|_| std::io::Error::other("restricted stderr relay panicked"))??;
    drop(private_desktop);
    drop(private_window_station);
    Ok((status, prelaunch_evidence))
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

    #[cfg(unix)]
    #[test]
    fn standard_tool_resolver_preserves_absolute_path_authority_order() {
        let first = ResolverDirectory::new("standard-first");
        let second = ResolverDirectory::new("standard-second");
        let expected = first.tool("chmod", true);
        second.tool("chmod", true);
        let resolved = resolve_standard_path_executable_from(
            OsStr::new("chmod"),
            &[
                PathBuf::from("relative-path-is-not-authority"),
                first.0.clone(),
                second.0.clone(),
            ],
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
        assert!(resolve_standard_path_executable_from(OsStr::new("bin/chmod"), &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn absolute_standard_tool_binding_rejects_relative_and_nonexecutables() {
        let root = ResolverDirectory::new("absolute-standard");
        let executable = root.tool("tool", true);
        let nonexecutable = root.tool("data", false);
        let resolved = resolve_absolute_standard_executable(&executable).unwrap();
        assert_eq!(
            resolved.invocation_path(),
            fs::canonicalize(executable).unwrap()
        );
        resolved.revalidate().unwrap();
        assert!(resolve_absolute_standard_executable(Path::new("tool")).is_err());
        assert!(resolve_absolute_standard_executable(&nonexecutable).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn standard_tool_resolver_revalidates_bound_identity_before_spawn() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = ResolverDirectory::new("standard-substitution");
        let first = root.tool("chmod-first", true);
        let second = root.tool("chmod-second", true);
        let alias = root.path().join("chmod");
        symlink(first, &alias).unwrap();
        let resolved = resolve_standard_path_executable_from(
            OsStr::new("chmod"),
            std::slice::from_ref(&root.0),
        )
        .unwrap();
        resolved.revalidate().unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(second, &alias).unwrap();
        assert!(resolved.revalidate().is_err());

        let unusable = ResolverDirectory::new("standard-not-effective");
        let unusable_chmod = unusable.tool("chmod", false);
        fs::set_permissions(&unusable_chmod, fs::Permissions::from_mode(0o001)).unwrap();
        let fallback = ResolverDirectory::new("standard-effective");
        let expected = fallback.tool("chmod", true);
        let resolved = resolve_standard_path_executable_from(
            OsStr::new("chmod"),
            &[unusable.0.clone(), fallback.0.clone()],
        )
        .unwrap();
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(expected).unwrap()
        );
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

    #[cfg(unix)]
    #[test]
    fn cargo_rustup_proxy_identity_requires_and_revalidates_the_same_file() {
        let cargo_root = ResolverDirectory::new("rustup-hardlink-cargo");
        let standard_root = ResolverDirectory::new("rustup-hardlink-standard");
        let rustup = standard_root.tool("rustup", true);
        let cargo = cargo_root.path().join("cargo");
        let rustc = standard_root.path().join("rustc");
        fs::hard_link(&rustup, &cargo).unwrap();
        fs::hard_link(&rustup, &rustc).unwrap();
        let resolved = resolve_cargo_from(Some(cargo.as_os_str()), &[], &[], true, false).unwrap();
        let standard_rustup = resolved_standard_candidate(&rustup).unwrap();
        let standard_rustc = resolved_standard_candidate(&rustc).unwrap();
        let identity = ResolvedPosixRustupProxyIdentity::bind(&resolved, &standard_rustup)
            .unwrap()
            .unwrap();
        let rustc_authority =
            ResolvedPosixRustcAuthority::bind(&standard_rustc, &identity, &rustc).unwrap();
        assert!(matches!(
            rustc_authority,
            ResolvedPosixRustcAuthority::RustupProxy { .. }
        ));
        assert_eq!(
            identity.cargo_invocation(),
            fs::canonicalize(&cargo).unwrap()
        );
        assert_eq!(identity.cargo(), fs::canonicalize(&cargo).unwrap());
        assert_eq!(identity.rustup(), fs::canonicalize(&rustup).unwrap());
        identity.revalidate().unwrap();

        fs::remove_file(&rustup).unwrap();
        let replacement = standard_root.tool("rustup", true);
        assert_eq!(fs::read(&replacement).unwrap(), fs::read(&cargo).unwrap());
        assert!(identity.revalidate().is_err());
        fs::remove_file(&rustup).unwrap();
        fs::hard_link(&cargo, &rustup).unwrap();
        fs::remove_file(&rustc).unwrap();
        let rustc_replacement = standard_root.tool("rustc", true);
        assert_eq!(
            fs::read(&rustc_replacement).unwrap(),
            fs::read(&cargo).unwrap()
        );
        assert!(
            rustc_authority.revalidate(&identity).is_err(),
            "a same-byte standard rustc proxy replacement must fail"
        );

        let selected_root = ResolverDirectory::new("selected-rustc");
        let selected_rustc = selected_root.tool("rustc", true);
        let canonical_selected_rustc = fs::canonicalize(&selected_rustc).unwrap();
        let selected_standard = resolved_standard_candidate(&selected_rustc).unwrap();
        let selected_authority = ResolvedPosixRustcAuthority::bind(
            &selected_standard,
            &identity,
            &canonical_selected_rustc,
        )
        .unwrap();
        assert!(matches!(
            selected_authority,
            ResolvedPosixRustcAuthority::SelectedToolchain { .. }
        ));
        selected_authority.revalidate(&identity).unwrap();
        let copied_root = ResolverDirectory::new("copied-rustc");
        let copied_rustc = copied_root.tool("rustc", true);
        assert_eq!(
            fs::read(&copied_rustc).unwrap(),
            fs::read(&selected_rustc).unwrap()
        );
        assert!(
            ResolvedPosixRustcAuthority::bind(
                &resolved_standard_candidate(&copied_rustc).unwrap(),
                &identity,
                &canonical_selected_rustc,
            )
            .is_err(),
            "a same-byte compiler outside the selected toolchain must fail"
        );
        let selected_replacement_source = selected_root.tool("rustc-replacement", true);
        fs::remove_file(&selected_rustc).unwrap();
        fs::rename(&selected_replacement_source, &selected_rustc).unwrap();
        let selected_replacement = selected_rustc;
        assert_eq!(
            fs::read(&selected_replacement).unwrap(),
            fs::read(&copied_rustc).unwrap()
        );
        assert!(
            selected_authority.revalidate(&identity).is_err(),
            "a same-byte selected compiler replacement must fail"
        );

        let distinct_root = ResolverDirectory::new("rustup-distinct");
        let distinct_cargo = distinct_root.tool("cargo", true);
        let distinct_rustup = distinct_root.tool("rustup", true);
        assert_eq!(
            fs::read(&distinct_cargo).unwrap(),
            fs::read(&distinct_rustup).unwrap()
        );
        let native =
            resolve_cargo_from(Some(distinct_cargo.as_os_str()), &[], &[], true, false).unwrap();
        let unrelated_rustup = resolved_standard_candidate(&distinct_rustup).unwrap();
        assert!(
            ResolvedPosixRustupProxyIdentity::bind(&native, &unrelated_rustup)
                .unwrap()
                .is_none()
        );

        let forged_root = ResolverDirectory::new("rustup-forged-name");
        let forged = forged_root.tool("rustup", true);
        let forged = resolve_cargo_from(Some(forged.as_os_str()), &[], &[], true, false).unwrap();
        assert!(
            ResolvedPosixRustupProxyIdentity::bind(&forged, &unrelated_rustup)
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            resolve_posix_cargo_authority(&forged, distinct_root.path()),
            Err(error) if error == "logical Cargo invocation must be named cargo"
        ));
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
    fn cargo_multicall_alias_preserves_invocation_name_and_exact_arguments() {
        use std::os::unix::fs::symlink;

        let cargo_root = ResolverDirectory::new("multicall-cargo");
        let standard_root = ResolverDirectory::new("multicall-standard");
        let target = std::env::current_exe().unwrap();
        let alias = cargo_root.path().join("cargo");
        let rustup = standard_root.path().join("rustup");
        let rustc = standard_root.path().join("rustc");
        symlink(&target, &alias).unwrap();
        symlink(&target, &rustup).unwrap();
        symlink(&target, &rustc).unwrap();
        let child_arguments = [
            "command::tests::cargo_multicall_argv_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ];

        let direct = CommandSpec::new(fs::canonicalize(&target).unwrap(), Duration::from_secs(1))
            .arguments(child_arguments)
            .run()
            .unwrap();
        assert!(!direct.status.success());

        let resolved = resolve_cargo_from(Some(alias.as_os_str()), &[], &[], true, false).unwrap();
        let standard_rustup = resolved_standard_candidate(&rustup).unwrap();
        let identity = ResolvedPosixRustupProxyIdentity::bind(&resolved, &standard_rustup)
            .unwrap()
            .unwrap();
        assert_eq!(
            identity.cargo_invocation(),
            fs::canonicalize(cargo_root.path()).unwrap().join("cargo")
        );
        assert_eq!(identity.cargo(), fs::canonicalize(&target).unwrap());
        assert_eq!(
            identity.cargo().file_name(),
            fs::canonicalize(&target).unwrap().file_name()
        );
        identity.revalidate().unwrap();

        let replacement_root = ResolverDirectory::new("replacement-engine");
        let replacement = replacement_root.tool("replacement-engine", true);
        fs::remove_file(&alias).unwrap();
        symlink(replacement, &alias).unwrap();
        assert!(
            identity.revalidate().is_err(),
            "a replaced logical Cargo alias must fail exact identity revalidation"
        );
        fs::remove_file(&alias).unwrap();
        symlink(&target, &alias).unwrap();
        identity.revalidate().unwrap();

        let mut forged_invocation_name = resolved.clone();
        forged_invocation_name.invocation_name = OsString::from("rustup");
        assert!(
            ResolvedPosixRustupProxyIdentity::bind(&forged_invocation_name, &standard_rustup,)
                .unwrap()
                .is_none(),
            "a canonical same-file target cannot mint a Cargo proxy without logical cargo identity"
        );
        let spec = CommandSpec::cargo_from_resolution(Duration::from_secs(1), Ok(resolved));
        assert_eq!(spec.display_invocation_name().as_deref(), Some("cargo"));
        let result = spec.arguments(child_arguments).run().unwrap();
        assert!(result.status.success());
        assert!(
            std::str::from_utf8(&result.stdout)
                .unwrap()
                .contains("cargo-multicall-argv-child")
        );
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "executed only through the typed Cargo multicall fixture"]
    fn cargo_multicall_argv_child() {
        let arguments = std::env::args_os().collect::<Vec<_>>();
        assert_eq!(
            arguments
                .first()
                .and_then(|value| Path::new(value).file_name()),
            Some(OsStr::new("cargo"))
        );
        assert_eq!(
            &arguments[1..],
            [
                OsStr::new("command::tests::cargo_multicall_argv_child"),
                OsStr::new("--exact"),
                OsStr::new("--ignored"),
                OsStr::new("--nocapture"),
            ]
        );
        println!("cargo-multicall-argv-child");
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
    fn windows_restricted_token_is_write_scoped_and_privilege_reduced() {
        assert_eq!(
            WINDOWS_RESTRICTED_TOKEN_CONSTRAINTS,
            [
                WindowsRestrictedTokenConstraint::DisableMaximumPrivileges,
                WindowsRestrictedTokenConstraint::LuaToken,
                WindowsRestrictedTokenConstraint::WriteRestricted,
            ]
        );
        assert_eq!(
            WINDOWS_RESTRICTING_SID_CONSTRAINTS,
            [
                WindowsRestrictingSidConstraint::RestrictedCode,
                WindowsRestrictingSidConstraint::LogonSession,
            ]
        );
        assert_eq!(
            WINDOWS_PRIVATE_WINDOW_STATION_AUTHORITIES,
            [
                WindowsPrivateGraphicalAuthority::LocalSystem,
                WindowsPrivateGraphicalAuthority::RestrictedCode,
                WindowsPrivateGraphicalAuthority::LogonSession,
            ]
        );
        assert_eq!(
            WINDOWS_PRIVATE_DESKTOP_AUTHORITIES,
            [
                WindowsPrivateGraphicalAuthority::LocalSystem,
                WindowsPrivateGraphicalAuthority::RestrictedCode,
                WindowsPrivateGraphicalAuthority::LogonSession,
            ]
        );
    }

    #[test]
    fn windows_private_graphical_session_is_exact_nonce_bound_and_noninheritable() {
        let first = windows_private_graphical_session_spec([0; 16]);
        let second = windows_private_graphical_session_spec([0xff; 16]);
        assert_eq!(
            first.window_station_name,
            "hell-rs-release-00000000000000000000000000000000"
        );
        assert_eq!(
            second.window_station_name,
            "hell-rs-release-ffffffffffffffffffffffffffffffff"
        );
        for spec in [first, second] {
            assert!(!spec.inherit_handle);
            assert_eq!(
                spec.window_station_creation,
                WindowsPrivateWindowStationCreation::CreateOnly
            );
            assert_eq!(
                spec.window_station_authorities,
                [
                    WindowsPrivateGraphicalAuthority::LocalSystem,
                    WindowsPrivateGraphicalAuthority::RestrictedCode,
                    WindowsPrivateGraphicalAuthority::LogonSession,
                ]
            );
            assert_eq!(
                spec.desktop_authorities,
                [
                    WindowsPrivateGraphicalAuthority::LocalSystem,
                    WindowsPrivateGraphicalAuthority::RestrictedCode,
                    WindowsPrivateGraphicalAuthority::LogonSession,
                ]
            );
            assert!(
                spec.window_station_name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            );
            assert_eq!(spec.desktop_name, "desktop");
            assert_eq!(
                spec.startup_binding,
                format!("{}\\desktop", spec.window_station_name)
            );
        }
    }

    #[test]
    fn windows_private_graphical_authorities_are_order_insensitive_but_exact() {
        for authorities in [
            [
                WindowsPrivateGraphicalAuthority::LocalSystem,
                WindowsPrivateGraphicalAuthority::RestrictedCode,
                WindowsPrivateGraphicalAuthority::LogonSession,
            ],
            [
                WindowsPrivateGraphicalAuthority::LogonSession,
                WindowsPrivateGraphicalAuthority::LocalSystem,
                WindowsPrivateGraphicalAuthority::RestrictedCode,
            ],
            [
                WindowsPrivateGraphicalAuthority::RestrictedCode,
                WindowsPrivateGraphicalAuthority::LogonSession,
                WindowsPrivateGraphicalAuthority::LocalSystem,
            ],
        ] {
            assert!(windows_private_graphical_authority_contract(&authorities).is_ok());
        }
        for authorities in [
            [
                WindowsPrivateGraphicalAuthority::RestrictedCode,
                WindowsPrivateGraphicalAuthority::RestrictedCode,
                WindowsPrivateGraphicalAuthority::LogonSession,
            ],
            [
                WindowsPrivateGraphicalAuthority::LogonSession,
                WindowsPrivateGraphicalAuthority::LocalSystem,
                WindowsPrivateGraphicalAuthority::LogonSession,
            ],
        ] {
            assert!(windows_private_graphical_authority_contract(&authorities).is_err());
        }
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
    fn native_stack_commands_keep_global_options_before_the_subcommand() {
        let source = Path::new("oracle-source");
        let stack_yaml = Path::new("stack.yaml");
        let build = native_stack_build(source, stack_yaml, Duration::from_secs(1));
        assert_eq!(
            build.display_arguments(),
            [
                "--lock-file",
                "error-on-write",
                "--stack-yaml",
                "stack.yaml",
                "build",
            ]
        );
        assert_eq!(build.current_directory.as_deref(), Some(source));
        let path = native_stack_path(source, stack_yaml);
        assert_eq!(
            path.display_arguments(),
            [
                "--lock-file",
                "error-on-write",
                "--stack-yaml",
                "stack.yaml",
                "path",
                "--local-install-root",
            ]
        );
        assert_eq!(path.current_directory.as_deref(), Some(source));
        let ghc = native_stack_ghc_version(source, stack_yaml);
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
        assert_eq!(ghc.current_directory.as_deref(), Some(source));

        let adapter_root = Path::new("/fixed/adapter");
        let adapter = NativeArchiveAdapter {
            _directory: None,
            llvm_ar: None,
            llvm_ar_version: None,
            path: None,
            stack_yaml: Some(adapter_root.join("stack.yaml")),
        };
        assert_eq!(
            adapter
                .stack_build(source, Duration::from_secs(1))
                .current_directory
                .as_deref(),
            Some(adapter_root)
        );
        assert_eq!(
            adapter.stack_path(source).current_directory.as_deref(),
            Some(adapter_root)
        );
        assert_eq!(
            adapter
                .stack_ghc_version(source)
                .current_directory
                .as_deref(),
            Some(adapter_root)
        );
    }

    #[test]
    fn native_stack_provenance_resolves_relative_configuration_from_source() {
        let base = std::env::temp_dir().join(format!(
            "hell-native-stack-provenance-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let source = base.join("oracle-source");
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .unwrap();
        fs::write(
            source.join("stack.yaml.lock"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock"),
        )
        .unwrap();
        let adapter = NativeArchiveAdapter {
            _directory: None,
            llvm_ar: None,
            llvm_ar_version: None,
            path: None,
            stack_yaml: None,
        };

        let provenance = adapter.stack_provenance(&source).unwrap();
        assert_eq!(
            provenance.effective_stack_yaml,
            fs::canonicalize(source.join("stack.yaml")).unwrap()
        );
        assert_eq!(
            provenance.effective_stack_yaml_sha256,
            sha256_file(&source.join("stack.yaml")).unwrap()
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn native_stack_overlay_preserves_policy_and_scopes_the_link_fix() {
        let base = std::env::temp_dir().join(format!(
            "hell-native-stack-overlay-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let source = base.join("oracle's source");
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .unwrap();
        fs::write(
            source.join("stack.yaml.lock"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock"),
        )
        .unwrap();
        let directory = create_adapter_directory(&base).unwrap();
        let overlay = write_native_stack_overlay(directory.path(), &source).unwrap();
        let content = fs::read_to_string(&overlay).unwrap();
        assert!(content.starts_with("resolver: nightly-2024-10-21\npackages:\n"));
        assert!(content.contains("oracle''s source'\n"));
        assert!(content.contains("system-ghc: true\nallow-different-user: true\n"));
        assert!(content.contains("  \"$everything\": \"-split-sections -j\"\n"));
        assert!(content.contains("  unix-time: \"-optl-all_load\"\n"));
        assert!(content.contains("  network-control: \"-fforce-recomp\"\n"));
        assert_eq!(content.matches("all_load").count(), 1);
        assert_eq!(content.matches("network-control").count(), 1);
        assert_eq!(content.matches("-fforce-recomp").count(), 1);
        assert!(!content.contains("apply-ghc-options"));
        assert_eq!(
            fs::read(directory.path().join("stack.yaml.lock")).unwrap(),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock")
        );
        fs::write(source.join("stack.yaml"), b"resolver: changed\n").unwrap();
        assert!(
            write_native_stack_overlay(directory.path(), &source)
                .unwrap_err()
                .contains("configuration differs")
        );
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .unwrap();
        fs::write(source.join("stack.yaml.lock"), b"snapshots: []\n").unwrap();
        assert!(
            write_native_stack_overlay(directory.path(), &source)
                .unwrap_err()
                .contains("lock differs")
        );
        drop(directory);
        assert!(!overlay.parent().unwrap().exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn native_stack_overlay_rejects_control_and_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt as _;

        assert!(yaml_single_quoted_path(Path::new("line\nbreak")).is_err());
        assert!(yaml_single_quoted_path(Path::new(&OsString::from_vec(vec![0xff, b'x']))).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_archive_path_removes_only_the_provision_directory() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let base = std::env::temp_dir().join(format!(
            "hell-native-archive-path-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let adapter = base.join("adapter");
        let provision = base.join("llvm-keg/bin");
        let provision_alias = base.join("provision-alias");
        let broad = base.join("broad");
        let first = base.join("first");
        let second = base.join("second");
        for directory in [&adapter, &provision, &broad, &first, &second] {
            fs::create_dir_all(directory).unwrap();
        }
        symlink(&provision, &provision_alias).unwrap();
        let llvm_ar = provision.join("llvm-ar");
        for executable in [llvm_ar.clone(), broad.join("clang"), first.join("clang")] {
            fs::write(&executable, b"not executed\n").unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        }
        symlink(&llvm_ar, broad.join("llvm-ar")).unwrap();
        let inherited = std::env::join_paths([
            provision.as_path(),
            first.as_path(),
            provision_alias.as_path(),
            Path::new("broad"),
            second.as_path(),
            first.as_path(),
        ])
        .unwrap();
        let filtered = native_archive_path(&inherited, &adapter, &llvm_ar, &base).unwrap();
        let paths = std::env::split_paths(&filtered).collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                adapter.clone(),
                first.clone(),
                second.clone(),
                first.clone()
            ]
        );
        assert!(paths.iter().skip(1).all(|entry| {
            fs::canonicalize(entry).unwrap() != fs::canonicalize(&provision).unwrap()
        }));
        let clang = paths
            .iter()
            .map(|entry| entry.join("clang"))
            .find(|candidate| candidate.is_file())
            .unwrap();
        assert_eq!(clang, first.join("clang"));
        fs::remove_dir_all(base).unwrap();
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
        for arguments in [
            vec![],
            vec!["01", "/trusted/cargo"],
            vec!["1", "HOME", "/isolated/home"],
            vec!["1", "CUSTOM", "forbidden", "/trusted/cargo"],
            vec![
                "2",
                "HOME",
                "/isolated/home",
                "HOME",
                "/other/home",
                "/trusted/cargo",
            ],
            vec!["0", "relative-cargo"],
        ] {
            let arguments = arguments
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>();
            assert!(posix_release_child_command(&arguments).is_err());
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

    #[cfg(unix)]
    #[test]
    fn native_archive_authority_binds_before_freezing() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let base = std::env::temp_dir().join(format!(
            "hell-native-adapter-permissions-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o2770)).unwrap();
        let directory = create_adapter_directory(&base).unwrap();
        let path = directory.path().to_owned();
        prepare_adapter_work_directory(&path).unwrap();
        let root = fs::metadata(&path).unwrap();
        let work = fs::metadata(path.join(".stack-work")).unwrap();
        assert_eq!(root.permissions().mode() & 0o7777, 0o755);
        assert_eq!(work.permissions().mode() & 0o7777, 0o700);
        assert_eq!(root.uid(), work.uid());
        let authority = path.join(".authority");
        fs::create_dir(&authority).unwrap();
        let llvm_ar = base.join("llvm-ar");
        fs::write(&llvm_ar, b"bound archiver\n").unwrap();
        fs::set_permissions(&llvm_ar, fs::Permissions::from_mode(0o755)).unwrap();
        bind_and_freeze_native_archive_authority(&authority, &llvm_ar).unwrap();
        assert_eq!(
            fs::metadata(&authority).unwrap().permissions().mode() & 0o7777,
            0o555
        );
        assert_eq!(
            fs::canonicalize(authority.join("llvm-ar")).unwrap(),
            fs::canonicalize(&llvm_ar).unwrap()
        );
        drop(directory);
        assert!(!path.exists());
        assert_eq!(
            fs::metadata(&base).unwrap().permissions().mode() & 0o7777,
            0o2770
        );
        fs::remove_file(&llvm_ar).unwrap();
        fs::remove_dir(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn native_archive_preflight_uses_bound_authority_and_combined_feature_argv() {
        let adapter_root = Path::new("/adapter");
        let authority = adapter_root.join(".authority");
        let work = adapter_root.join(".stack-work");
        let probe = native_archive_feature_probe(&authority.join("llvm-ar"), &work);

        assert_eq!(
            probe.program,
            authority.join("llvm-ar").into_os_string(),
            "preflight must execute the frozen authority binding"
        );
        assert_eq!(
            probe.arguments,
            [
                OsString::from("qL"),
                OsString::from("outer.a"),
                OsString::from("@response.rsp")
            ],
            "preflight must exercise flattening and response files in one bound invocation"
        );
        assert_eq!(probe.current_directory.as_deref(), Some(work.as_path()));
        assert_eq!(probe.timeout, Duration::from_secs(30));
    }

    #[test]
    fn native_archive_identity_accepts_only_policy_versions() {
        assert!(accepted_llvm_ar_version(
            "Homebrew LLVM version 18.1.8\n  Optimized build.\n"
        ));
        assert!(accepted_llvm_ar_version(
            "Homebrew LLVM version 22.1.8\n  Optimized build.\n"
        ));
        assert!(!accepted_llvm_ar_version("LLVM version 22.1.8\n"));
        assert!(!accepted_llvm_ar_version("Homebrew LLVM version 22.1.9\n"));
    }

    #[test]
    fn native_archive_adapter_directory_cleans_partial_setup() {
        let base = std::env::temp_dir().join(format!(
            "hell-archive-adapter-cleanup-{}",
            std::process::id()
        ));
        fs::create_dir_all(&base).unwrap();
        let directory = create_adapter_directory(&base).unwrap();
        let path = directory.path().to_owned();
        fs::write(path.join("member.o"), b"partial\n").unwrap();
        drop(directory);
        assert!(!path.exists());
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn tracked_oracle_checkout_rejects_modified_tracked_files() {
        let root = std::env::temp_dir().join(format!(
            "hell-oracle-checkout-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let git = |arguments: &[&str]| {
            let status = Command::new("git")
                .args(arguments)
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success());
        };
        git(&["init", "--quiet"]);
        fs::write(root.join("tracked"), b"original\n").unwrap();
        git(&["add", "tracked"]);
        git(&[
            "-c",
            "user.name=hell-ci",
            "-c",
            "user.email=hell-ci@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ]);
        let head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&root)
            .output()
            .unwrap();
        let head = std::str::from_utf8(&head.stdout).unwrap().trim();
        verify_tracked_checkout(&root, head).unwrap();
        fs::write(root.join("untracked"), b"rejected\n").unwrap();
        assert!(verify_tracked_checkout(&root, head).is_err());
        fs::remove_file(root.join("untracked")).unwrap();
        fs::write(root.join("tracked"), b"changed\n").unwrap();
        assert!(verify_tracked_checkout(&root, head).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
