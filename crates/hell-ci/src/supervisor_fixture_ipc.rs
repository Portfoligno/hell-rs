//! Private, identity-bound Unix IPC for real external-supervisor verifier processes.
//!
//! The verifier owns the private directory and is its only writer. Identity
//! checks reject redirection; digest/nonce framing authenticates each exchange.
//! This is not an isolation boundary against a concurrent malicious same-uid
//! writer with authority to replace the verifier's own directory.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

const ENDPOINT_LIMIT: usize = 4096;
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    schema_version: u32,
    path_bytes: Vec<u8>,
    parent_device: u64,
    parent_inode: u64,
    socket_device: u64,
    socket_inode: u64,
    owner: u32,
}

impl Endpoint {
    fn path(&self) -> PathBuf {
        PathBuf::from(std::ffi::OsString::from_vec(self.path_bytes.clone()))
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() > ENDPOINT_LIMIT {
            return Err("supervisor fixture endpoint exceeds byte bound".to_owned());
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > ENDPOINT_LIMIT {
            return Err("supervisor fixture endpoint exceeds byte bound".to_owned());
        }
        let endpoint: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid supervisor fixture endpoint: {error}"))?;
        endpoint.validate().map_err(|error| error.to_string())?;
        Ok(endpoint)
    }
    pub fn argument(&self) -> Result<std::ffi::OsString, String> {
        String::from_utf8(self.encode()?)
            .map(Into::into)
            .map_err(|error| error.to_string())
    }
    pub fn from_argument(value: &std::ffi::OsStr) -> Result<Self, String> {
        Self::decode(value.as_bytes())
    }
    fn validate(&self) -> io::Result<()> {
        let path = self.path();
        if self.schema_version != 1
            || !path.is_absolute()
            || path.file_name() != Some(std::ffi::OsStr::new("s"))
        {
            return Err(io::Error::other(
                "supervisor fixture endpoint shape differs",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("fixture socket has no parent"))?;
        let directory = fs::symlink_metadata(parent)?;
        let socket = fs::symlink_metadata(&path)?;
        if !directory.is_dir()
            || directory.file_type().is_symlink()
            || fs::canonicalize(parent)? != parent
            || directory.dev() != self.parent_device
            || directory.ino() != self.parent_inode
            || directory.uid() != self.owner
            || directory.mode() & 0o7777 != 0o700
            || !socket.file_type().is_socket()
            || socket.dev() != self.socket_device
            || socket.ino() != self.socket_inode
            || socket.uid() != self.owner
            || socket.mode() & 0o7777 != 0o600
        {
            return Err(io::Error::other(
                "supervisor fixture endpoint identity differs",
            ));
        }
        Ok(())
    }
}

struct Owner {
    directory: PathBuf,
    device: u64,
    inode: u64,
    endpoint: Option<Endpoint>,
}
impl Owner {
    fn close(&self) -> io::Result<()> {
        let metadata = fs::symlink_metadata(&self.directory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
        {
            return Err(io::Error::other(
                "supervisor IPC cleanup directory identity differs",
            ));
        }
        if let Some(endpoint) = &self.endpoint {
            let socket = fs::symlink_metadata(endpoint.path())?;
            if !socket.file_type().is_socket()
                || socket.dev() != endpoint.socket_device
                || socket.ino() != endpoint.socket_inode
                || socket.uid() != endpoint.owner
            {
                return Err(io::Error::other(
                    "supervisor IPC cleanup socket identity differs",
                ));
            }
            fs::remove_file(endpoint.path())?;
        }
        fs::remove_dir(&self.directory)
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            if std::thread::panicking() {
                eprintln!("supervisor fixture IPC cleanup failed: {error}");
            } else {
                panic!("supervisor fixture IPC cleanup failed: {error}");
            }
        }
    }
}

pub struct Listener {
    inner: UnixListener,
    owner: Arc<Owner>,
    timeout: Duration,
}
impl Listener {
    pub fn bind() -> io::Result<Self> {
        let base = fs::canonicalize(std::env::temp_dir())?;
        let directory = base.join(format!(
            "hs{:x}-{:x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let path = directory.join("s");
        nix::sys::socket::UnixAddr::new(&path).map_err(|error| {
            io::Error::other(format!(
                "supervisor fixture socket path unsupported: {error}"
            ))
        })?;
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let metadata = fs::symlink_metadata(&directory)?;
        let mut owner = Owner {
            directory,
            device: metadata.dev(),
            inode: metadata.ino(),
            endpoint: None,
        };
        let inner = UnixListener::bind(&path)?;
        let socket = fs::symlink_metadata(&path)?;
        owner.endpoint = Some(Endpoint {
            schema_version: 1,
            path_bytes: path.as_os_str().as_bytes().to_vec(),
            parent_device: metadata.dev(),
            parent_inode: metadata.ino(),
            socket_device: socket.dev(),
            socket_inode: socket.ino(),
            owner: metadata.uid(),
        });
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        owner.endpoint.as_ref().expect("bound socket").validate()?;
        inner.set_nonblocking(true)?;
        Ok(Self {
            inner,
            owner: Arc::new(owner),
            timeout: Duration::from_secs(30),
        })
    }
    pub fn endpoint(&self) -> Endpoint {
        self.owner.endpoint.as_ref().expect("bound socket").clone()
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
            owner: Arc::clone(&self.owner),
            timeout: self.timeout,
        })
    }
    pub fn with_accept_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub fn accept(&self) -> io::Result<(Stream, ())> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or_else(|| io::Error::other("fixture accept deadline overflowed"))?;
        loop {
            self.endpoint().validate()?;
            match self.inner.accept() {
                Ok((inner, _)) => {
                    inner.set_nonblocking(false)?;
                    inner.set_read_timeout(Some(self.timeout))?;
                    inner.set_write_timeout(Some(self.timeout))?;
                    return Ok((
                        Stream {
                            inner,
                            owner: Some(Arc::clone(&self.owner)),
                        },
                        (),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(&self.inner, nix::poll::PollFlags::POLLIN, deadline)?
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn wait(fd: &impl AsFd, events: nix::poll::PollFlags, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "supervisor fixture IPC deadline expired",
            ));
        }
        let mut descriptors = [nix::poll::PollFd::new(fd, events)];
        match nix::poll::poll(
            &mut descriptors,
            i32::try_from(remaining.as_millis())
                .unwrap_or(i32::MAX)
                .max(1),
        ) {
            Ok(0) => {}
            Ok(_) => return Ok(()),
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

pub struct Stream {
    inner: UnixStream,
    owner: Option<Arc<Owner>>,
}
impl Stream {
    pub fn connect(endpoint: &Endpoint, timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("fixture connect deadline overflowed"))?;
        if timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture connect deadline expired",
            ));
        }
        endpoint.validate()?;
        use nix::sys::socket::{
            AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket, sockopt,
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let descriptor = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )?;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let descriptor = {
            // Darwin has no atomic socket creation flags. Configure this owned
            // descriptor before connecting or transferring it to another thread.
            use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
            let descriptor = socket(
                AddressFamily::Unix,
                SockType::Stream,
                SockFlag::empty(),
                None,
            )?;
            fcntl(
                descriptor.as_raw_fd(),
                FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC),
            )?;
            fcntl(descriptor.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            descriptor
        };
        let address = UnixAddr::new(&endpoint.path())?;
        match connect(descriptor.as_raw_fd(), &address) {
            Ok(()) => {}
            Err(nix::errno::Errno::EINPROGRESS) => {
                wait(&descriptor, nix::poll::PollFlags::POLLOUT, deadline)?;
                let error = getsockopt(&descriptor, sockopt::SocketError)?;
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(error));
                }
            }
            Err(error) => return Err(error.into()),
        }
        endpoint.validate()?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture connect deadline expired",
            ));
        }
        let inner = UnixStream::from(descriptor);
        inner.set_nonblocking(false)?;
        inner.set_write_timeout(Some(timeout))?;
        // Connected target gates intentionally wait for their supervisor's
        // lifecycle-bound release. Observer readers additionally impose their
        // phase timeout or use the existing absolute-deadline protocol reader.
        Ok(Self { inner, owner: None })
    }
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
            owner: self.owner.clone(),
        })
    }
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }
}
impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl AsFd for Stream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}
impl AsRawFd for Stream {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.as_raw_fd()
    }
}
