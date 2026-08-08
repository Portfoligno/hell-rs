//! Isolated asynchronous HTTP/1 transport for the synchronous Hell runtime.
//!
//! Hyper owns protocol parsing and connection state. This crate exposes only
//! raw-byte requests, bounded blocking body handles, responses, and scoped
//! cancellation; asynchronous engine types do not cross into the evaluator.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

const ENGINE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const BODY_CHANNEL_CAPACITY: usize = 2;
const HYPER_MINIMUM_BUFFER_SIZE: usize = 8 * 1024;

pub type HostResult<T> = Result<T, HostError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostError {
    message: Arc<str>,
}

impl HostError {
    #[must_use]
    pub fn new(message: impl Into<Arc<str>>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for HostError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub name: Arc<[u8]>,
    pub value: Arc<[u8]>,
}

struct CancellationState {
    cancelled: AtomicBool,
    callbacks: Mutex<Vec<Box<dyn FnOnce() + Send>>>,
}

#[derive(Clone)]
pub struct Cancellation {
    state: Arc<CancellationState>,
}

impl Cancellation {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                callbacks: Mutex::new(Vec::new()),
            }),
        }
    }

    pub fn cancel(&self) {
        if self.state.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        let callbacks = self
            .state
            .callbacks
            .lock()
            .map(|mut callbacks| std::mem::take(&mut *callbacks))
            .unwrap_or_default();
        for callback in callbacks {
            callback();
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub fn on_cancel(&self, callback: impl FnOnce() + Send + 'static) {
        let mut callback = Some(Box::new(callback) as Box<dyn FnOnce() + Send>);
        if let Ok(mut callbacks) = self.state.callbacks.lock()
            && !self.is_cancelled()
            && let Some(callback) = callback.take()
        {
            callbacks.push(callback);
        }
        if let Some(callback) = callback {
            callback();
        }
    }
}

impl fmt::Debug for Cancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cancellation")
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct RequestBody {
    receiver: Mutex<tokio::sync::mpsc::Receiver<HostResult<Bytes>>>,
    cancellation: Cancellation,
}

impl RequestBody {
    fn new(
        receiver: tokio::sync::mpsc::Receiver<HostResult<Bytes>>,
        cancellation: Cancellation,
    ) -> Self {
        Self {
            receiver: Mutex::new(receiver),
            cancellation,
        }
    }

    /// Reads the next engine-delivered request-body chunk.
    ///
    /// # Errors
    ///
    /// Returns an error after cancellation, transport failure, or mutex poisoning.
    pub fn next_chunk(&self) -> HostResult<Option<Bytes>> {
        if self.cancellation.is_cancelled() {
            return Err(HostError::new("HTTP request was cancelled"));
        }
        self.receiver
            .lock()
            .map_err(|_| HostError::new("HTTP request-body mutex was poisoned"))?
            .blocking_recv()
            .transpose()
    }
}

#[derive(Debug)]
pub struct HostRequest {
    pub method: Arc<[u8]>,
    pub target: Arc<[u8]>,
    pub version: HttpVersion,
    pub headers: Arc<[Header]>,
    pub body: Arc<RequestBody>,
    pub cancellation: Cancellation,
}

pub trait BodyProducer: Send + 'static {
    /// Produces response bytes into the bounded transport sink.
    ///
    /// # Errors
    ///
    /// Returns an error when production fails or the client disconnects.
    fn produce(self: Box<Self>, sink: BodySink) -> HostResult<()>;
}

pub enum ResponseBody {
    Empty,
    Fixed(Arc<[u8]>),
    Stream {
        producer: Box<dyn BodyProducer>,
        content_length: Option<u64>,
    },
}

pub struct HostResponse {
    pub status: u16,
    pub reason: Arc<[u8]>,
    pub headers: Vec<Header>,
    pub body: ResponseBody,
}

pub trait Application: Send + Sync + 'static {
    /// Evaluates one request and constructs its one-shot response.
    ///
    /// # Errors
    ///
    /// Returns an error when guest evaluation or response construction fails.
    fn call(&self, request: HostRequest) -> HostResult<HostResponse>;
}

#[derive(Clone, Debug)]
pub struct BodySink {
    sender: tokio::sync::mpsc::Sender<BodyMessage>,
    cancellation: Cancellation,
}

#[derive(Debug)]
enum BodyMessage {
    Data(Bytes),
    Flush(std::sync::mpsc::SyncSender<()>),
    Error(HostError),
}

impl BodySink {
    /// Enqueues bytes with bounded backpressure.
    ///
    /// # Errors
    ///
    /// Returns an error after cancellation or transport closure.
    pub fn send(&self, bytes: impl Into<Bytes>) -> HostResult<()> {
        if self.cancellation.is_cancelled() {
            return Err(HostError::new("HTTP response stream was cancelled"));
        }
        self.sender
            .blocking_send(BodyMessage::Data(bytes.into()))
            .map_err(|_| HostError::new("HTTP response connection closed"))
    }

    /// Waits until the engine polls all previously enqueued bytes.
    ///
    /// # Errors
    ///
    /// Returns an error after cancellation or transport closure.
    pub fn flush(&self) -> HostResult<()> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(0);
        self.sender
            .blocking_send(BodyMessage::Flush(sender))
            .map_err(|_| HostError::new("HTTP response connection closed"))?;
        receiver
            .recv()
            .map_err(|_| HostError::new("HTTP response connection closed"))
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub loopback_only: bool,
    pub max_connections: Option<usize>,
    pub max_headers: Option<usize>,
    pub max_header_bytes: Option<usize>,
    pub max_body_bytes: Option<u64>,
    pub idle_timeout: Option<Duration>,
    pub graceful_shutdown: Duration,
    pub request_limit: Option<usize>,
    pub shutdown_requested: Arc<dyn Fn() -> bool + Send + Sync>,
    pub acquire_connection: Arc<dyn Fn() -> HostResult<Box<dyn Send>> + Send + Sync>,
}

/// Runs the asynchronous HTTP/1 host until shutdown or failure.
///
/// # Errors
///
/// Returns listener, protocol, application, or cleanup errors.
pub fn serve(config: ServerConfig, application: Arc<dyn Application>) -> HostResult<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| HostError::new(format!("create HTTP async runtime: {error}")))?
        .block_on(serve_async(config, application))
}

async fn serve_async(config: ServerConfig, application: Arc<dyn Application>) -> HostResult<()> {
    let bind_host = if config.loopback_only {
        "127.0.0.1"
    } else {
        "0.0.0.0"
    };
    let listener = TcpListener::bind((bind_host, config.port))
        .await
        .map_err(|error| HostError::new(format!("bind HTTP listener: {error}")))?;
    let server_cancellation = Cancellation::new();
    let abort_cancellation = Cancellation::new();
    let semaphore = config
        .max_connections
        .map(|limit| Arc::new(Semaphore::new(limit.max(1))));
    let completed_requests = Arc::new(AtomicUsize::new(0));
    let first_error = Arc::new(Mutex::new(None));
    let mut connections = JoinSet::new();

    loop {
        if (config.shutdown_requested)() || server_cancellation.is_cancelled() {
            abort_cancellation.cancel();
            break;
        }
        if config
            .request_limit
            .is_some_and(|limit| completed_requests.load(Ordering::Acquire) >= limit)
        {
            break;
        }
        reap_connections(&mut connections, &first_error);
        if first_error.lock().is_ok_and(|error| error.is_some()) {
            abort_cancellation.cancel();
            break;
        }
        let permit = match acquire_connection_permit(semaphore.as_ref()).await {
            PermitOutcome::Ready(permit) => permit,
            PermitOutcome::Retry => continue,
        };
        let accepted = tokio::time::timeout(ENGINE_POLL_INTERVAL, listener.accept()).await;
        let Ok(accepted) = accepted else {
            continue;
        };
        let (stream, _) =
            accepted.map_err(|error| HostError::new(format!("accept HTTP connection: {error}")))?;
        let connection_resource = (config.acquire_connection)()?;
        let connection_config = config.clone();
        let connection_application = Arc::clone(&application);
        let connection_cancellation = server_cancellation.clone();
        let connection_abort = abort_cancellation.clone();
        let connection_count = Arc::clone(&completed_requests);
        let connection_error = Arc::clone(&first_error);
        connections.spawn(async move {
            let _permit = permit;
            let _connection_resource = connection_resource;
            let result = serve_connection(
                stream,
                connection_config,
                connection_application,
                connection_cancellation,
                connection_abort,
                connection_count,
                Arc::clone(&connection_error),
            )
            .await;
            if let Err(error) = &result {
                record_first_error(&connection_error, error.clone());
            }
            result
        });
    }

    server_cancellation.cancel();
    let cleanup = async {
        while let Some(joined) = connections.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => record_first_error(&first_error, error),
                Err(error) => record_first_error(
                    &first_error,
                    HostError::new(format!("HTTP connection task failed: {error}")),
                ),
            }
        }
    };
    if tokio::time::timeout(config.graceful_shutdown, cleanup)
        .await
        .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        record_first_error(
            &first_error,
            HostError::new("HTTP graceful shutdown deadline elapsed"),
        );
    }
    let error = first_error
        .lock()
        .map_err(|_| HostError::new("HTTP server error mutex was poisoned"))?
        .take();
    error.map_or(Ok(()), Err)
}

enum PermitOutcome {
    Ready(Option<OwnedSemaphorePermit>),
    Retry,
}

async fn acquire_connection_permit(semaphore: Option<&Arc<Semaphore>>) -> PermitOutcome {
    let Some(semaphore) = semaphore else {
        return PermitOutcome::Ready(None);
    };
    match tokio::time::timeout(ENGINE_POLL_INTERVAL, Arc::clone(semaphore).acquire_owned()).await {
        Ok(Ok(permit)) => PermitOutcome::Ready(Some(permit)),
        Ok(Err(_)) | Err(_) => PermitOutcome::Retry,
    }
}

fn reap_connections(
    connections: &mut JoinSet<HostResult<()>>,
    first_error: &Arc<Mutex<Option<HostError>>>,
) {
    while let Some(joined) = connections.try_join_next() {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => record_first_error(first_error, error),
            Err(error) => record_first_error(
                first_error,
                HostError::new(format!("HTTP connection task failed: {error}")),
            ),
        }
    }
}

fn record_first_error(target: &Mutex<Option<HostError>>, error: HostError) {
    if let Ok(mut target) = target.lock()
        && target.is_none()
    {
        *target = Some(error);
    }
}

#[derive(Clone)]
struct IngressControl {
    state: Arc<Mutex<IngressState>>,
}

struct IngressState {
    phase: IngressPhase,
    waker: Option<std::task::Waker>,
}

#[derive(Clone, Copy)]
enum IngressPhase {
    Head,
    AwaitBody,
    Body { raw_remaining: Option<u64> },
    AwaitNext,
}

impl IngressControl {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(IngressState {
                phase: IngressPhase::Head,
                waker: None,
            })),
        }
    }

    fn begin_body(&self, raw_remaining: Option<u64>) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = if raw_remaining == Some(0) {
                IngressPhase::AwaitNext
            } else {
                IngressPhase::Body { raw_remaining }
            };
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
    }

    fn finish_request(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = IngressPhase::Head;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
    }
}

struct SanitizedIo {
    stream: TcpStream,
    ingress: IngressControl,
    head: Vec<u8>,
    output: std::collections::VecDeque<u8>,
    raw: std::collections::VecDeque<u8>,
    head_limit: Option<usize>,
    idle_timeout: Option<Duration>,
    idle_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    first_error: Arc<Mutex<Option<HostError>>>,
    wire: WireControl,
    wire_head: Vec<u8>,
    wire_output: std::collections::VecDeque<u8>,
}

impl SanitizedIo {
    fn new(
        stream: TcpStream,
        ingress: IngressControl,
        head_limit: Option<usize>,
        idle_timeout: Option<Duration>,
        first_error: Arc<Mutex<Option<HostError>>>,
        wire: WireControl,
    ) -> Self {
        Self {
            stream,
            ingress,
            head: Vec::new(),
            output: std::collections::VecDeque::new(),
            raw: std::collections::VecDeque::new(),
            head_limit,
            idle_timeout,
            idle_timer: idle_timeout.map(|timeout| Box::pin(tokio::time::sleep(timeout))),
            first_error,
            wire,
            wire_head: Vec::new(),
            wire_output: std::collections::VecDeque::new(),
        }
    }

    fn copy_output(&mut self, destination: &mut ReadBuf<'_>) -> bool {
        let amount = destination.remaining().min(self.output.len());
        if amount == 0 {
            return false;
        }
        let bytes = self.output.drain(..amount).collect::<Vec<_>>();
        destination.put_slice(&bytes);
        true
    }

    fn finish_head(&mut self, end: usize) -> std::io::Result<()> {
        let remainder = self.head.split_off(end);
        self.raw.extend(remainder);
        validate_raw_request_head(&self.head)?;
        self.output.extend(sanitize_request_head(&self.head));
        self.head.clear();
        if let Ok(mut state) = self.ingress.state.lock() {
            state.phase = IngressPhase::AwaitBody;
        }
        Ok(())
    }

    fn reset_idle_timer(&mut self) {
        if let (Some(timeout), Some(timer)) = (self.idle_timeout, self.idle_timer.as_mut()) {
            timer.as_mut().reset(tokio::time::Instant::now() + timeout);
        }
    }

    fn poll_idle_timeout(&mut self, context: &mut Context<'_>) -> std::io::Result<()> {
        if self
            .idle_timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(context).is_ready())
        {
            let message = "HTTP connection exceeded the configured idle timeout";
            record_first_error(&self.first_error, HostError::new(message));
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, message));
        }
        Ok(())
    }
}

impl AsyncRead for SanitizedIo {
    #[allow(clippy::too_many_lines)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            self.poll_idle_timeout(context)?;
            if self.copy_output(destination) {
                return Poll::Ready(Ok(()));
            }
            let phase = self
                .ingress
                .state
                .lock()
                .map_or(IngressPhase::AwaitNext, |state| state.phase);
            match phase {
                IngressPhase::Head => {
                    if let Some(end) = find_header_end(&self.head) {
                        if let Err(error) = self.finish_head(end) {
                            record_first_error(
                                &self.first_error,
                                HostError::new(error.to_string()),
                            );
                            return Poll::Ready(Err(error));
                        }
                        continue;
                    }
                    if self.head_limit.is_some_and(|limit| self.head.len() > limit) {
                        return Poll::Ready(Err(std::io::Error::other(
                            "HTTP request headers exceeded the configured byte limit",
                        )));
                    }
                    while let Some(byte) = self.raw.pop_front() {
                        self.head.push(byte);
                        if self.head_limit.is_some_and(|limit| self.head.len() > limit) {
                            let message = "HTTP request headers exceeded the configured byte limit";
                            record_first_error(&self.first_error, HostError::new(message));
                            return Poll::Ready(Err(std::io::Error::other(message)));
                        }
                        if let Some(end) = find_header_end(&self.head) {
                            if let Err(error) = self.finish_head(end) {
                                record_first_error(
                                    &self.first_error,
                                    HostError::new(error.to_string()),
                                );
                                return Poll::Ready(Err(error));
                            }
                            break;
                        }
                    }
                    if !self.output.is_empty() {
                        continue;
                    }
                    let mut buffer = [0_u8; 8 * 1024];
                    let mut read_buffer = ReadBuf::new(&mut buffer);
                    match Pin::new(&mut self.stream).poll_read(context, &mut read_buffer) {
                        Poll::Ready(Ok(())) => {
                            if read_buffer.filled().is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            self.reset_idle_timer();
                            self.raw.extend(read_buffer.filled());
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                IngressPhase::AwaitBody | IngressPhase::AwaitNext => {
                    if let Ok(mut state) = self.ingress.state.lock() {
                        state.waker = Some(context.waker().clone());
                    }
                    return Poll::Pending;
                }
                IngressPhase::Body { raw_remaining } => {
                    let allowance = raw_remaining
                        .map_or(1, |remaining| {
                            usize::try_from(remaining).unwrap_or(usize::MAX)
                        })
                        .min(destination.remaining());
                    let buffered = allowance.min(self.raw.len());
                    if buffered != 0 {
                        let bytes = self.raw.drain(..buffered).collect::<Vec<_>>();
                        destination.put_slice(&bytes);
                        reduce_ingress_body_remaining(&self.ingress, buffered);
                        return Poll::Ready(Ok(()));
                    }
                    let mut buffer = [0_u8; 8 * 1024];
                    let mut read_buffer = ReadBuf::new(&mut buffer[..allowance.max(1)]);
                    match Pin::new(&mut self.stream).poll_read(context, &mut read_buffer) {
                        Poll::Ready(Ok(())) => {
                            let bytes = read_buffer.filled();
                            if bytes.is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            destination.put_slice(bytes);
                            reduce_ingress_body_remaining(&self.ingress, bytes.len());
                            self.reset_idle_timer();
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for SanitizedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.poll_idle_timeout(context)?;
        if self.poll_wire_output(context)?.is_pending() {
            return Poll::Pending;
        }
        let informational = self
            .wire
            .informational
            .lock()
            .ok()
            .and_then(|informational| informational.clone());
        let Some(informational) = informational else {
            let result = Pin::new(&mut self.stream).poll_write(context, bytes);
            if matches!(result, Poll::Ready(Ok(written)) if written != 0) {
                self.reset_idle_timer();
            }
            return result;
        };
        self.wire_head.extend_from_slice(bytes);
        if let Some(end) = find_header_end(&self.wire_head) {
            let remainder = self.wire_head.split_off(end);
            let rewritten = rewrite_informational_head(&self.wire_head, &informational);
            self.wire_output.extend(rewritten);
            self.wire_output.extend(remainder);
            self.wire_head.clear();
            if let Ok(mut current) = self.wire.informational.lock() {
                *current = None;
            }
            let _ = self.poll_wire_output(context)?;
        }
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.poll_wire_output(context)?.is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl SanitizedIo {
    fn poll_wire_output(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while !self.wire_output.is_empty() {
            let (front, back) = self.wire_output.as_slices();
            let bytes = if front.is_empty() { back } else { front };
            match Pin::new(&mut self.stream).poll_write(context, bytes) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "HTTP connection stopped accepting response bytes",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    self.wire_output.drain(..written);
                    self.reset_idle_timer();
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct WireControl {
    informational: Arc<Mutex<Option<InformationalHead>>>,
}

#[derive(Clone)]
struct InformationalHead {
    status: u16,
    reason: Arc<[u8]>,
}

impl WireControl {
    fn new() -> Self {
        Self {
            informational: Arc::new(Mutex::new(None)),
        }
    }

    fn set_informational(&self, status: u16, reason: Arc<[u8]>) {
        if let Ok(mut informational) = self.informational.lock() {
            *informational = Some(InformationalHead { status, reason });
        }
    }
}

fn rewrite_informational_head(head: &[u8], informational: &InformationalHead) -> Vec<u8> {
    let mut lines = head.split(|byte| *byte == b'\n');
    let Some(status_line) = lines.next() else {
        return head.to_vec();
    };
    let version = status_line
        .split(|byte| *byte == b' ')
        .next()
        .unwrap_or(b"HTTP/1.1");
    let mut output = Vec::new();
    output.extend_from_slice(version);
    output.push(b' ');
    output.extend_from_slice(informational.status.to_string().as_bytes());
    output.push(b' ');
    output.extend_from_slice(&informational.reason);
    output.extend_from_slice(b"\r\n");
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let name = line.split(|byte| *byte == b':').next().unwrap_or_default();
        if name.eq_ignore_ascii_case(b"content-length")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
        {
            continue;
        }
        output.extend_from_slice(line);
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"\r\n");
    output
}

fn reduce_ingress_body_remaining(ingress: &IngressControl, consumed: usize) {
    if let Ok(mut state) = ingress.state.lock()
        && let IngressPhase::Body {
            raw_remaining: Some(remaining),
        } = &mut state.phase
    {
        *remaining = remaining.saturating_sub(u64::try_from(consumed).unwrap_or(u64::MAX));
        if *remaining == 0 {
            state.phase = IngressPhase::AwaitNext;
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + b"\r\n\r\n".len())
}

fn sanitize_request_head(head: &[u8]) -> Vec<u8> {
    let Some(line_end) = head
        .windows(b"\r\n".len())
        .position(|window| window == b"\r\n")
    else {
        return head.to_vec();
    };
    let line = &head[..line_end];
    let Some(method_end) = line.iter().position(|byte| *byte == b' ') else {
        return head.to_vec();
    };
    let Some(target_end) = line[method_end + 1..]
        .iter()
        .position(|byte| *byte == b' ')
        .map(|offset| method_end + 1 + offset)
    else {
        return head.to_vec();
    };
    let mut output = Vec::with_capacity(head.len());
    output.extend_from_slice(&head[..=method_end]);
    for byte in &head[method_end + 1..target_end] {
        if byte.is_ascii() {
            output.push(*byte);
        } else {
            output.push(b'%');
            output.push(hex_digit(*byte >> 4));
            output.push(hex_digit(*byte & 0x0f));
        }
    }
    output.extend_from_slice(&head[target_end..]);
    output
}

fn validate_raw_request_head(head: &[u8]) -> std::io::Result<()> {
    let mut content_lengths = Vec::new();
    let mut has_transfer_encoding = false;
    for line in head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = trim_ascii_whitespace(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            has_transfer_encoding = true;
        } else if name.eq_ignore_ascii_case(b"content-length") {
            for field in value.split(|byte| *byte == b',') {
                let field = trim_ascii_whitespace(field);
                let length = std::str::from_utf8(field)
                    .ok()
                    .and_then(|field| field.parse::<u64>().ok())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "HTTP Content-Length is invalid",
                        )
                    })?;
                content_lengths.push(length);
            }
        }
    }
    if has_transfer_encoding && !content_lengths.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP request cannot contain both Transfer-Encoding and Content-Length",
        ));
    }
    if let Some(first) = content_lengths.first()
        && content_lengths.iter().any(|length| length != first)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP Content-Length values are conflicting",
        ));
    }
    Ok(())
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + value - 10,
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    stream: TcpStream,
    config: ServerConfig,
    application: Arc<dyn Application>,
    server_cancellation: Cancellation,
    abort_cancellation: Cancellation,
    completed_requests: Arc<AtomicUsize>,
    first_error: Arc<Mutex<Option<HostError>>>,
) -> HostResult<()> {
    let ingress = IngressControl::new();
    let wire = WireControl::new();
    let requests = ActiveRequests::new();
    let service_requests = requests.clone();
    let service_config = config.clone();
    let service_ingress = ingress.clone();
    let service_wire = wire.clone();
    let service_first_error = Arc::clone(&first_error);
    let service = service_fn(move |request| {
        let dispatched = dispatch_request(
            request,
            Arc::clone(&application),
            service_config.clone(),
            service_requests.clone(),
            Arc::clone(&completed_requests),
            Arc::clone(&service_first_error),
            service_ingress.clone(),
            service_wire.clone(),
        );
        let service_error = Arc::clone(&service_first_error);
        async move {
            let result = dispatched.await;
            if let Err(error) = &result {
                record_first_error(&service_error, error.clone());
            }
            result
        }
    });
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .preserve_header_case(true)
        .title_case_headers(true);
    if let Some(max_headers) = config.max_headers {
        builder.max_headers(max_headers);
    }
    if let Some(max_header_bytes) = config.max_header_bytes {
        builder.max_buf_size(max_header_bytes.max(HYPER_MINIMUM_BUFFER_SIZE));
    }
    let stream = SanitizedIo::new(
        stream,
        ingress,
        config.max_header_bytes,
        config.idle_timeout,
        Arc::clone(&first_error),
        wire,
    );
    let mut connection = Box::pin(builder.serve_connection(TokioIo::new(stream), service));
    let result = loop {
        if server_cancellation.is_cancelled() || (config.shutdown_requested)() {
            if abort_cancellation.is_cancelled() || (config.shutdown_requested)() {
                requests.cancel_all();
            }
            connection.as_mut().graceful_shutdown();
            break tokio::time::timeout(config.graceful_shutdown, &mut connection)
                .await
                .map_err(|_| HostError::new("HTTP connection shutdown deadline elapsed"))?
                .map_err(|error| HostError::new(format!("serve HTTP connection: {error}")));
        }
        if let Ok(result) = tokio::time::timeout(ENGINE_POLL_INTERVAL, &mut connection).await {
            break result
                .map_err(|error| HostError::new(format!("serve HTTP connection: {error}")));
        }
    };
    requests.cancel_all();
    result
}

#[derive(Clone)]
struct ActiveRequests {
    state: Arc<Mutex<ActiveRequestState>>,
}

struct ActiveRequestState {
    next_id: u64,
    requests: BTreeMap<u64, Cancellation>,
}

impl ActiveRequests {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ActiveRequestState {
                next_id: 0,
                requests: BTreeMap::new(),
            })),
        }
    }

    fn register(&self, cancellation: Cancellation) -> ActiveRequest {
        let id = self.state.lock().map_or(0, |mut state| {
            let id = state.next_id;
            state.next_id = state.next_id.wrapping_add(1);
            state.requests.insert(id, cancellation);
            id
        });
        ActiveRequest {
            id,
            requests: self.clone(),
        }
    }

    fn cancel_all(&self) {
        if let Ok(state) = self.state.lock() {
            for request in state.requests.values() {
                request.cancel();
            }
        }
    }
}

struct ActiveRequest {
    id: u64,
    requests: ActiveRequests,
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        if let Ok(mut state) = self.requests.state.lock() {
            state.requests.remove(&self.id);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_request(
    request: Request<Incoming>,
    application: Arc<dyn Application>,
    config: ServerConfig,
    connection_requests: ActiveRequests,
    completed_requests: Arc<AtomicUsize>,
    first_error: Arc<Mutex<Option<HostError>>>,
    ingress: IngressControl,
    wire: WireControl,
) -> HostResult<Response<EngineBody>> {
    let (parts, body) = request.into_parts();
    let cancellation = Cancellation::new();
    let request_guard = connection_requests.register(cancellation.clone());
    let headers = request_headers(&parts.headers);
    enforce_request_framing(&parts.headers)?;
    enforce_request_head_limits(&parts.method, &parts.uri, parts.version, &headers, &config)?;
    if let Some(limit) = config.max_body_bytes
        && parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > limit)
    {
        return Err(HostError::new(
            "HTTP Content-Length is too large for the configured body limit",
        ));
    }
    let (body_sender, body_receiver) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
    ingress.begin_body(body.size_hint().exact());
    tokio::spawn(pump_request_body(
        body,
        body_sender,
        cancellation.clone(),
        config.max_body_bytes,
        ingress,
    ));
    let version = match parts.version {
        hyper::Version::HTTP_10 => HttpVersion::Http10,
        hyper::Version::HTTP_11 => HttpVersion::Http11,
        _ => return Err(HostError::new("HTTP version is unsupported")),
    };
    let request = HostRequest {
        method: Arc::from(parts.method.as_str().as_bytes()),
        target: Arc::from(
            parts
                .uri
                .path_and_query()
                .map_or(b"/".as_slice(), |target| target.as_str().as_bytes()),
        ),
        version,
        headers: headers.into(),
        body: Arc::new(RequestBody::new(body_receiver, cancellation.clone())),
        cancellation: cancellation.clone(),
    };
    let response = tokio::task::spawn_blocking(move || application.call(request))
        .await
        .map_err(|error| HostError::new(format!("HTTP application task failed: {error}")))?;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            cancellation.cancel();
            record_first_error(&first_error, error.clone());
            return Err(error);
        }
    };
    let response = build_response(
        response,
        cancellation,
        Arc::clone(&first_error),
        &wire,
        request_guard,
    )?;
    completed_requests.fetch_add(1, Ordering::AcqRel);
    Ok(response)
}

fn enforce_request_framing(headers: &hyper::HeaderMap) -> HostResult<()> {
    let transfer_encoding = headers.get_all(hyper::header::TRANSFER_ENCODING);
    let content_length = headers.get_all(hyper::header::CONTENT_LENGTH);
    if transfer_encoding.iter().next().is_some() && content_length.iter().next().is_some() {
        return Err(HostError::new(
            "HTTP request cannot contain both Transfer-Encoding and Content-Length",
        ));
    }
    let mut lengths = Vec::new();
    for value in content_length {
        for field in value.as_bytes().split(|byte| *byte == b',') {
            let field = trim_ascii_whitespace(field);
            if field.is_empty() || !field.iter().all(u8::is_ascii_digit) {
                return Err(HostError::new("HTTP Content-Length is invalid"));
            }
            let length = std::str::from_utf8(field)
                .ok()
                .and_then(|field| field.parse::<u64>().ok())
                .ok_or_else(|| HostError::new("HTTP Content-Length is invalid"))?;
            lengths.push(length);
        }
    }
    if let Some(first) = lengths.first()
        && lengths.iter().any(|length| length != first)
    {
        return Err(HostError::new("HTTP Content-Length values are conflicting"));
    }
    Ok(())
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while let Some(first) = value.first().filter(|byte| byte.is_ascii_whitespace()) {
        value = value
            .strip_prefix(std::slice::from_ref(first))
            .unwrap_or(value);
    }
    while let Some(last) = value.last().filter(|byte| byte.is_ascii_whitespace()) {
        value = value
            .strip_suffix(std::slice::from_ref(last))
            .unwrap_or(value);
    }
    value
}

fn request_headers(headers: &hyper::HeaderMap) -> Vec<Header> {
    headers
        .iter()
        .map(|(name, value)| Header {
            name: Arc::from(name.as_str().as_bytes()),
            value: Arc::from(value.as_bytes()),
        })
        .collect()
}

fn enforce_request_head_limits(
    method: &hyper::Method,
    uri: &hyper::Uri,
    version: hyper::Version,
    headers: &[Header],
    config: &ServerConfig,
) -> HostResult<()> {
    if config
        .max_headers
        .is_some_and(|limit| headers.len() > limit)
    {
        return Err(HostError::new(
            "HTTP request exceeded the configured header-count limit",
        ));
    }
    let version_length = match version {
        hyper::Version::HTTP_10 => b"HTTP/1.0".len(),
        hyper::Version::HTTP_11 => b"HTTP/1.1".len(),
        _ => 0,
    };
    let observed = method.as_str().len()
        + uri.to_string().len()
        + version_length
        + headers
            .iter()
            .map(|header| header.name.len() + header.value.len() + b": \r\n".len())
            .sum::<usize>();
    if config
        .max_header_bytes
        .is_some_and(|limit| observed > limit)
    {
        return Err(HostError::new(
            "HTTP request headers exceeded the configured byte limit",
        ));
    }
    Ok(())
}

async fn pump_request_body(
    mut body: Incoming,
    sender: tokio::sync::mpsc::Sender<HostResult<Bytes>>,
    cancellation: Cancellation,
    max_body_bytes: Option<u64>,
    ingress: IngressControl,
) {
    let mut consumed = 0_u64;
    let mut delivering = true;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let next = tokio::time::timeout(
            ENGINE_POLL_INTERVAL,
            poll_fn(|context| Pin::new(&mut body).poll_frame(context)),
        )
        .await;
        let Ok(next) = next else {
            continue;
        };
        let Some(frame) = next else {
            break;
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                let error = HostError::new(format!("read HTTP request body: {error}"));
                let _ignored = sender.send(Err(error)).await;
                cancellation.cancel();
                break;
            }
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        consumed = consumed.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if max_body_bytes.is_some_and(|limit| consumed > limit) {
            let _ignored = sender
                .send(Err(HostError::new(
                    "HTTP request body exceeded the configured limit",
                )))
                .await;
            cancellation.cancel();
            break;
        }
        if delivering && sender.send(Ok(data)).await.is_err() {
            delivering = false;
        }
    }
    ingress.finish_request();
}

fn build_response(
    response: HostResponse,
    cancellation: Cancellation,
    first_error: Arc<Mutex<Option<HostError>>>,
    wire: &WireControl,
    request_guard: ActiveRequest,
) -> HostResult<Response<EngineBody>> {
    let status = StatusCode::from_u16(response.status)
        .map_err(|error| HostError::new(format!("invalid HTTP response status: {error}")))?;
    let reason = hyper::ext::ReasonPhrase::try_from(response.reason.as_ref())
        .map_err(|error| HostError::new(format!("invalid HTTP reason phrase: {error}")))?;
    let informational = status.is_informational();
    let mut output = Response::builder().status(if informational {
        StatusCode::OK
    } else {
        status
    });
    for header in response.headers {
        let name = HeaderName::from_bytes(&header.name)
            .map_err(|error| HostError::new(format!("invalid HTTP response header: {error}")))?;
        let value = HeaderValue::from_bytes(&header.value)
            .map_err(|error| HostError::new(format!("invalid HTTP response header: {error}")))?;
        output = output.header(name, value);
    }
    let body = EngineBody::new(response.body, cancellation, first_error, request_guard);
    let mut output = output
        .body(body)
        .map_err(|error| HostError::new(format!("build HTTP response: {error}")))?;
    if informational {
        wire.set_informational(status.as_u16(), response.reason);
    } else {
        output.extensions_mut().insert(reason);
    }
    Ok(output)
}

enum EngineBodyState {
    Empty,
    Fixed(Option<Bytes>),
    Stream(tokio::sync::mpsc::Receiver<BodyMessage>),
}

struct EngineBody {
    state: EngineBodyState,
    exact_length: Option<u64>,
    cancellation: Cancellation,
    completed: bool,
    _request_guard: ActiveRequest,
}

impl EngineBody {
    fn new(
        body: ResponseBody,
        cancellation: Cancellation,
        first_error: Arc<Mutex<Option<HostError>>>,
        request_guard: ActiveRequest,
    ) -> Self {
        let (state, exact_length, completed) = match body {
            ResponseBody::Empty => (EngineBodyState::Empty, Some(0), true),
            ResponseBody::Fixed(bytes) => {
                let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                (
                    EngineBodyState::Fixed(Some(Bytes::copy_from_slice(&bytes))),
                    Some(length),
                    false,
                )
            }
            ResponseBody::Stream {
                producer,
                content_length,
            } => {
                let (sender, receiver) = tokio::sync::mpsc::channel(BODY_CHANNEL_CAPACITY);
                let sink = BodySink {
                    sender: sender.clone(),
                    cancellation: cancellation.clone(),
                };
                tokio::task::spawn_blocking(move || {
                    if let Err(error) = producer.produce(sink) {
                        record_first_error(&first_error, error.clone());
                        let _ignored = sender.blocking_send(BodyMessage::Error(error));
                    }
                });
                (EngineBodyState::Stream(receiver), content_length, false)
            }
        };
        Self {
            state,
            exact_length,
            cancellation,
            completed,
            _request_guard: request_guard,
        }
    }
}

impl Body for EngineBody {
    type Data = Bytes;
    type Error = HostError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        loop {
            match &mut self.state {
                EngineBodyState::Empty => {
                    self.completed = true;
                    return Poll::Ready(None);
                }
                EngineBodyState::Fixed(bytes) => {
                    let frame = bytes.take().map(|bytes| Ok(Frame::data(bytes)));
                    self.completed = true;
                    return Poll::Ready(frame);
                }
                EngineBodyState::Stream(receiver) => match receiver.poll_recv(context) {
                    Poll::Ready(Some(BodyMessage::Data(bytes))) => {
                        return Poll::Ready(Some(Ok(Frame::data(bytes))));
                    }
                    Poll::Ready(Some(BodyMessage::Flush(sender))) => {
                        let _ignored = sender.send(());
                    }
                    Poll::Ready(Some(BodyMessage::Error(error))) => {
                        return Poll::Ready(Some(Err(error)));
                    }
                    Poll::Ready(None) => {
                        self.completed = true;
                        return Poll::Ready(None);
                    }
                    Poll::Pending => return Poll::Pending,
                },
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(
            self.state,
            EngineBodyState::Empty | EngineBodyState::Fixed(None)
        )
    }

    fn size_hint(&self) -> SizeHint {
        self.exact_length
            .map_or_else(SizeHint::new, SizeHint::with_exact)
    }
}

impl Drop for EngineBody {
    fn drop(&mut self) {
        if !self.completed {
            self.cancellation.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::time::Instant;

    use super::*;

    #[test]
    fn completed_request_guards_do_not_accumulate_on_keep_alive_connections() {
        let requests = ActiveRequests::new();
        for _ in 0..10_000 {
            let guard = requests.register(Cancellation::new());
            assert_eq!(
                requests
                    .state
                    .lock()
                    .expect("active-request registry is available")
                    .requests
                    .len(),
                1
            );
            drop(guard);
        }
        assert!(
            requests
                .state
                .lock()
                .expect("active-request registry is available")
                .requests
                .is_empty()
        );
    }

    #[test]
    fn ingress_idle_timeout_and_head_limit_are_enforced_before_hyper() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime starts");
        runtime.block_on(async {
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("test listener binds");
            let address = listener.local_addr().expect("listener has an address");
            let idle_client = std::net::TcpStream::connect(address).expect("client connects");
            let (idle_stream, _) = listener.accept().await.expect("server accepts client");
            let first_error = Arc::new(Mutex::new(None));
            let mut idle = SanitizedIo::new(
                idle_stream,
                IngressControl::new(),
                Some(128),
                Some(Duration::from_millis(30)),
                Arc::clone(&first_error),
                WireControl::new(),
            );
            let started = Instant::now();
            let idle_error = poll_fn(|context| {
                let mut byte = [0_u8; 1];
                let mut output = ReadBuf::new(&mut byte);
                Pin::new(&mut idle).poll_read(context, &mut output)
            })
            .await
            .expect_err("idle ingress times out");
            assert_eq!(idle_error.kind(), std::io::ErrorKind::TimedOut);
            assert!(started.elapsed() >= Duration::from_millis(25));
            drop(idle_client);

            let mut oversized_client =
                std::net::TcpStream::connect(address).expect("second client connects");
            let (oversized_stream, _) = listener.accept().await.expect("server accepts client");
            oversized_client
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost")
                .expect("client writes an unterminated oversized head");
            let mut oversized = SanitizedIo::new(
                oversized_stream,
                IngressControl::new(),
                Some(16),
                None,
                Arc::new(Mutex::new(None)),
                WireControl::new(),
            );
            let head_error = poll_fn(|context| {
                let mut byte = [0_u8; 1];
                let mut output = ReadBuf::new(&mut byte);
                Pin::new(&mut oversized).poll_read(context, &mut output)
            })
            .await
            .expect_err("unterminated oversized head is rejected");
            assert_eq!(head_error.kind(), std::io::ErrorKind::Other);
        });
    }
}
