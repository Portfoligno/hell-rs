use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hell_compiler::{CompilerSession, compile_source};
use hell_http_host::{
    Application, BoundServerListener, HostRequest, HostResponse, HostResult, ServerConfig,
    ServerStartupEvent, ServerStartupObserver,
};
use hell_runtime::policy::{Limit, RuntimePolicy};
use hell_runtime::{RuntimeContext, RuntimeHttpServerControl, run_main};

const HTTP_FIXTURE_TIMEOUT: Duration = Duration::from_secs(3);

struct OneShotGateReader {
    receiver: mpsc::Receiver<()>,
    opened: bool,
}

impl OneShotGateReader {
    fn new(receiver: mpsc::Receiver<()>) -> Self {
        Self {
            receiver,
            opened: false,
        }
    }
}

impl Read for OneShotGateReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() || self.opened {
            return Ok(0);
        }
        self.receiver.recv().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HTTP cancellation gate was dropped",
            )
        })?;
        let signal = b"\n";
        let written = signal.len().min(buffer.len());
        buffer[..written].copy_from_slice(&signal[..written]);
        self.opened = true;
        Ok(written)
    }
}

static NEXT_HTTP_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct ReservedHttpListener {
    listener: BoundServerListener,
    address: SocketAddr,
}

impl ReservedHttpListener {
    fn bind() -> Self {
        let listener = BoundServerListener::bind_loopback().expect("HTTP test listener reserves");
        let address = listener.address();
        Self { listener, address }
    }

    const fn port(&self) -> u16 {
        self.address.port()
    }
}

fn next_http_fixture() -> u64 {
    NEXT_HTTP_FIXTURE.fetch_add(1, Ordering::Relaxed)
}

fn start_server(listener: ReservedHttpListener, source: &str, cwd: PathBuf) -> HttpTestServer {
    start_server_with_limit(listener, source, cwd, 1)
}

fn start_server_with_limit(
    listener: ReservedHttpListener,
    source: &str,
    cwd: PathBuf,
    request_limit: usize,
) -> HttpTestServer {
    let context = RuntimeContext::with_host(Vec::new(), Vec::new(), Vec::new(), cwd, true)
        .with_http_request_limit(request_limit);
    start_server_in_context(listener, source, context)
}

fn start_server_observed(
    listener: ReservedHttpListener,
    source: &str,
    cwd: PathBuf,
) -> HttpTestServer {
    let context = RuntimeContext::with_host(Vec::new(), Vec::new(), Vec::new(), cwd, true)
        .with_http_request_limit(1);
    start_server_in_context(listener, source, context)
}

fn start_server_in_context(
    listener: ReservedHttpListener,
    source: &str,
    context: RuntimeContext,
) -> HttpTestServer {
    let mut server = launch_server_in_context(listener, source, context, None);
    server.await_readiness();
    server
}

fn launch_server_in_context(
    listener: ReservedHttpListener,
    source: &str,
    mut context: RuntimeContext,
    before_run: Option<mpsc::Receiver<()>>,
) -> HttpTestServer {
    let deadline = Instant::now() + HTTP_FIXTURE_TIMEOUT;
    let program = compile_source(&mut CompilerSession::default(), "http.hell", source)
        .expect("HTTP source compiles");
    let address = listener.address;
    let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
    let startup_emitted = Arc::new(AtomicBool::new(false));
    let event_emitted = Arc::clone(&startup_emitted);
    let event_sender = startup_sender.clone();
    let startup: ServerStartupObserver = Arc::new(move |event| {
        if event_emitted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let _ = event_sender.try_send(event);
        }
    });
    let (configured_context, control) = context.with_http_listener(listener.listener, startup);
    context = configured_context;
    let returned_context = context.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let completion = Arc::new(HttpWorkerCompletion::default());
    let worker_completion = Arc::clone(&completion);
    let worker = std::thread::spawn(move || {
        let _completion_guard = HttpWorkerCompletionGuard(worker_completion);
        let result = if before_run.is_some_and(|gate| gate.recv().is_err()) {
            Err("HTTP server startup gate disconnected".into())
        } else {
            run_main(program, context).map_err(|error| error.to_string())
        };
        if startup_emitted
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let message = match &result {
                Ok(()) => Arc::from("HTTP server completed before readiness"),
                Err(error) => Arc::from(error.as_str()),
            };
            let _ = startup_sender.try_send(ServerStartupEvent::Failed {
                phase: "runtime",
                message,
            });
        }
        let _ = sender.send(result);
    });
    HttpTestServer {
        address,
        control,
        startup: Some(startup_receiver),
        terminal: receiver,
        terminal_result: None,
        worker: Some(worker),
        observer: returned_context,
        completion,
        deadline,
    }
}

#[derive(Default)]
struct HttpWorkerCompletion {
    completed: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}

impl HttpWorkerCompletion {
    fn wait_until(&self, deadline: Instant) -> bool {
        let completed = self
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (completed, _) = self
            .changed
            .wait_timeout_while(completed, remaining, |completed| !*completed)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *completed
    }
}

struct HttpWorkerCompletionGuard(Arc<HttpWorkerCompletion>);

impl Drop for HttpWorkerCompletionGuard {
    fn drop(&mut self) {
        let mut completed = self
            .0
            .completed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *completed = true;
        self.0.changed.notify_all();
    }
}

struct HttpTestServer {
    address: SocketAddr,
    control: RuntimeHttpServerControl,
    startup: Option<mpsc::Receiver<ServerStartupEvent>>,
    terminal: mpsc::Receiver<Result<(), String>>,
    terminal_result: Option<Result<(), String>>,
    worker: Option<std::thread::JoinHandle<()>>,
    observer: RuntimeContext,
    completion: Arc<HttpWorkerCompletion>,
    deadline: Instant,
}

impl HttpTestServer {
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    fn await_readiness(&mut self) {
        let startup = self.startup.take().expect("HTTP startup is awaited once");
        match startup
            .recv_timeout(self.remaining())
            .expect("HTTP server startup reached a terminal state")
        {
            ServerStartupEvent::Ready { address } => {
                assert_eq!(address, self.address, "HTTP server ready address changed");
            }
            ServerStartupEvent::Failed { phase, message } => {
                panic!("HTTP test server failed before readiness: phase={phase}; failure={message}")
            }
        }
    }

    fn connect(&self) -> TcpStream {
        let remaining = self.remaining();
        assert!(
            !remaining.is_zero(),
            "HTTP fixture deadline expired before connect"
        );
        let stream = TcpStream::connect_timeout(&self.address, remaining)
            .expect("ready HTTP test server accepts a connection");
        let remaining = self.remaining();
        assert!(
            !remaining.is_zero(),
            "HTTP fixture deadline expired after connect"
        );
        stream.set_read_timeout(Some(remaining)).unwrap();
        stream.set_write_timeout(Some(remaining)).unwrap();
        stream
    }

    fn terminal_result(&mut self) -> Result<(), String> {
        if self.terminal_result.is_none() {
            let remaining = self.remaining();
            match self.terminal.recv_timeout(remaining) {
                Ok(result) => self.terminal_result = Some(result),
                Err(error) => {
                    return Err(format!(
                        "HTTP server terminal state was unavailable: {error}"
                    ));
                }
            }
        }
        self.join_completed_worker();
        self.terminal_result
            .as_ref()
            .expect("HTTP terminal result is retained")
            .clone()
    }

    fn finish(&mut self) {
        self.terminal_result().unwrap();
    }

    fn observer(&self) -> &RuntimeContext {
        &self.observer
    }

    fn completion(&self) -> Arc<HttpWorkerCompletion> {
        Arc::clone(&self.completion)
    }

    fn try_terminal(&self) -> Result<Result<(), String>, mpsc::TryRecvError> {
        self.terminal.try_recv()
    }

    fn join_completed_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.join().expect("HTTP server worker joins");
        }
    }
}

impl Drop for HttpTestServer {
    fn drop(&mut self) {
        if self.worker.is_none() {
            return;
        }
        self.control.cancel();
        if self.terminal_result.is_none() {
            self.terminal_result = self.terminal.recv_timeout(self.remaining()).ok();
        }
        if self.terminal_result.is_some() {
            self.join_completed_worker();
        } else if let Some(worker) = self.worker.take() {
            reap_http_worker(worker);
        }
    }
}

fn reap_http_worker(worker: std::thread::JoinHandle<()>) {
    static REAPER: std::sync::OnceLock<mpsc::Sender<std::thread::JoinHandle<()>>> =
        std::sync::OnceLock::new();
    let sender = REAPER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<std::thread::JoinHandle<()>>();
        std::thread::Builder::new()
            .name("hell-http-test-reaper".into())
            .spawn(move || {
                while let Ok(worker) = receiver.recv() {
                    let _ = worker.join();
                }
            })
            .expect("HTTP test worker reaper starts");
        sender
    });
    sender
        .send(worker)
        .expect("HTTP test worker reaper retains timed-out worker");
}

#[test]
fn supplied_example_43_takes_all_three_response_branches() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond ->\n",
            "  if Eq.eq (Http.pathInfo request) []\n",
            "    then\n",
            "      case List.lookup (CI.mk $ Text.encodeUtf8 \"Content-Type\")\n",
            "             (Http.requestHeaders request) of\n",
            "        Maybe.Just _x ->\n",
            "          respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") [] $\n",
            "            Builder.byteString $ Text.encodeUtf8 \"Hello, World!\"\n",
            "        Maybe.Nothing ->\n",
            "          respond $ Http.responseBuilder (Http.mkStatus 500 \"Error\") [] $\n",
            "            (Builder.byteString $ Text.encodeUtf8 \"Wobble\") <>\n",
            "            (Builder.byteString $ Text.encodeUtf8 \"Wobble\")\n",
            "    else\n",
            "      respond $\n",
            "        Http.responseFile (Http.mkStatus 400 \"Not Found\")\n",
            "          [(CI.mk (Text.encodeUtf8 \"Content-Type\"),\n",
            "            Text.encodeUtf8 \"text/markdown\")]\n",
            "          \"docs/readme.md\"\n",
            "          Maybe.Nothing\n",
        ),
        port = port
    );
    let directory = std::env::temp_dir().join(format!(
        "hell-http-example-{}-{}",
        std::process::id(),
        next_http_fixture()
    ));
    std::fs::create_dir_all(directory.join("docs")).unwrap();
    std::fs::write(directory.join("docs").join("readme.md"), b"example file\n").unwrap();
    let mut server = start_server_with_limit(listener, &source, directory.clone(), 3);

    let present = exchange(
        &server,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n\r\n",
    );
    assert!(present.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(response_body(&present), b"Hello, World!");

    let absent = exchange(&server, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(absent.starts_with(b"HTTP/1.1 500 Error\r\n"));
    assert_eq!(response_body(&absent), b"WobbleWobble");

    let file = exchange(&server, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(file.starts_with(b"HTTP/1.1 400 Not Found\r\n"));
    assert!(
        file.windows(b"Content-Type: text/markdown\r\n".len())
            .any(|window| window == b"Content-Type: text/markdown\r\n")
    );
    assert_eq!(response_body(&file), b"example file\n");

    server.finish();
    std::fs::remove_file(directory.join("docs").join("readme.md")).unwrap();
    std::fs::remove_dir(directory.join("docs")).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

fn exchange(server: &HttpTestServer, request: &[u8]) -> Vec<u8> {
    let mut stream = server.connect();
    // Requests are self-delimiting; a half-close races the server's response close on macOS.
    stream.write_all(request).unwrap();
    read_response(&mut stream)
}

struct UnreachableHttpApplication;

impl Application for UnreachableHttpApplication {
    fn call(&self, _request: HostRequest) -> HostResult<HostResponse> {
        panic!("listener-policy rejection must precede HTTP application dispatch")
    }
}

#[test]
fn prebound_listener_remains_owned_through_exact_readiness() {
    let listener = ReservedHttpListener::bind();
    let address = listener.address;
    let port = listener.port();
    assert!(
        TcpListener::bind(address).is_err(),
        "a competitor acquired the retained HTTP listener address"
    );
    let source = format!(
        concat!(
            "main = Http.run {port} \\_request respond ->\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "    (Builder.byteString $ Text.encodeUtf8 \"owned\")\n",
        ),
        port = port
    );
    let mut server = start_server(listener, &source, std::env::temp_dir());
    let response = exchange(
        &server,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(response_body(&response), b"owned");
    server.finish();
}

#[test]
fn prebound_listener_policy_failure_is_typed_before_readiness() {
    let listener = BoundServerListener::bind_loopback().expect("HTTP test listener reserves");
    let address = listener.address();
    let requested_port = if address.port() == u16::MAX {
        address.port() - 1
    } else {
        address.port() + 1
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let startup: ServerStartupObserver = Arc::new(move |event| {
        let _ = sender.try_send(event);
    });
    let config = ServerConfig {
        port: requested_port,
        loopback_only: true,
        max_connections: Some(1),
        max_headers: None,
        max_header_bytes: None,
        max_body_bytes: None,
        idle_timeout: None,
        graceful_shutdown: Duration::from_secs(1),
        request_limit: Some(1),
        shutdown_requested: Arc::new(|| false),
        acquire_connection: Arc::new(|| Ok(Box::new(()))),
    };
    let error = hell_http_host::serve_with_listener(
        config,
        Arc::new(UnreachableHttpApplication),
        listener,
        &startup,
    )
    .expect_err("mismatched listener port fails before readiness");
    assert!(error.message().contains("differs from policy"));
    match receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("typed listener-policy failure arrives")
    {
        ServerStartupEvent::Failed { phase, message } => {
            assert_eq!(phase, "listener-policy");
            assert!(message.contains("differs from policy"));
        }
        ServerStartupEvent::Ready { address } => {
            panic!("mismatched listener unexpectedly became ready at {address}")
        }
    }
}

fn fixture_response_source(port: u16, body: &str) -> String {
    format!(
        concat!(
            "main = Http.run {port} \\_request respond ->\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "    (Builder.byteString $ Text.encodeUtf8 \"{body}\")\n",
        ),
        port = port,
        body = body,
    )
}

#[test]
fn delayed_http_fixture_waits_for_exact_readiness_without_polling() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let context = RuntimeContext::with_host(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        std::env::temp_dir(),
        true,
    )
    .with_http_request_limit(1);
    let (release, gate) = mpsc::sync_channel(0);
    let mut server = launch_server_in_context(
        listener,
        &fixture_response_source(port, "delayed"),
        context,
        Some(gate),
    );
    assert!(matches!(
        server
            .startup
            .as_ref()
            .expect("startup remains pending")
            .try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    release.send(()).unwrap();
    server.await_readiness();
    let response = exchange(
        &server,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(response_body(&response), b"delayed");
    server.finish();
}

#[test]
fn independently_prebound_http_fixtures_are_parallel_and_isolated() {
    let workers = (0..4)
        .map(|index| {
            std::thread::spawn(move || {
                let listener = ReservedHttpListener::bind();
                let port = listener.port();
                let body = format!("fixture-{index}");
                let mut server = start_server(
                    listener,
                    &fixture_response_source(port, &body),
                    std::env::temp_dir(),
                );
                let response = exchange(
                    &server,
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                );
                assert_eq!(response_body(&response), body.as_bytes());
                server.finish();
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn prebound_http_listener_authority_rejects_second_use() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = fixture_response_source(port, "once");
    let mut server = start_server(listener, &source, std::env::temp_dir());
    let reused_context = server.observer().clone();
    let response = exchange(
        &server,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(response_body(&response), b"once");
    server.finish();
    let program = compile_source(
        &mut CompilerSession::default(),
        "http-second.hell",
        source.as_str(),
    )
    .expect("second-use source compiles");
    let error = run_main(program, reused_context).unwrap_err();
    assert!(
        error
            .message
            .contains("listener authority was already used")
    );
}

#[test]
fn post_ready_panic_cancels_and_joins_the_http_worker() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let server = start_server(
        listener,
        &fixture_response_source(port, "unused"),
        std::env::temp_dir(),
    );
    let completion = server.completion();
    let observer = server.observer().clone();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _server = server;
        panic!("post-ready fixture assertion failed");
    }));
    assert!(panic.is_err());
    assert!(completion.wait_until(Instant::now() + HTTP_FIXTURE_TIMEOUT));
    let resources = observer.budget().snapshot();
    assert_eq!(resources.live_http_connections, 0);
    assert_eq!(resources.live_tasks, 0);
}

#[test]
fn readiness_timeout_transfers_stuck_worker_to_the_bounded_reaper() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let context = RuntimeContext::with_host(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        std::env::temp_dir(),
        true,
    )
    .with_http_request_limit(1);
    let (release, gate) = mpsc::sync_channel(0);
    let mut server = launch_server_in_context(
        listener,
        &fixture_response_source(port, "unused"),
        context,
        Some(gate),
    );
    let completion = server.completion();
    server.deadline = Instant::now();
    let timeout = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        server.await_readiness();
    }));
    assert!(timeout.is_err());
    drop(release);
    drop(server);
    assert!(completion.wait_until(Instant::now() + HTTP_FIXTURE_TIMEOUT));
}

fn read_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    while response_message_end(&response).is_none() {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..read]);
    }
    if let Some(end) = response_message_end(&response) {
        response.truncate(end);
    }
    response
}

fn response_message_end(response: &[u8]) -> Option<usize> {
    let boundary = response
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")?;
    let body_start = boundary + b"\r\n\r\n".len();
    let head = &response[..boundary];
    let mut content_length = None;
    let mut chunked = false;
    for line in head.split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = trim_ascii_space(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"content-length") {
            content_length = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<usize>().ok());
        }
        if name.eq_ignore_ascii_case(b"transfer-encoding") && value.eq_ignore_ascii_case(b"chunked")
        {
            chunked = true;
        }
    }
    if let Some(length) = content_length {
        return (response.len() >= body_start.saturating_add(length))
            .then_some(body_start + length);
    }
    if chunked {
        return chunked_body_end(&response[body_start..]).map(|end| body_start + end);
    }
    None
}

fn chunked_body_end(body: &[u8]) -> Option<usize> {
    let mut cursor = 0usize;
    loop {
        let line_end = body[cursor..]
            .windows(b"\r\n".len())
            .position(|window| window == b"\r\n")?
            + cursor;
        let size = std::str::from_utf8(body[cursor..line_end].split(|byte| *byte == b';').next()?)
            .ok()
            .and_then(|digits| usize::from_str_radix(digits, 16).ok())?;
        cursor = line_end + b"\r\n".len();
        if size == 0 {
            let trailer_end = body[cursor..]
                .windows(b"\r\n".len())
                .position(|window| window == b"\r\n")?;
            return Some(cursor + trailer_end + b"\r\n".len());
        }
        cursor = cursor.checked_add(size)?;
        if body.get(cursor..cursor + b"\r\n".len())? != b"\r\n" {
            return None;
        }
        cursor += b"\r\n".len();
    }
}

fn trim_ascii_space(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn response_body(response: &[u8]) -> &[u8] {
    let boundary = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response contains a header terminator");
    &response[boundary + 4..]
}

#[test]
fn request_metadata_and_body_streaming_round_trip_raw_bytes() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond ->\n",
            "  if Eq.eq (Http.pathInfo request) [\"hello world\"]\n",
            "    then if Eq.eq (Http.queryString request)\n",
            "      [(Text.encodeUtf8 \"novalue\", Maybe.Nothing),\n",
            "       (Text.encodeUtf8 \"empty\", Maybe.Just (Text.encodeUtf8 \"\")),\n",
            "       (Text.encodeUtf8 \"plus\", Maybe.Just (Text.encodeUtf8 \"a b\"))]\n",
            "      then case List.lookup (CI.mk (Text.encodeUtf8 \"X-Test\"))\n",
            "             (Http.requestHeaders request) of\n",
            "        Maybe.Just value -> if Eq.eq value (Text.encodeUtf8 \"present\")\n",
            "          then do\n",
            "            first <- Http.getRequestBodyChunk request\n",
            "            rest <- Http.consumeRequestBodyStrict request\n",
            "            respond $ Http.responseBuilder (Http.mkStatus 201 \"Created\")\n",
            "              [] (Builder.byteString first <> Builder.byteString rest)\n",
            "          else respond $ Http.responseBuilder (Http.mkStatus 400 \"Bad\") []\n",
            "            (Builder.byteString $ Text.encodeUtf8 \"header\")\n",
            "        Maybe.Nothing -> respond $ Http.responseBuilder\n",
            "          (Http.mkStatus 400 \"Bad\") []\n",
            "          (Builder.byteString $ Text.encodeUtf8 \"missing\")\n",
            "      else respond $ Http.responseBuilder (Http.mkStatus 400 \"Bad\") []\n",
            "        (Builder.byteString $ Text.encodeUtf8 \"query\")\n",
            "    else respond $ Http.responseBuilder (Http.mkStatus 404 \"Not Found\") []\n",
            "      (Builder.byteString $ Text.encodeUtf8 \"path\")\n",
        ),
        port = port
    );
    let mut server = start_server(listener, &source, std::env::temp_dir());
    let body = vec![b'a'; 9_000];
    let request_head = format!(
        "POST /hello%20world?novalue&empty=&plus=a+b HTTP/1.1\r\nHost: localhost\r\nX-Test: present\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    let mut stream = server.connect();
    stream.write_all(&request_head).unwrap();
    let split = body.len() / 2;
    stream.write_all(&body[..split]).unwrap();
    std::thread::sleep(Duration::from_millis(10));
    stream.write_all(&body[split..]).unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with(b"HTTP/1.1 201 Created\r\n"));
    assert_eq!(response_body(&response), body);
    server.finish();
}

#[test]
fn empty_request_body_repeats_eof_without_blocking() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond -> do\n",
            "  first <- Http.getRequestBodyChunk request\n",
            "  second <- Http.getRequestBodyChunk request\n",
            "  rest <- Http.consumeRequestBodyStrict request\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "    (Builder.byteString first <> Builder.byteString second <>\n",
            "     Builder.byteString rest)\n",
        ),
        port = port
    );
    let mut server = start_server(listener, &source, std::env::temp_dir());
    let response = exchange(
        &server,
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(response_body(&response), b"");
    server.finish();
}

#[test]
fn file_parts_and_stream_callbacks_have_exact_wire_bodies() {
    let directory = std::env::temp_dir().join(format!(
        "hell-http-test-{}-{}",
        std::process::id(),
        next_http_fixture()
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("body.bin"), b"01234567").unwrap();

    let file_listener = ReservedHttpListener::bind();
    let file_port = file_listener.port();
    let file_source = format!(
        concat!(
            "main = Http.run {file_port} \\_request respond ->\n",
            "  respond $ Http.responseFile (Http.mkStatus 206 \"Partial Content\") []\n",
            "    \"body.bin\" $ Maybe.Just $ Http.FilePart\n",
            "      (Int.toInteger 2) (Int.toInteger 4) (Int.toInteger 8)\n",
        ),
        file_port = file_port
    );
    let mut server = start_server_with_limit(file_listener, &file_source, directory.clone(), 2);
    let mut head_stream = server.connect();
    head_stream
        .write_all(b"HEAD /file HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let head = read_response_head(&mut head_stream);
    assert!(head.starts_with(b"HTTP/1.1 206 Partial Content\r\n"));
    assert!(
        head.windows(b"Content-Length: 4\r\n".len())
            .any(|window| { window == b"Content-Length: 4\r\n" })
    );
    let response = exchange(&server, b"GET /file HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.starts_with(b"HTTP/1.1 206 Partial Content\r\n"));
    assert_eq!(response_body(&response), b"2345");
    server.finish();

    let stream_listener = ReservedHttpListener::bind();
    let stream_port = stream_listener.port();
    let stream_source = format!(
        concat!(
            "main = Http.run {stream_port} \\_request respond ->\n",
            "  respond $ Http.responseStream (Http.mkStatus 200 \"OK\") []\n",
            "    (\\write flush -> do\n",
            "      write $ Builder.byteString $ Text.encodeUtf8 \"one\"\n",
            "      flush\n",
            "      write $ Builder.byteString $ Text.encodeUtf8 \"two\")\n",
        ),
        stream_port = stream_port
    );
    let mut server = start_server(stream_listener, &stream_source, directory.clone());
    let response = exchange(&server, b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        response
            .windows(b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n".len())
            .any(|window| window == b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n")
    );
    server.finish();

    std::fs::remove_file(directory.join("body.bin")).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn response_file_mutation_after_headers_is_structured_and_leak_free() {
    let directory = std::env::temp_dir().join(format!(
        "hell-http-file-mutation-{}-{}",
        std::process::id(),
        next_http_fixture()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("changing.bin");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    drop(file);

    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\_request respond ->\n",
            "  respond $ Http.responseFile (Http.mkStatus 200 \"OK\") []\n",
            "    \"changing.bin\" Maybe.Nothing\n",
        ),
        port = port
    );
    let mut server = start_server_observed(listener, &source, directory.clone());
    let mut stream = server.connect();
    stream
        .write_all(b"GET /file HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let head = read_response_head(&mut stream);
    assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));

    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(0)
        .unwrap();
    let mut partial_body = Vec::new();
    let _closed = stream.read_to_end(&mut partial_body);
    let error = server.terminal_result().unwrap_err();
    assert!(error.contains("file ended before the requested range"));
    let resources = server.observer().budget().snapshot();
    assert_eq!(resources.live_http_connections, 0);
    assert_eq!(resources.live_tasks, 0);

    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn streaming_client_disconnect_is_connection_local_and_releases_resource_permits() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let chunk = "x".repeat(1024);
    let source = format!(
        concat!(
            "main = Http.run {port} \\_request respond ->\n",
            "  respond $ Http.responseStream (Http.mkStatus 200 \"OK\") []\n",
            "    (\\write _flush -> IO.mapM_ write $ List.take 65536 $ List.repeat $\n",
            "      Builder.byteString $ Text.encodeUtf8 \"{chunk}\")\n",
        ),
        port = port,
        chunk = chunk,
    );
    let mut server = start_server_observed(listener, &source, std::env::temp_dir());
    let mut stream = server.connect();
    stream
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let head = read_response_head(&mut stream);
    assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
    stream.shutdown(Shutdown::Both).unwrap();
    drop(stream);

    server
        .terminal_result()
        .expect("client disconnect must not fail the HTTP application");
    let resources = server.observer().budget().snapshot();
    assert_eq!(resources.live_http_connections, 0);
    assert_eq!(resources.live_tasks, 0);
}

#[test]
fn file_and_chunked_fixed_disconnects_are_connection_local() {
    let directory = std::env::temp_dir().join(format!(
        "hell-http-peer-abort-{}-{}",
        std::process::id(),
        next_http_fixture()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("large.bin");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    drop(file);

    let file_listener = ReservedHttpListener::bind();
    let file_port = file_listener.port();
    let file_source = format!(
        concat!(
            "main = Http.run {file_port} \\_request respond ->\n",
            "  respond $ Http.responseFile (Http.mkStatus 200 \"OK\") []\n",
            "    \"large.bin\" Maybe.Nothing\n",
        ),
        file_port = file_port
    );
    let mut server = start_server_observed(file_listener, &file_source, directory.clone());
    let mut stream = server.connect();
    stream
        .write_all(b"GET /file HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let head = read_response_head(&mut stream);
    assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
    stream.shutdown(Shutdown::Both).unwrap();
    drop(stream);
    server
        .terminal_result()
        .expect("file disconnect must not fail the HTTP application");
    let resources = server.observer().budget().snapshot();
    assert_eq!(resources.live_http_connections, 0);
    assert_eq!(resources.live_tasks, 0);

    let fixed_listener = ReservedHttpListener::bind();
    let fixed_port = fixed_listener.port();
    let fixed_source = format!(
        concat!(
            "main = Http.run {fixed_port} \\_request respond -> do\n",
            "  body <- ByteString.readFile \"large.bin\"\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\")\n",
            "    [(CI.mk (Text.encodeUtf8 \"Transfer-Encoding\"), Text.encodeUtf8 \"chunked\")]\n",
            "    (Builder.byteString body)\n",
        ),
        fixed_port = fixed_port
    );
    let mut server = start_server_observed(fixed_listener, &fixed_source, directory.clone());
    let mut stream = server.connect();
    stream
        .write_all(b"GET /fixed HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let head = read_response_head(&mut stream);
    assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
    stream.shutdown(Shutdown::Both).unwrap();
    drop(stream);
    server
        .terminal_result()
        .expect("fixed disconnect must not fail the HTTP application");
    let resources = server.observer().budget().snapshot();
    assert_eq!(resources.live_http_connections, 0);
    assert_eq!(resources.live_tasks, 0);

    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

fn is_incomplete_request_failure(error: &str) -> bool {
    // Hyper connection teardown can cancel the request before the independent
    // body pump publishes its transport error, or the pump can publish first.
    // Hyper's transport error has one exact connection category and may append
    // one nonempty single-line cause. Runtime cancellation is the third source.
    error == "H0906: IO action was cancelled"
        || error == "H0908: HTTP request was cancelled"
        || error == "H0908: read HTTP request body: error reading a body from connection"
        || error
            .strip_prefix("H0908: read HTTP request body: error reading a body from connection: ")
            .is_some_and(|detail| {
                !detail.is_empty() && !detail.contains('\r') && !detail.contains('\n')
            })
}

#[test]
fn incomplete_request_failure_classification_is_closed_world() {
    for error in [
        "H0906: IO action was cancelled",
        "H0908: HTTP request was cancelled",
        "H0908: read HTTP request body: error reading a body from connection",
        "H0908: read HTTP request body: error reading a body from connection: incomplete message",
    ] {
        assert!(is_incomplete_request_failure(error));
    }
    for error in [
        "H0908: request was cancelled",
        "H0908: HTTP request was cancelled: response started",
        "H0908: read HTTP request body: error reading a body from connection: ",
        "H0908: read HTTP request body: error reading a body from connection: incomplete\nmessage",
        "H0908: HTTP response stream was cancelled",
        "H0908: network capability is disabled",
    ] {
        assert!(!is_incomplete_request_failure(error));
    }
}

#[test]
fn incomplete_request_before_response_remains_server_fatal() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond -> do\n",
            "  body <- Http.consumeRequestBodyStrict request\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "    (Builder.byteString body)\n",
        ),
        port = port
    );
    let mut server = start_server_observed(listener, &source, std::env::temp_dir());
    let mut stream = server.connect();
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\npartial")
        .unwrap();
    stream.shutdown(Shutdown::Write).unwrap();

    let error = server.terminal_result().unwrap_err();
    assert!(
        is_incomplete_request_failure(&error),
        "unexpected incomplete-request error: {error}"
    );
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(
        response.is_empty(),
        "incomplete request unexpectedly produced a response: {response:?}"
    );
    let resources = server.observer().budget().snapshot();
    assert_eq!(resources.live_http_connections, 0);
    assert_eq!(resources.live_tasks, 0);
}

#[test]
fn network_capability_and_invalid_status_fail_explicitly() {
    let source =
        "main = Http.run 12345 (\\_request _respond -> IO.pure (Error.error \"unused\"))\n";
    let program = compile_source(&mut CompilerSession::default(), "http-denied.hell", source)
        .expect("HTTP source compiles");
    let error = run_main(
        program,
        RuntimeContext::new(Vec::new(), Vec::new()).with_network_capability(false),
    )
    .unwrap_err();
    assert_eq!(error.code, "H0908");
    assert!(error.message.contains("network capability is disabled"));

    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let invalid = format!(
        concat!(
            "main = Http.run {port} \\_request respond ->\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 99 \"Bad\") []\n",
            "    (Builder.byteString $ Text.encodeUtf8 \"unused\")\n",
        ),
        port = port
    );
    let mut server = start_server(listener, &invalid, std::env::temp_dir());
    let response = exchange(&server, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.is_empty());
    let error = server.terminal_result().unwrap_err();
    assert!(error.starts_with("H0908:"));
}

#[test]
fn keep_alive_reuses_connections_and_drains_unconsumed_request_bodies() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond ->\n",
            "  if Eq.eq (Http.pathInfo request) [\"first\"]\n",
            "    then respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "      (Builder.byteString $ Text.encodeUtf8 \"one\")\n",
            "    else respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "      (Builder.byteString $ Text.encodeUtf8 \"two\")\n",
        ),
        port = port
    );
    let mut server = start_server_with_limit(listener, &source, std::env::temp_dir(), 2);
    let mut stream = server.connect();
    stream
        .write_all(
            concat!(
                "POST /first HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Content-Length: 4\r\n",
                "Content-Length: 4\r\n\r\n",
                "DATA",
            )
            .as_bytes(),
        )
        .unwrap();
    let first = read_response(&mut stream);
    assert_eq!(response_body(&first), b"one");
    assert!(
        !first
            .windows(b"Connection: close".len())
            .any(|window| { window.eq_ignore_ascii_case(b"Connection: close") })
    );
    stream
        .write_all(b"GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let second = read_response(&mut stream);
    assert_eq!(response_body(&second), b"two");
    server.finish();
}

#[test]
fn chunked_extensions_and_trailers_preserve_exact_body_bytes() {
    // The guest API has no trailer accessor; the host must still validate and drain them so the
    // next keep-alive request starts at the exact framing boundary.
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond -> do\n",
            "  body <- Http.consumeRequestBodyStrict request\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "    (Builder.byteString body)\n",
        ),
        port = port
    );
    let mut server = start_server_with_limit(listener, &source, std::env::temp_dir(), 2);
    let mut stream = server.connect();
    stream
        .write_all(
            concat!(
                "POST / HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Transfer-Encoding: chunked\r\n",
                "\r\n",
                "4;name=value\r\nDATA\r\n",
                "3\r\nxyz\r\n",
                "0\r\nX-Trailer: yes\r\n\r\n",
            )
            .as_bytes(),
        )
        .unwrap();
    let first = read_response(&mut stream);
    assert_eq!(response_body(&first), b"DATAxyz");
    stream
        .write_all(b"GET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let second = read_response(&mut stream);
    assert_eq!(response_body(&second), b"");
    server.finish();
}

#[test]
fn ambiguous_request_framing_is_rejected_without_running_the_application() {
    let source_for = |port| {
        format!(
            concat!(
                "main = Http.run {port} \\_request respond ->\n",
                "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
                "    (Builder.byteString $ Text.encodeUtf8 \"unexpected\")\n",
            ),
            port = port
        )
    };

    for request in [
        concat!(
            "POST / HTTP/1.1\r\nHost: localhost\r\n",
            "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n",
        ),
        concat!(
            "POST / HTTP/1.1\r\nHost: localhost\r\n",
            "Content-Length: 4\r\nContent-Length: 5\r\n\r\n",
        ),
    ] {
        let listener = ReservedHttpListener::bind();
        let port = listener.port();
        let mut server = start_server(listener, &source_for(port), std::env::temp_dir());
        let mut stream = server.connect();
        stream.write_all(request.as_bytes()).unwrap();
        let error = server.terminal_result().unwrap_err();
        assert!(error.contains("H0908:"));
    }
}

#[test]
fn sandbox_http_header_and_body_limits_are_explicit_policy() {
    let source_for = |port| {
        format!(
            concat!(
                "main = Http.run {port} \\_request respond ->\n",
                "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
                "    (Builder.byteString $ Text.encodeUtf8 \"unexpected\")\n",
            ),
            port = port
        )
    };
    for (request, header_limit, expected) in [
        (
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: 1234567890\r\n\r\n".as_slice(),
            48,
            "headers exceeded",
        ),
        (
            b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n".as_slice(),
            1024,
            "too large",
        ),
    ] {
        let listener = ReservedHttpListener::bind();
        let port = listener.port();
        let mut policy = RuntimePolicy::sandboxed();
        policy.limits.http_header_bytes = Limit::At(header_limit);
        policy.limits.http_body_bytes = Limit::At(4);
        let context = RuntimeContext::with_host(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            std::env::temp_dir(),
            true,
        )
        .with_policy(policy)
        .with_http_request_limit(1);
        let mut server = start_server_in_context(listener, &source_for(port), context);
        let mut stream = server.connect();
        stream.write_all(request).unwrap();
        let error = server.terminal_result().unwrap_err();
        assert!(error.contains(expected), "unexpected error: {error}");
    }
}

#[test]
fn malformed_request_targets_match_the_pinned_warp_oracle() {
    // Measured against the pinned Hell/Warp oracle: an invalid percent escape remains literal,
    // while percent-encoded and raw invalid UTF-8 octets both decode to U+FFFD in pathInfo.
    for (target, expected) in [
        (b"/%ZZ".as_slice(), "%ZZ"),
        (b"/%FF".as_slice(), "�"),
        (b"/\xff".as_slice(), "�"),
    ] {
        let listener = ReservedHttpListener::bind();
        let port = listener.port();
        let source = format!(
            concat!(
                "main = Http.run {port} \\request respond ->\n",
                "  if Eq.eq (Http.pathInfo request) [\"{expected}\"]\n",
                "    then respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
                "      (Builder.byteString $ Text.encodeUtf8 \"exact\")\n",
                "    else respond $ Http.responseBuilder (Http.mkStatus 400 \"Mismatch\") []\n",
                "      (Builder.byteString $ Text.encodeUtf8 \"mismatch\")\n",
            ),
            port = port,
            expected = expected,
        );
        let mut server = start_server(listener, &source, std::env::temp_dir());
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(target);
        request.extend_from_slice(b" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let response = exchange(&server, &request);
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(response_body(&response), b"exact");
        server.finish();
    }
}

#[test]
fn path_query_and_duplicate_header_shapes_are_preserved() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond ->\n",
            "  if Eq.eq (Http.pathInfo request) [\"a\", \"\", \"/\", \"☃\", \"\"]\n",
            "    then if Eq.eq (Http.queryString request)\n",
            "      [(Text.encodeUtf8 \"bad\", Maybe.Just (Text.encodeUtf8 \"%ZZ\")),\n",
            "       (Text.encodeUtf8 \"again\", Maybe.Nothing)]\n",
            "      then if Eq.eq (Http.requestHeaders request)\n",
            "        [(CI.mk (Text.encodeUtf8 \"Host\"), Text.encodeUtf8 \"localhost\"),\n",
            "         (CI.mk (Text.encodeUtf8 \"X-Dupe\"), Text.encodeUtf8 \"first\"),\n",
            "         (CI.mk (Text.encodeUtf8 \"x-dupe\"), Text.encodeUtf8 \"second\")]\n",
            "        then respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "          (Builder.byteString $ Text.encodeUtf8 \"exact\")\n",
            "        else respond $ Http.responseBuilder (Http.mkStatus 400 \"Headers\") []\n",
            "          (Builder.byteString $ Text.encodeUtf8 \"headers\")\n",
            "      else respond $ Http.responseBuilder (Http.mkStatus 400 \"Query\") []\n",
            "        (Builder.byteString $ Text.encodeUtf8 \"query\")\n",
            "    else respond $ Http.responseBuilder (Http.mkStatus 400 \"Path\") []\n",
            "      (Builder.byteString $ Text.encodeUtf8 \"path\")\n",
        ),
        port = port
    );
    let mut server = start_server(listener, &source, std::env::temp_dir());
    let response = exchange(
        &server,
        concat!(
            "GET /a//%2F/%E2%98%83/?bad=%ZZ&again HTTP/1.1\r\n",
            "Host: localhost\r\nX-Dupe: first\r\nx-dupe: second\r\n\r\n",
        )
        .as_bytes(),
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(response_body(&response), b"exact");
    server.finish();
}

#[test]
fn http_10_keep_alive_and_head_and_no_body_statuses_are_framed() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond ->\n",
            "  if Eq.eq (Http.pathInfo request) [\"empty\"]\n",
            "    then respond $ Http.responseBuilder (Http.mkStatus 204 \"No Content\") []\n",
            "      (Builder.byteString $ Text.encodeUtf8 \"forbidden\")\n",
            "    else if Eq.eq (Http.pathInfo request) [\"not-modified\"]\n",
            "      then respond $ Http.responseBuilder (Http.mkStatus 304 \"Not Modified\") []\n",
            "        (Builder.byteString $ Text.encodeUtf8 \"forbidden\")\n",
            "      else if Eq.eq (Http.pathInfo request) [\"informational\"]\n",
            "        then respond $ Http.responseBuilder (Http.mkStatus 103 \"Early Hints\") []\n",
            "          (Builder.byteString $ Text.encodeUtf8 \"forbidden\")\n",
            "        else respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "          (Builder.byteString $ Text.encodeUtf8 \"hello\")\n",
        ),
        port = port
    );
    let mut server = start_server_with_limit(listener, &source, std::env::temp_dir(), 4);
    let mut stream = server.connect();
    stream
        .write_all(b"HEAD /head HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    let head = read_response_head(&mut stream);
    assert!(head.starts_with(b"HTTP/1.0 200 OK\r\n"));
    assert!(
        head.windows(b"Content-Length: 5\r\n".len())
            .any(|window| { window == b"Content-Length: 5\r\n" })
    );
    assert!(
        head.windows(b"Connection: keep-alive\r\n".len())
            .any(|window| { window.eq_ignore_ascii_case(b"Connection: keep-alive\r\n") })
    );
    stream
        .write_all(b"GET /empty HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    let no_content = read_response_head(&mut stream);
    assert!(no_content.starts_with(b"HTTP/1.0 204 No Content\r\n"));
    stream
        .write_all(b"GET /not-modified HTTP/1.0\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    let not_modified = read_response_head(&mut stream);
    assert!(not_modified.starts_with(b"HTTP/1.0 304 Not Modified\r\n"));
    stream
        .write_all(b"GET /informational HTTP/1.0\r\nConnection: close\r\n\r\n")
        .unwrap();
    let informational = read_response_head(&mut stream);
    assert!(informational.starts_with(b"HTTP/1.0 103 Early Hints\r\n"));
    server.finish();
}

#[test]
fn response_stream_flush_is_visible_before_callback_completion() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\_request respond ->\n",
            "  respond $ Http.responseStream (Http.mkStatus 200 \"OK\") []\n",
            "    (\\write flush -> do\n",
            "      write $ Builder.byteString $ Text.encodeUtf8 \"one\"\n",
            "      flush\n",
            "      Concurrent.threadDelay 250000\n",
            "      write $ Builder.byteString $ Text.encodeUtf8 \"two\")\n",
        ),
        port = port
    );
    let mut server = start_server(listener, &source, std::env::temp_dir());
    let mut stream = server.connect();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut before_completion = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !before_completion
        .windows(b"3\r\none\r\n".len())
        .any(|window| window == b"3\r\none\r\n")
    {
        let read = stream.read(&mut buffer).unwrap();
        assert_ne!(read, 0, "stream closed before the flushed chunk arrived");
        before_completion.extend_from_slice(&buffer[..read]);
    }
    assert!(
        !before_completion
            .windows(b"two".len())
            .any(|window| { window == b"two" })
    );
    assert!(matches!(
        server.try_terminal(),
        Err(mpsc::TryRecvError::Empty)
    ));
    stream.read_to_end(&mut before_completion).unwrap();
    assert!(
        before_completion
            .windows(b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n".len())
            .any(|window| window == b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n")
    );
    server.finish();
}

#[test]
fn timed_cancellation_wakes_a_partial_request_body_read() {
    let listener = ReservedHttpListener::bind();
    let port = listener.port();
    let source = format!(
        concat!(
            "server = Http.run {port} \\request respond -> do\n",
            "  body <- Http.consumeRequestBodyStrict request\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "    (Builder.byteString body)\n",
            "cancel = do\n",
            "  _ready <- Text.getLine\n",
            "  Concurrent.threadDelay 200000\n",
            "main = do\n",
            "  _result <- Async.race Main.server Main.cancel\n",
            "  IO.pure ()\n",
        ),
        port = port
    );
    let (cancel_sender, cancel_receiver) = mpsc::channel();
    let context = RuntimeContext::with_host(
        Vec::new(),
        Vec::new(),
        Vec::new(),
        std::env::temp_dir(),
        true,
    )
    .with_http_request_limit(100)
    .with_stdin(OneShotGateReader::new(cancel_receiver));
    let mut server = start_server_in_context(listener, &source, context);
    let mut stream = server.connect();
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\npartial")
        .unwrap();
    cancel_sender.send(()).unwrap();
    server.finish();
}

#[cfg(feature = "mutation-testing")]
#[test]
fn blocked_body_test_detects_removed_process_stream_cancellation() {
    let executable = std::env::current_exe().expect("HTTP integration test executable exists");
    let mut command = std::process::Command::new(executable);
    command.args([
        "--exact",
        "timed_cancellation_wakes_a_partial_request_body_read",
        "--nocapture",
        "--skip",
        "__hell_mutant",
        "--skip",
        "process-stream-cancellation",
    ]);
    let output =
        hell_testkit::run_supervised_command(&mut command, &[], std::time::Duration::from_secs(30))
            .expect("supervise activated HTTP cancellation test");
    assert!(
        !output.timed_out,
        "activated HTTP cancellation test exceeded its deadline"
    );
    assert!(
        !output.status.success(),
        "activated process-stream cancellation mutant survived: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout.retained_bytes()),
        String::from_utf8_lossy(&output.stderr.retained_bytes())
    );
}

#[test]
fn responder_is_one_shot_and_application_failures_are_visible() {
    for (application, expected, assert_no_response) in [
        ("Error.error \"before response\"\n", "before response", true),
        (
            concat!(
                "do\n",
                "    let response = Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
                "          (Builder.byteString $ Text.encodeUtf8 \"unused\")\n",
                "    _first <- respond response\n",
                "    respond response\n",
            ),
            "exactly once",
            true,
        ),
        (
            concat!(
                "do\n",
                "    _first <- respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
                "      (Builder.byteString $ Text.encodeUtf8 \"unused\")\n",
                "    Error.error \"after response\"\n",
            ),
            "after response",
            true,
        ),
        (
            concat!(
                "respond $ Http.responseStream (Http.mkStatus 200 \"OK\") []\n",
                "  (\\_write _flush -> Error.error \"stream failure\")\n",
            ),
            "stream failure",
            false,
        ),
    ] {
        let listener = ReservedHttpListener::bind();
        let port = listener.port();
        let source = format!("main = Http.run {port} \\_request respond -> {application}");
        let mut server = start_server(listener, &source, std::env::temp_dir());
        let mut stream = server.connect();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let error = server.terminal_result().unwrap_err();
        assert!(error.contains(expected), "unexpected error: {error}");
        if assert_no_response {
            stream.set_nonblocking(true).unwrap();
            let mut response = [0_u8; 1];
            match stream.read(&mut response) {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::ConnectionReset
                    ) => {}
                Ok(_) => panic!("failed application emitted a partial response"),
                Err(error) => panic!("unexpected client read failure: {error}"),
            }
        }
    }
}

fn read_response_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
    }
    response
}
