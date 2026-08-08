use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::policy::{Limit, RuntimePolicy};
use hell_runtime::{RuntimeContext, run_main};

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

fn available_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_server(
    source: &str,
    cwd: PathBuf,
) -> (JoinHandle<()>, mpsc::Receiver<Result<(), String>>) {
    start_server_with_limit(source, cwd, 1)
}

fn start_server_with_limit(
    source: &str,
    cwd: PathBuf,
    request_limit: usize,
) -> (JoinHandle<()>, mpsc::Receiver<Result<(), String>>) {
    let program = compile_source(&mut CompilerSession::default(), "http.hell", source)
        .expect("HTTP source compiles");
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let context = RuntimeContext::with_host(Vec::new(), Vec::new(), Vec::new(), cwd, true)
            .with_http_request_limit(request_limit);
        let result = run_main(program, context).map_err(|error| error.to_string());
        sender.send(result).unwrap();
    });
    (worker, receiver)
}

fn start_server_observed(
    source: &str,
    cwd: PathBuf,
) -> (
    JoinHandle<()>,
    mpsc::Receiver<Result<(), String>>,
    RuntimeContext,
) {
    let context = RuntimeContext::with_host(Vec::new(), Vec::new(), Vec::new(), cwd, true)
        .with_http_request_limit(1);
    start_server_in_context(source, context)
}

fn start_server_in_context(
    source: &str,
    context: RuntimeContext,
) -> (
    JoinHandle<()>,
    mpsc::Receiver<Result<(), String>>,
    RuntimeContext,
) {
    let program = compile_source(&mut CompilerSession::default(), "http.hell", source)
        .expect("HTTP source compiles");
    let observer = context.clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let result = run_main(program, context).map_err(|error| error.to_string());
        sender.send(result).unwrap();
    });
    (worker, receiver, observer)
}

#[test]
fn supplied_example_43_takes_all_three_response_branches() {
    let port = available_port();
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
        available_port()
    ));
    std::fs::create_dir_all(directory.join("docs")).unwrap();
    std::fs::write(directory.join("docs/readme.md"), b"example file\n").unwrap();
    let (worker, receiver) = start_server_with_limit(&source, directory.clone(), 3);

    let present = exchange(
        port,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n\r\n",
    );
    assert!(present.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(response_body(&present), b"Hello, World!");

    let absent = exchange(port, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(absent.starts_with(b"HTTP/1.1 500 Error\r\n"));
    assert_eq!(response_body(&absent), b"WobbleWobble");

    let file = exchange(port, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(file.starts_with(b"HTTP/1.1 400 Not Found\r\n"));
    assert!(
        file.windows(b"Content-Type: text/markdown\r\n".len())
            .any(|window| window == b"Content-Type: text/markdown\r\n")
    );
    assert_eq!(response_body(&file), b"example file\n");

    finish(worker, &receiver);
    std::fs::remove_file(directory.join("docs/readme.md")).unwrap();
    std::fs::remove_dir(directory.join("docs")).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

fn exchange(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = connect(port);
    // Requests are self-delimiting; a half-close races the server's response close on macOS.
    stream.write_all(request).unwrap();
    read_response(&mut stream)
}

fn connect(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    let stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("HTTP test server did not start: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
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

fn finish(worker: JoinHandle<()>, receiver: &mpsc::Receiver<Result<(), String>>) {
    receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("HTTP server completed")
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn request_metadata_and_body_streaming_round_trip_raw_bytes() {
    let port = available_port();
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
    let (worker, receiver) = start_server(&source, std::env::temp_dir());
    let body = vec![b'a'; 9_000];
    let request_head = format!(
        "POST /hello%20world?novalue&empty=&plus=a+b HTTP/1.1\r\nHost: localhost\r\nX-Test: present\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    let mut stream = connect(port);
    stream.write_all(&request_head).unwrap();
    let split = body.len() / 2;
    stream.write_all(&body[..split]).unwrap();
    std::thread::sleep(Duration::from_millis(10));
    stream.write_all(&body[split..]).unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with(b"HTTP/1.1 201 Created\r\n"));
    assert_eq!(response_body(&response), body);
    finish(worker, &receiver);
}

#[test]
fn empty_request_body_repeats_eof_without_blocking() {
    let port = available_port();
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
    let (worker, receiver) = start_server(&source, std::env::temp_dir());
    let response = exchange(
        port,
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(response_body(&response), b"");
    finish(worker, &receiver);
}

#[test]
fn file_parts_and_stream_callbacks_have_exact_wire_bodies() {
    let directory = std::env::temp_dir().join(format!(
        "hell-http-test-{}-{}",
        std::process::id(),
        available_port()
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("body.bin"), b"01234567").unwrap();

    let file_port = available_port();
    let file_source = format!(
        concat!(
            "main = Http.run {file_port} \\_request respond ->\n",
            "  respond $ Http.responseFile (Http.mkStatus 206 \"Partial Content\") []\n",
            "    \"body.bin\" $ Maybe.Just $ Http.FilePart\n",
            "      (Int.toInteger 2) (Int.toInteger 4) (Int.toInteger 8)\n",
        ),
        file_port = file_port
    );
    let (worker, receiver) = start_server_with_limit(&file_source, directory.clone(), 2);
    let mut head_stream = connect(file_port);
    head_stream
        .write_all(b"HEAD /file HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let head = read_response_head(&mut head_stream);
    assert!(head.starts_with(b"HTTP/1.1 206 Partial Content\r\n"));
    assert!(
        head.windows(b"Content-Length: 4\r\n".len())
            .any(|window| { window == b"Content-Length: 4\r\n" })
    );
    let response = exchange(file_port, b"GET /file HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.starts_with(b"HTTP/1.1 206 Partial Content\r\n"));
    assert_eq!(response_body(&response), b"2345");
    finish(worker, &receiver);

    let stream_port = available_port();
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
    let (worker, receiver) = start_server(&stream_source, directory.clone());
    let response = exchange(
        stream_port,
        b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n",
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        response
            .windows(b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n".len())
            .any(|window| window == b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n")
    );
    finish(worker, &receiver);

    std::fs::remove_file(directory.join("body.bin")).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn response_file_mutation_after_headers_is_structured_and_leak_free() {
    let directory = std::env::temp_dir().join(format!(
        "hell-http-file-mutation-{}-{}",
        std::process::id(),
        available_port()
    ));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("changing.bin");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    drop(file);

    let port = available_port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\_request respond ->\n",
            "  respond $ Http.responseFile (Http.mkStatus 200 \"OK\") []\n",
            "    \"changing.bin\" Maybe.Nothing\n",
        ),
        port = port
    );
    let (worker, receiver, observer) = start_server_observed(&source, directory.clone());
    let mut stream = connect(port);
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
    let error = receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("file mutation reached the server scope")
        .unwrap_err();
    assert!(error.contains("file ended before the requested range"));
    worker.join().unwrap();
    let resources = observer.budget().snapshot();
    assert_eq!(resources.live_http_connections, 0);
    assert_eq!(resources.live_tasks, 0);

    std::fs::remove_file(path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn streaming_client_disconnect_unwinds_and_releases_resource_permits() {
    let port = available_port();
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
    let (worker, receiver, observer) = start_server_observed(&source, std::env::temp_dir());
    let mut stream = connect(port);
    stream
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let head = read_response_head(&mut stream);
    assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
    stream.shutdown(Shutdown::Both).unwrap();
    drop(stream);

    let error = receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("client disconnect unwound the response stream")
        .unwrap_err();
    assert!(error.starts_with("H0908:"), "unexpected error: {error}");
    worker.join().unwrap();
    let resources = observer.budget().snapshot();
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

    let port = available_port();
    let invalid = format!(
        concat!(
            "main = Http.run {port} \\_request respond ->\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 99 \"Bad\") []\n",
            "    (Builder.byteString $ Text.encodeUtf8 \"unused\")\n",
        ),
        port = port
    );
    let (worker, receiver) = start_server(&invalid, std::env::temp_dir());
    let response = exchange(port, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(response.is_empty());
    let error = receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("HTTP server completed")
        .unwrap_err();
    assert!(error.starts_with("H0908:"));
    worker.join().unwrap();
}

#[test]
fn keep_alive_reuses_connections_and_drains_unconsumed_request_bodies() {
    let port = available_port();
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
    let (worker, receiver) = start_server_with_limit(&source, std::env::temp_dir(), 2);
    let mut stream = connect(port);
    stream
        .write_all(
            concat!(
                "POST /first HTTP/1.1\r\n",
                "Host: localhost\r\n",
                "Content-Length: 4\r\n",
                "Content-Length: 4\r\n\r\n",
                "DATA",
                "GET /second HTTP/1.1\r\n",
                "Host: localhost\r\n\r\n",
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
    let second = read_response(&mut stream);
    assert_eq!(response_body(&second), b"two");
    finish(worker, &receiver);
}

#[test]
fn chunked_extensions_and_trailers_preserve_exact_body_bytes() {
    // The guest API has no trailer accessor; the host must still validate and drain them so the
    // next keep-alive request starts at the exact framing boundary.
    let port = available_port();
    let source = format!(
        concat!(
            "main = Http.run {port} \\request respond -> do\n",
            "  body <- Http.consumeRequestBodyStrict request\n",
            "  respond $ Http.responseBuilder (Http.mkStatus 200 \"OK\") []\n",
            "    (Builder.byteString body)\n",
        ),
        port = port
    );
    let (worker, receiver) = start_server_with_limit(&source, std::env::temp_dir(), 2);
    let mut stream = connect(port);
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
                "GET /next HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .as_bytes(),
        )
        .unwrap();
    let first = read_response(&mut stream);
    assert_eq!(response_body(&first), b"DATAxyz");
    let second = read_response(&mut stream);
    assert_eq!(response_body(&second), b"");
    finish(worker, &receiver);
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
        let port = available_port();
        let (worker, receiver) = start_server(&source_for(port), std::env::temp_dir());
        let mut stream = connect(port);
        stream.write_all(request.as_bytes()).unwrap();
        let error = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("HTTP server rejected ambiguous framing")
            .unwrap_err();
        assert!(error.contains("H0908:"));
        worker.join().unwrap();
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
        let port = available_port();
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
        let (worker, receiver, _observer) = start_server_in_context(&source_for(port), context);
        let mut stream = connect(port);
        stream.write_all(request).unwrap();
        let error = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("sandbox HTTP policy rejected an oversized request")
            .unwrap_err();
        assert!(error.contains(expected), "unexpected error: {error}");
        worker.join().unwrap();
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
        let port = available_port();
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
        let (worker, receiver) = start_server(&source, std::env::temp_dir());
        let mut request = b"GET ".to_vec();
        request.extend_from_slice(target);
        request.extend_from_slice(b" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let response = exchange(port, &request);
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(response_body(&response), b"exact");
        finish(worker, &receiver);
    }
}

#[test]
fn path_query_and_duplicate_header_shapes_are_preserved() {
    let port = available_port();
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
    let (worker, receiver) = start_server(&source, std::env::temp_dir());
    let response = exchange(
        port,
        concat!(
            "GET /a//%2F/%E2%98%83/?bad=%ZZ&again HTTP/1.1\r\n",
            "Host: localhost\r\nX-Dupe: first\r\nx-dupe: second\r\n\r\n",
        )
        .as_bytes(),
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_eq!(response_body(&response), b"exact");
    finish(worker, &receiver);
}

#[test]
fn http_10_keep_alive_and_head_and_no_body_statuses_are_framed() {
    let port = available_port();
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
    let (worker, receiver) = start_server_with_limit(&source, std::env::temp_dir(), 4);
    let mut stream = connect(port);
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
    finish(worker, &receiver);
}

#[test]
fn response_stream_flush_is_visible_before_callback_completion() {
    let port = available_port();
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
    let (worker, receiver) = start_server(&source, std::env::temp_dir());
    let mut stream = connect(port);
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
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    stream.read_to_end(&mut before_completion).unwrap();
    assert!(
        before_completion
            .windows(b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n".len())
            .any(|window| window == b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n")
    );
    finish(worker, &receiver);
}

#[test]
fn timed_cancellation_wakes_a_partial_request_body_read() {
    let port = available_port();
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
    let (worker, receiver, _) = start_server_in_context(&source, context);
    let mut stream = connect(port);
    stream
        .write_all(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\npartial")
        .unwrap();
    cancel_sender.send(()).unwrap();
    receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("timed cancellation woke the partial HTTP request body")
        .unwrap();
    worker.join().unwrap();
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
        let port = available_port();
        let source = format!("main = Http.run {port} \\_request respond -> {application}");
        let (worker, receiver) = start_server(&source, std::env::temp_dir());
        let mut stream = connect(port);
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let error = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("HTTP application failure reached the server scope")
            .unwrap_err();
        assert!(error.contains(expected), "unexpected error: {error}");
        worker.join().unwrap();
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
