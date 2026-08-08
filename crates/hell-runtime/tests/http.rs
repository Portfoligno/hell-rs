use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{RuntimeContext, run_main};

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
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut stream = loop {
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
    stream.write_all(request).unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
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
    let mut request = format!(
        "POST /hello%20world?novalue&empty=&plus=a+b HTTP/1.1\r\nHost: localhost\r\nX-Test: present\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(&body);
    let response = exchange(port, &request);
    assert!(response.starts_with(b"HTTP/1.1 201 Created\r\n"));
    assert_eq!(response_body(&response), body);
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
    let (worker, receiver) = start_server(&file_source, directory.clone());
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
