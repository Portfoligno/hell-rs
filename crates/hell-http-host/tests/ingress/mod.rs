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
        let (idle_client, idle_stream) = connected_streams().await;
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

        let (mut oversized_client, oversized_stream) = connected_streams().await;
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

#[cfg(unix)]
async fn connected_streams() -> (std::os::unix::net::UnixStream, tokio::net::UnixStream) {
    // These assertions concern ingress bytes and timers, not TCP addressing.
    // An actual anonymous local stream preserves kernel I/O and idle behavior.
    let (client, server) = std::os::unix::net::UnixStream::pair().expect("local stream pair opens");
    server
        .set_nonblocking(true)
        .expect("server stream becomes asynchronous");
    let server = tokio::net::UnixStream::from_std(server).expect("server stream installs");
    (client, server)
}

#[cfg(not(unix))]
async fn connected_streams() -> (std::net::TcpStream, TcpStream) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener binds");
    let address = listener.local_addr().expect("listener has an address");
    let client = std::net::TcpStream::connect(address).expect("client connects");
    let (server, _) = listener.accept().await.expect("server accepts client");
    (client, server)
}
