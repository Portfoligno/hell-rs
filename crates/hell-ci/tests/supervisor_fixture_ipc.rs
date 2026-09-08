#![cfg(unix)]

use hell_ci::supervisor_fixture_ipc::{Endpoint, Listener, Stream};
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn endpoint_path(endpoint: &Endpoint) -> PathBuf {
    let value: serde_json::Value = serde_json::from_slice(&endpoint.encode().unwrap()).unwrap();
    let bytes: Vec<u8> = serde_json::from_value(value["path_bytes"].clone()).unwrap();
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

#[test]
fn endpoint_codec_rejects_unknown_fields_and_changed_authority() {
    let listener = Listener::bind().unwrap();
    let endpoint = listener.endpoint();
    assert_eq!(
        Endpoint::from_argument(&endpoint.argument().unwrap())
            .unwrap()
            .encode()
            .unwrap(),
        endpoint.encode().unwrap()
    );
    for field in [
        "schema_version",
        "parent_device",
        "parent_inode",
        "socket_device",
        "socket_inode",
        "owner",
        "unknown",
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&endpoint.encode().unwrap()).unwrap();
        value[field] = serde_json::json!(value[field].as_u64().unwrap_or(0) + 1);
        assert!(
            Endpoint::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "accepted changed {field}"
        );
    }
    assert!(Endpoint::decode(&vec![b' '; 4097]).is_err());
}

#[test]
fn endpoint_rejects_socket_symlink_and_parent_mode_changes() {
    let listener = Listener::bind().unwrap();
    let endpoint = listener.endpoint();
    let path = endpoint_path(&endpoint);
    let parent = path.parent().unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750)).unwrap();
    let rejected_mode = Stream::connect(&endpoint, Duration::from_secs(1)).is_err();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(rejected_mode);
    let moved = parent.join("original");
    fs::rename(&path, &moved).unwrap();
    symlink(&moved, &path).unwrap();
    let rejected_link = Stream::connect(&endpoint, Duration::from_secs(1)).is_err();
    fs::remove_file(&path).unwrap();
    fs::rename(&moved, &path).unwrap();
    assert!(rejected_link);
}

#[test]
fn sequential_connections_keep_endpoint_until_last_owned_stream_closes() {
    let listener = Listener::bind().unwrap();
    let endpoint = listener.endpoint();
    let path = endpoint_path(&endpoint);
    let first_client = Stream::connect(&endpoint, Duration::from_secs(1)).unwrap();
    let (first_server, ()) = listener.accept().unwrap();
    drop(first_client);
    drop(first_server);
    let mut second_client = Stream::connect(&endpoint, Duration::from_secs(1)).unwrap();
    let (mut second_server, ()) = listener.try_clone().unwrap().accept().unwrap();
    let retained = second_server.try_clone().unwrap();
    drop(listener);
    assert!(
        path.exists(),
        "accepted stream must retain socket authority"
    );
    second_client.write_all(b"terminal").unwrap();
    let mut frame = [0_u8; b"terminal".len()];
    second_server.read_exact(&mut frame).unwrap();
    assert_eq!(&frame, b"terminal");
    drop(second_server);
    assert!(
        path.exists(),
        "retained finalizer stream must retain authority"
    );
    drop(retained);
    assert!(!path.exists());
    assert!(!path.parent().unwrap().exists());
    assert!(Stream::connect(&endpoint, Duration::from_secs(1)).is_err());
}

#[test]
fn connect_and_accept_deadlines_are_bounded() {
    let listener = Listener::bind()
        .unwrap()
        .with_accept_timeout(Duration::from_millis(10));
    assert_eq!(
        Stream::connect(&listener.endpoint(), Duration::ZERO)
            .err()
            .unwrap()
            .kind(),
        std::io::ErrorKind::TimedOut
    );
    let start = Instant::now();
    assert_eq!(
        listener.accept().err().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn accepted_silent_peer_cannot_hold_a_protocol_read_forever() {
    let listener = Listener::bind()
        .unwrap()
        .with_accept_timeout(Duration::from_millis(10));
    let _client = Stream::connect(&listener.endpoint(), Duration::from_secs(1)).unwrap();
    let (mut server, ()) = listener.accept().unwrap();
    let started = Instant::now();
    let error = server.read(&mut [0]).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn real_owned_child_and_grandchild_obey_receipt_bound_release() {
    let listener = Listener::bind()
        .unwrap()
        .with_accept_timeout(Duration::from_secs(10));
    let endpoint = listener.endpoint().argument().unwrap();
    let request_digest = hell_digest::Digest([0x11; 32]);
    let nonce = hell_digest::Digest([0x22; 32]);
    let worker = std::thread::spawn(move || {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_hell-ci"));
        command.args([
            std::ffi::OsString::from("__nightly-supervisor-owned-child"),
            endpoint,
            std::ffi::OsString::from(request_digest.hex()),
            std::ffi::OsString::from(nonce.hex()),
        ]);
        hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(15)).unwrap()
    });
    let (mut gate, ()) = listener.accept().unwrap();
    gate.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // Existing protocol discriminants and complete digest/nonce framing, not a
    // substitute target: the executable above spawns its real owned grandchild.
    let mut expected = vec![3_u8];
    expected.extend_from_slice(&[0x11; 32]);
    expected.extend_from_slice(&[0x22; 32]);
    let mut started = vec![0; expected.len()];
    gate.read_exact(&mut started).unwrap();
    assert_eq!(started, expected);
    let mut identities = [0_u8; size_of::<u32>() * 2];
    gate.read_exact(&mut identities).unwrap();
    let target = u32::from_be_bytes(identities[..size_of::<u32>()].try_into().unwrap());
    let descendant = u32::from_be_bytes(identities[size_of::<u32>()..].try_into().unwrap());
    assert_ne!(target, descendant);
    for pid in [target, descendant] {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
            None,
        )
        .expect("both real processes must remain alive behind the gate");
    }
    expected[0] = 2;
    gate.write_all(&expected).unwrap();
    let output = worker.join().unwrap();
    assert!(
        output.status.success() && !output.timed_out,
        "owned child failed: {:?}",
        output.stderr
    );
    for pid in [target, descendant] {
        assert_eq!(
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
                None
            ),
            Err(nix::errno::Errno::ESRCH)
        );
    }
    assert_eq!(gate.read(&mut [0]).unwrap(), 0);
}
