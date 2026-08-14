#[path = "../src/peer_disconnect.rs"]
mod peer_disconnect;

#[test]
fn peer_disconnect_error_kinds_are_closed_world() {
    for accepted in [
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::UnexpectedEof,
    ] {
        assert!(peer_disconnect::io_kind(accepted));
    }
    for rejected in [
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::WriteZero,
        std::io::ErrorKind::NotConnected,
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::WouldBlock,
        std::io::ErrorKind::Interrupted,
        std::io::ErrorKind::InvalidData,
        std::io::ErrorKind::Other,
    ] {
        assert!(!peer_disconnect::io_kind(rejected));
    }
}
