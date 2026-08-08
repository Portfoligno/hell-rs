use std::path::Path;
use std::sync::Arc;

use hell_platform::{CapabilityPolicy, PlatformContext, decode_utf8};
use hell_runtime::RuntimeContext;

#[test]
fn invalid_utf8_reports_the_exact_operation_and_offset() {
    let error = decode_utf8("Text.readFile", vec![b'a', 0xff]).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("Text.readFile"));
    assert!(error.to_string().contains("byte 1"));
}

#[test]
fn every_host_operation_checks_its_capability() {
    let context = PlatformContext {
        runtime: RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
        cwd: Arc::new(std::env::temp_dir()),
        capabilities: CapabilityPolicy::default(),
    };

    assert_eq!(
        context
            .require_filesystem(Path::new("blocked"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        context
            .require_process(Path::new("blocked"))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        context.require_network("blocked").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
