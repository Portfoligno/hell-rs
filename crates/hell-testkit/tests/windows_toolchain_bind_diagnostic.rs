use std::io;
use std::path::Path;

use hell_testkit::{WindowsToolchainBindOperation, windows_toolchain_bind_failure};

#[test]
fn windows_toolchain_bind_failure_retains_closed_operation_path_and_error_identity() {
    let path = Path::new(r"C:\trusted\missing");
    let error = windows_toolchain_bind_failure(
        WindowsToolchainBindOperation::BindTrustedPathEntry,
        path,
        &io::Error::from_raw_os_error(3),
    );
    let diagnostic = error.to_string();

    assert_eq!(error.kind(), io::Error::from_raw_os_error(3).kind());
    assert!(diagnostic.contains("operation=bind-trusted-path-entry"));
    assert!(diagnostic.contains(&format!("path={}", path.display())));
    assert!(diagnostic.contains("osError=3"));
    assert!(diagnostic.contains("source="));
}

#[test]
fn windows_toolchain_bind_operation_labels_are_closed_and_stable() {
    let operations = [
        WindowsToolchainBindOperation::CanonicalizeInventoryRoot,
        WindowsToolchainBindOperation::BindTrustedPathEntry,
        WindowsToolchainBindOperation::BindSystemRoot,
        WindowsToolchainBindOperation::BindCargoSource,
        WindowsToolchainBindOperation::BindRustcSource,
        WindowsToolchainBindOperation::BindSelectedCargo,
        WindowsToolchainBindOperation::BindStagedCargo,
        WindowsToolchainBindOperation::BindSelectedRustc,
        WindowsToolchainBindOperation::BindStagedRustc,
        WindowsToolchainBindOperation::BindInventoryFile,
        WindowsToolchainBindOperation::HashSelectedCargo,
        WindowsToolchainBindOperation::HashStagedCargo,
        WindowsToolchainBindOperation::HashSelectedRustc,
        WindowsToolchainBindOperation::HashStagedRustc,
        WindowsToolchainBindOperation::RevalidateInventory,
    ];
    let labels = operations.map(|operation| operation.to_string());

    assert_eq!(labels.len(), 15);
    assert_eq!(labels[0], "canonicalize-inventory-root");
    assert_eq!(labels[14], "revalidate-inventory");
    assert!(labels.iter().all(|label| !label.contains(' ')));
}
