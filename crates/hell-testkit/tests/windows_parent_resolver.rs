use std::ffi::{OsStr, OsString};
use std::fs;

use hell_testkit::resolve_windows_parent_program_from;

#[test]
fn bare_windows_program_uses_only_ordered_native_extensions() {
    let root = std::env::temp_dir().join(format!(
        "hell-windows-parent-resolver-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    fs::write(root.join("rustc.COM"), b"com").unwrap();
    fs::write(root.join("rustc.EXE"), b"exe").unwrap();
    fs::write(root.join("rustc.BAT"), b"bat").unwrap();

    let resolved = resolve_windows_parent_program_from(
        OsStr::new("rustc"),
        std::slice::from_ref(&root),
        &[
            OsString::from(".BAT"),
            OsString::from(".EXE"),
            OsString::from(".COM"),
        ],
    )
    .unwrap();
    assert_eq!(resolved, fs::canonicalize(root.join("rustc.EXE")).unwrap());
    assert!(
        resolve_windows_parent_program_from(
            OsStr::new("rustc.BAT"),
            std::slice::from_ref(&root),
            &[OsString::from(".EXE")],
        )
        .is_err()
    );
    for invalid in [
        ".",
        "..",
        "rust c",
        "rustc.",
        "rustc:alternate",
        "CON",
        "NUL.exe",
        "COM1",
        "LPT9.exe",
    ] {
        assert!(
            resolve_windows_parent_program_from(
                OsStr::new(invalid),
                std::slice::from_ref(&root),
                &[OsString::from(".EXE")],
            )
            .is_err(),
            "invalid Windows tool name was accepted: {invalid}"
        );
    }
    fs::remove_dir_all(root).unwrap();
}
