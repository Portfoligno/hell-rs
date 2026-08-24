#![cfg(unix)]

use hell_testkit::{
    PosixRustcAuthority, PosixRustupAuthority, PosixRustupAuthorityReceiptForIntegration,
    PosixRustupCompilerMapping, PosixRustupProxyIdentity, PosixStandardExecutableIdentity,
    bind_posix_rustup_authority_for_integration, sha256_file,
};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn create_rustup_home(home: &Path, toolchain: &OsStr) {
    let bin = home.join("toolchains").join(toolchain).join("bin");
    let update_hashes = home.join("update-hashes");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir(&update_hashes).unwrap();
    fs::write(home.join("settings.toml"), b"default_toolchain = none\n").unwrap();
    fs::write(update_hashes.join(toolchain), b"stable test update hash\n").unwrap();
    fs::write(bin.join("rustc"), b"staged rustc fixture version 1\n").unwrap();
    fs::write(bin.join("cargo"), b"staged cargo fixture version 1\n").unwrap();
    fs::write(bin.join("rustdoc"), b"staged rustdoc fixture version 1\n").unwrap();
    for executable in [bin.join("rustc"), bin.join("cargo"), bin.join("rustdoc")] {
        fs::set_permissions(executable, fs::Permissions::from_mode(0o555)).unwrap();
    }
    fs::set_permissions(
        home.join("settings.toml"),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    fs::set_permissions(
        update_hashes.join(toolchain),
        fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    for directory in [
        home.to_path_buf(),
        home.join("toolchains"),
        home.join("toolchains").join(toolchain),
        bin,
        update_hashes,
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn create_authority_definition(
    root: &Path,
    source_home: PathBuf,
    rustup_home: PathBuf,
    toolchain: OsString,
) -> (PosixRustupAuthority, PathBuf) {
    let rustup = root.join("rustup");
    let cargo = root.join("cargo");
    let rustc_invocation = root.join("rustc");
    fs::write(&rustup, b"rustup multicall fixture\n").unwrap();
    fs::set_permissions(&rustup, fs::Permissions::from_mode(0o555)).unwrap();
    fs::hard_link(&rustup, &cargo).unwrap();
    fs::hard_link(&rustup, &rustc_invocation).unwrap();
    let cargo = fs::canonicalize(cargo).unwrap();
    let rustup = fs::canonicalize(rustup).unwrap();
    let rustc_invocation = fs::canonicalize(rustc_invocation).unwrap();
    let proxy_metadata = fs::metadata(&cargo).unwrap();
    let rustc_metadata = fs::metadata(&rustc_invocation).unwrap();
    let source_home = fs::canonicalize(source_home).unwrap();
    let rustup_home = fs::canonicalize(rustup_home).unwrap();
    let source_rustc = source_home
        .join("toolchains")
        .join(&toolchain)
        .join("bin/rustc");
    let rustc = rustup_home
        .join("toolchains")
        .join(&toolchain)
        .join("bin/rustc");
    let authority = PosixRustupAuthority::new(
        PosixRustupProxyIdentity::new(
            cargo.clone(),
            cargo,
            rustup.clone(),
            rustup,
            proxy_metadata.dev(),
            proxy_metadata.ino(),
        ),
        PosixRustcAuthority::RustupProxy(PosixStandardExecutableIdentity::new(
            rustc_invocation.clone(),
            rustc_invocation,
            rustc_metadata.dev(),
            rustc_metadata.ino(),
        )),
        source_home,
        rustup_home,
        toolchain,
        PosixRustupCompilerMapping::new(
            source_rustc.clone(),
            sha256_file(&source_rustc).unwrap(),
            rustc.clone(),
            sha256_file(&rustc).unwrap(),
        ),
    );
    (authority, rustc)
}

struct Fixture {
    root: PathBuf,
    authority: PathBuf,
    rustup_home: PathBuf,
    rustc: PathBuf,
    authority_definition: PosixRustupAuthority,
    candidate_uid: u32,
    candidate_group_ids: Vec<u32>,
}

impl Fixture {
    fn new() -> Self {
        #[cfg(target_os = "linux")]
        let temporary = fs::canonicalize("/var/tmp").unwrap();
        #[cfg(target_os = "macos")]
        let temporary = fs::canonicalize("/private/tmp").unwrap();
        let root = temporary.join(format!(
            "hell-posix-rustup-authority-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let authority = root.join("authority");
        let rustup_home = authority.join("rustup-home");
        let source_home = root.join("source-rustup-home");
        let toolchain = OsString::from("stable-test");
        for home in [&source_home, &rustup_home] {
            create_rustup_home(home, &toolchain);
        }
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o755)).unwrap();
        let (authority_definition, rustc) =
            create_authority_definition(&root, source_home, rustup_home.clone(), toolchain);
        let metadata = fs::metadata(&root).unwrap();
        let candidate_uid = metadata.uid().checked_add(1).unwrap_or(metadata.uid() - 1);
        Self {
            root,
            authority,
            rustup_home,
            rustc,
            authority_definition,
            candidate_uid,
            candidate_group_ids: vec![metadata.gid()],
        }
    }

    fn receipt(&self) -> PosixRustupAuthorityReceiptForIntegration {
        bind_posix_rustup_authority_for_integration(
            self.authority_definition.clone(),
            self.candidate_uid,
            self.candidate_group_ids.clone(),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn traversal_authority_ignores_only_sibling_membership_churn() {
    let fixture = Fixture::new();
    let receipt = fixture.receipt();
    let links_before = fs::metadata(&fixture.authority).unwrap().nlink();
    let sibling = fixture.authority.join("unrelated-cache-writer");
    fs::create_dir(&sibling).unwrap();
    let links_during_churn = fs::metadata(&fixture.authority).unwrap().nlink();
    assert_ne!(links_before, links_during_churn);
    receipt.revalidate().unwrap();
    fs::remove_dir(&sibling).unwrap();
    receipt.revalidate().unwrap();
}

#[test]
fn traversal_authority_rejects_mode_and_inode_substitution_with_typed_evidence() {
    let fixture = Fixture::new();
    let receipt = fixture.receipt();
    fs::set_permissions(&fixture.authority, fs::Permissions::from_mode(0o555)).unwrap();
    let mode_error = receipt.revalidate().unwrap_err().to_string();
    assert!(mode_error.contains("field=mode"));
    assert!(mode_error.contains(&format!("path={}", fixture.authority.display())));
    fs::set_permissions(&fixture.authority, fs::Permissions::from_mode(0o755)).unwrap();

    let retired = fixture.root.join("retired-authority");
    fs::rename(&fixture.authority, &retired).unwrap();
    fs::create_dir(&fixture.authority).unwrap();
    fs::set_permissions(&fixture.authority, fs::Permissions::from_mode(0o755)).unwrap();
    let inode_error = receipt.revalidate().unwrap_err().to_string();
    assert!(inode_error.contains("field=inode"));
    assert!(inode_error.contains(&format!("path={}", fixture.authority.display())));
    fs::remove_dir(&fixture.authority).unwrap();
    fs::rename(retired, &fixture.authority).unwrap();
}

#[test]
fn private_staged_tree_and_compiler_identity_remain_exact() {
    let fixture = Fixture::new();
    let receipt = fixture.receipt();

    let rustdoc = fixture.rustc.parent().unwrap().join("rustdoc");
    let renamed_rustdoc = fixture.rustc.parent().unwrap().join("rustdoc-renamed");
    fs::rename(&rustdoc, &renamed_rustdoc).unwrap();
    let inventory_error = receipt.revalidate().unwrap_err().to_string();
    assert!(
        inventory_error.contains("field=inventory"),
        "{inventory_error}"
    );
    assert!(
        inventory_error.contains("expected=present observed=absent"),
        "{inventory_error}"
    );
    fs::rename(renamed_rustdoc, rustdoc).unwrap();
    receipt.revalidate().unwrap();

    let linked = fixture.rustup_home.join("linked-rustc");
    fs::hard_link(&fixture.rustc, &linked).unwrap();
    let link_error = receipt.revalidate().unwrap_err().to_string();
    assert!(
        link_error.contains("multiple hard links") || link_error.contains("field=links"),
        "{link_error}"
    );
    fs::remove_file(linked).unwrap();
    receipt.revalidate().unwrap();

    fs::set_permissions(&fixture.rustc, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&fixture.rustc, b"staged rustc fixture version 2\n").unwrap();
    fs::set_permissions(&fixture.rustc, fs::Permissions::from_mode(0o555)).unwrap();
    let digest_error = receipt.revalidate().unwrap_err().to_string();
    assert!(digest_error.contains("field=sha256"));
    assert!(digest_error.contains(&format!("path={}", fixture.rustc.display())));
}
