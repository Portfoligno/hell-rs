#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use hell_testkit::PosixDirectoryCheckpoint;

const FIXTURE_ALLOCATION_ATTEMPTS: usize = 64;
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct FixtureRootIdentity {
    guard: fs::File,
    path: FixturePathIdentity,
}

#[derive(Clone, Copy)]
struct FixturePathIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
}

impl FixturePathIdentity {
    fn capture(path: &Path) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect created fixture directory: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("created fixture path is not a directory".to_owned());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
        })
    }

    fn matches(&self, metadata: &fs::Metadata) -> bool {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.uid() == self.owner
            && metadata.gid() == self.group
    }
}

struct Fixture {
    root: PathBuf,
    identity: Option<FixtureRootIdentity>,
}

impl Fixture {
    fn new() -> Self {
        let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary parent");
        Self::allocate(&parent, &NEXT_FIXTURE).expect("allocate directory checkpoint fixture")
    }

    fn allocate(parent: &Path, sequence: &AtomicU64) -> Result<Self, String> {
        for _ in 0..FIXTURE_ALLOCATION_ATTEMPTS {
            let candidate = sequence.fetch_add(1, Ordering::Relaxed);
            let root = parent.join(format!(
                "hell-posix-directory-checkpoint-{}-{candidate}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Self::bind_created(root),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "cannot create directory checkpoint fixture at {}: {error}",
                        root.display()
                    ));
                }
            }
        }
        Err(format!(
            "cannot allocate directory checkpoint fixture below {} after {FIXTURE_ALLOCATION_ATTEMPTS} attempts",
            parent.display()
        ))
    }

    fn bind_created(root: PathBuf) -> Result<Self, String> {
        let created = FixturePathIdentity::capture(&root)?;
        let guard = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&root)
        {
            Ok(guard) => guard,
            Err(error) => {
                let cleanup = remove_empty_fixture_root(&root, created);
                return Err(match cleanup {
                    Ok(()) => format!("cannot retain directory checkpoint fixture: {error}"),
                    Err(cleanup) => format!(
                        "cannot retain directory checkpoint fixture: {error}; cleanup failed: {cleanup}"
                    ),
                });
            }
        };
        let handle = guard
            .metadata()
            .map_err(|error| format!("cannot inspect fixture directory handle: {error}"))?;
        let path = fs::symlink_metadata(&root)
            .map_err(|error| format!("cannot inspect fixture directory path: {error}"))?;
        if !created.matches(&handle) || !created.matches(&path) {
            return Err("directory checkpoint fixture identity changed during creation".to_owned());
        }
        Ok(Self {
            root,
            identity: Some(FixtureRootIdentity {
                guard,
                path: created,
            }),
        })
    }

    fn candidate(&self) -> PathBuf {
        let candidate = self.root.join("release-child-environment");
        fs::create_dir(&candidate).unwrap();
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o2750)).unwrap();
        for name in ["home", "cargo", "sccache", "tmp"] {
            let child = candidate.join(name);
            fs::create_dir(&child).unwrap();
            fs::set_permissions(&child, fs::Permissions::from_mode(0o2770)).unwrap();
        }
        candidate
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| "directory checkpoint fixture was already cleaned".to_owned())?;
        let handle = identity
            .guard
            .metadata()
            .map_err(|error| format!("cannot revalidate fixture directory handle: {error}"))?;
        let path = fs::symlink_metadata(&self.root)
            .map_err(|error| format!("cannot revalidate fixture directory path: {error}"))?;
        if !handle.is_dir()
            || !path.is_dir()
            || path.file_type().is_symlink()
            || !identity.path.matches(&handle)
            || !identity.path.matches(&path)
        {
            return Err("directory checkpoint fixture identity changed before cleanup".to_owned());
        }
        fs::remove_dir_all(&self.root).map_err(|error| {
            format!("cannot remove owned directory checkpoint fixture: {error}")
        })?;
        match fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.identity = None;
                Ok(())
            }
            Ok(_) => Err("directory checkpoint fixture remains after cleanup".to_owned()),
            Err(error) => Err(format!(
                "cannot attest directory checkpoint fixture absence: {error}"
            )),
        }
    }

    fn close(mut self) -> Result<(), String> {
        self.cleanup()
    }
}

fn remove_empty_fixture_root(root: &Path, identity: FixturePathIdentity) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect partial fixture cleanup path: {error}"))?;
    if !identity.matches(&metadata) {
        return Err("partial fixture identity changed before cleanup".to_owned());
    }
    fs::remove_dir(root)
        .map_err(|error| format!("cannot remove partial fixture directory: {error}"))
}

fn checkpoint(path: &Path, mode: u32, label: &str) -> PosixDirectoryCheckpoint {
    let metadata = fs::symlink_metadata(path).unwrap();
    PosixDirectoryCheckpoint::capture(path, metadata.uid(), metadata.gid(), mode, label).unwrap()
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.identity.is_some() {
            let _ = self.cleanup();
        }
    }
}

#[test]
fn fixture_allocation_is_parallel_collision_aware_and_ownership_bound() {
    const WORKERS: usize = 8;

    let barrier = Arc::new(Barrier::new(WORKERS));
    let workers = (0..WORKERS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                Fixture::new()
            })
        })
        .collect::<Vec<_>>();
    let fixtures = workers
        .into_iter()
        .map(|worker| worker.join().expect("fixture allocation worker"))
        .collect::<Vec<_>>();
    let mut roots = fixtures
        .iter()
        .map(|fixture| fixture.root.clone())
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    assert_eq!(roots.len(), WORKERS);
    assert!(roots.iter().all(|root| root.is_dir()));
    for fixture in fixtures {
        let root = fixture.root.clone();
        fixture.close().expect("clean owned parallel fixture");
        assert!(!root.exists());
    }

    let outer = Fixture::new();
    let collision_parent = outer.root.join("collision-parent");
    fs::create_dir(&collision_parent).unwrap();
    let sequence = AtomicU64::new(0);
    let collision = collision_parent.join(format!(
        "hell-posix-directory-checkpoint-{}-0",
        std::process::id()
    ));
    fs::create_dir(&collision).unwrap();
    fs::write(collision.join("owned-by-sibling"), b"retain\n").unwrap();
    let allocated = Fixture::allocate(&collision_parent, &sequence)
        .expect("retry after an existing fixture path");
    assert_ne!(allocated.root, collision);
    let allocated_root = allocated.root.clone();
    allocated.close().expect("clean retried fixture");
    assert!(!allocated_root.exists());
    assert_eq!(
        fs::read(collision.join("owned-by-sibling")).unwrap(),
        b"retain\n"
    );
}

#[test]
fn directory_checkpoint_names_link_substitution_and_checkpoint() {
    let fixture = Fixture::new();
    let candidate = fixture.candidate();
    let authority = checkpoint(&candidate, 0o2750, "before directory substitution");
    let original = fixture.root.join("original");
    fs::rename(&candidate, &original).unwrap();
    symlink(&original, &candidate).unwrap();

    let error = authority
        .validate("after directory link substitution")
        .unwrap_err();
    assert!(error.contains("checkpoint=\"after directory link substitution\""));
    assert!(error.contains(&format!("path={:?}", authority.path())));
    assert!(error.contains("expected=kind=directory"));
    assert!(error.contains("observed=kind=symlink"));

    fs::remove_file(&candidate).unwrap();
    fs::rename(original, &candidate).unwrap();
}

#[test]
fn environment_checkpoints_cover_every_identity_and_allow_legal_nested_content() {
    let fixture = Fixture::new();
    let candidate = fixture.candidate();
    let root = checkpoint(&candidate, 0o2750, "candidate capture");
    let children = ["home", "cargo", "sccache", "tmp"]
        .map(|name| checkpoint(&candidate.join(name), 0o2770, "candidate capture"));
    root.validate_exact_children(
        "after legal nested content",
        &["home", "cargo", "sccache", "tmp"],
    )
    .unwrap();
    fs::create_dir(candidate.join("home/nested")).unwrap();
    fs::write(candidate.join("home/nested/config"), b"trusted\n").unwrap();
    root.validate_exact_children(
        "after legal nested content",
        &["home", "cargo", "sccache", "tmp"],
    )
    .unwrap();
    for authority in &children {
        authority.validate("after legal nested content").unwrap();
    }

    for (authority, name) in children.iter().zip(["home", "cargo", "sccache", "tmp"]) {
        let path = candidate.join(name);
        let retained = fixture.root.join(format!("retained-{name}"));
        fs::rename(&path, &retained).unwrap();
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o2770)).unwrap();
        let checkpoint = format!("after {name} inode replacement");
        let error = authority.validate(&checkpoint).unwrap_err();
        assert!(error.contains(&format!("checkpoint={checkpoint:?}")));
        assert!(error.contains(&format!("path={path:?}")));
        assert!(error.contains("expected=kind=directory,dev="));
        assert!(error.contains("observed=kind=directory,dev="));
        fs::remove_dir(&path).unwrap();
        fs::rename(&retained, &path).unwrap();
    }

    let retained_root = fixture.root.join("retained-root");
    fs::rename(&candidate, &retained_root).unwrap();
    fs::create_dir(&candidate).unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o2750)).unwrap();
    let error = root.validate("after root inode replacement").unwrap_err();
    assert!(error.contains("checkpoint=\"after root inode replacement\""));
    assert!(error.contains(&format!("path={candidate:?}")));
    fs::remove_dir(&candidate).unwrap();
    fs::rename(&retained_root, &candidate).unwrap();
}

#[test]
fn environment_checkpoints_localize_kind_owner_group_mode_and_inventory_failures() {
    let fixture = Fixture::new();
    let candidate = fixture.candidate();
    let root = checkpoint(&candidate, 0o2750, "candidate capture");
    let home = checkpoint(&candidate.join("home"), 0o2770, "candidate capture");
    let metadata = fs::symlink_metadata(home.path()).unwrap();

    for (owner, group, label) in [
        (metadata.uid() ^ 1, metadata.gid(), "wrong owner"),
        (metadata.uid(), metadata.gid() ^ 1, "wrong group"),
    ] {
        let error = PosixDirectoryCheckpoint::capture(home.path(), owner, group, 0o2770, label)
            .unwrap_err();
        assert!(error.contains(&format!("checkpoint={label:?}")));
        assert!(error.contains(&format!("path={:?}", home.path())));
    }

    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o770)).unwrap();
    let error = home.validate("after home mode change").unwrap_err();
    assert!(error.contains("checkpoint=\"after home mode change\""));
    assert!(error.contains("mode=0o2770"));
    assert!(error.contains("mode=0o0770"));
    fs::set_permissions(home.path(), fs::Permissions::from_mode(0o2770)).unwrap();
    home.validate("after trusted home mode restoration")
        .unwrap();

    let sccache = checkpoint(&candidate.join("sccache"), 0o2770, "candidate capture");
    fs::set_permissions(sccache.path(), fs::Permissions::from_mode(0o2750)).unwrap();
    let error = sccache
        .validate("after candidate environment mode mutation")
        .unwrap_err();
    assert!(error.contains("checkpoint=\"after candidate environment mode mutation\""));
    assert!(error.contains(&format!("path={:?}", sccache.path())));
    assert!(error.contains("expected=kind=directory"));
    assert!(error.contains("mode=0o2770"));
    assert!(error.contains("observed=kind=directory"));
    assert!(error.ends_with("mode=0o2750"));
    fs::set_permissions(sccache.path(), fs::Permissions::from_mode(0o2770)).unwrap();
    sccache
        .validate("after trusted sccache mode restoration")
        .unwrap();

    let retained_home = fixture.root.join("retained-home");
    fs::rename(home.path(), &retained_home).unwrap();
    symlink(&retained_home, home.path()).unwrap();
    let error = home
        .validate("after home symlink substitution")
        .unwrap_err();
    assert!(error.contains("checkpoint=\"after home symlink substitution\""));
    assert!(error.contains("observed=kind=symlink"));
    fs::remove_file(home.path()).unwrap();
    fs::rename(&retained_home, home.path()).unwrap();

    let cargo = candidate.join("cargo");
    let retained_cargo = fixture.root.join("retained-cargo");
    let cargo_checkpoint = checkpoint(&cargo, 0o2770, "candidate capture");
    fs::rename(&cargo, &retained_cargo).unwrap();
    fs::write(&cargo, b"not a directory\n").unwrap();
    let error = cargo_checkpoint
        .validate("after cargo non-directory substitution")
        .unwrap_err();
    assert!(error.contains("checkpoint=\"after cargo non-directory substitution\""));
    assert!(error.contains("observed=kind=file"));
    fs::remove_file(&cargo).unwrap();
    fs::rename(&retained_cargo, &cargo).unwrap();

    fs::create_dir(candidate.join("unexpected")).unwrap();
    let error = root
        .validate_exact_children(
            "after unexpected root member",
            &["home", "cargo", "sccache", "tmp"],
        )
        .unwrap_err();
    assert!(error.contains("checkpoint=\"after unexpected root member\""));
    assert!(error.contains("expectedInventory=[\"cargo\", \"home\", \"sccache\", \"tmp\"]"));
    assert!(error.contains("observedInventory="));
    assert!(error.contains("\"unexpected\""));
    fs::remove_dir(candidate.join("unexpected")).unwrap();

    root.validate_exact_children(
        "before trusted cleanup transition",
        &["home", "cargo", "sccache", "tmp"],
    )
    .unwrap();
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
    let error = root
        .validate("during trusted cleanup transition")
        .unwrap_err();
    assert!(error.contains("checkpoint=\"during trusted cleanup transition\""));
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o2750)).unwrap();
    root.validate("after trusted cleanup transition restoration")
        .unwrap();
}
