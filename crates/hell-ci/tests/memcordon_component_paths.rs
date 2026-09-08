use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hell_ci::find_memcordon_component_for_integration as find_component;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
const RELATIVE_TEST: &str =
    "relative_runtime_root_returns_absolute_canonical_component_with_spaces";
const CHILD_MARKER: &str = "__hell_component_relative_fixture_child";
const COMPLETION: &str = "relative-assertions-completed";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "memcordon path fixture {} {}",
            std::process::id(),
            FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }

    fn component(&self) -> PathBuf {
        self.0
            .join("release bundle")
            .join("memcordon-sealed-agent.exe")
    }

    fn populate(&self) {
        fs::create_dir(self.0.join("release bundle")).unwrap();
        fs::write(self.component(), b"pinned component fixture").unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn relative_runtime_root_returns_absolute_canonical_component_with_spaces() {
    if let Some(relative) = relative_child_argument() {
        verify_relative_component(&relative);
        // A successful harness exit alone could mean zero selected tests.
        // This create-new receipt is emitted only after all child assertions.
        let mut receipt = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(relative.join(COMPLETION))
            .unwrap();
        std::io::Write::write_all(&mut receipt, b"relative assertions passed\n").unwrap();
        return;
    }
    let parent_cwd = std::env::current_dir().unwrap();
    let fixture = Fixture::new();
    fixture.populate();
    assert!(fixture.0.is_absolute());
    assert_eq!(
        fixture.0.parent().unwrap(),
        fs::canonicalize(std::env::temp_dir()).unwrap()
    );
    let relative = PathBuf::from(fixture.0.file_name().unwrap());
    assert!(!RELATIVE_TEST.contains(CHILD_MARKER));
    assert!(!RELATIVE_TEST.contains(relative.to_str().unwrap()));
    assert!(!fixture.0.join(COMPLETION).exists());
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.current_dir(fixture.0.parent().unwrap()).args([
        std::ffi::OsString::from("--exact"),
        RELATIVE_TEST.into(),
        "--skip".into(),
        CHILD_MARKER.into(),
        "--skip".into(),
        relative.into_os_string(),
    ]);
    // --skip carries typed fixture metadata using the existing libtest marker
    // convention. Neither value matches the exact selected test; none is skipped.
    let output =
        hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(10)).unwrap();
    assert!(output.status.success() && !output.timed_out, "{output:?}");
    assert_eq!(
        fs::read(fixture.0.join(COMPLETION)).unwrap(),
        b"relative assertions passed\n"
    );
    assert_eq!(std::env::current_dir().unwrap(), parent_cwd);
}

fn relative_child_argument() -> Option<PathBuf> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if !arguments.iter().any(|argument| argument == CHILD_MARKER) {
        return None;
    }
    let matches = arguments
        .windows(4)
        .filter(|parts| parts[0] == "--skip" && parts[1] == CHILD_MARKER && parts[2] == "--skip")
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "child marker requires exactly one structured relative root"
    );
    let relative = PathBuf::from(&matches[0][3]);
    assert!(relative.is_relative());
    assert!(matches!(
        relative.components().collect::<Vec<_>>().as_slice(),
        [Component::Normal(_)]
    ));
    assert!(!RELATIVE_TEST.contains(relative.to_str().unwrap()));
    Some(relative)
}

fn verify_relative_component(relative: &Path) {
    assert!(
        relative.is_relative(),
        "resolver must receive a genuinely relative root"
    );
    let cwd = std::env::current_dir().unwrap();
    let selected = find_component(relative, "memcordon-sealed-agent.exe").unwrap();
    assert!(selected.is_absolute());
    assert_eq!(
        selected,
        fs::canonicalize(
            relative
                .join("release bundle")
                .join("memcordon-sealed-agent.exe")
        )
        .unwrap()
    );
    assert!(
        selected
            .components()
            .any(|part| part.as_os_str() == "release bundle")
    );
    assert!(selected.is_file());
    assert_eq!(std::env::current_dir().unwrap(), cwd);
}

#[test]
fn runtime_discovery_rejects_missing_ambiguous_and_excessive_inventory() {
    let fixture = Fixture::new();
    assert!(
        find_component(&fixture.0, "memcordon-sealed-agent.exe")
            .unwrap_err()
            .contains("missing")
    );
    fixture.populate();
    fs::write(fixture.0.join("memcordon-sealed-agent.exe"), b"duplicate").unwrap();
    assert!(
        find_component(&fixture.0, "memcordon-sealed-agent.exe")
            .unwrap_err()
            .contains("ambiguous")
    );
    for index in 0..256 {
        fs::write(fixture.0.join(index.to_string()), b"entry").unwrap();
    }
    assert!(
        find_component(&fixture.0, "memcordon-sealed-agent.exe")
            .unwrap_err()
            .contains("more than 256")
    );
}

#[cfg(unix)]
#[test]
fn runtime_discovery_rejects_symbolic_link_components_directories_and_roots() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    fixture.populate();
    let alias = Fixture::new();
    symlink(
        fs::canonicalize(fixture.component()).unwrap(),
        alias.0.join("memcordon-sealed-agent.exe"),
    )
    .unwrap();
    assert!(
        find_component(&alias.0, "memcordon-sealed-agent.exe")
            .unwrap_err()
            .contains("symbolic link")
    );
    let directories = Fixture::new();
    symlink(
        fs::canonicalize(&fixture.0).unwrap(),
        directories.0.join("linked-root"),
    )
    .unwrap();
    assert!(
        find_component(&directories.0, "memcordon-sealed-agent.exe")
            .unwrap_err()
            .contains("symbolic link")
    );
    assert!(
        find_component(
            &directories.0.join("linked-root"),
            "memcordon-sealed-agent.exe"
        )
        .unwrap_err()
        .contains("real directory")
    );
}
