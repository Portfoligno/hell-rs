use std::fs;
use std::path::Path;

use hell_memcordon::{Platform, RuntimeLock};

#[test]
fn committed_runtime_lock_pins_both_complete_native_bundles() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let lock = fs::read_to_string(root.join("ci/memcordon-runtime-v1.toml")).unwrap();
    let lock = RuntimeLock::parse(&lock).unwrap();
    assert_eq!(
        lock.asset(Platform::LinuxX86_64)
            .unwrap()
            .required_components,
        ["memcordon", "memcordon-sealed-agent"]
    );
    assert_eq!(
        lock.asset(Platform::WindowsX86_64)
            .unwrap()
            .required_components,
        [
            "memcordon.exe",
            "memcordon-sealed-agent.exe",
            "memcordon-target-desktop-bootstrap.exe",
            "memcordon-session-broker.exe",
        ]
    );
}

#[test]
fn committed_task_policy_has_exact_root_coverage_without_environment_authority() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let task = fs::read_to_string(root.join("ci/memcordon-tasks-v1.toml")).unwrap();
    for operation in [
        "readiness",
        "release",
        "nightly",
        "mutation",
        "regression-corpus",
        "regression-subject",
        "fuzz",
    ] {
        assert!(task.contains(&format!("[operation.{operation}]\n")));
        assert!(task.contains(&format!("required-operation-ids = [\"{operation}\"]\n")));
    }
    assert!(
        !task
            .lines()
            .any(|line| line.trim_start().starts_with("env"))
    );
}

#[test]
fn workflow_protocol_uses_static_memcordon_commands_without_environment_authority() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let protocol = fs::read_to_string(root.join("ci/protocol/v1.toml")).unwrap();
    for operation in [
        "readiness",
        "release",
        "nightly",
        "mutation",
        "regression-corpus",
        "regression-subject",
        "fuzz",
    ] {
        for action in ["acquire", "prepare", "canary", "cleanup", "finalize"] {
            let task_prefix = if matches!(operation, "readiness" | "release") {
                "automation/"
            } else {
                ""
            };
            let unix = format!(
                "arguments = [\"memcordon\", \"{action}\", \"--task\", \"{task_prefix}ci/memcordon-tasks-v1.toml\", \"--operation\", \"{operation}\""
            );
            let windows_prefix = task_prefix.replace('/', "\\\\");
            let windows = format!(
                "arguments = [\"memcordon\", \"{action}\", \"--task\", \"{windows_prefix}ci\\\\memcordon-tasks-v1.toml\", \"--operation\", \"{operation}\""
            );
            assert!(
                protocol.contains(&unix) || protocol.contains(&windows),
                "missing static MemCordon {operation}/{action} command"
            );
        }
    }
    for operation in [
        "nightly",
        "mutation",
        "regression-corpus",
        "regression-subject",
        "fuzz",
    ] {
        assert!(protocol.contains(&format!(
            "arguments = [\"memcordon\", \"execute\", \"--task\", \"ci/memcordon-tasks-v1.toml\", \"--operation\", \"{operation}\"]"
        )));
    }
    assert!(!protocol.contains("MEMCORDON_"));
}

#[test]
fn consumer_does_not_add_provider_source_or_raw_platform_dependencies() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifests = [
        fs::read_to_string(root.join("Cargo.toml")).unwrap(),
        fs::read_to_string(root.join("crates/hell-ci/Cargo.toml")).unwrap(),
    ];
    for manifest in manifests {
        assert!(!manifest.contains("memcordon-platform"));
        assert!(!manifest.contains("memcordon-windows-launch-core"));
        assert!(!manifest.contains("[patch."));
    }
    let external_inputs = fs::read_to_string(root.join("ci/external-inputs.toml")).unwrap();
    assert!(!external_inputs.contains("git-checkout"));
    assert!(!external_inputs.contains("source-archive"));
}
