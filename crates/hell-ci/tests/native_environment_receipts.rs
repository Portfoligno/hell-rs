use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-native-environment-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture");
        Self { root }
    }

    fn write(&self, relative: &str, contents: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove fixture");
    }
}

#[test]
fn native_receipts_bind_tools_external_inputs_and_exact_three_platform_set() {
    let fixture = Fixture::new();
    let repository_name = "Portfoligno/hell-rs";
    let repository_id = fixture_repository_id(repository_name);
    let event = canonical_json(&serde_json::json!({
        "repository": {"full_name": repository_name, "id": repository_id}
    }));
    let event_path = fixture.write("event.json", &event);
    let lock_path = fixture.write(
        "external-inputs.toml",
        b"schema-version = 1\nlock-id = \"native-fixture-v1\"\n\n[[input]]\nid = \"upstream-oracle-source\"\nkind = \"git-commit\"\nrepository = \"chrisdone/hell\"\ncommit = \"8e952cf9de4ab25d7716982a9ca234f9bdcf1bff\"\nacquisition-phase = \"native-platform\"\n",
    );
    let receipt_path = fixture.root.join("collected.json");
    let (host_platform, runner_os, runner_architecture, image_os) = host_runner_identity();
    let mut collect_command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    collect_command
        .args(["environment", "collect", "--platform", host_platform])
        .args(["--external-inputs"])
        .arg(&lock_path)
        .args(["--output"])
        .arg(&receipt_path)
        .env("GITHUB_API_URL", "http://127.0.0.1:9")
        .env("GITHUB_EVENT_NAME", "workflow_dispatch")
        .env("GITHUB_EVENT_PATH", &event_path)
        .env("GITHUB_REF_NAME", "main")
        .env("GITHUB_REPOSITORY", repository_name)
        .env("GITHUB_REPOSITORY_ID", repository_id.to_string())
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("GITHUB_RUN_ID", "93482217")
        .env("GITHUB_WORKSPACE", &fixture.root)
        .env(
            "GITHUB_WORKFLOW_REF",
            "Portfoligno/hell-rs/.github/workflows/release.yml@refs/heads/main",
        )
        .env(
            "GITHUB_WORKFLOW_SHA",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .env("ImageOS", image_os)
        .env("ImageVersion", "20260817.1")
        .env("RUNNER_ARCH", runner_architecture)
        .env("RUNNER_OS", runner_os);
    let collect = run_bounded(&mut collect_command, "collect native environment");
    assert!(collect.status.success(), "{:?}", collect.stderr);
    let collected = read_json(&receipt_path);
    let external_digest = collected["externalInputsSha256"]
        .as_str()
        .expect("external digest")
        .to_owned();
    assert_ne!(collected["tools"].as_array().expect("tools").len(), 0);
    assert!(
        collected["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .all(|tool| {
                tool["executableSha256"] != serde_json::Value::Null
                    && tool["outputSha256"] != serde_json::Value::Null
            })
    );

    let receipts_root = fixture.root.join("receipts");
    for (platform, os, architecture, runner_os, runner_arch) in [
        ("linux-x86_64", "linux", "x86_64", "Linux", "X64"),
        ("macos-aarch64", "macos", "aarch64", "macOS", "ARM64"),
        ("windows-x86_64", "windows", "x86_64", "Windows", "X64"),
    ] {
        let receipt = synthetic_receipt(
            platform,
            os,
            architecture,
            runner_os,
            runner_arch,
            &external_digest,
        );
        let path = receipts_root.join(platform).join("native-environment.json");
        fs::create_dir_all(path.parent().expect("receipt parent")).expect("create receipt parent");
        fs::write(path, canonical_json(&receipt)).expect("write receipt");
    }
    let set_path = fixture.root.join("native-environment-set.json");
    let assemble = environment_command("assemble-set", &receipts_root, &lock_path, &set_path);
    assert!(assemble.status.success(), "{:?}", assemble.stderr);
    let verify_report = fixture.root.join("verify-report.json");
    let verify = environment_command("verify-set", &set_path, &lock_path, &verify_report);
    assert!(verify.status.success(), "{:?}", verify.stderr);
    assert_eq!(read_json(&verify_report)["admitted"], true);

    let mut tampered = read_json(&set_path);
    tampered["receipts"][0]["receipt"]["tools"][0]["parsedVersion"] =
        serde_json::Value::String("substituted-tool".to_owned());
    let tampered_path = fixture.write("tampered-set.json", &canonical_json(&tampered));
    let rejection_report = fixture.root.join("rejection-report.json");
    let rejected = environment_command("verify-set", &tampered_path, &lock_path, &rejection_report);
    assert!(!rejected.status.success());
    let rejection = read_json(&rejection_report);
    assert_eq!(rejection["admitted"], false);
    assert_eq!(
        rejection["diagnostic"]["code"],
        "native-environment.set.rejected"
    );
}

fn fixture_repository_id(repository: &str) -> u64 {
    repository.bytes().fold(1_u64, |value, byte| {
        value
            .wrapping_mul(1_099_511_628_211)
            .wrapping_add(u64::from(byte))
    }) | 1
}

#[cfg(target_os = "linux")]
fn host_runner_identity() -> (&'static str, &'static str, &'static str, &'static str) {
    ("linux-x86_64", "Linux", "X64", "ubuntu24")
}

#[cfg(target_os = "macos")]
fn host_runner_identity() -> (&'static str, &'static str, &'static str, &'static str) {
    ("macos-aarch64", "macOS", "ARM64", "macos15")
}

#[cfg(target_os = "windows")]
fn host_runner_identity() -> (&'static str, &'static str, &'static str, &'static str) {
    ("windows-x86_64", "Windows", "X64", "win25")
}

fn synthetic_receipt(
    platform: &str,
    os: &str,
    architecture: &str,
    runner_os: &str,
    runner_architecture: &str,
    external_inputs: &str,
) -> serde_json::Value {
    let tools = ["cargo", "kernel", "rustc"]
        .iter()
        .map(|tool| {
            serde_json::json!({
                "executableSha256": digest(&format!("{platform}-{tool}-executable")),
                "id": tool,
                "lockVersion": null,
                "outputSha256": digest(&format!("{platform}-{tool}-output")),
                "parsedVersion": format!("{tool}-{platform}-version")
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "architecture": architecture,
        "archiveImplementationProtocolVersion": 1,
        "candidateExecutableSha256": null,
        "externalInputsSha256": external_inputs,
        "githubHostedRunner": {
            "imageOs": format!("{os}-image"),
            "imageVersion": format!("{platform}-image-version"),
            "runnerArchitecture": runner_architecture,
            "runnerOs": runner_os
        },
        "kernelVersion": format!("{platform}-kernel"),
        "logicalPlatformId": platform,
        "operatingSystemName": os,
        "operatingSystemVersion": format!("{platform}-os-version"),
        "oracleExecutableSha256": null,
        "oracleSourceSha": "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
        "schemaVersion": 1,
        "tools": tools
    })
}

fn environment_command(
    command: &str,
    input: &Path,
    external_inputs: &Path,
    output: &Path,
) -> hell_testkit::SupervisedOutput {
    let mut process = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    process
        .args(["environment", command, "--input"])
        .arg(input)
        .args(["--external-inputs"])
        .arg(external_inputs)
        .args(["--output"])
        .arg(output);
    run_bounded(&mut process, "run environment command")
}

fn run_bounded(command: &mut Command, context: &str) -> hell_testkit::SupervisedOutput {
    let result = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("{context} under process-tree supervision: {error}"));
    assert!(!result.timed_out, "{context} exceeded its deadline");
    assert!(
        result
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete"),
        "{context} did not reach process-tree quiescence"
    );
    assert_eq!(
        result.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined"),
        "{context} did not produce the terminal supervised I/O receipt"
    );
    result
}

fn digest(label: &str) -> String {
    hell_testkit::sha256_bytes(label.as_bytes()).hex()
}

fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("serialize JSON");
    bytes.push(b'\n');
    bytes
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = fs::read(path).expect("read JSON");
    assert_eq!(bytes.last(), Some(&b'\n'));
    serde_json::from_slice(&bytes).expect("parse JSON")
}
