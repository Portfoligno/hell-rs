use std::fmt::Write as _;
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
    assert_live_candidate_confined_collection(&fixture);

    let lock_path = fixture.write(
        "synthetic-external-inputs.toml",
        b"schema-version = 1\nlock-id = \"native-synthetic-fixture-v1\"\n\n[[input]]\nid = \"upstream-oracle-source\"\nkind = \"git-commit\"\nrepository = \"chrisdone/hell\"\ncommit = \"8e952cf9de4ab25d7716982a9ca234f9bdcf1bff\"\nacquisition-phase = \"native-platform\"\n\n[[input]]\nid = \"cargo-deny\"\nkind = \"cargo-package\"\npackage = \"cargo-deny\"\nversion = \"0.20.2\"\nplatforms = [\"linux-x86_64\"]\nacquisition-phase = \"native-platform\"\n\n[[input]]\nid = \"ghc\"\nkind = \"tool-version\"\nversion = \"9.8.2\"\nplatforms = [\"windows-x86_64\"]\nacquisition-phase = \"native-platform\"\n",
    );
    let external_digest =
        hell_ci::native_environment_external_inputs_sha256_for_integration(&lock_path)
            .expect("bind synthetic external-input authority with production digest");

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

    let admitted_set = read_json(&set_path);
    assert_eq!(admitted_set["receipts"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        receipt_tools(&admitted_set, "linux-x86_64")
            .iter()
            .filter(|tool| tool["id"] == "cargo-deny")
            .count(),
        1
    );
    for platform in ["macos-aarch64", "windows-x86_64"] {
        assert!(
            receipt_tools(&admitted_set, platform)
                .iter()
                .all(|tool| tool["id"] != "cargo-deny"),
            "{platform} unexpectedly retained Linux-only cargo-deny"
        );
    }
    assert_cargo_deny_receipt_mutations_rejected(&fixture, &lock_path, &admitted_set);
    assert_ghc_receipt_near_matches_rejected(&fixture, &lock_path, &admitted_set);

    let mut tampered = admitted_set;
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

fn assert_live_candidate_confined_collection(fixture: &Fixture) {
    let live_lock_path = fixture.write(
        "live-external-inputs.toml",
        &live_external_inputs(Some(("9.8.2", "windows-x86_64"))),
    );

    #[cfg(windows)]
    assert_windows_live_ghc_contract(fixture, &live_lock_path);

    #[cfg(not(windows))]
    {
        let repository_name = "Portfoligno/hell-rs";
        let repository_id = fixture_repository_id(repository_name);
        let event = canonical_json(&serde_json::json!({
            "repository": {"full_name": repository_name, "id": repository_id}
        }));
        let event_path = fixture.write("event.json", &event);
        let (collect, receipt_path) = collect_live_environment(
            fixture,
            &event_path,
            &live_lock_path,
            "collected.json",
            "collect native environment",
        );
        assert!(collect.status.success(), "{:?}", collect.stderr);
        let collected = read_json(&receipt_path);
        assert_live_tool_receipts(&collected);
    }
}

#[cfg(not(windows))]
fn collect_live_environment(
    fixture: &Fixture,
    event_path: &Path,
    live_lock_path: &Path,
    receipt_name: &str,
    context: &str,
) -> (hell_testkit::SupervisedOutput, PathBuf) {
    let repository_name = "Portfoligno/hell-rs";
    let repository_id = fixture_repository_id(repository_name);
    let receipt_path = fixture.root.join(receipt_name);
    let (host_platform, runner_os, runner_architecture, image_os) = host_runner_identity();
    let mut collect_command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    collect_command
        .args(["environment", "collect", "--platform", host_platform])
        .args(["--external-inputs"])
        .arg(live_lock_path)
        .args(["--output"])
        .arg(&receipt_path)
        .env("GITHUB_API_URL", "http://127.0.0.1:9")
        .env("GITHUB_EVENT_NAME", "workflow_dispatch")
        .env("GITHUB_EVENT_PATH", event_path)
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
    (run_bounded(&mut collect_command, context), receipt_path)
}

fn live_external_inputs(ghc: Option<(&str, &str)>) -> Vec<u8> {
    let mut contents = String::from(
        "schema-version = 1\nlock-id = \"native-live-fixture-v1\"\n\n[[input]]\nid = \"upstream-oracle-source\"\nkind = \"git-commit\"\nrepository = \"chrisdone/hell\"\ncommit = \"8e952cf9de4ab25d7716982a9ca234f9bdcf1bff\"\nacquisition-phase = \"native-platform\"\n",
    );
    if let Some((version, platform)) = ghc {
        write!(
            contents,
            "\n[[input]]\nid = \"ghc\"\nkind = \"tool-version\"\nversion = \"{version}\"\nplatforms = [\"{platform}\"]\nacquisition-phase = \"native-platform\"\n"
        )
        .expect("write live GHC lock entry");
    }
    contents.into_bytes()
}

#[cfg(not(windows))]
fn assert_live_tool_receipts(collected: &serde_json::Value) {
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
    assert!(
        collected["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .all(|tool| tool["id"] != "cargo-deny"),
        "live candidate-confined collection must not require trusted cargo-deny authority"
    );
}

#[cfg(windows)]
fn assert_windows_live_ghc_contract(fixture: &Fixture, live_lock_path: &Path) {
    let ghc = hell_ci::windows_native_ghc_authority_for_integration(live_lock_path)
        .expect("collect typed Windows GHC authority");
    assert_eq!(ghc.parsed_version, "9.8.2");
    for (field, digest) in [
        ("executableSha256", ghc.executable_sha256),
        ("outputSha256", ghc.output_sha256),
    ] {
        assert_eq!(digest.len(), 64, "GHC {field} must be SHA-256");
    }

    assert_windows_live_ghc_rejected(
        fixture,
        "missing-ghc",
        None,
        "Windows native environment has no GHC specification",
    );
    assert_windows_live_ghc_rejected(
        fixture,
        "wrong-ghc-version",
        Some(("0.0.0", "windows-x86_64")),
        "native tool ghc differs from external-input lock",
    );
    assert_windows_live_ghc_rejected(
        fixture,
        "mis-scoped-ghc",
        Some(("9.8.2", "macos-aarch64")),
        "Windows native environment has no GHC specification",
    );
}

#[cfg(windows)]
fn assert_windows_live_ghc_rejected(
    fixture: &Fixture,
    label: &str,
    ghc: Option<(&str, &str)>,
    expected_diagnostic: &str,
) {
    let lock_path = fixture.write(
        &format!("{label}-external-inputs.toml"),
        &live_external_inputs(ghc),
    );
    let stderr = hell_ci::windows_native_ghc_authority_for_integration(&lock_path)
        .expect_err(&format!("{label} unexpectedly succeeded"));
    assert!(
        stderr.contains(expected_diagnostic),
        "{label} failed outside the GHC authority boundary: {stderr}"
    );
}

fn assert_cargo_deny_receipt_mutations_rejected(
    fixture: &Fixture,
    lock_path: &Path,
    admitted_set: &serde_json::Value,
) {
    let mut missing_linux_tool = admitted_set.clone();
    let linux_tools = receipt_tools_mut(&mut missing_linux_tool, "linux-x86_64");
    linux_tools.retain(|tool| tool["id"] != "cargo-deny");
    assert_inventory_rejected(
        fixture,
        lock_path,
        "missing-linux-cargo-deny",
        &missing_linux_tool,
    );

    let mut unexpected_windows_tool = admitted_set.clone();
    let windows_tools = receipt_tools_mut(&mut unexpected_windows_tool, "windows-x86_64");
    windows_tools.insert(
        1,
        synthetic_tool("windows-x86_64", "cargo-deny", Some("0.20.2")),
    );
    assert_inventory_rejected(
        fixture,
        lock_path,
        "unexpected-windows-cargo-deny",
        &unexpected_windows_tool,
    );

    let mut drifting_linux_tool = admitted_set.clone();
    let cargo_deny = receipt_tools_mut(&mut drifting_linux_tool, "linux-x86_64")
        .iter_mut()
        .find(|tool| tool["id"] == "cargo-deny")
        .expect("Linux receipt contains cargo-deny");
    cargo_deny["parsedVersion"] = serde_json::Value::String("cargo-deny 0.20.3".to_owned());
    assert_inventory_rejected(
        fixture,
        lock_path,
        "drifting-linux-cargo-deny",
        &drifting_linux_tool,
    );
}

fn assert_ghc_receipt_near_matches_rejected(
    fixture: &Fixture,
    lock_path: &Path,
    admitted_set: &serde_json::Value,
) {
    for (label, near_match) in [
        ("longer-ghc-version", "9.8.20"),
        ("wrapped-ghc-version", "x9.8.2y"),
    ] {
        let mut substituted_set = admitted_set.clone();
        let ghc = receipt_tools_mut(&mut substituted_set, "windows-x86_64")
            .iter_mut()
            .find(|tool| tool["id"] == "ghc")
            .expect("Windows receipt contains GHC");
        ghc["parsedVersion"] = serde_json::Value::String(near_match.to_owned());
        assert_inventory_rejected(fixture, lock_path, label, &substituted_set);
    }
}

#[cfg(not(windows))]
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

fn synthetic_receipt(
    platform: &str,
    os: &str,
    architecture: &str,
    runner_os: &str,
    runner_architecture: &str,
    external_inputs: &str,
) -> serde_json::Value {
    let tool_inventory: &[(&str, Option<&str>)] = match platform {
        "linux-x86_64" => &[
            ("cargo", None),
            ("cargo-deny", Some("0.20.2")),
            ("kernel", None),
            ("linker", None),
            ("rustc", None),
        ],
        "macos-aarch64" => &[
            ("apple-sdk", None),
            ("cargo", None),
            ("kernel", None),
            ("linker", None),
            ("rustc", None),
        ],
        "windows-x86_64" => &[
            ("cargo", None),
            ("ghc", Some("9.8.2")),
            ("kernel", None),
            ("msvc-toolset", None),
            ("rustc", None),
        ],
        _ => panic!("unknown synthetic platform {platform}"),
    };
    let tools = tool_inventory
        .iter()
        .map(|(tool, lock_version)| synthetic_tool(platform, tool, *lock_version))
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

fn synthetic_tool(platform: &str, tool: &str, lock_version: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "executableSha256": digest(&format!("{platform}-{tool}-executable")),
        "id": tool,
        "lockVersion": lock_version,
        "outputSha256": digest(&format!("{platform}-{tool}-output")),
        "parsedVersion": lock_version.map_or_else(
            || format!("{tool}-{platform}-version"),
            |version| if tool == "ghc" { version.to_owned() } else { format!("{tool} {version}") },
        )
    })
}

fn receipt_tools_mut<'a>(
    set: &'a mut serde_json::Value,
    platform: &str,
) -> &'a mut Vec<serde_json::Value> {
    set["receipts"]
        .as_array_mut()
        .expect("receipt records")
        .iter_mut()
        .find(|record| record["platformId"] == platform)
        .expect("platform receipt record")["receipt"]["tools"]
        .as_array_mut()
        .expect("platform tool receipts")
}

fn receipt_tools<'a>(set: &'a serde_json::Value, platform: &str) -> &'a [serde_json::Value] {
    set["receipts"]
        .as_array()
        .expect("receipt records")
        .iter()
        .find(|record| record["platformId"] == platform)
        .expect("platform receipt record")["receipt"]["tools"]
        .as_array()
        .expect("platform tool receipts")
}

fn assert_inventory_rejected(
    fixture: &Fixture,
    lock_path: &Path,
    label: &str,
    set: &serde_json::Value,
) {
    let set_path = fixture.write(&format!("{label}-set.json"), &canonical_json(set));
    let report_path = fixture.root.join(format!("{label}-report.json"));
    let rejected = environment_command("verify-set", &set_path, lock_path, &report_path);
    assert!(!rejected.status.success(), "{label} unexpectedly admitted");
    let report = read_json(&report_path);
    assert_eq!(report["admitted"], false);
    assert!(
        report["diagnostic"]["message"]
            .as_str()
            .expect("rejection message")
            .contains("native tool receipt"),
        "{label} did not fail at the native tool receipt boundary: {report:?}",
    );
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
