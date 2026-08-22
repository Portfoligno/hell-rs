use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must follow the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("hell-ci-{label}-{nonce}"));
        fs::create_dir(&root).expect("fixture root must be created");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn hell_ci() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hell-ci"))
}

fn stage(input: &Path, runner_temp: &Path) -> Output {
    hell_ci()
        .arg("release")
        .arg("stage-attestations")
        .arg("--input")
        .arg(input)
        .env("RUNNER_TEMP", runner_temp)
        .output()
        .expect("stage-attestations must execute")
}

#[cfg(unix)]
#[test]
fn attestation_registry_stages_two_distinct_exact_json_files() {
    let fixture = Fixture::new("attestation-registry");
    let runner_temp = fixture.path("runner-temp");
    let input = fixture.path("release-bundle");
    fs::create_dir(&runner_temp).unwrap();
    fs::create_dir(&input).unwrap();
    let provenance = runner_temp.join("provenance.json");
    let gate = runner_temp.join("gate.json");
    let provenance_bytes = b"{\"bundle\":\"provenance\"}\n";
    let gate_bytes = b"{\"bundle\":\"gate\"}\r\n";
    fs::write(&provenance, provenance_bytes).unwrap();
    fs::write(&gate, gate_bytes).unwrap();
    fs::write(
        runner_temp.join("created_attestation_paths.txt"),
        format!("{}\n{}\n", provenance.display(), gate.display()),
    )
    .unwrap();

    let output = stage(&input, &runner_temp);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout, "staged exact GitHub attestation bundles\n");
    assert!(!stdout.contains(provenance.to_string_lossy().as_ref()));
    assert!(!stdout.contains(gate.to_string_lossy().as_ref()));
    assert_eq!(
        fs::read(input.join("github-provenance.sigstore.json")).unwrap(),
        provenance_bytes
    );
    assert_eq!(
        fs::read(input.join("github-release-gate.sigstore.json")).unwrap(),
        gate_bytes
    );
}

#[cfg(unix)]
#[test]
fn attestation_registry_rejects_ambiguous_or_external_sources() {
    for scenario in [
        "missing",
        "zero",
        "one",
        "three",
        "interior-blank",
        "control",
        "non-utf8-registry",
        "oversized-registry",
        "duplicate",
        "relative",
        "outside",
        "missing-source",
        "directory-source",
        "non-utf8-source",
        "oversized-source",
        "invalid-json",
        "destination-exists",
    ] {
        let fixture = Fixture::new(scenario);
        let runner_temp = fixture.path("runner-temp");
        let input = fixture.path("release-bundle");
        fs::create_dir(&runner_temp).unwrap();
        fs::create_dir(&input).unwrap();
        let first = runner_temp.join("first.json");
        let second = runner_temp.join("second.json");
        let third = runner_temp.join("third.json");
        fs::write(&first, b"{}\n").unwrap();
        fs::write(&second, b"{}\n").unwrap();
        fs::write(&third, b"{}\n").unwrap();
        let registry = match scenario {
            "missing" | "zero" | "non-utf8-registry" | "oversized-registry" => String::new(),
            "one" => format!("{}\n", first.display()),
            "three" => format!(
                "{}\n{}\n{}\n",
                first.display(),
                second.display(),
                third.display()
            ),
            "interior-blank" => format!("{}\n\n{}\n", first.display(), second.display()),
            "control" => format!("{}\t\n{}\n", first.display(), second.display()),
            "duplicate" => format!("{}\n{}\n", first.display(), first.display()),
            "relative" => format!("first.json\n{}\n", second.display()),
            "outside" => {
                let outside = fixture.path("outside.json");
                fs::write(&outside, b"{}\n").unwrap();
                format!("{}\n{}\n", first.display(), outside.display())
            }
            "missing-source" => {
                fs::remove_file(&second).unwrap();
                format!("{}\n{}\n", first.display(), second.display())
            }
            "directory-source" => {
                fs::remove_file(&second).unwrap();
                fs::create_dir(&second).unwrap();
                format!("{}\n{}\n", first.display(), second.display())
            }
            "non-utf8-source" => {
                fs::write(&second, [0xff, 0xfe]).unwrap();
                format!("{}\n{}\n", first.display(), second.display())
            }
            "oversized-source" => {
                let file = fs::OpenOptions::new().write(true).open(&second).unwrap();
                file.set_len(16 * 1024 * 1024 + 1).unwrap();
                format!("{}\n{}\n", first.display(), second.display())
            }
            "invalid-json" => {
                fs::write(&second, b"not-json\n").unwrap();
                format!("{}\n{}\n", first.display(), second.display())
            }
            "destination-exists" => {
                fs::write(input.join("github-provenance.sigstore.json"), b"sentinel\n").unwrap();
                format!("{}\n{}\n", first.display(), second.display())
            }
            _ => unreachable!(),
        };
        let registry_path = runner_temp.join("created_attestation_paths.txt");
        if scenario == "non-utf8-registry" {
            fs::write(&registry_path, [0xff, 0xfe]).unwrap();
        } else if scenario == "oversized-registry" {
            let file = fs::File::create(&registry_path).unwrap();
            file.set_len(64 * 1024 + 1).unwrap();
        } else if scenario != "missing" {
            fs::write(&registry_path, registry).unwrap();
        }
        let output = stage(&input, &runner_temp);
        assert!(!output.status.success(), "scenario {scenario} was accepted");
        if scenario != "destination-exists" {
            assert!(!input.join("github-provenance.sigstore.json").exists());
        }
        assert!(!input.join("github-release-gate.sigstore.json").exists());
    }
}

#[cfg(unix)]
#[test]
fn attestation_registry_rejects_registry_source_and_destination_symlinks() {
    use std::os::unix::fs::symlink;

    for scenario in ["runner-temp", "registry", "source", "destination-directory"] {
        let fixture = Fixture::new(scenario);
        let real_temp = fixture.path("real-temp");
        let runner_temp = if matches!(scenario, "runner-temp" | "destination-directory") {
            real_temp.clone()
        } else {
            fixture.path("runner-temp")
        };
        let real_input = fixture.path("real-input");
        let input = if scenario == "destination-directory" {
            fixture.path("release-bundle")
        } else {
            real_input.clone()
        };
        fs::create_dir(&real_temp).unwrap();
        if runner_temp != real_temp {
            fs::create_dir(&runner_temp).unwrap();
        }
        fs::create_dir(&real_input).unwrap();
        let first = runner_temp.join("first.json");
        let second = runner_temp.join("second.json");
        fs::write(&first, b"{}\n").unwrap();
        fs::write(&second, b"{}\n").unwrap();
        let registry = runner_temp.join("created_attestation_paths.txt");
        fs::write(
            &registry,
            format!("{}\n{}\n", first.display(), second.display()),
        )
        .unwrap();
        match scenario {
            "runner-temp" => {
                let linked_temp = fixture.path("linked-temp");
                symlink(&real_temp, &linked_temp).unwrap();
                let output = stage(&input, &linked_temp);
                assert!(!output.status.success(), "scenario {scenario} was accepted");
                continue;
            }
            "registry" => {
                let real = runner_temp.join("real-registry.txt");
                fs::rename(&registry, &real).unwrap();
                symlink(&real, &registry).unwrap();
            }
            "source" => {
                let real = runner_temp.join("real-first.json");
                fs::rename(&first, &real).unwrap();
                symlink(&real, &first).unwrap();
            }
            "destination-directory" => symlink(&real_input, &input).unwrap(),
            _ => unreachable!(),
        }
        let output = stage(&input, &runner_temp);
        assert!(!output.status.success(), "scenario {scenario} was accepted");
    }
}

#[cfg(unix)]
#[test]
fn attestation_registry_accepts_crlf_line_endings() {
    let fixture = Fixture::new("attestation-crlf");
    let runner_temp = fixture.path("runner-temp");
    let input = fixture.path("release-bundle");
    fs::create_dir(&runner_temp).unwrap();
    fs::create_dir(&input).unwrap();
    let first = runner_temp.join("first.json");
    let second = runner_temp.join("second.json");
    fs::write(&first, b"{}\n").unwrap();
    fs::write(&second, b"{}\n").unwrap();
    fs::write(
        runner_temp.join("created_attestation_paths.txt"),
        format!("{}\r\n{}\r\n", first.display(), second.display()),
    )
    .unwrap();
    assert!(stage(&input, &runner_temp).status.success());
}

#[cfg(not(unix))]
#[test]
fn attestation_staging_rejects_platforms_without_unix_file_identity() {
    let fixture = Fixture::new("attestation-unsupported-platform");
    let runner_temp = fixture.path("runner-temp");
    let input = fixture.path("release-bundle");
    fs::create_dir(&runner_temp).unwrap();
    fs::create_dir(&input).unwrap();

    let output = stage(&input, &runner_temp);
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "attestation staging requires Unix file identity\n"
    );
}

fn release_plan(candidate_sha: &str) -> Vec<u8> {
    let without_digest = format!(
        concat!(
            "{{\"actor\":\"actor\",\"actorId\":2,",
            "\"buildInputsSha256\":\"{}\",",
            "\"candidateBranch\":\"release/1.0.0\",\"candidateSha\":\"{}\",",
            "\"changelogSha256\":\"{}\",",
            "\"commitAuthor\":\"Author <author@example.com>\",",
            "\"commitCommitter\":\"Committer <committer@example.com>\",",
            "\"conformancePlanSha256\":\"{}\",",
            "\"conformanceStandard\":\"upstream-release-v1\",",
            "\"defaultBranch\":\"main\",",
            "\"expectedPlatforms\":[\"linux-x86_64\",\"macos-aarch64\",\"windows-x86_64\"],",
            "\"policySha256\":\"{}\",\"prerelease\":false,",
            "\"releaseBinary\":\"hell\",",
            "\"releaseEvaluationInstant\":\"2026-08-13T00:00:00Z\",",
            "\"releasePackage\":\"hell-cli\",\"repository\":\"o/r\",",
            "\"repositoryId\":1,\"runAttempt\":1,\"runId\":3,",
            "\"schemaVersion\":2,\"sourceDateEpoch\":1,",
            "\"sourceInventorySha256\":\"{}\",\"tag\":\"v1.0.0\",",
            "\"trustedConformanceInputsSha256\":\"{}\",",
            "\"version\":\"1.0.0\",",
            "\"workflowRef\":\"o/r/.github/workflows/release.yml@refs/heads/main\",",
            "\"workflowSha\":\"{}\"}}\n"
        ),
        "1".repeat(64),
        candidate_sha,
        "2".repeat(64),
        "3".repeat(64),
        "4".repeat(64),
        "5".repeat(64),
        "6".repeat(64),
        "b".repeat(40),
    );
    let digest = hell_testkit::sha256_bytes(without_digest.as_bytes()).hex();
    without_digest
        .replacen(
            "\"policySha256\"",
            &format!("\"planSha256\":\"{digest}\",\"policySha256\""),
            1,
        )
        .into_bytes()
}

#[test]
fn remote_state_requires_the_standard_token_name() {
    let fixture = Fixture::new("remote-token");
    let plan = fixture.path("release-plan.json");
    let report = fixture.path("remote-state.json");
    fs::write(&plan, release_plan(&"a".repeat(40))).unwrap();
    let output = hell_ci()
        .args(["release", "check-remote-state", "--plan"])
        .arg(&plan)
        .arg("--report")
        .arg(&report)
        .env("GITHUB_API_URL", "http://127.0.0.1:1")
        .env_remove("GITHUB_TOKEN")
        .output()
        .expect("check-remote-state must execute");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("GITHUB_TOKEN is required"));
}

#[cfg(unix)]
#[test]
fn stack_work_cleanup_precedes_exact_oracle_snapshot_validation() {
    let output = hell_ci()
        .arg("__verify-posix-source-stack-cleanup-order")
        .output()
        .expect("POSIX archive cleanup lifecycle verifier must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn staged_native_toolchain_accepts_real_ghc_without_inner_launcher_aliases() {
    let fixture = Fixture::new("staged-native-toolchain");
    let adapter = fixture.path("adapter");
    let status = hell_ci()
        .arg("__verify-staged-native-toolchain")
        .arg(&adapter)
        .status()
        .expect("staged native toolchain verification must execute");
    assert!(status.success());
}

#[cfg(target_os = "macos")]
#[test]
fn sealed_native_archive_authority_rebinds_before_use_and_rejects_later_mutation() {
    let fixture = Fixture::new("native-archive-seal-rebinding");
    let adapter = fixture.path("adapter");
    let output = hell_ci()
        .arg("__verify-native-archive-seal-rebinding")
        .arg(&adapter)
        .output()
        .expect("native archive seal verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn archive_adapter_transition_rejects_cleared_setgid_and_substitution() {
    let output = hell_ci()
        .arg("__verify-posix-archive-adapter-transition")
        .output()
        .expect("POSIX archive adapter transition verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn native_archive_policy_preserves_commands_overlay_path_and_inventory() {
    let output = hell_ci()
        .arg("__verify-native-archive-policy")
        .output()
        .expect("native archive policy verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn nightly_workspace_partition_preserves_the_existing_total_deadline() {
    let output = hell_ci()
        .arg("__verify-nightly-workspace-partition")
        .output()
        .expect("nightly workspace partition verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(windows)]
#[test]
fn windows_hell_testkit_diagnostics_preserve_exact_targets_and_aggregate_budget() {
    let output = hell_ci()
        .arg("__verify-windows-hell-testkit-diagnostics")
        .output()
        .expect("Windows hell-testkit diagnostic verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
