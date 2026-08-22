use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::command::CommandSpec;
use crate::github_runtime::{GithubRuntime, RunnerIdentity};
use crate::json::{JsonValue, canonical_json_bytes, json_member};
use crate::process_environment::ExecutableSearchPath;

use super::governance::{
    TomlDocument, boolean, integer, member, quoted, require_allowed_keys, require_identifier,
    require_keys, string_array,
};
use super::manifest::{read_json, read_regular, write_json_new};
use super::schema::{PLATFORMS, ReleasePlatform, number, object, require_digest, string};

const EXTERNAL_INPUT_DOMAIN: &[u8] = b"hell-rs:external-input-lock:1";
const NATIVE_ENVIRONMENT_DOMAIN: &[u8] = b"hell-rs:native-environment:1";
const NATIVE_ENVIRONMENT_SET_DOMAIN: &[u8] = b"hell-rs:native-environment-set:1";
const MAX_LOCK_BYTES: u64 = 1024 * 1024;
const MAX_TOOL_BYTES: u64 = 512 * 1024 * 1024;
const COLLECTION_TIMEOUT: Duration = Duration::from_mins(5);
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct ExternalInputLock {
    lock_id: String,
    inputs: Vec<ExternalInput>,
}

#[derive(Clone, Debug)]
struct ExternalInput {
    id: String,
    kind: String,
    acquisition_phase: String,
    platforms: Vec<String>,
    fields: BTreeMap<String, JsonValue>,
}

#[derive(Clone, Debug)]
struct ToolSpec {
    id: &'static str,
    executable: &'static str,
    arguments: &'static [&'static str],
    expected_version: Option<String>,
}

#[derive(Clone, Debug)]
struct ToolReceipt {
    id: String,
    executable_sha256: String,
    output_sha256: String,
    parsed_version: String,
    lock_version: Option<String>,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .is_some_and(|argument| argument == "environment")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let command = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(usage)?;
    let options = Options::parse(&arguments[2..])?;
    match command {
        "collect" => collect_for_platform(
            ReleasePlatform::parse(&required_string(options.platform, "--platform")?)?,
            &required_path(options.external_inputs, "--external-inputs")?,
            &required_path(options.output, "--output")?,
        ),
        "assemble-set" => assemble_set(
            &required_path(options.input, "--input")?,
            &required_path(options.external_inputs, "--external-inputs")?,
            &required_path(options.output, "--output")?,
        ),
        "verify-set" => verify_set_command(
            &required_path(options.input, "--input")?,
            &required_path(options.external_inputs, "--external-inputs")?,
            &required_path(options.output, "--output")?,
        ),
        _ => Err(usage()),
    }
}

pub(crate) fn external_inputs_sha256(path: &Path) -> Result<String, String> {
    let lock = ExternalInputLock::read(path)?;
    domain_digest(EXTERNAL_INPUT_DOMAIN, &lock.json())
}

pub(crate) fn collect_for_platform(
    platform: ReleasePlatform,
    external_inputs: &Path,
    output: &Path,
) -> Result<String, String> {
    let lock = ExternalInputLock::read(external_inputs)?;
    let external_inputs_sha256 = domain_digest(EXTERNAL_INPUT_DOMAIN, &lock.json())?;
    let runtime = GithubRuntime::from_process()?;
    let runner = runtime.runner.as_ref().ok_or_else(|| {
        "native environment collection requires GitHub runner identity".to_owned()
    })?;
    validate_runner(platform, runner)?;
    let deadline = Instant::now()
        .checked_add(COLLECTION_TIMEOUT)
        .ok_or_else(|| "native environment collection deadline overflowed".to_owned())?;
    let search = ExecutableSearchPath::from_process()?;
    let specs = tool_specs(platform, &lock);
    let mut receipts = Vec::new();
    for spec in specs {
        receipts.push(collect_tool(&search, &spec, deadline)?);
    }
    receipts.sort_by(|left, right| left.id.cmp(&right.id));
    let oracle_source_sha = lock
        .inputs
        .iter()
        .find(|input| input.id == "upstream-oracle-source")
        .and_then(|input| input.fields.get("commit"))
        .and_then(|value| value.string().ok())
        .ok_or_else(|| "external-input lock lacks upstream oracle source commit".to_owned())?;
    let receipt = object([
        ("architecture", string(std::env::consts::ARCH)),
        ("archiveImplementationProtocolVersion", number(1)),
        ("candidateExecutableSha256", JsonValue::Null),
        ("externalInputsSha256", string(&external_inputs_sha256)),
        (
            "githubHostedRunner",
            object([
                ("imageOs", option_string(runner.image_os.as_deref())),
                (
                    "imageVersion",
                    option_string(runner.image_version.as_deref()),
                ),
                ("runnerArchitecture", string(&runner.runner_architecture)),
                ("runnerOs", string(&runner.runner_os)),
            ]),
        ),
        ("kernelVersion", tool_version(&receipts, "kernel")),
        ("logicalPlatformId", string(platform.id())),
        ("operatingSystemName", string(std::env::consts::OS)),
        (
            "operatingSystemVersion",
            option_string(runner.image_version.as_deref()),
        ),
        ("oracleExecutableSha256", JsonValue::Null),
        ("oracleSourceSha", string(oracle_source_sha)),
        ("schemaVersion", number(1)),
        (
            "tools",
            JsonValue::Array(receipts.iter().map(ToolReceipt::json).collect()),
        ),
    ]);
    let bytes = write_json_new(output, &receipt)?;
    let digest = domain_digest_bytes(NATIVE_ENVIRONMENT_DOMAIN, &bytes);
    Ok(format!(
        "collected native environment {} as {digest}",
        platform.id()
    ))
}

pub(crate) fn assemble_set(
    input: &Path,
    external_inputs: &Path,
    output: &Path,
) -> Result<String, String> {
    let expected_external = external_inputs_sha256(external_inputs)?;
    let inventory = exact_receipt_inventory(input)?;
    let mut records = Vec::new();
    for platform in PLATFORMS {
        let path = inventory
            .get(platform.id())
            .ok_or_else(|| format!("native receipt inventory lacks {}", platform.id()))?;
        let bytes = read_regular(path)?;
        let receipt = read_json(path)?;
        validate_receipt(&receipt, platform, &expected_external)?;
        records.push(object([
            (
                "nativeEnvironmentSha256",
                string(&domain_digest_bytes(NATIVE_ENVIRONMENT_DOMAIN, &bytes)),
            ),
            ("platformId", string(platform.id())),
            ("receipt", receipt),
        ]));
    }
    let set = object([
        ("externalInputsSha256", string(&expected_external)),
        ("receipts", JsonValue::Array(records)),
        ("schemaVersion", number(1)),
    ]);
    let bytes = write_json_new(output, &set)?;
    let digest = domain_digest_bytes(NATIVE_ENVIRONMENT_SET_DOMAIN, &bytes);
    Ok(format!("assembled native environment set {digest}"))
}

fn verify_set_command(
    input: &Path,
    external_inputs: &Path,
    output: &Path,
) -> Result<String, String> {
    let outcome = verify_set(input, external_inputs);
    let report = match &outcome {
        Ok(digest) => object([
            ("admitted", JsonValue::Bool(true)),
            ("diagnostic", JsonValue::Null),
            ("nativeEnvironmentSetSha256", string(digest)),
            ("schemaVersion", number(1)),
            ("state", string("verified")),
        ]),
        Err(error) => object([
            ("admitted", JsonValue::Bool(false)),
            (
                "diagnostic",
                object([
                    ("code", string("native-environment.set.rejected")),
                    ("message", string(&bounded_message(error))),
                ]),
            ),
            ("nativeEnvironmentSetSha256", JsonValue::Null),
            ("schemaVersion", number(1)),
            ("state", string("rejected")),
        ]),
    };
    write_json_new(output, &report)?;
    let digest = outcome?;
    Ok(format!("verified native environment set {digest}"))
}

pub(crate) fn verify_set(input: &Path, external_inputs: &Path) -> Result<String, String> {
    let expected_external = external_inputs_sha256(external_inputs)?;
    let bytes = read_regular(input)?;
    let set = read_json(input)?;
    let fields = set.object()?;
    require_json_keys(
        fields,
        &["externalInputsSha256", "receipts", "schemaVersion"],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 1
        || json_member(fields, "externalInputsSha256")?.string()? != expected_external
    {
        return Err("native environment set schema or external-input binding differs".to_owned());
    }
    let records = json_member(fields, "receipts")?.array()?;
    if records.len() != PLATFORMS.len() {
        return Err("native environment set receipt count differs".to_owned());
    }
    for (record, platform) in records.iter().zip(PLATFORMS) {
        let record = record.object()?;
        require_json_keys(
            record,
            &["nativeEnvironmentSha256", "platformId", "receipt"],
        )?;
        if json_member(record, "platformId")?.string()? != platform.id() {
            return Err("native environment set platform ordering differs".to_owned());
        }
        let receipt = json_member(record, "receipt")?;
        validate_receipt(receipt, platform, &expected_external)?;
        let receipt_bytes = canonical_json_bytes(receipt)?;
        let expected_digest = domain_digest_bytes(NATIVE_ENVIRONMENT_DOMAIN, &receipt_bytes);
        if json_member(record, "nativeEnvironmentSha256")?.string()? != expected_digest {
            return Err(format!(
                "native receipt digest differs for {}",
                platform.id()
            ));
        }
    }
    Ok(domain_digest_bytes(NATIVE_ENVIRONMENT_SET_DOMAIN, &bytes))
}

pub(crate) fn verify_receipt(
    path: &Path,
    platform: ReleasePlatform,
    expected_external_inputs: &str,
) -> Result<String, String> {
    let bytes = read_regular(path)?;
    let receipt = read_json(path)?;
    validate_receipt(&receipt, platform, expected_external_inputs)?;
    Ok(domain_digest_bytes(NATIVE_ENVIRONMENT_DOMAIN, &bytes))
}

fn validate_receipt(
    receipt: &JsonValue,
    platform: ReleasePlatform,
    external_inputs: &str,
) -> Result<(), String> {
    let fields = receipt.object()?;
    require_json_keys(
        fields,
        &[
            "architecture",
            "archiveImplementationProtocolVersion",
            "candidateExecutableSha256",
            "externalInputsSha256",
            "githubHostedRunner",
            "kernelVersion",
            "logicalPlatformId",
            "operatingSystemName",
            "operatingSystemVersion",
            "oracleExecutableSha256",
            "oracleSourceSha",
            "schemaVersion",
            "tools",
        ],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 1
        || json_member(fields, "archiveImplementationProtocolVersion")?.number()? != 1
        || json_member(fields, "logicalPlatformId")?.string()? != platform.id()
        || json_member(fields, "externalInputsSha256")?.string()? != external_inputs
    {
        return Err(format!(
            "native receipt binding differs for {}",
            platform.id()
        ));
    }
    let tools = json_member(fields, "tools")?.array()?;
    if tools.is_empty() {
        return Err(format!("native receipt has no tools for {}", platform.id()));
    }
    let mut prior = None::<String>;
    for tool in tools {
        let fields = tool.object()?;
        require_json_keys(
            fields,
            &[
                "executableSha256",
                "id",
                "lockVersion",
                "outputSha256",
                "parsedVersion",
            ],
        )?;
        let id = json_member(fields, "id")?.string()?.to_owned();
        if prior.as_ref().is_some_and(|prior| prior >= &id) {
            return Err("native tool receipt inventory is not strictly ordered".to_owned());
        }
        prior = Some(id);
        require_digest(
            json_member(fields, "executableSha256")?.string()?,
            "native executable digest",
        )?;
        require_digest(
            json_member(fields, "outputSha256")?.string()?,
            "native tool output digest",
        )?;
    }
    Ok(())
}

pub(crate) fn fuzz_parse_receipt(receipt: &JsonValue) -> Result<(), String> {
    let fields = receipt.object()?;
    let platform = ReleasePlatform::parse(json_member(fields, "logicalPlatformId")?.string()?)?;
    let external_inputs = json_member(fields, "externalInputsSha256")?.string()?;
    require_digest(external_inputs, "native external-input digest")?;
    validate_receipt(receipt, platform, external_inputs)
}

impl ToolReceipt {
    fn json(&self) -> JsonValue {
        object([
            ("executableSha256", string(&self.executable_sha256)),
            ("id", string(&self.id)),
            ("lockVersion", option_string(self.lock_version.as_deref())),
            ("outputSha256", string(&self.output_sha256)),
            ("parsedVersion", string(&self.parsed_version)),
        ])
    }
}

fn collect_tool(
    search: &ExecutableSearchPath,
    spec: &ToolSpec,
    deadline: Instant,
) -> Result<ToolReceipt, String> {
    if Instant::now() >= deadline {
        return Err("native environment absolute deadline expired".to_owned());
    }
    let executable = search.resolve(OsStr::new(spec.executable))?;
    let metadata = std::fs::symlink_metadata(&executable)
        .map_err(|error| format!("cannot inspect native tool {}: {error}", spec.id))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_TOOL_BYTES {
        return Err(format!(
            "native tool {} is not one bounded regular file",
            spec.id
        ));
    }
    let executable_sha256 = hell_testkit::sha256_file(&executable)
        .map_err(|error| format!("cannot hash native tool {}: {error}", spec.id))?
        .hex();
    let execution_deadline = Instant::now()
        .checked_add(TOOL_TIMEOUT)
        .unwrap_or(deadline)
        .min(deadline);
    let (progress, _receiver) = hell_testkit::SupervisedProgressObserver::bounded(1);
    let result = CommandSpec::new(executable.clone(), TOOL_TIMEOUT)
        .arguments(spec.arguments.iter().copied())
        .release_candidate_environment()
        .run_until(execution_deadline, deadline, progress)
        .map_err(|error| format!("native tool {} failed to execute: {error}", spec.id))?;
    if result.timed_out
        || !result.status.success()
        || result.stdout_truncated
        || result.stderr_truncated
        || (result.termination.forced && !result.termination.reaped)
    {
        return Err(format!(
            "native tool {} did not complete cleanly: status={} timedOut={} stdoutTruncated={} stderrTruncated={} forced={} reaped={}",
            spec.id,
            result.status,
            result.timed_out,
            result.stdout_truncated,
            result.stderr_truncated,
            result.termination.forced,
            result.termination.reaped
        ));
    }
    let mut output = result.stdout;
    output.push(0);
    output.extend_from_slice(&result.stderr);
    let output_sha256 = hell_testkit::sha256_bytes(&output).hex();
    let parsed_version = parse_version_output(spec.id, &output)?;
    if spec
        .expected_version
        .as_ref()
        .is_some_and(|expected| !parsed_version.contains(expected))
    {
        return Err(format!(
            "native tool {} differs from external-input lock",
            spec.id
        ));
    }
    let after = hell_testkit::sha256_file(&executable)
        .map_err(|error| format!("cannot rehash native tool {}: {error}", spec.id))?
        .hex();
    if after != executable_sha256 || Instant::now() >= deadline {
        return Err(format!(
            "native tool {} changed or exceeded its deadline",
            spec.id
        ));
    }
    Ok(ToolReceipt {
        id: spec.id.to_owned(),
        executable_sha256,
        output_sha256,
        parsed_version,
        lock_version: spec.expected_version.clone(),
    })
}

fn parse_version_output(id: &str, output: &[u8]) -> Result<String, String> {
    let text =
        std::str::from_utf8(output).map_err(|_| format!("native tool {id} output is not UTF-8"))?;
    let line = text
        .split(['\r', '\n', '\0'])
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| format!("native tool {id} produced no version line"))?;
    if line.len() > 1024 || line.chars().any(char::is_control) {
        return Err(format!("native tool {id} version line is invalid"));
    }
    Ok(line.to_owned())
}

fn tool_version(receipts: &[ToolReceipt], id: &str) -> JsonValue {
    receipts
        .iter()
        .find(|receipt| receipt.id == id)
        .map_or(JsonValue::Null, |receipt| string(&receipt.parsed_version))
}

fn tool_specs(platform: ReleasePlatform, lock: &ExternalInputLock) -> Vec<ToolSpec> {
    let mut specs = vec![
        ToolSpec {
            id: "cargo",
            executable: "cargo",
            arguments: &["-Vv"],
            expected_version: None,
        },
        ToolSpec {
            id: "rustc",
            executable: "rustc",
            arguments: &["-vV"],
            expected_version: None,
        },
    ];
    match platform {
        ReleasePlatform::LinuxX86_64 => specs.extend([
            ToolSpec {
                id: "kernel",
                executable: "uname",
                arguments: &["-srvmo"],
                expected_version: None,
            },
            ToolSpec {
                id: "linker",
                executable: "cc",
                arguments: &["--version"],
                expected_version: None,
            },
        ]),
        ReleasePlatform::MacosAarch64 => specs.extend([
            ToolSpec {
                id: "apple-sdk",
                executable: "xcrun",
                arguments: &["--show-sdk-version"],
                expected_version: None,
            },
            ToolSpec {
                id: "kernel",
                executable: "uname",
                arguments: &["-srvmo"],
                expected_version: None,
            },
            ToolSpec {
                id: "linker",
                executable: "clang",
                arguments: &["--version"],
                expected_version: None,
            },
        ]),
        ReleasePlatform::WindowsX86_64 => specs.extend([
            ToolSpec {
                id: "kernel",
                executable: "rustc",
                arguments: &["-vV"],
                expected_version: None,
            },
            ToolSpec {
                id: "msvc-toolset",
                executable: "cl.exe",
                arguments: &["/Bv"],
                expected_version: None,
            },
        ]),
    }
    for (id, executable, arguments) in [
        ("stack", "stack", &["--numeric-version"][..]),
        ("ghc", "ghc", &["--numeric-version"][..]),
        ("llvm", "llvm-ar", &["--version"][..]),
        ("cargo-deny", "cargo-deny", &["--version"][..]),
    ] {
        if let Some(input) = lock.input_for_tool(id, platform) {
            specs.push(ToolSpec {
                id,
                executable,
                arguments,
                expected_version: input
                    .fields
                    .get("version")
                    .and_then(|value| value.string().ok())
                    .map(str::to_owned),
            });
        }
    }
    specs
}

fn validate_runner(platform: ReleasePlatform, runner: &RunnerIdentity) -> Result<(), String> {
    let (expected_os, expected_arch) = platform.runner();
    if runner.runner_os != expected_os || runner.runner_architecture != expected_arch {
        return Err(format!(
            "GitHub runner identity differs from logical platform {}",
            platform.id()
        ));
    }
    Ok(())
}

impl ExternalInputLock {
    fn read(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect external-input lock: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_LOCK_BYTES
        {
            return Err("external-input lock is not one bounded regular file".to_owned());
        }
        let bytes = read_regular(path)?;
        if !bytes.ends_with(b"\n") {
            return Err("external-input lock lacks its trailing newline".to_owned());
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "external-input lock is not UTF-8".to_owned())?;
        let document = TomlDocument::parse(text)?;
        document.require_table_inventory(&[""])?;
        document.require_array_inventory(&["input"])?;
        let root = document.table("")?;
        require_keys(root, &["lock-id", "schema-version"])?;
        if integer(member(root, "schema-version")?)? != 1 {
            return Err("unsupported external-input lock schema".to_owned());
        }
        let lock_id = quoted(member(root, "lock-id")?)?;
        require_identifier(&lock_id, "external-input lock ID")?;
        let mut ids = BTreeSet::new();
        let mut inputs = Vec::new();
        for table in document.arrays("input")? {
            require_allowed_keys(
                table,
                &[
                    "acquisition-phase",
                    "cache-permitted",
                    "commit",
                    "expected-filename",
                    "id",
                    "kind",
                    "maximum-compressed-bytes",
                    "maximum-expanded-bytes",
                    "media-type",
                    "package",
                    "platform",
                    "platforms",
                    "repository",
                    "sha256",
                    "timeout-seconds",
                    "toolchain",
                    "version",
                ],
            )?;
            for required in ["acquisition-phase", "id", "kind"] {
                if !table.contains_key(required) {
                    return Err(format!("external input lacks {required}"));
                }
            }
            let id = quoted(member(table, "id")?)?;
            require_identifier(&id, "external input ID")?;
            if !ids.insert(id.clone()) {
                return Err(format!("duplicate external input {id}"));
            }
            let kind = quoted(member(table, "kind")?)?;
            let acquisition_phase = quoted(member(table, "acquisition-phase")?)?;
            let platforms = table
                .get("platforms")
                .map(|value| string_array(value))
                .transpose()?
                .unwrap_or_default();
            let mut fields = BTreeMap::new();
            for (key, value) in table {
                let json = match key.as_str() {
                    "cache-permitted" => JsonValue::Bool(boolean(value)?),
                    "maximum-compressed-bytes" | "maximum-expanded-bytes" | "timeout-seconds" => {
                        number(integer(value)?)
                    }
                    "platforms" => JsonValue::Array(
                        string_array(value)?
                            .iter()
                            .map(|value| string(value))
                            .collect(),
                    ),
                    _ => string(&quoted(value)?),
                };
                fields.insert(key.clone(), json);
            }
            validate_external_input(&id, &kind, &fields)?;
            inputs.push(ExternalInput {
                id,
                kind,
                acquisition_phase,
                platforms,
                fields,
            });
        }
        Ok(Self { lock_id, inputs })
    }

    fn json(&self) -> JsonValue {
        object([
            (
                "inputs",
                JsonValue::Array(
                    self.inputs
                        .iter()
                        .map(|input| JsonValue::Object(input.fields.clone()))
                        .collect(),
                ),
            ),
            ("lockId", string(&self.lock_id)),
            ("schemaVersion", number(1)),
        ])
    }

    fn input_for_tool(&self, id: &str, platform: ReleasePlatform) -> Option<&ExternalInput> {
        self.inputs.iter().find(|input| {
            input.id == id
                && matches!(input.kind.as_str(), "tool-version" | "cargo-package")
                && input.acquisition_phase == "native-platform"
                && (input.platforms.is_empty()
                    || input.platforms.iter().any(|value| value == platform.id()))
        })
    }
}

fn validate_external_input(
    id: &str,
    kind: &str,
    fields: &BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let required: &[&str] = match kind {
        "git-commit" => &["commit", "repository"],
        "https-file" => &[
            "expected-filename",
            "maximum-compressed-bytes",
            "maximum-expanded-bytes",
            "media-type",
            "sha256",
            "timeout-seconds",
        ],
        "tool-version" => &["version"],
        "cargo-package" => &["package", "version"],
        _ => return Err(format!("external input {id} has unsupported kind {kind}")),
    };
    if required.iter().any(|key| !fields.contains_key(*key)) {
        return Err(format!("external input {id} lacks kind-specific fields"));
    }
    if let Some(value) = fields.get("sha256") {
        require_digest(value.string()?, "external-input digest")?;
    }
    for key in [
        "maximum-compressed-bytes",
        "maximum-expanded-bytes",
        "timeout-seconds",
    ] {
        if fields
            .get(key)
            .is_some_and(|value| value.number().ok().is_some_and(|value| value == 0))
        {
            return Err(format!("external input {id} has a zero bound"));
        }
    }
    Ok(())
}

fn exact_receipt_inventory(root: &Path) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut inventory = BTreeMap::new();
    let entries = std::fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate native receipt root: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read native receipt entry: {error}"))?;
        let metadata = entry
            .file_type()
            .map_err(|error| format!("cannot inspect native receipt entry: {error}"))?;
        if !metadata.is_dir() || metadata.is_symlink() {
            return Err("native receipt root contains an unexpected non-directory".to_owned());
        }
        let platform = entry
            .file_name()
            .into_string()
            .map_err(|_| "native receipt platform name is not UTF-8".to_owned())?;
        ReleasePlatform::parse(&platform)?;
        let mut children = std::fs::read_dir(entry.path())
            .map_err(|error| format!("cannot enumerate native receipt platform: {error}"))?;
        let receipt = children
            .next()
            .transpose()
            .map_err(|error| format!("cannot read native receipt file: {error}"))?
            .ok_or_else(|| format!("native receipt directory {platform} is empty"))?;
        if children.next().is_some()
            || receipt.file_name() != OsStr::new("native-environment.json")
            || !receipt
                .file_type()
                .map_err(|error| format!("cannot inspect native receipt file: {error}"))?
                .is_file()
        {
            return Err(format!(
                "native receipt directory {platform} inventory differs"
            ));
        }
        inventory.insert(platform, receipt.path());
    }
    if inventory.len() != PLATFORMS.len() {
        return Err("native receipt platform inventory differs".to_owned());
    }
    Ok(inventory)
}

fn domain_digest(domain: &[u8], value: &JsonValue) -> Result<String, String> {
    Ok(domain_digest_bytes(domain, &canonical_json_bytes(value)?))
}

fn domain_digest_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut input = Vec::with_capacity(domain.len() + 1 + bytes.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(bytes);
    hell_testkit::sha256_bytes(&input).hex()
}

fn option_string(value: Option<&str>) -> JsonValue {
    value.map_or(JsonValue::Null, string)
}

fn bounded_message(value: &str) -> String {
    value.chars().take(4096).collect()
}

fn require_json_keys(
    values: &BTreeMap<String, JsonValue>,
    expected: &[&str],
) -> Result<(), String> {
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(format!("JSON key inventory differs: {observed:?}"));
    }
    Ok(())
}

#[derive(Default)]
struct Options {
    external_inputs: Option<PathBuf>,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    platform: Option<String>,
}

impl Options {
    fn parse(arguments: &[OsString]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            let flag = arguments[index]
                .to_str()
                .ok_or_else(|| "environment option name must be UTF-8".to_owned())?;
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            index += 1;
            match flag {
                "--external-inputs" => set_path(&mut options.external_inputs, value, flag)?,
                "--input" => set_path(&mut options.input, value, flag)?,
                "--output" => set_path(&mut options.output, value, flag)?,
                "--platform" => {
                    if options.platform.is_some() {
                        return Err(format!("{flag} was provided more than once"));
                    }
                    options.platform = Some(
                        value
                            .to_str()
                            .ok_or_else(|| "platform ID must be UTF-8".to_owned())?
                            .to_owned(),
                    );
                }
                _ => return Err(format!("unknown environment option {flag:?}")),
            }
        }
        Ok(options)
    }
}

fn set_path(target: &mut Option<PathBuf>, value: &OsString, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}

fn required_path(value: Option<PathBuf>, flag: &str) -> Result<PathBuf, String> {
    value.ok_or_else(|| format!("environment command requires {flag}"))
}

fn required_string(value: Option<String>, flag: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("environment command requires {flag}"))
}

fn usage() -> String {
    "usage: hell-ci environment collect --platform ID --external-inputs PATH --output PATH | assemble-set|verify-set --input PATH --external-inputs PATH --output PATH".to_owned()
}
