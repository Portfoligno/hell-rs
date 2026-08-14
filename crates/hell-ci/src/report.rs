use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::{CommandResult, CommandRunError, CommandSpec};
use crate::json::{JsonValue, canonical_json_bytes};

#[derive(Clone, Debug)]
pub enum StepStatus {
    Passed,
    Failed,
}

#[derive(Clone, Debug)]
pub struct StepReport {
    pub name: String,
    pub status: StepStatus,
    pub duration: Duration,
    pub program: Option<String>,
    pub invocation_name: Option<String>,
    pub canonical_executable_identity: Option<String>,
    pub arguments: Vec<String>,
    pub detail: Option<String>,
    pub command_error: Option<CommandErrorReport>,
}

#[derive(Clone, Debug)]
pub struct CommandErrorReport {
    pub stage: &'static str,
    pub phase: &'static str,
    pub kind: String,
    pub raw_os_error: Option<i32>,
    pub message: String,
    pub completed_child: Option<CompletedCommandReport>,
}

#[derive(Clone, Debug)]
pub struct CompletedCommandReport {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout_bytes: u64,
    pub stdout_sha256: String,
    pub stderr_bytes: u64,
    pub stderr_sha256: String,
}

#[derive(Debug)]
pub struct Report {
    pub suite: String,
    pub steps: Vec<StepReport>,
    pub failures: Vec<String>,
    evidence: Vec<(String, JsonValue)>,
    authoritative: bool,
}

impl Report {
    pub fn new(suite: impl Into<String>) -> Self {
        Self {
            suite: suite.into(),
            steps: Vec::new(),
            failures: Vec::new(),
            evidence: Vec::new(),
            authoritative: true,
        }
    }

    pub fn mark_non_authoritative(&mut self) {
        self.authoritative = false;
    }

    pub fn passed(&self) -> bool {
        self.failures.is_empty()
            && self
                .steps
                .iter()
                .all(|step| matches!(step.status, StepStatus::Passed))
    }

    pub fn command(&mut self, name: impl Into<String>, spec: &CommandSpec, result: &CommandResult) {
        let passed = result.status.success() && !result.timed_out;
        let name = name.into();
        if !passed {
            self.failures.push(format!(
                "{name}: status {:?}, timed out: {}",
                result.status.code(),
                result.timed_out
            ));
        }
        self.steps.push(StepReport {
            name,
            status: if passed {
                StepStatus::Passed
            } else {
                StepStatus::Failed
            },
            duration: result.duration,
            program: Some(spec.display_program()),
            invocation_name: spec.display_invocation_name(),
            canonical_executable_identity: spec.display_canonical_executable_identity(),
            arguments: spec.display_arguments(),
            detail: if result.stdout_truncated || result.stderr_truncated {
                Some(format!(
                    "bounded capture: stdout={} bytes sha256={}, stderr={} bytes sha256={}",
                    result.stdout_bytes,
                    result.stdout_sha256.hex(),
                    result.stderr_bytes,
                    result.stderr_sha256.hex()
                ))
            } else {
                None
            },
            command_error: None,
        });
    }

    pub fn command_error(
        &mut self,
        name: impl Into<String>,
        spec: &CommandSpec,
        duration: Duration,
        error: &CommandRunError,
    ) {
        let name = name.into();
        let completed_child = error.completed().map(|result| CompletedCommandReport {
            success: result.status.success(),
            exit_code: result.status.code(),
            timed_out: result.timed_out,
            stdout_bytes: result.stdout_bytes,
            stdout_sha256: result.stdout_sha256.hex(),
            stderr_bytes: result.stderr_bytes,
            stderr_sha256: result.stderr_sha256.hex(),
        });
        let error = CommandErrorReport {
            stage: "command-run",
            phase: error.phase().as_str(),
            kind: format!("{:?}", error.kind()),
            raw_os_error: error.raw_os_error(),
            message: bounded_command_error_message(&error.message()),
            completed_child,
        };
        self.failures.push(format!(
            "{name}: command error {}: {}",
            error.kind, error.message
        ));
        self.steps.push(StepReport {
            name,
            status: StepStatus::Failed,
            duration,
            program: Some(spec.display_program()),
            invocation_name: spec.display_invocation_name(),
            canonical_executable_identity: spec.display_canonical_executable_identity(),
            arguments: spec.display_arguments(),
            detail: None,
            command_error: Some(error),
        });
    }

    pub fn run_command(
        &mut self,
        name: impl Into<String>,
        spec: &CommandSpec,
    ) -> Result<CommandResult, CommandRunError> {
        let name = name.into();
        let started = std::time::Instant::now();
        match spec.run() {
            Ok(result) => {
                self.command(name, spec, &result);
                Ok(result)
            }
            Err(error) => {
                self.command_error(name, spec, started.elapsed(), &error);
                Err(error)
            }
        }
    }

    pub fn check(
        &mut self,
        name: impl Into<String>,
        duration: Duration,
        result: Result<(), String>,
    ) {
        let name = name.into();
        let (status, detail) = match result {
            Ok(()) => (StepStatus::Passed, None),
            Err(detail) => {
                self.failures.push(format!("{name}: {detail}"));
                (StepStatus::Failed, Some(detail))
            }
        };
        self.steps.push(StepReport {
            name,
            status,
            duration,
            program: None,
            invocation_name: None,
            canonical_executable_identity: None,
            arguments: Vec::new(),
            detail,
            command_error: None,
        });
    }

    /// Retains non-authoritative timing/diagnostic telemetry as a passing
    /// report step. Measurements never decide suite status.
    pub fn measurement(
        &mut self,
        name: impl Into<String>,
        duration: Duration,
        detail: impl Into<String>,
    ) {
        self.steps.push(StepReport {
            name: name.into(),
            status: StepStatus::Passed,
            duration,
            program: None,
            invocation_name: None,
            canonical_executable_identity: None,
            arguments: Vec::new(),
            detail: Some(detail.into()),
            command_error: None,
        });
    }

    /// Retains typed deterministic evidence independently from step status.
    ///
    /// Evidence is serialized even when a later gate fails, so failure reports
    /// remain self-contained and auditable.
    pub(crate) fn evidence(&mut self, name: impl Into<String>, value: JsonValue) {
        self.evidence.push((name.into(), value));
    }

    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = temporary_sibling(path);
        fs::write(&temporary, self.to_json())?;
        fs::rename(temporary, path)
    }

    pub(crate) fn to_json(&self) -> String {
        let mut json = String::from("{\n  \"schemaVersion\": 1,\n  \"suite\": ");
        push_json_string(&mut json, &self.suite);
        json.push_str(",\n  \"passed\": ");
        json.push_str(if self.passed() { "true" } else { "false" });
        if !self.authoritative {
            json.push_str(",\n  \"authoritative\": false");
        }
        json.push_str(",\n  \"steps\": [");
        for (index, step) in self.steps.iter().enumerate() {
            if index != 0 {
                json.push(',');
            }
            json.push_str("\n    {\"name\": ");
            push_json_string(&mut json, &step.name);
            json.push_str(", \"status\": ");
            push_json_string(
                &mut json,
                match step.status {
                    StepStatus::Passed => "passed",
                    StepStatus::Failed => "failed",
                },
            );
            json.push_str(", \"durationMillis\": ");
            json.push_str(&step.duration.as_millis().to_string());
            if let Some(program) = &step.program {
                json.push_str(", \"command\": {\"program\": ");
                push_json_string(&mut json, program);
                if let Some(invocation_name) = &step.invocation_name {
                    json.push_str(", \"invocationName\": ");
                    push_json_string(&mut json, invocation_name);
                }
                if let Some(identity) = &step.canonical_executable_identity {
                    json.push_str(", \"canonicalExecutableIdentity\": ");
                    push_json_string(&mut json, identity);
                }
                json.push_str(", \"arguments\": [");
                for (argument_index, argument) in step.arguments.iter().enumerate() {
                    if argument_index != 0 {
                        json.push_str(", ");
                    }
                    push_json_string(&mut json, argument);
                }
                json.push_str("]}");
            }
            if let Some(detail) = &step.detail {
                json.push_str(", \"detail\": ");
                push_json_string(&mut json, detail);
            }
            if let Some(error) = &step.command_error {
                json.push_str(", \"error\": {\"stage\": ");
                push_json_string(&mut json, error.stage);
                json.push_str(", \"phase\": ");
                push_json_string(&mut json, error.phase);
                json.push_str(", \"kind\": ");
                push_json_string(&mut json, &error.kind);
                json.push_str(", \"rawOsError\": ");
                match error.raw_os_error {
                    Some(code) => json.push_str(&code.to_string()),
                    None => json.push_str("null"),
                }
                json.push_str(", \"message\": ");
                push_json_string(&mut json, &error.message);
                if let Some(child) = &error.completed_child {
                    json.push_str(", \"completedChild\": {\"success\": ");
                    json.push_str(if child.success { "true" } else { "false" });
                    json.push_str(", \"exitCode\": ");
                    match child.exit_code {
                        Some(code) => json.push_str(&code.to_string()),
                        None => json.push_str("null"),
                    }
                    json.push_str(", \"timedOut\": ");
                    json.push_str(if child.timed_out { "true" } else { "false" });
                    json.push_str(", \"stdoutBytes\": ");
                    json.push_str(&child.stdout_bytes.to_string());
                    json.push_str(", \"stdoutSha256\": ");
                    push_json_string(&mut json, &child.stdout_sha256);
                    json.push_str(", \"stderrBytes\": ");
                    json.push_str(&child.stderr_bytes.to_string());
                    json.push_str(", \"stderrSha256\": ");
                    push_json_string(&mut json, &child.stderr_sha256);
                    json.push('}');
                }
                json.push('}');
            }
            json.push('}');
        }
        json.push_str("\n  ],\n  \"evidence\": [");
        for (index, (name, value)) in self.evidence.iter().enumerate() {
            if index != 0 {
                json.push(',');
            }
            json.push_str("\n    {\"name\": ");
            push_json_string(&mut json, name);
            json.push_str(", \"value\": ");
            let encoded = canonical_json_bytes(value)
                .expect("report evidence JSON serialization cannot fail");
            let encoded =
                std::str::from_utf8(&encoded).expect("report evidence JSON serialization is UTF-8");
            json.push_str(encoded.trim_end_matches('\n'));
            json.push('}');
        }
        json.push_str("\n  ],\n  \"failures\": [");
        for (index, failure) in self.failures.iter().enumerate() {
            if index != 0 {
                json.push_str(", ");
            }
            push_json_string(&mut json, failure);
        }
        json.push_str("]\n}\n");
        json
    }
}

fn bounded_command_error_message(message: &str) -> String {
    const LIMIT: usize = 512;
    message.chars().take(LIMIT).collect()
}

fn temporary_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                output.push_str("\\u");
                write!(output, "{:04x}", u32::from(value)).expect("writing to String cannot fail");
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_encoder_escapes_control_characters() {
        let mut encoded = String::new();
        push_json_string(&mut encoded, "quote \" slash \\ line\n\u{1}");
        assert_eq!(encoded, "\"quote \\\" slash \\\\ line\\n\\u0001\"");
    }

    #[test]
    fn diagnostic_report_is_explicitly_non_authoritative() {
        let mut report = Report::new("diagnostic");
        report.mark_non_authoritative();
        report.measurement("timing", Duration::ZERO, "measurement only");
        let json = report.to_json();
        assert!(json.contains("\"authoritative\": false"));
        assert!(json.contains("\"passed\": true"));
    }

    #[test]
    fn typed_evidence_survives_a_later_failed_step() {
        let mut report = Report::new("authoritative");
        report.evidence(
            "identity",
            JsonValue::Object(std::collections::BTreeMap::from([
                ("role".to_owned(), JsonValue::String("oracle".to_owned())),
                ("sizeBytes".to_owned(), JsonValue::Number(123)),
            ])),
        );
        report.check("differential", Duration::ZERO, Err("mismatch".to_owned()));
        let json = report.to_json();
        assert!(json.contains("\"passed\": false"));
        assert!(json.contains(
            "\"evidence\": [\n    {\"name\": \"identity\", \"value\": {\"role\":\"oracle\",\"sizeBytes\":123}}"
        ));
        assert!(json.contains("\"failures\": [\"differential: mismatch\"]"));
    }

    #[test]
    fn missing_command_records_typed_stage_argv_and_io_error() {
        let missing =
            std::env::temp_dir().join(format!("hell-ci-missing-command-{}", std::process::id()));
        let spec = CommandSpec::new(missing.as_os_str(), Duration::from_secs(1))
            .arguments(["test", "--locked"]);
        let mut report = Report::new("diagnostic");
        let error = report
            .run_command("workspace-tests", &spec)
            .expect_err("missing command must fail");
        assert_eq!(error.phase().as_str(), "supervised-execution");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!report.passed());
        let step = report.steps.last().expect("failed command step");
        assert_eq!(step.name, "workspace-tests");
        assert_eq!(step.program.as_deref(), Some(&*missing.to_string_lossy()));
        assert_eq!(step.arguments, ["test", "--locked"]);
        let retained = step.command_error.as_ref().expect("typed command error");
        assert_eq!(retained.stage, "command-run");
        assert_eq!(retained.phase, "supervised-execution");
        assert_eq!(retained.kind, "NotFound");
        assert!(retained.message.chars().count() <= 512);
        assert!(retained.completed_child.is_none());
        let json = report.to_json();
        assert!(json.contains("\"command\": {\"program\":"));
        assert!(json.contains("\"arguments\": [\"test\", \"--locked\"]"));
        assert!(json.contains(
            "\"error\": {\"stage\": \"command-run\", \"phase\": \"supervised-execution\", \"kind\": \"NotFound\", \"rawOsError\":"
        ));
        assert!(json.contains("\"passed\": false"));
        assert_eq!(bounded_command_error_message(&"x".repeat(600)).len(), 512);
    }

    #[test]
    fn cargo_resolution_failure_is_a_failed_typed_command_step() {
        let spec = CommandSpec::cargo_resolution_failure(
            Duration::from_secs(1),
            "CARGO does not name an executable file",
        )
        .arguments(["test", "--locked"]);
        let mut report = Report::new("diagnostic");
        let error = report
            .run_command("workspace-tests", &spec)
            .expect_err("Cargo resolution must fail closed");
        assert_eq!(error.phase().as_str(), "program-resolution");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!report.passed());
        let step = report.steps.last().expect("failed command step");
        assert_eq!(step.program.as_deref(), Some("cargo"));
        assert_eq!(step.invocation_name.as_deref(), Some("cargo"));
        assert!(step.canonical_executable_identity.is_none());
        assert_eq!(step.arguments, ["test", "--locked"]);
        let retained = step.command_error.as_ref().expect("typed command error");
        assert_eq!(retained.stage, "command-run");
        assert_eq!(retained.phase, "program-resolution");
        assert_eq!(retained.kind, "NotFound");
        assert_eq!(retained.raw_os_error, None);
        assert!(
            retained
                .message
                .contains("CARGO does not name an executable file")
        );
        assert!(retained.completed_child.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn resolved_cargo_report_binds_the_canonical_program_and_exact_argv() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = std::env::temp_dir().join(format!(
            "hell-ci-resolved-cargo-report-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let executable = root.join("rustup");
        std::fs::write(
            &executable,
            b"#!/bin/sh\ncase \"$0\" in */cargo) exit 0 ;; *) exit 91 ;; esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let invocation = root.join("cargo");
        symlink(&executable, &invocation).unwrap();
        let canonical = std::fs::canonicalize(&executable).unwrap();
        let spec = CommandSpec::cargo_resolution_success(
            Duration::from_secs(1),
            invocation.clone(),
            canonical.clone(),
        )
        .arguments(["test", "--workspace", "--locked"]);
        let mut report = Report::new("diagnostic");
        let result = report
            .run_command("workspace-tests", &spec)
            .expect("resolved Cargo proxy must run");
        assert!(result.status.success());
        let step = report.steps.last().expect("successful command step");
        assert_eq!(
            step.program.as_deref(),
            Some(&*invocation.to_string_lossy())
        );
        assert_eq!(step.invocation_name.as_deref(), Some("cargo"));
        assert_eq!(
            step.canonical_executable_identity.as_deref(),
            Some(&*canonical.to_string_lossy())
        );
        assert_eq!(step.arguments, ["test", "--workspace", "--locked"]);
        assert!(step.command_error.is_none());
        assert!(report.passed());
        let json = report.to_json();
        assert!(json.contains("\"invocationName\": \"cargo\""));
        assert!(json.contains("\"canonicalExecutableIdentity\":"));
        std::fs::remove_dir_all(root).unwrap();
    }
}
