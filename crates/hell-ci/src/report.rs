use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::{CommandResult, CommandSpec};

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
    pub arguments: Vec<String>,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub struct Report {
    pub suite: String,
    pub steps: Vec<StepReport>,
    pub failures: Vec<String>,
}

impl Report {
    pub fn new(suite: impl Into<String>) -> Self {
        Self {
            suite: suite.into(),
            steps: Vec::new(),
            failures: Vec::new(),
        }
    }

    pub fn passed(&self) -> bool {
        self.failures.is_empty()
            && self
                .steps
                .iter()
                .all(|step| matches!(step.status, StepStatus::Passed))
    }

    pub fn has_failed_command(&self) -> bool {
        self.steps
            .iter()
            .any(|step| step.program.is_some() && matches!(step.status, StepStatus::Failed))
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
            arguments: spec.display_arguments(),
            detail: if result.stdout_truncated || result.stderr_truncated {
                Some("captured output was truncated to 1 MiB per stream".to_owned())
            } else {
                None
            },
        });
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
            arguments: Vec::new(),
            detail,
        });
    }

    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = temporary_sibling(path);
        fs::write(&temporary, self.to_json())?;
        fs::rename(temporary, path)
    }

    fn to_json(&self) -> String {
        let mut json = String::from("{\n  \"schemaVersion\": 1,\n  \"suite\": ");
        push_json_string(&mut json, &self.suite);
        json.push_str(",\n  \"passed\": ");
        json.push_str(if self.passed() { "true" } else { "false" });
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
}
