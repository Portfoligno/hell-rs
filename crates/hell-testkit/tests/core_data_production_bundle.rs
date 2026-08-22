#![cfg(feature = "compat-tracing")]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hell_testkit::{
    BoundedCapture, DifferentialCase, DifferentialComparisonProjection, DifferentialMode,
    DifferentialReport, EnvironmentProfile, ExecutableIdentity, ExecutableRole, LogicalTraceEvent,
    NormalizerId, Observation, ProcessStatus, ResourceAudit,
};

#[derive(Clone, Default)]
struct SharedOutput(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for SharedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("shared output mutex was poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl SharedOutput {
    fn bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

fn observation(role: ExecutableRole) -> Observation {
    Observation {
        identity: ExecutableIdentity {
            path: PathBuf::from(match role {
                ExecutableRole::Oracle => "oracle-hell",
                ExecutableRole::Candidate => "candidate-hell",
            }),
            sha256: hell_testkit::sha256_bytes(match role {
                ExecutableRole::Oracle => b"oracle",
                ExecutableRole::Candidate => b"candidate",
            }),
            reported_version: "2026-05-29".into(),
            build_info: None,
            role,
            assurance_epoch_sha256: Some(hell_testkit::sha256_bytes(b"epoch")),
            acquisition_receipt_id: (role == ExecutableRole::Oracle)
                .then(|| Arc::from("github-release:17:23")),
            acquisition_receipt_sha256: (role == ExecutableRole::Oracle)
                .then(|| hell_testkit::sha256_bytes(b"acquisition")),
            acquisition_attestation_sha256: (role == ExecutableRole::Oracle)
                .then(|| hell_testkit::sha256_bytes(b"acquisition-attestation")),
        },
        case_id: "layout".into(),
        environment_profile: EnvironmentProfile::Explicit,
        process_helper_sha256: None,
        mode: DifferentialMode::Run,
        status: ProcessStatus {
            success: true,
            code: Some(0),
        },
        stdout: BoundedCapture::from_bytes(b"ok\n".to_vec()),
        raw_stderr: BoundedCapture::from_bytes(Vec::new()),
        claim_input_stderr: BoundedCapture::from_bytes(Vec::new()),
        stderr: BoundedCapture::from_bytes(Vec::new()),
        normalizer_sandbox: PathBuf::from("sandbox"),
        normalizer_script: PathBuf::from("sandbox").join("main.hell"),
        timed_out: false,
        diagnostic: None,
        filesystem: Vec::new(),
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        resource_audit: (role == ExecutableRole::Candidate).then(ResourceAudit::default),
        semantic: None,
    }
}

fn report() -> DifferentialReport {
    DifferentialReport {
        oracle: observation(ExecutableRole::Oracle),
        candidate: observation(ExecutableRole::Candidate),
        comparison_projection: DifferentialComparisonProjection::Exact,
        mismatches: Vec::new(),
    }
}

fn typed_result_target(
    case: &DifferentialCase,
) -> std::io::Result<Option<(hell_builtins::BuiltinId, Option<Arc<str>>)>> {
    let targets = case
        .claim_evidence
        .iter()
        .flat_map(|descriptor| &descriptor.semantic_targets)
        .filter(|target| {
            target.expected_typed_result_sha256.is_some()
                || target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "typed-result")
        })
        .map(|target| {
            hell_builtins::lookup(&target.builtin)
                .map(|spec| (spec.id, target.expected_instance_target.clone()))
                .ok_or_else(|| std::io::Error::other("typed-result target is not registry-backed"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let Some(first) = targets.first().cloned() else {
        return Ok(None);
    };
    if targets.iter().all(|target| *target == first) {
        Ok(Some(first))
    } else {
        Err(std::io::Error::other(
            "one evidence case cannot retain multiple typed-result targets",
        ))
    }
}

fn runtime_arguments(case: &DifferentialCase) -> Vec<Arc<str>> {
    if case.environment_profile == EnvironmentProfile::ProcessCapable {
        let helper = case
            .process_helper_directory
            .as_ref()
            .expect("process-capable case has a helper directory")
            .join(format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX));
        return vec![Arc::from(helper.to_str().expect("helper path is UTF-8"))];
    }
    case.arguments
        .iter()
        .map(|argument| Arc::from(argument.to_str().expect("committed argument is UTF-8")))
        .collect()
}

fn runtime_environment(case: &DifferentialCase) -> Vec<(Arc<str>, Arc<str>)> {
    case.environment
        .iter()
        .map(|(name, value)| {
            (
                Arc::from(name.to_str().expect("committed environment name is UTF-8")),
                Arc::from(
                    value
                        .to_str()
                        .expect("committed environment value is UTF-8"),
                ),
            )
        })
        .collect()
}

fn execute(
    case: &DifferentialCase,
    root: &Path,
    compiler: &mut hell_compiler::CompilerSession,
) -> std::io::Result<(bool, DifferentialReport)> {
    let profile = case
        .claim_evidence
        .as_ref()
        .map_or(hell_builtins::ExecutionProfile::Upstream, |descriptor| {
            descriptor.profile
        });
    let program =
        hell_compiler::compile_source(compiler, case.id.to_string(), case.source.to_string())
            .map_err(|error| {
                std::io::Error::other(format!("{} did not compile: {error:?}", case.id))
            })?;
    let trace = root.join(format!("{}.json", case.id));
    let stdout = SharedOutput::default();
    let stderr = SharedOutput::default();
    let mut context = hell_runtime::RuntimeContext::with_host_capabilities(
        runtime_arguments(case),
        runtime_environment(case),
        stdout.clone(),
        root.to_path_buf(),
        true,
        true,
    );
    if profile == hell_builtins::ExecutionProfile::Sandboxed {
        context = context.with_policy(hell_runtime::policy::RuntimePolicy::sandboxed());
    }
    let context = context
        .with_stdin(std::io::Cursor::new(case.stdin.clone()))
        .with_stderr(stderr.clone());
    let outcome = match typed_result_target(case)? {
        Some((builtin, Some(instance))) => {
            hell_runtime::run_main_with_semantic_trace_target_instance(
                program, context, &trace, builtin, instance,
            )
        }
        Some((builtin, None)) => {
            hell_runtime::run_main_with_semantic_trace_target(program, context, &trace, builtin)
        }
        None => hell_runtime::run_main_with_semantic_trace(program, context, &trace),
    };
    if let Err(error) = &outcome
        && !matches!(error.kind, hell_runtime::RuntimeErrorKind::Exit(_))
    {
        let mut retained_stderr = stderr.clone();
        retained_stderr.write_all(format!("{error}\n").as_bytes())?;
    }
    let status = match &outcome {
        Ok(()) => ProcessStatus {
            success: true,
            code: Some(0),
        },
        Err(error) => match error.kind {
            hell_runtime::RuntimeErrorKind::Exit(code) => ProcessStatus {
                success: code == 0,
                code: Some(code),
            },
            _ => ProcessStatus {
                success: false,
                code: Some(1),
            },
        },
    };
    let semantic = hell_testkit::parse_semantic_trace(&std::fs::read(&trace)?)?;
    if case.id.ends_with("http-stream-disconnect") {
        let http_run = hell_builtins::lookup("Http.run")
            .expect("HTTP interaction target")
            .id;
        assert!(semantic.task_trace.iter().any(|event| matches!(
            event,
            LogicalTraceEvent::TaskEvent { event, .. } if event.as_ref() == "cancelled"
        )));
        assert!(semantic.effect_trace.iter().any(|event| matches!(
            event,
            LogicalTraceEvent::HostEffect { builtin, effect, .. }
                if *builtin == http_run && effect.as_ref() == "completed"
        )));
        assert!(!semantic.effect_trace.iter().any(|event| matches!(
            event,
            LogicalTraceEvent::HostEffect { builtin, effect, .. }
                if *builtin == http_run && effect.as_ref() == "failed"
        )));
    }
    let stdout = stdout.bytes();
    let stderr = stderr.bytes();
    let mut retained = report();
    for observation in [&mut retained.oracle, &mut retained.candidate] {
        observation.case_id = Arc::clone(&case.id);
        observation.environment_profile = case.environment_profile;
        observation.process_helper_sha256 = case.process_helper_sha256;
        observation.stdout = BoundedCapture::from_bytes(stdout.clone());
        observation.raw_stderr = BoundedCapture::from_bytes(stderr.clone());
        observation.claim_input_stderr = BoundedCapture::from_bytes(stderr.clone());
        observation.stderr = BoundedCapture::from_bytes(stderr.clone());
        observation.status = status.clone();
    }
    retained.candidate.semantic = Some(semantic);
    Ok((outcome.is_ok(), retained))
}

#[test]
fn core_data_obligations_round_trip_through_the_production_bundle_gate() {
    let helper = Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    let mut cases = hell_testkit::committed_differential_cases()
        .into_iter()
        .filter(|case| {
            case.claim_evidence
                .as_ref()
                .is_some_and(|descriptor| !descriptor.semantic_targets.is_empty())
        })
        .collect::<Vec<_>>();
    hell_testkit::bind_process_helper_directory(
        &mut cases,
        helper.parent().expect("test helper directory"),
    )
    .expect("bind process test helper");
    hell_testkit::run_core_data_production_bundle_gate(&cases, || {
        let mut upstream = hell_compiler::CompilerSession::upstream();
        let mut sandboxed = hell_compiler::CompilerSession::default();
        move |case: &DifferentialCase, root: &Path| {
            let profile = case
                .claim_evidence
                .as_ref()
                .map_or(hell_builtins::ExecutionProfile::Upstream, |descriptor| {
                    descriptor.profile
                });
            let compiler = match profile {
                hell_builtins::ExecutionProfile::Upstream => &mut upstream,
                hell_builtins::ExecutionProfile::Sandboxed => &mut sandboxed,
            };
            execute(case, root, compiler)
        }
    })
    .expect("all committed core-data obligations pass the production bundle gate");
}
