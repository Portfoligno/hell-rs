use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::release::manifest::{write_atomic, write_atomic_new};
use hell_memcordon::{
    CandidateBoundaryPolicy, NativeArgument, OperationGroupV2, OperationLedgerEntryV1,
    OperationLedgerV2, SealedTerminal,
};

#[derive(Debug)]
struct Reservation {
    id: String,
    request_digest: String,
    completed: Option<OperationLedgerEntryV1>,
}

#[derive(Debug, Default)]
struct State {
    reservations: Vec<Reservation>,
    phases: Vec<String>,
    sealed: bool,
}

#[derive(Debug)]
pub struct ExecutionCollector {
    root: PathBuf,
    operation: String,
    plan_digest: String,
    boundary: CandidateBoundaryPolicy,
    state: Mutex<State>,
}

impl ExecutionCollector {
    pub fn new(
        root: PathBuf,
        operation: &str,
        plan_digest: &str,
        boundary: CandidateBoundaryPolicy,
    ) -> Result<Self, String> {
        if !matches!(operation, "readiness" | "release") || !root.is_absolute() {
            return Err("platform execution collector requires an exact logical task and absolute authority".to_owned());
        }
        for name in ["operations.json", "invocation-reservations.json"] {
            match std::fs::symlink_metadata(root.join(name)) {
                Ok(_) => {
                    return Err(
                        "platform execution accounting is not a fresh reservation".to_owned()
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(Self {
            root,
            operation: operation.to_owned(),
            plan_digest: plan_digest.to_owned(),
            boundary,
            state: Mutex::new(State::default()),
        })
    }

    fn journal(&self, state: &State) -> Result<Vec<u8>, String> {
        json_bytes(&serde_json::json!({
            "schema_version": 1, "operation_id": self.operation,
            "invocations": state.reservations.iter().map(|reservation| serde_json::json!({
                "invocation_id": reservation.id, "request_digest": reservation.request_digest,
            })).collect::<Vec<_>>(),
        }))
    }

    pub fn complete_phase(&self, phase: &str) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "execution collector lock poisoned")?;
        if state.sealed
            || hell_memcordon::OPERATION_GROUP_PHASES_V2
                .get(state.phases.len())
                .copied()
                != Some(phase)
        {
            return Err(
                "platform execution phases completed out of their typed plan order".to_owned(),
            );
        }
        state.phases.push(phase.to_owned());
        Ok(())
    }

    pub fn seal(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "execution collector lock poisoned")?;
        if state.sealed
            || state.reservations.is_empty()
            || state
                .reservations
                .iter()
                .any(|reservation| reservation.completed.is_none())
        {
            return Err(
                "platform group has no complete authenticated invocation coverage".to_owned(),
            );
        }
        let journal = self.journal(&state)?;
        if std::fs::read(self.root.join("invocation-reservations.json"))
            .map_err(|error| error.to_string())?
            != journal
        {
            return Err("platform reservation journal changed before group sealing".to_owned());
        }
        let ledger = OperationLedgerV2 {
            schema_version: 2,
            groups: vec![OperationGroupV2 {
                operation_id: self.operation.clone(),
                platform_plan_digest: self.plan_digest.clone(),
                required_phases: hell_memcordon::OPERATION_GROUP_PHASES_V2
                    .iter()
                    .map(|phase| (*phase).to_owned())
                    .collect(),
                completed_phases: state.phases.clone(),
                reserved_invocation_ids: state
                    .reservations
                    .iter()
                    .map(|reservation| reservation.id.clone())
                    .collect(),
                invocations: state
                    .reservations
                    .iter()
                    .map(|reservation| {
                        reservation
                            .completed
                            .clone()
                            .expect("checked complete reservation")
                    })
                    .collect(),
                reservation_ledger_path: "invocation-reservations.json".to_owned(),
                reservation_ledger_digest: hell_testkit::sha256_bytes(&journal).hex(),
                sealed: true,
            }],
        };
        let bytes =
            hell_memcordon::operation_ledger_v2_json(&ledger).map_err(|error| error.to_string())?;
        write_atomic_new(&self.root.join("operations.json"), &bytes)?;
        state.sealed = true;
        Ok(())
    }
}

impl hell_testkit::SealedExecutionObserver for ExecutionCollector {
    fn rejected(
        &self,
        id: &str,
        report: &Path,
        stdout: &hell_testkit::BoundedCapture,
        stderr: &hell_testkit::BoundedCapture,
        detail: &str,
    ) -> std::io::Result<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("execution collector lock poisoned"))?;
        if !state
            .reservations
            .iter()
            .any(|reservation| reservation.id == id)
            || !report.starts_with(self.root.join("raw"))
        {
            return Err(std::io::Error::other(
                "rejected completion differs from task reservation",
            ));
        }
        let directory = self.root.join("operations").join(id);
        write_atomic_new(&directory.join("stdout"), &stdout.retained_bytes())
            .map_err(std::io::Error::other)?;
        write_atomic_new(&directory.join("stderr"), &stderr.retained_bytes())
            .map_err(std::io::Error::other)?;
        let bytes = json_bytes(&serde_json::json!({"admitted":false,"invocation_id":id,"raw_report":report,"failure":detail})).map_err(std::io::Error::other)?;
        write_atomic_new(&directory.join("rejected.json"), &bytes).map_err(std::io::Error::other)
    }
    fn reserve(&self, argv: &[NativeArgument]) -> std::io::Result<String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("execution collector lock poisoned"))?;
        if state.sealed {
            return Err(std::io::Error::other(
                "cannot reserve an invocation in a sealed group",
            ));
        }
        let id = format!(
            "{}-invocation-{:08}",
            self.operation,
            state.reservations.len()
        );
        let request = serde_json::to_vec(argv).map_err(std::io::Error::other)?;
        state.reservations.push(Reservation {
            id: id.clone(),
            request_digest: hell_testkit::sha256_bytes(&request).hex(),
            completed: None,
        });
        write_atomic(
            &self.root.join("invocation-reservations.json"),
            &self.journal(&state).map_err(std::io::Error::other)?,
        )
        .map_err(std::io::Error::other)?;
        Ok(id)
    }

    fn completed(
        &self,
        id: &str,
        output: &mut hell_testkit::SupervisedOutput,
        identity: Option<&hell_memcordon::WindowsCandidateIdentityReceiptV1>,
    ) -> std::io::Result<()> {
        self.retain_completion(id, output, identity)
            .map_err(std::io::Error::other)
    }
}

impl ExecutionCollector {
    fn retain_completion(
        &self,
        id: &str,
        output: &mut hell_testkit::SupervisedOutput,
        identity: Option<&hell_memcordon::WindowsCandidateIdentityReceiptV1>,
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "execution collector lock poisoned")?;
        let reservation = state
            .reservations
            .iter_mut()
            .find(|reservation| reservation.id == id)
            .ok_or("unreserved sealed completion")?;
        if reservation.completed.is_some() {
            return Err("sealed invocation completed twice".to_owned());
        }
        let projection = output
            .memcordon_projection
            .as_ref()
            .ok_or("authenticated sealed projection is absent")?;
        let request =
            serde_json::to_vec(&projection.target_argv).map_err(|error| error.to_string())?;
        if hell_testkit::sha256_bytes(&request).hex() != reservation.request_digest {
            return Err("sealed completion differs from its reserved argv".to_owned());
        }
        let source = output
            .memcordon_report_path
            .as_ref()
            .ok_or("authenticated raw report is absent")?;
        if !source.starts_with(self.root.join("raw")) {
            return Err("authenticated report escaped task-owned raw authority".to_owned());
        }
        let raw = crate::release::manifest::read_regular(source)?;
        let raw_digest = hell_testkit::sha256_bytes(&raw);
        if output.memcordon_report_sha256 != Some(raw_digest) {
            return Err("authenticated raw report digest changed".to_owned());
        }
        let actual = hell_memcordon::project_schema8_report(
            &raw,
            &projection.mechanism,
            &projection.target_argv,
        )
        .map_err(|error| error.to_string())?;
        if actual != *projection {
            return Err("authenticated report projection changed".to_owned());
        }
        let raw_relative = format!("raw/{id}.json");
        write_atomic_new(&self.root.join(&raw_relative), &raw)?;
        let normalized_relative = format!("normalized/{id}.json");
        let normalized = json_bytes(projection)?;
        write_atomic_new(&self.root.join(&normalized_relative), &normalized)?;
        let (adapter_path, adapter_digest) = if let Some(identity) = identity {
            identity.validate().map_err(|error| error.to_string())?;
            if identity.operation_id != id {
                return Err("Windows identity belongs to another invocation".to_owned());
            }
            let relative = format!("adapters/{id}.json");
            let bytes = json_bytes(identity)?;
            write_atomic_new(&self.root.join(&relative), &bytes)?;
            (
                Some(relative),
                Some(hell_testkit::sha256_bytes(&bytes).hex()),
            )
        } else {
            (None, None)
        };
        let terminal = match projection.terminal {
            hell_memcordon::Schema8TerminalV1::InnerDeadline => SealedTerminal::InnerDeadline,
            _ => SealedTerminal::OrdinaryResult,
        };
        let entry = OperationLedgerEntryV1 {
            operation_id: id.to_owned(),
            boundary: self.boundary,
            request_digest: reservation.request_digest.clone(),
            raw_report_path: Some(raw_relative.clone()),
            raw_report_digest: Some(raw_digest.hex()),
            normalized_report_path: Some(normalized_relative),
            normalized_report_digest: Some(hell_testkit::sha256_bytes(&normalized).hex()),
            identity_adapter_path: adapter_path,
            identity_adapter_digest: adapter_digest,
            terminal,
        };
        entry.validate().map_err(|error| error.to_string())?;
        let streams = self.root.join("operations").join(id);
        write_atomic_new(&streams.join("stdout"), &output.stdout.retained_bytes())?;
        write_atomic_new(&streams.join("stderr"), &output.stderr.retained_bytes())?;
        std::fs::remove_file(source)
            .map_err(|error| format!("cannot retire retained raw reservation: {error}"))?;
        output.memcordon_report_path = Some(self.root.join(raw_relative));
        reservation.completed = Some(entry);
        Ok(())
    }
}

fn json_bytes(value: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}
