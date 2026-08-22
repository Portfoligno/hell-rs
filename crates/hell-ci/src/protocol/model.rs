use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub(super) struct Manifest {
    pub sha256: String,
    pub action_metadata: PathBuf,
    pub merge_queue: bool,
    pub readiness: ReadinessSummary,
    pub workflows: BTreeMap<String, Workflow>,
    pub actions: BTreeMap<String, Action>,
    pub permissions: BTreeMap<String, Permission>,
    pub commands: BTreeMap<String, Invocation>,
}

#[derive(Clone, Debug)]
pub(super) struct ReadinessSummary {
    pub jobs: Vec<String>,
    pub artifacts: Vec<ReadinessArtifact>,
}

#[derive(Clone, Debug)]
pub(super) struct ReadinessArtifact {
    pub job: String,
    pub platform_id: Option<String>,
    pub input_path: String,
    pub artifact_id_output: String,
    pub artifact_digest_output: String,
}

#[derive(Clone, Debug)]
pub(super) struct Workflow {
    pub id: String,
    pub path: PathBuf,
    pub name: String,
    pub jobs: Vec<String>,
    pub trigger: Trigger,
    pub concurrency: Concurrency,
    pub physical: PhysicalWorkflow,
    pub job_specs: BTreeMap<String, Job>,
}

#[derive(Clone, Debug)]
pub(super) struct PhysicalWorkflow {
    pub run_name: Option<String>,
    pub permission: String,
    pub dispatch_inputs: Vec<DispatchInput>,
}

#[derive(Clone, Debug)]
pub(super) struct DispatchInput {
    pub id: String,
    pub description: String,
    pub required: bool,
    pub kind: String,
}

#[derive(Clone, Debug)]
pub(super) struct Trigger {
    pub push: PushTrigger,
    pub pull_request: bool,
    pub workflow_dispatch: bool,
    pub merge_group: MergeGroup,
    pub paths: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PushTrigger {
    pub branches: bool,
    pub tags: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MergeGroup {
    Always,
    Conditional,
    Never,
}

#[derive(Clone, Debug)]
pub(super) struct Concurrency {
    pub group: String,
    pub cancel_in_progress: bool,
}

#[derive(Clone, Debug)]
pub(super) struct Job {
    pub needs: Vec<String>,
    pub runner: String,
    pub timeout_minutes: u64,
    pub permission: String,
    pub command: String,
    pub artifact_output: String,
    pub physical_name: String,
    pub condition: Option<String>,
    pub outputs: Vec<(String, String)>,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug)]
pub(super) struct Step {
    pub name: String,
    pub id: Option<String>,
    pub condition: Option<String>,
    pub working_directory: Option<String>,
    pub operation: Operation,
}

#[derive(Clone, Debug)]
pub(super) enum Operation {
    Run(Invocation),
    Action {
        action: String,
        inputs: Vec<(String, String)>,
    },
}

#[derive(Clone, Debug)]
pub(super) struct Action {
    pub repository: String,
    pub revision: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Permission {
    pub actions: Access,
    pub contents: Access,
    pub id_token: Access,
    pub attestations: Access,
    pub artifact_metadata: Access,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Access {
    None,
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub(super) struct Invocation {
    pub executable: String,
    pub arguments: Vec<String>,
    pub credential: Credential,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Credential {
    None,
    GithubToken,
}
