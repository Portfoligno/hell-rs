use hell_workflow_auditor::fuzz::{Target, exercise};

#[test]
fn committed_workflow_seed_corpus_is_accepted_by_production_parsers() {
    for (target, seed) in [
        (
            Target::WorkflowYamlSubset,
            include_bytes!("../corpus/workflow_yaml_subset/seed.yml").as_slice(),
        ),
        (
            Target::WorkflowExpression,
            include_bytes!("../corpus/workflow_expression/seed.txt").as_slice(),
        ),
        (
            Target::WorkflowRunInvocation,
            include_bytes!("../corpus/workflow_run_invocation/seed.txt").as_slice(),
        ),
    ] {
        exercise(target, seed).expect("committed workflow fuzz seed must be accepted");
    }
}
