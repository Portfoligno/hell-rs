use std::path::PathBuf;
use std::sync::Arc;

use hell_testkit::{
    DifferentialMode, ExecutableIdentity, ExecutableRole, ExecutionProfile,
    committed_differential_cases, observe_verified_executable_profile, sha256_bytes, sha256_file,
};

fn reviewed_profile_case(profile: ExecutionProfile) -> hell_testkit::DifferentialCase {
    let mut case = committed_differential_cases()
        .into_iter()
        .find(|case| case.claim_evidence.is_some())
        .expect("committed reviewed case");
    case.id = Arc::from("explicit-profile-process-observer");
    case.source = Arc::from("main = IO.pure ()\n");
    case.mode = DifferentialMode::Check;
    let descriptor = case.claim_evidence.as_mut().expect("reviewed descriptor");
    descriptor.profile = profile;
    descriptor.source_sha256 = sha256_bytes(case.source.as_bytes());
    case
}

#[test]
fn explicit_profiles_reach_the_observed_process_as_two_structured_arguments() {
    let executable = PathBuf::from(env!("CARGO_BIN_EXE_hell-test-helper"));
    let identity = ExecutableIdentity {
        sha256: sha256_file(&executable).unwrap(),
        path: executable,
        reported_version: Arc::from("hell-test-helper-1"),
        build_info: None,
        role: ExecutableRole::Candidate,
        assurance_epoch_sha256: Some(sha256_bytes(b"profile-observer-epoch")),
        acquisition_receipt_id: None,
        acquisition_receipt_sha256: None,
        acquisition_attestation_sha256: None,
    };
    for profile in [ExecutionProfile::Upstream, ExecutionProfile::Sandboxed] {
        let case = reviewed_profile_case(profile);
        let retained = observe_verified_executable_profile(&identity, &case, profile).unwrap();
        assert_eq!(retained.profile, profile);
        assert_eq!(
            retained.observation.stdout.complete.as_deref(),
            Some(format!("{}\n", profile.as_str()).as_bytes())
        );
    }
}
