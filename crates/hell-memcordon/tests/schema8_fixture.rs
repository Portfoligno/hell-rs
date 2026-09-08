use hell_memcordon::{NativeArgument, Schema8TerminalV1, project_schema8_report};

const LINUX_EXIT_123: &[u8] =
    include_bytes!("../../../fixtures/memcordon-rc23/schema8-linux-exit-123.json");

#[test]
fn shared_rc23_linux_fixture_projects_reserved_exit_as_candidate_status() {
    let projection = project_schema8_report(
        LINUX_EXIT_123,
        "linux-pid-namespace-cgroup-v2",
        &[NativeArgument {
            display: "/opt/hell/bin/candidate".to_owned(),
            raw: None,
        }],
    )
    .expect("shared rc.23 schema-8 fixture");
    assert_eq!(projection.wrapper_status, 123);
    assert_eq!(projection.target_status, Some(123));
    assert_eq!(
        projection.terminal,
        Schema8TerminalV1::CandidateExit { native_status: 123 }
    );
    assert!(projection.sealed_boundary_retired);
}
