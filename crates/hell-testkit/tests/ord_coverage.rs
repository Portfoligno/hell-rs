use hell_testkit::verify_committed_ord_boolean_partition_for_integration;

#[test]
fn ord_targets_require_both_boolean_paths_for_every_registry_instance() {
    verify_committed_ord_boolean_partition_for_integration()
        .expect("every committed Ord scope must retain both Boolean outcomes");
}
