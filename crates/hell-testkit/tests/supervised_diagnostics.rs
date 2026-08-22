#[test]
fn supervised_diagnostics_are_bounded_typed_and_ordered() {
    hell_testkit::verify_supervised_diagnostics_for_integration()
        .expect("supervised diagnostic integration verifier passes");
}
