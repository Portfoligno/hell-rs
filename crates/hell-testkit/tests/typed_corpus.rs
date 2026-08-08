use hell_compiler::{CompilerSession, compile_source};
use hell_testkit::{committed_differential_cases, generated_typed_cases};

#[test]
fn committed_and_generated_differential_sources_compile() {
    let mut session = CompilerSession::upstream();
    for case in committed_differential_cases() {
        let result = compile_source(&mut session, case.id.to_string(), case.source.to_string());
        if case.id.strip_prefix("check-negative-").is_some() {
            assert!(result.is_err(), "{} unexpectedly compiled", case.id);
        } else {
            result.unwrap_or_else(|diagnostics| {
                panic!("{} did not compile: {diagnostics:#?}", case.id)
            });
        }
    }
    for case in generated_typed_cases(0x4845_4c4c_2026, 1_024) {
        compile_source(&mut session, case.id.to_string(), case.source.to_string())
            .unwrap_or_else(|diagnostics| panic!("{} did not compile: {diagnostics:#?}", case.id));
    }
}
