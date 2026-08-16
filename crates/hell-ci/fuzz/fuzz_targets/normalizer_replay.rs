#![no_main]

use std::path::Path;

use hell_builtins::NormalizerId;
use hell_testkit::{RetainedNormalizerInput, apply_retained_normalizer_twice};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let normalizer = if data.first().is_some_and(|byte| byte & 1 == 0) {
        NormalizerId::DiagnosticSandboxPathV1
    } else {
        NormalizerId::DiagnosticPathSeparatorV1
    };
    let passes = apply_retained_normalizer_twice(RetainedNormalizerInput {
        normalizer,
        observation: data,
        executable: Path::new("hell"),
        sandbox: Path::new(r"C:\fuzz\sandbox"),
        script: Path::new(r"C:\fuzz\sandbox\main.hell"),
    });
    assert_eq!(passes.first_pass, passes.second_pass);
});
