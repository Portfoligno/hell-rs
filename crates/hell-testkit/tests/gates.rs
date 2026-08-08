use std::sync::Arc;
use std::time::Duration;

use hell_testkit::{
    ClassifiedMismatch, DeterministicBytes, DeterministicUtf8, DifferentialCase,
    DifferentialMismatch, DivergenceClass, MismatchKind, differential, release_gate,
};

#[test]
fn deterministic_corpus_is_reproducible_and_bounded() {
    let left = DeterministicBytes::new(0x5eed, 128, 192).collect::<Vec<_>>();
    let right = DeterministicBytes::new(0x5eed, 128, 192).collect::<Vec<_>>();
    assert_eq!(left, right);
    assert_eq!(left.len(), 128);
    assert!(left.iter().all(|bytes| bytes.len() <= 192));
    assert!(left.iter().any(Vec::is_empty));
    assert!(left.iter().any(|bytes| !bytes.is_empty()));

    let utf8 = DeterministicUtf8::new(0x5eed, 128, 192).collect::<Vec<_>>();
    assert_eq!(utf8.len(), 128);
    assert!(utf8.iter().all(|text| text.len() <= 192));
}

#[test]
fn identical_processes_pass_the_isolated_differential_gate() {
    let executable = std::env::current_exe().expect("current test executable");
    let case = DifferentialCase {
        source: Arc::from("main = IO.pure ()\n"),
        timeout: Duration::from_secs(2),
        ..DifferentialCase::default()
    };
    let report = differential(&executable, &executable, &case).expect("run isolated processes");
    assert!(report.agrees(), "unexpected mismatch: {report:#?}");
    assert!(!report.oracle.timed_out);
}

#[test]
fn release_gate_requires_volume_and_explanations() {
    let mismatch = DifferentialMismatch {
        kind: MismatchKind::Stdout,
        oracle: b"oracle".to_vec(),
        candidate: b"candidate".to_vec(),
    };
    let unexplained = ClassifiedMismatch {
        mismatch: mismatch.clone(),
        classification: None,
        explanation: Arc::from(""),
    };
    assert!(!release_gate(99, 100, &[]).passed());
    assert!(!release_gate(100, 100, &[unexplained]).passed());

    let explained = ClassifiedMismatch {
        mismatch: mismatch.clone(),
        classification: Some(DivergenceClass::DeliberateDivergence),
        explanation: Arc::from("reviewed compatibility boundary"),
    };
    assert!(release_gate(100, 100, &[explained]).passed());

    let rust_bug = ClassifiedMismatch {
        mismatch,
        classification: Some(DivergenceClass::RustBug),
        explanation: Arc::from("confirmed candidate defect"),
    };
    let report = release_gate(100, 100, &[rust_bug]);
    assert_eq!(report.rust_bug_mismatches, 1);
    assert!(!report.passed());
}
