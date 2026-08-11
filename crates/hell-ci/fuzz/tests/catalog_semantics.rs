#[path = "../../../hell-builtins/build.rs"]
#[allow(dead_code)]
mod production_catalog;

use std::sync::atomic::{AtomicUsize, Ordering};

static CATALOG_ADMISSION_PANICS: AtomicUsize = AtomicUsize::new(0);

fn assert_bounded_exact_catalog_admission(kind: &str, canonical: &str) {
    assert!(production_catalog::fuzz_validate_catalog(kind, canonical).is_ok());
    for index in (0..canonical.len()).step_by(canonical.len().div_ceil(256)) {
        let mut bytes = canonical.as_bytes().to_vec();
        bytes[index] = 0;
        let mutated = String::from_utf8(bytes).unwrap();
        assert!(production_catalog::fuzz_validate_catalog(kind, &mutated).is_err());
    }
}

#[test]
fn exact_production_catalog_parsers_are_bounded_and_fail_closed() {
    assert_bounded_exact_catalog_admission(
        "claim",
        include_str!("../../../../compat/claims/2026-05-29.toml"),
    );
    assert_bounded_exact_catalog_admission(
        "normalizer",
        include_str!("../../../../compat/normalizers.toml"),
    );
    assert_bounded_exact_catalog_admission(
        "divergence",
        include_str!("../../../../compat/divergences.toml"),
    );
}

#[test]
fn malformed_catalog_admission_returns_errors_without_invoking_a_panic_hook() {
    CATALOG_ADMISSION_PANICS.store(0, Ordering::SeqCst);
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {
        CATALOG_ADMISSION_PANICS.fetch_add(1, Ordering::SeqCst);
    }));
    let admissions = std::panic::catch_unwind(|| {
        [
            (
                "claim",
                include_str!("../corpus/claim_toml/panic-line-regression.toml"),
            ),
            ("normalizer", "schema_version = 1\nbroken line\n"),
            ("divergence", "schema_version = 2\n[[]]\n"),
        ]
        .map(|(kind, source)| production_catalog::fuzz_validate_catalog(kind, source))
    });
    let _ = std::panic::take_hook();
    std::panic::set_hook(prior_hook);
    assert!(admissions.is_ok());
    assert!(admissions.unwrap().iter().all(Result::is_err));
    assert_eq!(CATALOG_ADMISSION_PANICS.load(Ordering::SeqCst), 0);
}

#[test]
fn every_semantic_fuzz_target_has_an_accepted_canonical_seed() {
    production_catalog::fuzz_validate_catalog(
        "claim",
        include_str!("../corpus/claim_toml/seed.toml"),
    )
    .unwrap();
    production_catalog::fuzz_validate_catalog(
        "normalizer",
        include_str!("../corpus/normalizer_toml/seed.toml"),
    )
    .unwrap();
    production_catalog::fuzz_validate_catalog(
        "divergence",
        include_str!("../corpus/divergence_toml/seed.toml"),
    )
    .unwrap();
    hell_ci::fuzz_admit_dsse_envelope(include_bytes!(
        "../corpus/dsse_envelope/seed.json"
    ))
    .unwrap();
    assert!(hell_ci::fuzz_admit_acquisition_receipt(include_bytes!(
        "../corpus/acquisition_receipt/seed.json"
    ))
    .is_ok());
    assert!(hell_testkit::verify_observation_bundle_manifest_bytes(include_bytes!(
        "../corpus/observation_bundle_manifest/seed.json"
    ))
    .is_ok());
    assert!(hell_ci::fuzz_admit_provenance_record(include_bytes!(
        "../corpus/provenance_record/seed.json"
    ))
    .is_ok());
    assert!(hell_ci::fuzz_admit_custody_receipt(include_bytes!(
        "../corpus/custody_receipt/seed.json"
    ))
    .is_ok());
    assert!(hell_ci::fuzz_admit_review_graph(include_bytes!(
        "../corpus/review_graph/seed.json"
    ))
    .is_ok());
    let evidence_seed = include_bytes!("../corpus/evidence_graph_merge/seed.json");
    let rendered_evidence_seed = hell_ci::fuzz_evidence_graph_seed().unwrap();
    assert_eq!(
        evidence_seed.as_slice(),
        rendered_evidence_seed,
        "canonical evidence seed: {}",
        String::from_utf8_lossy(&rendered_evidence_seed)
    );
    hell_ci::fuzz_admit_evidence_graph_merge(evidence_seed).unwrap();
    assert_eq!(
        include_str!("../fixtures/semantic-trace-seed.hell"),
        "main = IO.print $ Alternative.optional (Maybe.Just 3 :: Maybe Int)\n"
    );
    let semantic = hell_testkit::parse_semantic_trace(include_bytes!(
        "../corpus/semantic_trace/seed.json"
    ))
    .unwrap();
    let optional = hell_builtins::lookup("Alternative.optional").unwrap().id;
    assert!(semantic.force_trace.len() >= 2);
    assert!(semantic.effect_trace.len() >= 2);
    assert!(semantic.obligation_trace.len() >= 4);
    assert!(semantic.obligation_trace.iter().any(|event| {
        event.builtin == optional
            && event.instance_target.as_deref() == Some("Maybe")
            && event.parent_sequence.is_none()
    }));
    assert!(semantic
        .obligation_trace
        .iter()
        .any(|event| event.parent_sequence.is_some()));
}
