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
        "requirement",
        include_str!("../../../../compat/requirements/2026-05-29.toml"),
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
                "requirement",
                include_str!("../corpus/requirement_toml/panic-line-regression.toml"),
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
        "requirement",
        include_str!("../corpus/requirement_toml/seed.toml"),
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
    hell_testkit::verify_observation_bundle_manifest_bytes(include_bytes!(
        "../corpus/observation_bundle_manifest/seed.json",
    ))
    .unwrap();
    assert_eq!(
        include_str!("../fixtures/semantic-trace-seed.hell"),
        "main = IO.print $ Alternative.optional (Maybe.Just 3 :: Maybe Int)\n"
    );
    hell_testkit::parse_semantic_trace(include_bytes!(
        "../corpus/semantic_trace/seed.json"
    ))
    .unwrap();
}
