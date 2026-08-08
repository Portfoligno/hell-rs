use hell_docgen::{ReleaseEnvironment, render_api_markdown, render_compatibility_json};

const REVIEWED_SNAPSHOT: &str = include_str!("../../../compat/upstream-2026-05-29.json");

#[test]
fn api_markdown_is_sorted_and_manifest_complete() {
    let rendered = render_api_markdown();
    assert!(rendered.starts_with("# Hell 2026-05-29 API\n"));
    assert_eq!(rendered.matches(" — compatibility: `").count(), 345);
    assert_eq!(
        rendered.matches(" — `direct").count() + rendered.matches(" — `entail").count(),
        98
    );
    assert!(rendered.contains("- `Either` :: `Type -> Type -> Type`"));
    assert!(rendered.contains("- `Alternative` :: `Type -> Type`"));
    assert!(rendered.contains("- `Show` :: `Type`"));
    assert!(rendered.contains("- `Show Either` — `entail2`"));
    assert!(rendered.find("- `$`").unwrap() < rendered.find("- `Alternative.many`").unwrap());
}

#[test]
fn compatibility_snapshot_has_pinned_metadata_and_exact_inventory_counts() {
    let rendered = render_compatibility_json();
    assert_eq!(rendered, render_compatibility_json());
    assert_eq!(rendered, REVIEWED_SNAPSHOT);
    hell_docgen::verify_compatibility_snapshot(REVIEWED_SNAPSHOT)
        .expect("reviewed snapshot matches");
    assert!(rendered.ends_with("}\n"));
    assert!(rendered.contains("\"languageVersion\": \"2026-05-29\""));
    assert!(rendered.contains(
        "\"upstreamSourceSha256\": \"6b59dbbdaaa1e31938e8cbdf93ffb2b981fe8064009693f92fbdd134f7dd25f9\""
    ));
    assert!(rendered.contains("\"publicTerms\": 345"));
    assert!(rendered.contains("\"internalTerms\": 10"));
    assert!(rendered.contains("\"typeConstructors\": 31"));
    assert!(rendered.contains("\"classes\": 10"));
    assert!(rendered.contains("\"instances\": 98"));
    assert!(rendered.contains("\"upstreamExamples\": 44"));
    assert_eq!(rendered.matches("\"resolution\":").count(), 98);
    assert_eq!(rendered.matches("\"headKind\":").count(), 10);
    assert!(
        rendered.contains("{ \"name\": \"Alternative\", \"headKind\": \"type-constructor-1\" }")
    );
    assert!(rendered.contains("{ \"name\": \"Show\", \"headKind\": \"type\" }"));
    assert_eq!(rendered.matches("\"implementation\":").count(), 355);
    let classified_terms = hell_builtins::registry()
        .iter()
        .filter(|term| term.type_class.is_some())
        .count();
    assert_eq!(
        rendered
            .lines()
            .filter(|line| {
                line.contains("\"implementation\":") && line.contains("\"class\": \"")
            })
            .count(),
        classified_terms
    );

    let mut stale = rendered;
    stale.replace_range(0..1, "[");
    let mismatch = hell_docgen::verify_compatibility_snapshot(&stale)
        .expect_err("mutated snapshot must fail the release gate");
    assert_eq!(mismatch.first_differing_byte, 0);
}

#[test]
fn release_environment_is_deterministic_and_sorts_reviewed_lists() {
    let rendered = hell_docgen::render_release_environment(&ReleaseEnvironment {
        implementation_version: "0.1.0",
        rust_toolchain: "rustc pinned",
        target: "test-target",
        cargo_lock_checksum: "lock-sha256",
        enabled_features: &["zeta", "alpha"],
        oracle_executable_checksum: "oracle-sha256",
        known_divergences: &["second", "first"],
    });
    assert!(rendered.contains("enabled features: `alpha,zeta`"));
    assert!(rendered.find("- first").unwrap() < rendered.find("- second").unwrap());
    assert!(rendered.contains("test network: `loopback only`"));
}
