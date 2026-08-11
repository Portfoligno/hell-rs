use hell_docgen::{
    BoundedCompatibilityReport, ReleaseEnvironment, render_api_markdown,
    render_bounded_compatibility_report, render_compatibility_json,
};

const REVIEWED_SNAPSHOT: &str = include_str!("../../../compat/upstream-2026-05-29.json");

#[test]
fn api_markdown_is_sorted_and_manifest_complete() {
    let rendered = render_api_markdown();
    assert!(rendered.starts_with("# Hell 2026-05-29 API\n"));
    assert_eq!(rendered.matches(" — wiring: `").count(), 345);
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

#[test]
fn bounded_report_exposes_scope_and_residual_risk_without_universal_claims() {
    let report = BoundedCompatibilityReport {
        baseline: "2026-05-29",
        candidate_commit: "candidate",
        assurance_epoch_sha256: "epoch",
        promotion_state: "at-risk",
        profiles: &["upstream"],
        platforms: &["windows-amd64", "linux-amd64", "macos-arm64"],
        toolchains: &["runner-z", "runner-a"],
        runner_identities: &["runner-id-z", "runner-id-a"],
        exact_cells: 11,
        normalized_cells: 2,
        platform_dependent_cells: 3,
        deliberate_divergence_cells: 5,
        unverified_cells: 7,
        out_of_scope_cells: 13,
        missing_obligations: 17,
        undetected_critical_mutants: 19,
        residual_risk_tier: "high",
        custody_state: "at-risk",
        open_compatibility_issues: &["ISSUE-2", "ISSUE-1", "ISSUE-1"],
        accepted_divergences: &[],
    };
    let rendered = render_bounded_compatibility_report(&report).expect("valid bounded report");
    assert_eq!(
        rendered,
        render_bounded_compatibility_report(&report).expect("deterministic bounded report")
    );
    assert!(rendered.ends_with('\n'));
    assert!(rendered.contains("- promoted: `21`"));
    assert!(rendered.contains("- unverified: `7`"));
    assert!(rendered.contains("- missing mandatory obligations: `17`"));
    assert!(rendered.contains("- undetected critical mutants: `19`"));
    assert!(rendered.find("`ISSUE-1`").unwrap() < rendered.find("`ISSUE-2`").unwrap());
    assert_eq!(rendered.matches("`ISSUE-1`").count(), 1);
    assert!(rendered.contains("not proof of universal equivalence"));
}

#[test]
fn bounded_report_rejects_markdown_injection_and_count_overflow() {
    let mut report = BoundedCompatibilityReport {
        baseline: "2026-05-29",
        candidate_commit: "candidate",
        assurance_epoch_sha256: "epoch",
        promotion_state: "pending\n\n# Forged promotion",
        profiles: &["upstream"],
        platforms: &["linux-amd64"],
        toolchains: &["runner"],
        runner_identities: &["runner-id"],
        exact_cells: 0,
        normalized_cells: 0,
        platform_dependent_cells: 0,
        deliberate_divergence_cells: 0,
        unverified_cells: 1,
        out_of_scope_cells: 0,
        missing_obligations: 1,
        undetected_critical_mutants: 1,
        residual_risk_tier: "unacceptable",
        custody_state: "not-uploaded",
        open_compatibility_issues: &[],
        accepted_divergences: &[],
    };
    assert_eq!(
        render_bounded_compatibility_report(&report),
        Err("promotion state")
    );

    report.promotion_state = "pending";
    report.exact_cells = usize::MAX;
    report.normalized_cells = 1;
    assert_eq!(
        render_bounded_compatibility_report(&report),
        Err("claim cell count overflow")
    );

    report.exact_cells = 0;
    report.normalized_cells = 0;
    report.open_compatibility_issues = &["ISSUE-1`\n# Forged section"];
    assert_eq!(
        render_bounded_compatibility_report(&report),
        Err("compatibility issue")
    );
}
