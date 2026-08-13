use std::collections::HashSet;

use hell_builtins::{
    AssuranceSensitivity, CompatibilityDimension, ExecutionProfile, INTERNAL_NAME_COUNT,
    INTERNAL_NAMES, NormalizerId, PUBLIC_NAME_COUNT, RequirementPlatform, RequirementStrategy,
    RequirementValidationError, ScopedRequirement, UNIQUE_NAME_COUNT, Visibility, WiringStatus,
    assurance_catalogs, compatibility_requirements, registry, validate_compatibility_requirements,
};

const UPSTREAM: &[ExecutionProfile] = &[ExecutionProfile::Upstream];
const NATIVE_PLATFORMS: &[RequirementPlatform] = &[
    RequirementPlatform::LinuxX86_64,
    RequirementPlatform::MacosAarch64,
    RequirementPlatform::WindowsX86_64,
];

#[test]
fn pinned_registry_counts_and_names_are_unique() {
    let registry = registry();
    assert_eq!(registry.len(), UNIQUE_NAME_COUNT);
    assert_eq!(
        registry
            .iter()
            .filter(|item| item.visibility == Visibility::Public)
            .count(),
        PUBLIC_NAME_COUNT
    );
    assert_eq!(INTERNAL_NAMES.len(), INTERNAL_NAME_COUNT);
    let unique: HashSet<_> = registry.iter().map(|item| item.name).collect();
    assert_eq!(unique.len(), UNIQUE_NAME_COUNT);
}

#[test]
fn io_print_is_explicitly_presentation_sensitive_without_classifying_other_io_values() {
    let print = hell_builtins::lookup("IO.print").unwrap();
    assert!(
        print
            .assurance_metadata()
            .sensitivities
            .contains(&AssuranceSensitivity::Presentation)
    );
    let pure = hell_builtins::lookup("IO.pure").unwrap();
    assert!(
        !pure
            .assurance_metadata()
            .sensitivities
            .contains(&AssuranceSensitivity::Presentation)
    );
}

#[test]
fn known_quirk_has_an_explicit_wiring_adapter() {
    let spec = hell_builtins::lookup("List.mapAccumR").unwrap();
    assert_eq!(spec.implementation, Some("list_map_accum_l_compat"));
    assert_eq!(spec.wiring, WiringStatus::Executable);
}

#[test]
fn internal_row_and_tag_registry_is_fully_executable() {
    let internal = registry()
        .iter()
        .filter(|spec| spec.visibility == Visibility::Internal)
        .collect::<Vec<_>>();
    assert_eq!(internal.len(), 10);
    assert!(internal.iter().all(|spec| {
        spec.scheme.is_some()
            && spec.implementation.is_some()
            && spec.wiring == WiringStatus::Executable
            && spec.type_class.is_none()
    }));
    let implementations = internal
        .iter()
        .map(|spec| spec.implementation.unwrap())
        .collect::<HashSet<_>>();
    assert_eq!(implementations.len(), 10);
}

#[test]
fn requirements_do_not_author_final_statuses() {
    let spec = hell_builtins::lookup("List.map").unwrap();
    assert_eq!(spec.wiring, WiringStatus::Executable);
    let requirement = &compatibility_requirements()[usize::from(spec.id.0)];
    assert!(requirement.dimensions.iter().all(|dimension| {
        dimension.scopes.iter().all(|scope| {
            !scope.applicability_rule.is_empty()
                && !scope.rationale.is_empty()
                && !scope.tracking_issue.is_empty()
                && !scope.review_group.is_empty()
        })
    }));
}

#[test]
fn requirement_scopes_reject_overlap_and_duplicate_obligations() {
    const OVERLAPPING: &[ScopedRequirement] = &[
        ScopedRequirement {
            profiles: UPSTREAM,
            platforms: NATIVE_PLATFORMS,
            strategy: RequirementStrategy::CommittedDifferentialCorpus,
            evidence: &[],
            normalizers: &[],
            obligations: &[],
            applicability_rule: "test-rule",
            rationale: "Pending evidence.",
            tracking_issue: "COMPAT-EVIDENCE",
            review_group: "compatibility",
        },
        ScopedRequirement {
            profiles: UPSTREAM,
            platforms: &[RequirementPlatform::LinuxX86_64],
            strategy: RequirementStrategy::CommittedDifferentialCorpus,
            evidence: &[],
            normalizers: &[],
            obligations: &[],
            applicability_rule: "test-rule",
            rationale: "Pending evidence.",
            tracking_issue: "COMPAT-EVIDENCE",
            review_group: "compatibility",
        },
    ];
    const DUPLICATE_OBLIGATIONS: &[ScopedRequirement] = &[ScopedRequirement {
        profiles: UPSTREAM,
        platforms: NATIVE_PLATFORMS,
        strategy: RequirementStrategy::NativeOracle,
        evidence: &[],
        normalizers: &[],
        obligations: &["boundary", "boundary"],
        applicability_rule: "test-rule",
        rationale: "Pending evidence.",
        tracking_issue: "COMPAT-EVIDENCE",
        review_group: "compatibility",
    }];
    let mut requirements = compatibility_requirements().to_vec();
    requirements[0].dimensions[0].scopes = OVERLAPPING;
    assert_eq!(
        validate_compatibility_requirements(&requirements),
        Err(RequirementValidationError::OverlappingScope)
    );
    let mut requirements = compatibility_requirements().to_vec();
    requirements[0].dimensions[0].scopes = DUPLICATE_OBLIGATIONS;
    assert_eq!(
        validate_compatibility_requirements(&requirements),
        Err(RequirementValidationError::DuplicateObligation)
    );
}

#[test]
fn all_registry_ids_have_all_dimension_requirements() {
    let requirements = compatibility_requirements();
    validate_compatibility_requirements(requirements).unwrap();
    assert_eq!(requirements.len(), UNIQUE_NAME_COUNT);
    for (index, requirement) in requirements.iter().enumerate() {
        assert_eq!(usize::from(requirement.builtin.0), index);
        assert_eq!(
            requirement.dimensions.map(|dimension| dimension.dimension),
            CompatibilityDimension::ALL
        );
    }
}

#[test]
fn declarative_requirement_override_is_scoped_without_a_final_status() {
    let builtin = hell_builtins::lookup("Bool.bool").unwrap();
    let requirement = &compatibility_requirements()[usize::from(builtin.id.0)];
    let runtime = requirement
        .dimensions
        .iter()
        .find(|requirement| requirement.dimension == CompatibilityDimension::PureRuntime)
        .unwrap();
    assert_eq!(runtime.scopes.len(), 2);
    assert_eq!(
        runtime.scopes[0].strategy,
        RequirementStrategy::NativeOracle
    );
    assert_eq!(runtime.scopes[0].applicability_rule, "pure-runtime-value");
    assert_eq!(runtime.scopes[0].review_group, "bool-conditional-v1");
    assert_eq!(runtime.scopes[0].profiles, [ExecutionProfile::Upstream]);
    assert_eq!(runtime.scopes[1].profiles, [ExecutionProfile::Sandboxed]);
}

#[test]
fn generated_normalizer_contracts_are_total_typed_and_drift_bound() {
    assert_eq!(
        NormalizerId::ALL.len(),
        assurance_catalogs::NORMALIZER_CONTRACTS.len()
    );
    let mut implementation_digests = HashSet::new();
    for id in NormalizerId::ALL {
        let contract = assurance_catalogs::NORMALIZER_CONTRACTS
            .iter()
            .find(|contract| contract.id == *id)
            .unwrap();
        assert_eq!(contract.id.as_str(), id.as_str());
        assert!(contract.idempotent);
        assert!(!contract.allowed_dimensions.is_empty());
        assert!(!contract.allowed_fields.is_empty());
        assert!(!contract.forbidden_fields.is_empty());
        assert!(implementation_digests.insert(contract.implementation_sha256));
    }
}

#[test]
fn applicability_defaults_are_exact_and_fail_closed() {
    assert_eq!(
        assurance_catalogs::DEFAULT_APPLICABILITY_DECISION,
        "applicable-review-required"
    );
    assert_eq!(
        assurance_catalogs::UNKNOWN_BUILTIN_DECISION,
        "applicable-review-required"
    );
    assert_eq!(assurance_catalogs::UNKNOWN_DIMENSION_DECISION, "reject");
    const { assert!(!assurance_catalogs::AUTOMATIC_NOT_APPLICABLE) };
}
