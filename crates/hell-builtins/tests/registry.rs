use std::collections::HashSet;

use hell_builtins::{
    AssuranceSensitivity, ClaimPlatform, ClaimStatus, ClaimValidationError, CompatibilityDimension,
    ExecutionProfile, INTERNAL_NAME_COUNT, INTERNAL_NAMES, NormalizerId, PUBLIC_NAME_COUNT,
    ScopedClaim, UNIQUE_NAME_COUNT, Visibility, WiringStatus, assurance_catalogs,
    compatibility_claims, registry, validate_compatibility_claims,
};

const UPSTREAM: &[ExecutionProfile] = &[ExecutionProfile::Upstream];
const NATIVE_PLATFORMS: &[ClaimPlatform] = &[
    ClaimPlatform::Linux,
    ClaimPlatform::MacOs,
    ClaimPlatform::Windows,
];
const EXACT_MISSING_EVIDENCE: &[ScopedClaim] = &[ScopedClaim {
    status: ClaimStatus::Exact,
    profiles: UPSTREAM,
    platforms: NATIVE_PLATFORMS,
    evidence: &[],
    normalizers: &[],
    obligations: &[],
    applicability_rule: "test-rule",
    rationale: None,
    issue: None,
    review_group: None,
}];
const NORMALIZED_MISSING_NORMALIZER: &[ScopedClaim] = &[ScopedClaim {
    status: ClaimStatus::Normalized,
    profiles: UPSTREAM,
    platforms: NATIVE_PLATFORMS,
    evidence: &["differential:case-evidence-v1"],
    normalizers: &[],
    obligations: &[],
    applicability_rule: "test-rule",
    rationale: Some("Reviewed presentation-only variation."),
    issue: None,
    review_group: None,
}];
const DIVERGENCE_MISSING_RATIONALE: &[ScopedClaim] = &[ScopedClaim {
    status: ClaimStatus::DeliberateDivergence,
    profiles: UPSTREAM,
    platforms: NATIVE_PLATFORMS,
    evidence: &["differential:case-evidence-v1"],
    normalizers: &[],
    obligations: &[],
    applicability_rule: "test-rule",
    rationale: None,
    issue: Some("COMPAT-DIVERGENCE"),
    review_group: None,
}];

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
fn evidence_bearing_promotions_fail_closed() {
    let mut claims = compatibility_claims().to_vec();
    claims[0].dimensions[0].scopes = EXACT_MISSING_EVIDENCE;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::MissingEvidence)
    );

    claims[0].dimensions[0].scopes = NORMALIZED_MISSING_NORMALIZER;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::MissingNormalizer)
    );

    claims[0].dimensions[0].scopes = DIVERGENCE_MISSING_RATIONALE;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::MissingRationale)
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
fn executable_does_not_imply_exact() {
    let spec = hell_builtins::lookup("List.map").unwrap();
    assert_eq!(spec.wiring, WiringStatus::Executable);
    let claim = &compatibility_claims()[usize::from(spec.id.0)];
    assert!(
        claim
            .dimensions
            .iter()
            .flat_map(|dimension| dimension.scopes.iter())
            .all(|scope| scope.status == ClaimStatus::Unverified)
    );
}

#[test]
fn claim_dimensions_and_references_are_canonical() {
    const BAD_REFERENCE: &[ScopedClaim] = &[ScopedClaim {
        status: ClaimStatus::Exact,
        profiles: UPSTREAM,
        platforms: NATIVE_PLATFORMS,
        evidence: &["differential:../escape"],
        normalizers: &[],
        obligations: &[],
        applicability_rule: "test-rule",
        rationale: None,
        issue: None,
        review_group: None,
    }];
    let mut claims = compatibility_claims().to_vec();
    claims[0].dimensions.swap(0, 1);
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::DimensionOrder)
    );
    let mut claims = compatibility_claims().to_vec();
    claims[0].dimensions[0].scopes = BAD_REFERENCE;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::InvalidEvidence)
    );
}

#[test]
fn claim_scopes_reject_overlap_and_duplicate_normalizers() {
    const OVERLAPPING: &[ScopedClaim] = &[
        ScopedClaim {
            status: ClaimStatus::Unverified,
            profiles: UPSTREAM,
            platforms: &[ClaimPlatform::All],
            evidence: &[],
            normalizers: &[],
            obligations: &[],
            applicability_rule: "test-rule",
            rationale: Some("Pending evidence."),
            issue: Some("COMPAT-EVIDENCE"),
            review_group: None,
        },
        ScopedClaim {
            status: ClaimStatus::Unverified,
            profiles: UPSTREAM,
            platforms: &[ClaimPlatform::Linux],
            evidence: &[],
            normalizers: &[],
            obligations: &[],
            applicability_rule: "test-rule",
            rationale: Some("Pending evidence."),
            issue: Some("COMPAT-EVIDENCE"),
            review_group: None,
        },
    ];
    const DUPLICATE_NORMALIZERS: &[ScopedClaim] = &[ScopedClaim {
        status: ClaimStatus::Normalized,
        profiles: UPSTREAM,
        platforms: NATIVE_PLATFORMS,
        evidence: &["differential:case-evidence-v1"],
        normalizers: &[
            NormalizerId::DiagnosticPathSeparatorV1,
            NormalizerId::DiagnosticPathSeparatorV1,
        ],
        obligations: &[],
        applicability_rule: "test-rule",
        rationale: Some("Reviewed presentation-only variation."),
        issue: None,
        review_group: None,
    }];
    let mut claims = compatibility_claims().to_vec();
    claims[0].dimensions[0].scopes = OVERLAPPING;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::OverlappingScope)
    );
    let mut claims = compatibility_claims().to_vec();
    claims[0].dimensions[0].scopes = DUPLICATE_NORMALIZERS;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::MissingNormalizer)
    );
}

#[test]
fn claim_scopes_reject_contract_scope_and_obligation_drift() {
    const WRONG_DIMENSION: &[ScopedClaim] = &[ScopedClaim {
        status: ClaimStatus::Normalized,
        profiles: UPSTREAM,
        platforms: NATIVE_PLATFORMS,
        evidence: &["differential:case-evidence-v1"],
        normalizers: &[NormalizerId::DiagnosticPathSeparatorV1],
        obligations: &[],
        applicability_rule: "test-rule",
        rationale: Some("Path normalization is not valid for parse semantics."),
        issue: None,
        review_group: None,
    }];
    const DUPLICATE_OBLIGATIONS: &[ScopedClaim] = &[ScopedClaim {
        status: ClaimStatus::Unverified,
        profiles: UPSTREAM,
        platforms: NATIVE_PLATFORMS,
        evidence: &[],
        normalizers: &[],
        obligations: &["boundary", "boundary"],
        applicability_rule: "test-rule",
        rationale: Some("Pending evidence."),
        issue: Some("COMPAT-EVIDENCE"),
        review_group: None,
    }];
    const MISSING_RULE: &[ScopedClaim] = &[ScopedClaim {
        status: ClaimStatus::Unverified,
        profiles: UPSTREAM,
        platforms: NATIVE_PLATFORMS,
        evidence: &[],
        normalizers: &[],
        obligations: &[],
        applicability_rule: "",
        rationale: Some("Pending evidence."),
        issue: Some("COMPAT-EVIDENCE"),
        review_group: None,
    }];

    let mut claims = compatibility_claims().to_vec();
    claims[0].dimensions[0].scopes = WRONG_DIMENSION;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::InvalidNormalizerScope)
    );
    let mut claims = compatibility_claims().to_vec();
    claims[0].dimensions[0].scopes = DUPLICATE_OBLIGATIONS;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::DuplicateObligation)
    );
    let mut claims = compatibility_claims().to_vec();
    claims[0].dimensions[0].scopes = MISSING_RULE;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::MissingApplicabilityRule)
    );
}

#[test]
fn all_registry_ids_have_all_dimension_claims() {
    let claims = compatibility_claims();
    validate_compatibility_claims(claims).unwrap();
    assert_eq!(claims.len(), UNIQUE_NAME_COUNT);
    for (index, claim) in claims.iter().enumerate() {
        assert_eq!(usize::from(claim.builtin.0), index);
        assert_eq!(
            claim.dimensions.map(|dimension| dimension.dimension),
            CompatibilityDimension::ALL
        );
    }
}

#[test]
fn declarative_claim_override_is_scoped_to_one_catalog_cell() {
    let builtin = hell_builtins::lookup("Bool.bool").unwrap();
    let claim = &compatibility_claims()[usize::from(builtin.id.0)];
    let runtime = claim
        .dimensions
        .iter()
        .find(|claim| claim.dimension == CompatibilityDimension::PureRuntime)
        .unwrap();
    assert_eq!(runtime.scopes.len(), 2);
    assert_eq!(
        runtime.scopes[0].obligations,
        [
            "adapter-success",
            "lazy-boundary",
            "conditional-selected",
            "conditional-unselected",
            "typed-result",
            "constructor-eliminator",
        ]
    );
    assert_eq!(
        runtime.scopes[0].applicability_rule,
        "implemented-runtime-adapter"
    );
    assert_eq!(runtime.scopes[0].review_group, Some("bool-conditional-v1"));
    assert_eq!(runtime.scopes[0].profiles, [ExecutionProfile::Upstream]);
    assert_eq!(runtime.scopes[1].profiles, [ExecutionProfile::Sandboxed]);
    assert_eq!(
        runtime.scopes[1].applicability_rule,
        "sandboxed-profile-review-required"
    );

    let parse = claim
        .dimensions
        .iter()
        .find(|claim| claim.dimension == CompatibilityDimension::Parse)
        .unwrap();
    assert_eq!(
        parse.scopes[0].applicability_rule,
        "catalog-default-review-required"
    );
    assert!(parse.scopes[0].obligations.is_empty());
    assert_eq!(parse.scopes[0].review_group, None);
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
        assert!(
            contract
                .allowed_fields
                .iter()
                .all(|field| !contract.forbidden_fields.contains(field))
        );
        assert_eq!(contract.requires_platforms, NATIVE_PLATFORMS);
        assert!(!contract.mutation_suite.is_empty());
        assert_eq!(
            contract.implementation_sha256.len(),
            hell_builtins::UPSTREAM_SOURCE_SHA256.len()
        );
        assert!(
            contract
                .implementation_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(implementation_digests.insert(contract.implementation_sha256));
    }
    assert!(
        NormalizerId::ALL
            .iter()
            .all(|id| id.as_str() != "stderr-fixture-root-v1")
    );
}
