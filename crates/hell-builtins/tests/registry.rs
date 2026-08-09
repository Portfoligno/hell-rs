use std::collections::HashSet;

use hell_builtins::{
    ClaimPlatform, ClaimStatus, ClaimValidationError, CompatibilityDimension, ExecutionProfile,
    INTERNAL_NAME_COUNT, INTERNAL_NAMES, NormalizerId, PUBLIC_NAME_COUNT, ScopedClaim,
    UNIQUE_NAME_COUNT, Visibility, WiringStatus, compatibility_claims, registry,
    validate_compatibility_claims,
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
    rationale: None,
    issue: None,
}];
const NORMALIZED_MISSING_NORMALIZER: &[ScopedClaim] = &[ScopedClaim {
    status: ClaimStatus::Normalized,
    profiles: UPSTREAM,
    platforms: NATIVE_PLATFORMS,
    evidence: &["differential:case-evidence-v1"],
    normalizers: &[],
    rationale: Some("Reviewed presentation-only variation."),
    issue: None,
}];
const DIVERGENCE_MISSING_RATIONALE: &[ScopedClaim] = &[ScopedClaim {
    status: ClaimStatus::DeliberateDivergence,
    profiles: UPSTREAM,
    platforms: NATIVE_PLATFORMS,
    evidence: &["differential:case-evidence-v1"],
    normalizers: &[],
    rationale: None,
    issue: Some("COMPAT-DIVERGENCE"),
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
        rationale: None,
        issue: None,
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
            rationale: Some("Pending evidence."),
            issue: Some("COMPAT-EVIDENCE"),
        },
        ScopedClaim {
            status: ClaimStatus::Unverified,
            profiles: UPSTREAM,
            platforms: &[ClaimPlatform::Linux],
            evidence: &[],
            normalizers: &[],
            rationale: Some("Pending evidence."),
            issue: Some("COMPAT-EVIDENCE"),
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
        rationale: Some("Reviewed presentation-only variation."),
        issue: None,
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
