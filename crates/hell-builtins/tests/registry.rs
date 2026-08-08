use std::collections::HashSet;

use hell_builtins::{
    ClaimStatus, ClaimValidationError, CompatibilityDimension, INTERNAL_NAME_COUNT, INTERNAL_NAMES,
    PUBLIC_NAME_COUNT, UNIQUE_NAME_COUNT, Visibility, WiringStatus, compatibility_claims, registry,
    validate_compatibility_claims,
};

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
    claims[0].dimensions[0].status = ClaimStatus::Exact;
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::MissingEvidence)
    );

    claims[0].dimensions[0].status = ClaimStatus::Normalized;
    claims[0].dimensions[0].evidence = &["case-evidence-v1"];
    assert_eq!(
        validate_compatibility_claims(&claims),
        Err(ClaimValidationError::MissingNormalizer)
    );

    claims[0].dimensions[0].status = ClaimStatus::DeliberateDivergence;
    claims[0].dimensions[0].normalizers = &[];
    claims[0].dimensions[0].rationale = None;
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
            .all(|dimension| dimension.status == ClaimStatus::Unverified)
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
