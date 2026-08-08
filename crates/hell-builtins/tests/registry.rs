use std::collections::HashSet;

use hell_builtins::{
    INTERNAL_NAME_COUNT, INTERNAL_NAMES, PUBLIC_NAME_COUNT, UNIQUE_NAME_COUNT, Visibility, registry,
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
fn known_quirk_has_an_explicit_compatibility_adapter() {
    let spec = hell_builtins::lookup("List.mapAccumR").unwrap();
    assert_eq!(spec.implementation, Some("list_map_accum_l_compat"));
    assert_eq!(spec.compatibility, hell_builtins::Compatibility::Exact);
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
            && spec.compatibility == hell_builtins::Compatibility::Exact
            && spec.type_class.is_none()
    }));
    let implementations = internal
        .iter()
        .map(|spec| spec.implementation.unwrap())
        .collect::<HashSet<_>>();
    assert_eq!(implementations.len(), 10);
}
