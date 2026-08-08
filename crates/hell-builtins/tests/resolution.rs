use std::collections::HashSet;

use hell_builtins::{
    InstanceResolution, ManifestKind, TypeClass, Visibility, instance, instances,
    public_type_arity, resolve_instance, type_constructor, type_constructors,
};

#[test]
fn every_manifest_instance_drives_the_closed_resolver() {
    assert_eq!(instances().len(), 98);
    let mut keys = HashSet::new();
    for spec in instances() {
        assert!(keys.insert((spec.class, spec.target)));
        let arity = usize::from(spec.resolution.head_arity());
        assert!(
            resolve_instance(spec.class, spec.target, arity, |_| true),
            "manifest entry did not resolve: {spec:?}"
        );
        assert!(!resolve_instance(
            spec.class,
            spec.target,
            arity.saturating_add(1),
            |_| true
        ));
        if let InstanceResolution::Entail(count) = spec.resolution {
            for rejected in 0..usize::from(count) {
                assert!(!resolve_instance(spec.class, spec.target, arity, |index| {
                    index != rejected
                }));
            }
        }
    }
    assert_eq!(keys.len(), 98);
    assert!(instance(TypeClass::Show, "Either").is_some());
    assert!(instance(TypeClass::Show, "IO").is_none());
}

#[test]
fn type_constructor_loader_exposes_all_kinds_and_only_public_type_arities() {
    assert_eq!(type_constructors().len(), 31);
    assert_eq!(
        type_constructors()
            .iter()
            .filter(|spec| spec.visibility == Visibility::Public)
            .count(),
        25
    );
    assert_eq!(public_type_arity("Text"), Some(0));
    assert_eq!(public_type_arity("Maybe"), Some(1));
    assert_eq!(public_type_arity("Either"), Some(2));
    assert_eq!(public_type_arity("hell:Hell.Tagged"), None);
    assert_eq!(public_type_arity("Missing"), None);

    let tagged = type_constructor("hell:Hell.Tagged").expect("internal Tagged constructor");
    assert_eq!(tagged.visibility, Visibility::Internal);
    assert_eq!(
        tagged.kind.arguments.as_ref(),
        &[ManifestKind::Symbol, ManifestKind::Type]
    );
    assert_eq!(tagged.kind.result, ManifestKind::Type);
}

#[test]
fn recursive_entailment_is_distinct_from_unconditional_parameterized_heads() {
    fn resolves(class: TypeClass, target: &str, children: &[bool]) -> bool {
        resolve_instance(class, target, children.len(), |index| children[index])
    }

    assert!(resolves(TypeClass::Show, "Either", &[true, true]));
    assert!(!resolves(TypeClass::Show, "Either", &[true, false]));
    assert!(!resolves(TypeClass::Eq, "Maybe", &[false]));
    assert!(!resolves(TypeClass::Semigroup, "Maybe", &[false]));

    assert!(resolves(TypeClass::Semigroup, "[]", &[false]));
    assert!(resolves(TypeClass::Monad, "IO", &[]));
    assert!(!resolves(TypeClass::Monad, "IO", &[true]));
    assert!(resolves(TypeClass::Monad, "Either", &[false]));
    assert!(resolves(TypeClass::Functor, "(,)", &[false]));
    assert!(resolves(TypeClass::Monoid, "Options.Mod", &[false, false]));
}
