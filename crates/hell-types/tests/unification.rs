use hell_types::{KindArena, KindNode, TypeArena, TypeError, Unifier};

#[test]
fn unifies_function_types_and_zonks() {
    let mut kinds = KindArena::default();
    let mut types = TypeArena::default();
    let mut unifier = Unifier::default();
    let int = types.constructor("Int", KindArena::TYPE);
    let unknown = unifier.fresh(&mut types, KindArena::TYPE);
    let left = types.function(unknown, unknown);
    let right = types.function(int, int);
    unifier.unify(&mut types, &kinds, left, right).unwrap();
    let closed = unifier.zonk(&mut types, left).unwrap();
    assert_eq!(types.display(closed.raw()), "Int -> Int");

    let constructor_kind = kinds.intern(KindNode::Arrow(KindArena::TYPE, KindArena::TYPE));
    assert_ne!(constructor_kind, KindArena::TYPE);
}

#[test]
fn occurs_check_rejects_infinite_type() {
    let kinds = KindArena::default();
    let mut types = TypeArena::default();
    let mut unifier = Unifier::default();
    let unknown = unifier.fresh(&mut types, KindArena::TYPE);
    let recursive = types.list(unknown, &mut kinds.clone());
    assert!(matches!(
        unifier.unify(&mut types, &kinds, unknown, recursive),
        Err(TypeError::Occurs { .. })
    ));
}
