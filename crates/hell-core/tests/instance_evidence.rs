use std::sync::Arc;

use hell_builtins::{InstanceResolution, TypeClass};
use hell_core::{
    ClassEvidence, CompilerBuiltinEvidence, Constant, CoreId, CoreKind, CoreNode, CoreProgram,
    InstanceEvidencePlan, InstanceEvidencePlanId, verify,
};
use hell_source::{SourceId, Span};
use hell_types::{KindArena, KindNode, TypeArena, TypeId, Unifier};

fn closed(types: &mut TypeArena, ty: TypeId) -> hell_types::ClosedTypeId {
    Unifier::default()
        .zonk(types, ty)
        .expect("fixture type is closed")
}

fn node(ty: hell_types::ClosedTypeId, kind: CoreKind) -> CoreNode {
    CoreNode {
        ty,
        span: Span::empty(SourceId(0), 0),
        kind,
    }
}

fn builtin_node(
    ty: hell_types::ClosedTypeId,
    name: &str,
    evidence: Option<ClassEvidence>,
) -> CoreNode {
    node(
        ty,
        CoreKind::Builtin {
            builtin: hell_builtins::lookup(name).unwrap().id,
            evidence,
        },
    )
}

fn apply_node(ty: hell_types::ClosedTypeId, function: u32, argument: u32) -> CoreNode {
    node(
        ty,
        CoreKind::Apply {
            function: CoreId(function),
            argument: CoreId(argument),
        },
    )
}

fn list_node<const N: usize>(ty: hell_types::ClosedTypeId, elements: [CoreId; N]) -> CoreNode {
    node(
        ty,
        CoreKind::List {
            elements: Arc::from(elements),
        },
    )
}

fn eq_program(evidence_head_is_text: bool) -> CoreProgram {
    let span = Span::empty(SourceId(0), 0);
    let mut kinds = KindArena::default();
    let mut types = TypeArena::default();
    let unit = types.constructor("()", KindArena::TYPE);
    let boolean = types.constructor("Bool", KindArena::TYPE);
    let int = types.constructor("Int", KindArena::TYPE);
    let text = types.constructor("Text", KindArena::TYPE);
    let io_unit = types.io(unit, &mut kinds);
    let eq_tail = types.function(int, boolean);
    let eq_type = types.function(int, eq_tail);
    let print_type = types.function(boolean, io_unit);
    let evidence_head = if evidence_head_is_text { text } else { int };
    let int_closed = closed(&mut types, int);
    let bool_closed = closed(&mut types, boolean);
    let io_unit_closed = closed(&mut types, io_unit);
    let eq_tail_closed = closed(&mut types, eq_tail);
    let eq_type_closed = closed(&mut types, eq_type);
    let print_type_closed = closed(&mut types, print_type);
    let evidence_head_closed = closed(&mut types, evidence_head);
    CoreProgram {
        root: CoreId(6),
        nodes: vec![
            CoreNode {
                ty: eq_type_closed,
                span,
                kind: CoreKind::Builtin {
                    builtin: hell_builtins::lookup("Eq.eq").unwrap().id,
                    evidence: Some(ClassEvidence {
                        class: TypeClass::Eq,
                        head: evidence_head_closed,
                        plan: InstanceEvidencePlanId(0),
                    }),
                },
            },
            CoreNode {
                ty: int_closed,
                span,
                kind: CoreKind::Constant(Constant::Int(1)),
            },
            CoreNode {
                ty: eq_tail_closed,
                span,
                kind: CoreKind::Apply {
                    function: CoreId(0),
                    argument: CoreId(1),
                },
            },
            CoreNode {
                ty: int_closed,
                span,
                kind: CoreKind::Constant(Constant::Int(1)),
            },
            CoreNode {
                ty: bool_closed,
                span,
                kind: CoreKind::Apply {
                    function: CoreId(2),
                    argument: CoreId(3),
                },
            },
            CoreNode {
                ty: print_type_closed,
                span,
                kind: CoreKind::Builtin {
                    builtin: hell_builtins::lookup("IO.print").unwrap().id,
                    evidence: Some(ClassEvidence {
                        class: TypeClass::Show,
                        head: bool_closed,
                        plan: InstanceEvidencePlanId(1),
                    }),
                },
            },
            CoreNode {
                ty: io_unit_closed,
                span,
                kind: CoreKind::Apply {
                    function: CoreId(5),
                    argument: CoreId(4),
                },
            },
        ],
        types,
        main_type: io_unit_closed,
        instance_evidence: vec![
            InstanceEvidencePlan {
                class: TypeClass::Eq,
                head: evidence_head,
                resolution: InstanceResolution::Direct(0),
                premises: Arc::from([]),
            },
            InstanceEvidencePlan {
                class: TypeClass::Show,
                head: boolean,
                resolution: InstanceResolution::Direct(0),
                premises: Arc::from([]),
            },
        ],
        compiler_evidence: CompilerBuiltinEvidence::default(),
    }
}

fn entailed_eq_program() -> CoreProgram {
    let mut kinds = KindArena::default();
    let mut types = TypeArena::default();
    let unit = types.constructor("()", KindArena::TYPE);
    let int = types.constructor("Int", KindArena::TYPE);
    let boolean = types.constructor("Bool", KindArena::TYPE);
    let list_int = types.list(int, &mut kinds);
    let io_unit = types.io(unit, &mut kinds);
    let eq_tail = types.function(list_int, boolean);
    let eq_type = types.function(list_int, eq_tail);
    let print_type = types.function(boolean, io_unit);
    let int_closed = closed(&mut types, int);
    let list_int_closed = closed(&mut types, list_int);
    let bool_closed = closed(&mut types, boolean);
    let io_unit_closed = closed(&mut types, io_unit);
    let eq_tail_closed = closed(&mut types, eq_tail);
    let eq_type_closed = closed(&mut types, eq_type);
    let print_type_closed = closed(&mut types, print_type);
    CoreProgram {
        root: CoreId(8),
        nodes: vec![
            builtin_node(
                eq_type_closed,
                "Eq.eq",
                Some(ClassEvidence {
                    class: TypeClass::Eq,
                    head: list_int_closed,
                    plan: InstanceEvidencePlanId(0),
                }),
            ),
            node(int_closed, CoreKind::Constant(Constant::Int(1))),
            list_node(list_int_closed, [CoreId(1)]),
            apply_node(eq_tail_closed, 0, 2),
            node(int_closed, CoreKind::Constant(Constant::Int(1))),
            list_node(list_int_closed, [CoreId(4)]),
            apply_node(bool_closed, 3, 5),
            builtin_node(
                print_type_closed,
                "IO.print",
                Some(ClassEvidence {
                    class: TypeClass::Show,
                    head: bool_closed,
                    plan: InstanceEvidencePlanId(2),
                }),
            ),
            apply_node(io_unit_closed, 7, 6),
        ],
        types,
        main_type: io_unit_closed,
        instance_evidence: vec![
            InstanceEvidencePlan {
                class: TypeClass::Eq,
                head: list_int,
                resolution: InstanceResolution::Entail(1),
                premises: Arc::from([InstanceEvidencePlanId(1)]),
            },
            InstanceEvidencePlan {
                class: TypeClass::Eq,
                head: int,
                resolution: InstanceResolution::Direct(0),
                premises: Arc::from([]),
            },
            InstanceEvidencePlan {
                class: TypeClass::Show,
                head: boolean,
                resolution: InstanceResolution::Direct(0),
                premises: Arc::from([]),
            },
        ],
        compiler_evidence: CompilerBuiltinEvidence::default(),
    }
}

fn functor_program(evidence_head_is_maybe: bool) -> CoreProgram {
    let mut kinds = KindArena::default();
    let mut types = TypeArena::default();
    let unary = kinds.intern(KindNode::Arrow(KindArena::TYPE, KindArena::TYPE));
    let maybe = types.constructor("Maybe", unary);
    let list = types.constructor("[]", unary);
    let unit = types.constructor("()", KindArena::TYPE);
    let int = types.constructor("Int", KindArena::TYPE);
    let text = types.constructor("Text", KindArena::TYPE);
    let list_int = types.apply(list, int);
    let list_text = types.apply(list, text);
    let io_unit = types.io(unit, &mut kinds);
    let transform = types.function(int, text);
    let mapped = types.function(list_int, list_text);
    let fmap = types.function(transform, mapped);
    let print = types.function(list_text, io_unit);
    let int_closed = closed(&mut types, int);
    let list_int_closed = closed(&mut types, list_int);
    let list_text_closed = closed(&mut types, list_text);
    let io_unit_closed = closed(&mut types, io_unit);
    let transform_closed = closed(&mut types, transform);
    let mapped_closed = closed(&mut types, mapped);
    let fmap_closed = closed(&mut types, fmap);
    let print_closed = closed(&mut types, print);
    let evidence_head = if evidence_head_is_maybe { maybe } else { list };
    let evidence_head_closed = closed(&mut types, evidence_head);
    CoreProgram {
        root: CoreId(7),
        nodes: vec![
            builtin_node(
                fmap_closed,
                "Functor.fmap",
                Some(ClassEvidence {
                    class: TypeClass::Functor,
                    head: evidence_head_closed,
                    plan: InstanceEvidencePlanId(0),
                }),
            ),
            builtin_node(transform_closed, "Int.show", None),
            apply_node(mapped_closed, 0, 1),
            node(int_closed, CoreKind::Constant(Constant::Int(1))),
            list_node(list_int_closed, [CoreId(3)]),
            apply_node(list_text_closed, 2, 4),
            builtin_node(
                print_closed,
                "IO.print",
                Some(ClassEvidence {
                    class: TypeClass::Show,
                    head: list_text_closed,
                    plan: InstanceEvidencePlanId(1),
                }),
            ),
            apply_node(io_unit_closed, 6, 5),
        ],
        types,
        main_type: io_unit_closed,
        instance_evidence: vec![
            InstanceEvidencePlan {
                class: TypeClass::Functor,
                head: evidence_head,
                resolution: InstanceResolution::Direct(0),
                premises: Arc::from([]),
            },
            InstanceEvidencePlan {
                class: TypeClass::Show,
                head: list_text,
                resolution: InstanceResolution::Entail(1),
                premises: Arc::from([InstanceEvidencePlanId(2)]),
            },
            InstanceEvidencePlan {
                class: TypeClass::Show,
                head: text,
                resolution: InstanceResolution::Direct(0),
                premises: Arc::from([]),
            },
        ],
        compiler_evidence: CompilerBuiltinEvidence::default(),
    }
}

#[test]
fn verifier_binds_same_class_evidence_plan_to_builtin_instantiation() {
    verify(eq_program(false)).expect("Eq Int evidence matches the Eq.eq instantiation");
    let error = verify(eq_program(true)).expect_err("Eq Text evidence cannot bless Eq.eq at Int");
    assert_eq!(error.code, "H0703");
    assert!(error.message.contains("class evidence"));
}

#[test]
fn verifier_rejects_every_recursive_plan_graph_substitution() {
    verify(entailed_eq_program()).expect("canonical Eq Maybe evidence is accepted");

    let mut missing = entailed_eq_program();
    missing.instance_evidence[0].premises = Arc::from([]);
    assert!(verify(missing).is_err());

    let mut extra = entailed_eq_program();
    extra.instance_evidence[0].premises =
        Arc::from([InstanceEvidencePlanId(1), InstanceEvidencePlanId(1)]);
    assert!(verify(extra).is_err());

    let mut cycle = entailed_eq_program();
    cycle.instance_evidence[0].premises = Arc::from([InstanceEvidencePlanId(0)]);
    assert!(verify(cycle).is_err());

    let mut wrong_resolution = entailed_eq_program();
    wrong_resolution.instance_evidence[0].resolution = InstanceResolution::Direct(0);
    assert!(verify(wrong_resolution).is_err());

    let mut wrong_child = entailed_eq_program();
    let text = wrong_child.types.constructor("Text", KindArena::TYPE);
    wrong_child.instance_evidence[1].head = text;
    assert!(verify(wrong_child).is_err());

    let mut orphan = entailed_eq_program();
    let boolean = orphan.types.constructor("Bool", KindArena::TYPE);
    orphan.instance_evidence.push(InstanceEvidencePlan {
        class: TypeClass::Eq,
        head: boolean,
        resolution: InstanceResolution::Direct(0),
        premises: Arc::from([]),
    });
    assert!(verify(orphan).is_err());

    let mut duplicate_identity = entailed_eq_program();
    let int = duplicate_identity
        .instance_evidence
        .get(1)
        .expect("Eq Int premise")
        .head;
    let boolean = duplicate_identity
        .types
        .constructor("Bool", KindArena::TYPE);
    let eq_tail = duplicate_identity.types.function(int, boolean);
    let eq_type = duplicate_identity.types.function(int, eq_tail);
    let eq_type = closed(&mut duplicate_identity.types, eq_type);
    let int_closed = closed(&mut duplicate_identity.types, int);
    duplicate_identity
        .instance_evidence
        .push(duplicate_identity.instance_evidence[1].clone());
    duplicate_identity.nodes.push(CoreNode {
        ty: eq_type,
        span: Span::empty(SourceId(0), 0),
        kind: CoreKind::Builtin {
            builtin: hell_builtins::lookup("Eq.eq").unwrap().id,
            evidence: Some(ClassEvidence {
                class: TypeClass::Eq,
                head: int_closed,
                plan: InstanceEvidencePlanId(3),
            }),
        },
    });
    assert!(verify(duplicate_identity).is_err());
}

#[test]
fn verifier_binds_higher_kinded_plan_to_functor_instantiation() {
    verify(functor_program(false)).expect("Functor List evidence matches fmap");
    let error = verify(functor_program(true)).expect_err("Functor Maybe cannot bless fmap at List");
    assert_eq!(error.code, "H0703");
    assert!(error.message.contains("class evidence"));
}
