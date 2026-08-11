use hell_core::{Constant, CoreId, CoreKind, CoreNode, CoreProgram, verify};
use hell_source::{SourceId, Span};
use hell_types::{ClosedTypeId, KindArena, TypeArena, TypeId, Unifier};

fn closed(types: &mut TypeArena, ty: TypeId) -> ClosedTypeId {
    Unifier::default()
        .zonk(types, ty)
        .expect("fixture type is closed")
}

fn internal_types(types: &mut TypeArena) -> Vec<(&'static str, TypeId)> {
    let unit = types.constructor("()", KindArena::TYPE);
    let nullary = types.constructor("hell:Hell.Nullary", KindArena::TYPE);
    let record = types.constructor("hell:Hell.Record", KindArena::TYPE);
    let variant = types.constructor("hell:Hell.Variant", KindArena::TYPE);
    let accessor = types.constructor("hell:Hell.Accessor", KindArena::TYPE);
    let tagged = types.constructor("hell:Hell.Tagged", KindArena::TYPE);
    let handler = types.function(nullary, unit);
    let record_cons_tail = types.function(record, record);
    let record_cons = types.function(nullary, record_cons_tail);
    let accessor_cons_tail = types.function(accessor, accessor);
    let accessor_cons = types.function(handler, accessor_cons_tail);
    let run_tail = types.function(accessor, unit);
    vec![
        ("hell:Hell.ConsA", accessor_cons),
        ("hell:Hell.ConsR", record_cons),
        ("hell:Hell.LeftV", types.function(nullary, variant)),
        ("hell:Hell.NilA", accessor),
        ("hell:Hell.NilR", record),
        ("hell:Hell.Nullary", nullary),
        ("hell:Hell.RightV", types.function(variant, variant)),
        ("hell:Hell.Tagged", types.function(variant, tagged)),
        ("hell:Hell.WildA", types.function(unit, accessor)),
        ("hell:Hell.runAccessor", types.function(tagged, run_tail)),
    ]
}

fn wrapped_program(mut types: TypeArena, name: &str, internal_type: TypeId) -> CoreProgram {
    let span = Span::empty(SourceId(0), 0);
    let unit = types.constructor("()", KindArena::TYPE);
    let mut kinds = KindArena::default();
    let io_unit = types.io(unit, &mut kinds);
    let pure_type = types.function(unit, io_unit);
    let lambda_type = types.function(internal_type, io_unit);
    let internal_type = closed(&mut types, internal_type);
    let unit = closed(&mut types, unit);
    let io_unit = closed(&mut types, io_unit);
    let pure_type = closed(&mut types, pure_type);
    let lambda_type = closed(&mut types, lambda_type);
    let internal = hell_builtins::lookup(name).expect("internal registry entry");
    let pure = hell_builtins::lookup("IO.pure").expect("IO.pure registry entry");
    CoreProgram {
        root: CoreId(5),
        nodes: vec![
            CoreNode {
                ty: internal_type,
                span,
                kind: CoreKind::Builtin {
                    builtin: internal.id,
                    evidence: None,
                },
            },
            CoreNode {
                ty: unit,
                span,
                kind: CoreKind::Constant(Constant::Unit),
            },
            CoreNode {
                ty: pure_type,
                span,
                kind: CoreKind::Builtin {
                    builtin: pure.id,
                    evidence: None,
                },
            },
            CoreNode {
                ty: io_unit,
                span,
                kind: CoreKind::Apply {
                    function: CoreId(2),
                    argument: CoreId(1),
                },
            },
            CoreNode {
                ty: lambda_type,
                span,
                kind: CoreKind::Lambda {
                    parameter_type: internal_type,
                    body: CoreId(3),
                },
            },
            CoreNode {
                ty: io_unit,
                span,
                kind: CoreKind::Apply {
                    function: CoreId(4),
                    argument: CoreId(0),
                },
            },
        ],
        types,
        main_type: io_unit,
        instance_evidence: Vec::new(),
        #[cfg(feature = "compat-tracing")]
        compiler_evidence: hell_core::CompilerBuiltinEvidence::default(),
    }
}

#[test]
fn every_internal_registry_entry_crosses_the_independent_core_boundary() {
    let mut types = TypeArena::default();
    let entries = internal_types(&mut types);
    assert_eq!(entries.len(), 10);
    for (name, ty) in entries {
        verify(wrapped_program(types.clone(), name, ty))
            .unwrap_or_else(|error| panic!("{name} did not verify: {error}"));
    }
}

#[test]
fn internal_registry_entries_reject_unrelated_stored_types() {
    let mut types = TypeArena::default();
    let text = types.constructor("Text", KindArena::TYPE);
    let error = verify(wrapped_program(types, "hell:Hell.NilR", text))
        .expect_err("NilR typed as Text must fail verification");
    assert_eq!(error.code, "H0703");
    assert_eq!(
        error.message.as_ref(),
        "built-in type does not instantiate its registry scheme"
    );
}
