use hell_core::{Constant, CoreId, CoreKind, CoreNode, CoreProgram, VerifiedProgram, verify};
use hell_runtime::{RuntimeContext, run_main};
use hell_source::{SourceId, Span};
use hell_types::{ClosedTypeId, KindArena, TypeArena, TypeId, Unifier};

struct CoreBuilder {
    types: TypeArena,
    nodes: Vec<CoreNode>,
    span: Span,
    unit: TypeId,
    io_unit: TypeId,
}

impl CoreBuilder {
    fn new() -> Self {
        let mut types = TypeArena::default();
        let mut kinds = KindArena::default();
        let unit = types.constructor("()", KindArena::TYPE);
        let io_unit = types.io(unit, &mut kinds);
        Self {
            types,
            nodes: Vec::new(),
            span: Span::empty(SourceId(0), 0),
            unit,
            io_unit,
        }
    }

    fn closed(&mut self, ty: TypeId) -> ClosedTypeId {
        Unifier::default()
            .zonk(&mut self.types, ty)
            .expect("fixture type is closed")
    }

    fn push(&mut self, ty: TypeId, kind: CoreKind) -> CoreId {
        let ty = self.closed(ty);
        let id = CoreId(u32::try_from(self.nodes.len()).expect("fixture core id overflow"));
        self.nodes.push(CoreNode {
            ty,
            span: self.span,
            kind,
        });
        id
    }

    fn builtin(&mut self, name: &str, ty: TypeId) -> CoreId {
        let builtin = hell_builtins::lookup(name).expect("fixture builtin");
        self.push(
            ty,
            CoreKind::Builtin {
                builtin: builtin.id,
                evidence: None,
            },
        )
    }

    fn apply(&mut self, function: CoreId, argument: CoreId, result: TypeId) -> CoreId {
        self.push(result, CoreKind::Apply { function, argument })
    }

    fn pure_unit(&mut self) -> CoreId {
        let pure_type = self.types.function(self.unit, self.io_unit);
        let pure = self.builtin("IO.pure", pure_type);
        let unit = self.push(self.unit, CoreKind::Constant(Constant::Unit));
        self.apply(pure, unit, self.io_unit)
    }

    fn ignore_handler(&mut self, parameter: TypeId) -> CoreId {
        let body = self.pure_unit();
        let ty = self.types.function(parameter, self.io_unit);
        let parameter_type = self.closed(parameter);
        self.push(
            ty,
            CoreKind::Lambda {
                parameter_type,
                body,
            },
        )
    }

    fn finish(mut self, root: CoreId) -> VerifiedProgram {
        let main_type = self.closed(self.io_unit);
        verify(CoreProgram {
            root,
            nodes: self.nodes,
            types: self.types,
            main_type,
            instance_evidence: Vec::new(),
            compiler_evidence: hell_core::CompilerBuiltinEvidence::default(),
        })
        .expect("internal compatibility fixture verifies")
    }
}

fn tagged_right_variant(
    builder: &mut CoreBuilder,
    nullary: TypeId,
    variant: TypeId,
    tagged: TypeId,
) -> CoreId {
    let nullary_value = builder.builtin("hell:Hell.Nullary", nullary);
    let left_type = builder.types.function(nullary, variant);
    let left = builder.builtin("hell:Hell.LeftV", left_type);
    let left = builder.apply(left, nullary_value, variant);
    let right_type = builder.types.function(variant, variant);
    let right = builder.builtin("hell:Hell.RightV", right_type);
    let right = builder.apply(right, left, variant);
    let tagged_type = builder.types.function(variant, tagged);
    let tagged_function = builder.builtin("hell:Hell.Tagged", tagged_type);
    builder.apply(tagged_function, right, tagged)
}

#[test]
fn internal_accessor_spine_selects_the_matching_right_variant_handler() {
    let mut builder = CoreBuilder::new();
    let nullary = builder
        .types
        .constructor("hell:Hell.Nullary", KindArena::TYPE);
    let variant = builder
        .types
        .constructor("hell:Hell.Variant", KindArena::TYPE);
    let tagged = builder
        .types
        .constructor("hell:Hell.Tagged", KindArena::TYPE);
    let accessor = builder
        .types
        .constructor("hell:Hell.Accessor", KindArena::TYPE);
    let tagged_value = tagged_right_variant(&mut builder, nullary, variant, tagged);
    let nil = builder.builtin("hell:Hell.NilA", accessor);
    let handler_type = builder.types.function(nullary, builder.io_unit);
    let cons_tail = builder.types.function(accessor, accessor);
    let cons_type = builder.types.function(handler_type, cons_tail);
    let second_handler = builder.ignore_handler(nullary);
    let second_cons = builder.builtin("hell:Hell.ConsA", cons_type);
    let second_cons = builder.apply(second_cons, second_handler, cons_tail);
    let accessor_value = builder.apply(second_cons, nil, accessor);
    let first_handler = builder.ignore_handler(nullary);
    let first_cons = builder.builtin("hell:Hell.ConsA", cons_type);
    let first_cons = builder.apply(first_cons, first_handler, cons_tail);
    let accessor_value = builder.apply(first_cons, accessor_value, accessor);
    let run_tail = builder.types.function(accessor, builder.io_unit);
    let run_type = builder.types.function(tagged, run_tail);
    let run = builder.builtin("hell:Hell.runAccessor", run_type);
    let run = builder.apply(run, tagged_value, run_tail);
    let root = builder.apply(run, accessor_value, builder.io_unit);
    run_main(
        builder.finish(root),
        RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
    )
    .expect("selected internal accessor returns IO ()");
}

#[test]
fn internal_wild_accessor_handles_an_unlisted_variant() {
    let mut builder = CoreBuilder::new();
    let nullary = builder
        .types
        .constructor("hell:Hell.Nullary", KindArena::TYPE);
    let variant = builder
        .types
        .constructor("hell:Hell.Variant", KindArena::TYPE);
    let tagged = builder
        .types
        .constructor("hell:Hell.Tagged", KindArena::TYPE);
    let accessor = builder
        .types
        .constructor("hell:Hell.Accessor", KindArena::TYPE);
    let tagged_value = tagged_right_variant(&mut builder, nullary, variant, tagged);
    let fallback = builder.pure_unit();
    let wild_type = builder.types.function(builder.io_unit, accessor);
    let wild = builder.builtin("hell:Hell.WildA", wild_type);
    let wild = builder.apply(wild, fallback, accessor);
    let handler_type = builder.types.function(nullary, builder.io_unit);
    let cons_tail = builder.types.function(accessor, accessor);
    let cons_type = builder.types.function(handler_type, cons_tail);
    let handler = builder.ignore_handler(nullary);
    let cons = builder.builtin("hell:Hell.ConsA", cons_type);
    let cons = builder.apply(cons, handler, cons_tail);
    let accessor_value = builder.apply(cons, wild, accessor);
    let run_tail = builder.types.function(accessor, builder.io_unit);
    let run_type = builder.types.function(tagged, run_tail);
    let run = builder.builtin("hell:Hell.runAccessor", run_type);
    let run = builder.apply(run, tagged_value, run_tail);
    let root = builder.apply(run, accessor_value, builder.io_unit);
    run_main(
        builder.finish(root),
        RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
    )
    .expect("wild internal accessor returns IO ()");
}
