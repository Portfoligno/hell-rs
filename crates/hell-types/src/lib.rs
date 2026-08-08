//! Kinded Hell types, monomorphic unification, rows, and closed evidence.

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write as _};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KindId(pub u32);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KindNode {
    Type,
    Constraint,
    Symbol,
    Row,
    StreamType,
    Opaque(Arc<str>),
    Arrow(KindId, KindId),
}

#[derive(Clone, Debug)]
pub struct KindArena {
    nodes: Vec<KindNode>,
    interned: HashMap<KindNode, KindId>,
}

impl Default for KindArena {
    fn default() -> Self {
        let mut arena = Self {
            nodes: Vec::new(),
            interned: HashMap::new(),
        };
        for kind in [
            KindNode::Type,
            KindNode::Constraint,
            KindNode::Symbol,
            KindNode::Row,
            KindNode::StreamType,
        ] {
            arena.intern(kind);
        }
        arena
    }
}

impl KindArena {
    pub const TYPE: KindId = KindId(0);
    pub const CONSTRAINT: KindId = KindId(1);
    pub const SYMBOL: KindId = KindId(2);
    pub const ROW: KindId = KindId(3);
    pub const STREAM_TYPE: KindId = KindId(4);

    /// Interns a kind node.
    ///
    /// # Panics
    ///
    /// Panics if more than `u32::MAX` distinct kinds are interned.
    pub fn intern(&mut self, node: KindNode) -> KindId {
        if let Some(id) = self.interned.get(&node) {
            return *id;
        }
        let id = KindId(u32::try_from(self.nodes.len()).expect("kind arena overflow"));
        self.nodes.push(node.clone());
        self.interned.insert(node, id);
        id
    }

    #[must_use]
    pub fn get(&self, id: KindId) -> &KindNode {
        &self.nodes[id.0 as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClosedTypeId(TypeId);

impl ClosedTypeId {
    #[must_use]
    pub const fn raw(self) -> TypeId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MetaId(pub u32);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TypeNode {
    Meta(MetaId),
    Bound(u16),
    Constructor {
        name: Arc<str>,
        kind: KindId,
    },
    Apply(TypeId, TypeId),
    Function(TypeId, TypeId),
    Symbol(Arc<str>),
    RowNil,
    RowCons {
        label: Arc<str>,
        field: TypeId,
        tail: TypeId,
    },
}

#[derive(Clone, Debug, Default)]
pub struct TypeArena {
    nodes: Vec<TypeNode>,
    interned: HashMap<TypeNode, TypeId>,
}

impl TypeArena {
    /// Interns a type node.
    ///
    /// # Panics
    ///
    /// Panics if more than `u32::MAX` type nodes are allocated.
    pub fn intern(&mut self, node: TypeNode) -> TypeId {
        if !matches!(node, TypeNode::Meta(_))
            && let Some(id) = self.interned.get(&node)
        {
            return *id;
        }
        let id = TypeId(u32::try_from(self.nodes.len()).expect("type arena overflow"));
        self.nodes.push(node.clone());
        if !matches!(node, TypeNode::Meta(_)) {
            self.interned.insert(node, id);
        }
        id
    }

    #[must_use]
    pub fn get(&self, id: TypeId) -> &TypeNode {
        &self.nodes[id.0 as usize]
    }

    pub fn constructor(&mut self, name: impl Into<Arc<str>>, kind: KindId) -> TypeId {
        self.intern(TypeNode::Constructor {
            name: name.into(),
            kind,
        })
    }

    pub fn function(&mut self, argument: TypeId, result: TypeId) -> TypeId {
        self.intern(TypeNode::Function(argument, result))
    }

    pub fn apply(&mut self, constructor: TypeId, argument: TypeId) -> TypeId {
        self.intern(TypeNode::Apply(constructor, argument))
    }

    pub fn list(&mut self, item: TypeId, kinds: &mut KindArena) -> TypeId {
        let list_kind = kinds.intern(KindNode::Arrow(KindArena::TYPE, KindArena::TYPE));
        let list = self.constructor("[]", list_kind);
        self.apply(list, item)
    }

    pub fn io(&mut self, item: TypeId, kinds: &mut KindArena) -> TypeId {
        let io_kind = kinds.intern(KindNode::Arrow(KindArena::TYPE, KindArena::TYPE));
        let io = self.constructor("IO", io_kind);
        self.apply(io, item)
    }

    /// Constructs a pair, triple, or quadruple type.
    ///
    /// # Panics
    ///
    /// Panics when `items` has an unsupported arity.
    pub fn tuple(&mut self, items: &[TypeId], kinds: &mut KindArena) -> TypeId {
        let mut kind = KindArena::TYPE;
        for _ in items {
            kind = kinds.intern(KindNode::Arrow(KindArena::TYPE, kind));
        }
        let name: Arc<str> = match items.len() {
            2 => "(,)",
            3 => "(,,)",
            4 => "(,,,)",
            _ => panic!("tuple arity invariant"),
        }
        .into();
        let mut ty = self.constructor(name, kind);
        for item in items {
            ty = self.apply(ty, *item);
        }
        ty
    }

    /// Computes the kind of a type while validating all child kinds.
    ///
    /// # Errors
    ///
    /// Returns a kind mismatch, invalid application, or escaped-bound error
    /// when the type is not well-kinded.
    #[allow(clippy::missing_panics_doc)]
    pub fn kind_of(
        &self,
        kinds: &KindArena,
        ty: TypeId,
        meta_kinds: impl Fn(MetaId) -> KindId + Copy,
    ) -> Result<KindId, TypeError> {
        enum Work {
            Visit(TypeId),
            Function,
            Row,
            Apply,
        }

        let mut work = vec![Work::Visit(ty)];
        let mut results = Vec::new();
        while let Some(next) = work.pop() {
            match next {
                Work::Visit(ty) => match self.get(ty) {
                    TypeNode::Meta(meta) => results.push(meta_kinds(*meta)),
                    TypeNode::Bound(_) => {
                        return Err(TypeError::Internal("unsubstituted bound type".into()));
                    }
                    TypeNode::Constructor { kind, .. } => results.push(*kind),
                    TypeNode::Function(argument, result) => {
                        work.push(Work::Function);
                        work.push(Work::Visit(*result));
                        work.push(Work::Visit(*argument));
                    }
                    TypeNode::Symbol(_) => results.push(KindArena::SYMBOL),
                    TypeNode::RowNil => results.push(KindArena::ROW),
                    TypeNode::RowCons { field, tail, .. } => {
                        work.push(Work::Row);
                        work.push(Work::Visit(*tail));
                        work.push(Work::Visit(*field));
                    }
                    TypeNode::Apply(function, argument) => {
                        work.push(Work::Apply);
                        work.push(Work::Visit(*argument));
                        work.push(Work::Visit(*function));
                    }
                },
                Work::Function => {
                    let result = results.pop().expect("function result kind computed");
                    let argument = results.pop().expect("function argument kind computed");
                    if argument != KindArena::TYPE {
                        return Err(TypeError::KindMismatch {
                            expected: KindArena::TYPE,
                            actual: argument,
                        });
                    }
                    if result != KindArena::TYPE {
                        return Err(TypeError::KindMismatch {
                            expected: KindArena::TYPE,
                            actual: result,
                        });
                    }
                    results.push(KindArena::TYPE);
                }
                Work::Row => {
                    let tail = results.pop().expect("row tail kind computed");
                    let field = results.pop().expect("row field kind computed");
                    if field != KindArena::TYPE {
                        return Err(TypeError::KindMismatch {
                            expected: KindArena::TYPE,
                            actual: field,
                        });
                    }
                    if tail != KindArena::ROW {
                        return Err(TypeError::KindMismatch {
                            expected: KindArena::ROW,
                            actual: tail,
                        });
                    }
                    results.push(KindArena::ROW);
                }
                Work::Apply => {
                    let argument = results.pop().expect("type argument kind computed");
                    let function = results.pop().expect("type function kind computed");
                    match kinds.get(function) {
                        KindNode::Arrow(expected, result) if *expected == argument => {
                            results.push(*result);
                        }
                        KindNode::Arrow(expected, _) => {
                            return Err(TypeError::KindMismatch {
                                expected: *expected,
                                actual: argument,
                            });
                        }
                        _ => return Err(TypeError::NotATypeConstructor(function)),
                    }
                }
            }
        }
        Ok(results.pop().expect("root kind computed"))
    }

    #[must_use]
    pub fn display(&self, ty: TypeId) -> String {
        enum Work {
            Visit(TypeId, u8),
            Text(&'static str),
            Character(char),
        }

        let mut result = String::new();
        let mut work = vec![Work::Visit(ty, 0)];
        while let Some(next) = work.pop() {
            match next {
                Work::Text(text) => result.push_str(text),
                Work::Character(character) => result.push(character),
                Work::Visit(ty, precedence) => match self.get(ty) {
                    TypeNode::Meta(id) => {
                        write!(result, "t{}", id.0).expect("writing to String");
                    }
                    TypeNode::Bound(id) => {
                        write!(result, "a{id}").expect("writing to String");
                    }
                    TypeNode::Constructor { name, .. } => result.push_str(name),
                    TypeNode::Symbol(value) => {
                        result.push('"');
                        result.push_str(value);
                        result.push('"');
                    }
                    TypeNode::RowNil => result.push_str("{}"),
                    TypeNode::RowCons { label, field, tail } => {
                        result.push('{');
                        result.push_str(label);
                        result.push_str(" :: ");
                        work.push(Work::Character('}'));
                        if !matches!(self.get(*tail), TypeNode::RowNil) {
                            work.push(Work::Text(", .."));
                        }
                        work.push(Work::Visit(*field, 0));
                    }
                    TypeNode::Function(argument, function_result) => {
                        let parenthesized = precedence > 0;
                        if parenthesized {
                            result.push('(');
                            work.push(Work::Character(')'));
                        }
                        work.push(Work::Visit(*function_result, 0));
                        work.push(Work::Text(" -> "));
                        work.push(Work::Visit(*argument, 1));
                    }
                    TypeNode::Apply(function, argument) => {
                        if let TypeNode::Constructor { name, .. } = self.get(*function)
                            && name.as_ref() == "[]"
                        {
                            result.push('[');
                            work.push(Work::Character(']'));
                            work.push(Work::Visit(*argument, 0));
                            continue;
                        }
                        let parenthesized = precedence > 1;
                        if parenthesized {
                            result.push('(');
                            work.push(Work::Character(')'));
                        }
                        work.push(Work::Visit(*argument, 2));
                        work.push(Work::Character(' '));
                        work.push(Work::Visit(*function, 1));
                    }
                },
            }
        }
        result
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemeBinder {
    pub name: Arc<str>,
    pub kind: KindId,
    pub visible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassConstraint {
    pub class: Arc<str>,
    pub argument: TypeId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scheme {
    pub binders: Arc<[SchemeBinder]>,
    pub constraints: Arc<[ClassConstraint]>,
    pub body: TypeId,
}

#[derive(Clone, Debug)]
struct MetaVar {
    kind: KindId,
    binding: Option<TypeId>,
}

#[derive(Clone, Debug, Default)]
pub struct Unifier {
    metas: Vec<MetaVar>,
    zonked: HashMap<TypeId, TypeId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeError {
    Mismatch { left: TypeId, right: TypeId },
    KindMismatch { expected: KindId, actual: KindId },
    NotATypeConstructor(KindId),
    Occurs { meta: MetaId, within: TypeId },
    Ambiguous(MetaId),
    Internal(Arc<str>),
}

impl fmt::Display for TypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch { .. } => f.write_str("type mismatch"),
            Self::KindMismatch { .. } => f.write_str("kind mismatch"),
            Self::NotATypeConstructor(_) => f.write_str("type is not a type constructor"),
            Self::Occurs { meta, .. } => write!(f, "infinite type involving t{}", meta.0),
            Self::Ambiguous(meta) => write!(f, "ambiguous type t{}", meta.0),
            Self::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for TypeError {}

impl Unifier {
    /// Allocates a fresh metavariable of `kind`.
    ///
    /// # Panics
    ///
    /// Panics if more than `u32::MAX` metavariables are allocated.
    pub fn fresh(&mut self, arena: &mut TypeArena, kind: KindId) -> TypeId {
        self.zonked.clear();
        let id = MetaId(u32::try_from(self.metas.len()).expect("metavariable overflow"));
        self.metas.push(MetaVar {
            kind,
            binding: None,
        });
        arena.intern(TypeNode::Meta(id))
    }

    #[must_use]
    pub fn meta_kind(&self, meta: MetaId) -> KindId {
        self.metas[meta.0 as usize].kind
    }

    fn prune(&mut self, arena: &mut TypeArena, ty: TypeId) -> TypeId {
        let mut current = ty;
        let mut path = Vec::new();
        while let TypeNode::Meta(meta) = arena.get(current).clone() {
            let Some(bound) = self.metas[meta.0 as usize].binding else {
                break;
            };
            path.push(meta);
            current = bound;
        }
        for meta in path {
            self.metas[meta.0 as usize].binding = Some(current);
        }
        current
    }

    fn occurs(&mut self, arena: &mut TypeArena, needle: MetaId, ty: TypeId) -> bool {
        let mut work = vec![ty];
        let mut visited = HashSet::new();
        while let Some(ty) = work.pop() {
            let ty = self.prune(arena, ty);
            if !visited.insert(ty) {
                continue;
            }
            match arena.get(ty).clone() {
                TypeNode::Meta(meta) if meta == needle => return true,
                TypeNode::Apply(left, right) | TypeNode::Function(left, right) => {
                    work.push(right);
                    work.push(left);
                }
                TypeNode::RowCons { field, tail, .. } => {
                    work.push(tail);
                    work.push(field);
                }
                _ => {}
            }
        }
        false
    }

    /// Unifies two well-kinded types.
    ///
    /// # Errors
    ///
    /// Returns a mismatch, occurs-check failure, or kind error when the types
    /// cannot be unified.
    pub fn unify(
        &mut self,
        arena: &mut TypeArena,
        kinds: &KindArena,
        left: TypeId,
        right: TypeId,
    ) -> Result<(), TypeError> {
        let mut work = vec![(left, right)];
        while let Some((left, right)) = work.pop() {
            let left = self.prune(arena, left);
            let right = self.prune(arena, right);
            if left == right {
                continue;
            }
            match (arena.get(left).clone(), arena.get(right).clone()) {
                (TypeNode::Meta(meta), _) => self.bind(arena, kinds, meta, right)?,
                (_, TypeNode::Meta(meta)) => self.bind(arena, kinds, meta, left)?,
                (TypeNode::Function(a1, b1), TypeNode::Function(a2, b2))
                | (TypeNode::Apply(a1, b1), TypeNode::Apply(a2, b2)) => {
                    work.push((b1, b2));
                    work.push((a1, a2));
                }
                (
                    TypeNode::RowCons {
                        label: l1,
                        field: f1,
                        tail: t1,
                    },
                    TypeNode::RowCons {
                        label: l2,
                        field: f2,
                        tail: t2,
                    },
                ) if l1 == l2 => {
                    work.push((t1, t2));
                    work.push((f1, f2));
                }
                (left_node, right_node) if left_node == right_node => {}
                _ => return Err(TypeError::Mismatch { left, right }),
            }
        }
        Ok(())
    }

    fn bind(
        &mut self,
        arena: &mut TypeArena,
        kinds: &KindArena,
        meta: MetaId,
        ty: TypeId,
    ) -> Result<(), TypeError> {
        if self.occurs(arena, meta, ty) {
            return Err(TypeError::Occurs { meta, within: ty });
        }
        let expected = self.meta_kind(meta);
        let actual = arena.kind_of(kinds, ty, |id| self.meta_kind(id))?;
        if expected != actual {
            return Err(TypeError::KindMismatch { expected, actual });
        }
        self.zonked.clear();
        self.metas[meta.0 as usize].binding = Some(ty);
        Ok(())
    }

    /// Resolves all metavariables and proves that `ty` is closed.
    ///
    /// # Errors
    ///
    /// Returns an ambiguity, escaped-bound, or cyclic-type error when a closed
    /// type cannot be produced.
    #[allow(clippy::missing_panics_doc)]
    pub fn zonk(&mut self, arena: &mut TypeArena, ty: TypeId) -> Result<ClosedTypeId, TypeError> {
        enum Work {
            Visit(TypeId),
            Apply(TypeId),
            Function(TypeId),
            Row(TypeId, Arc<str>),
        }

        let mut work = vec![Work::Visit(ty)];
        let mut results = Vec::new();
        let mut visiting = HashSet::new();
        while let Some(next) = work.pop() {
            match next {
                Work::Visit(ty) => {
                    let ty = self.prune(arena, ty);
                    if let Some(zonked) = self.zonked.get(&ty).copied() {
                        results.push(zonked);
                        continue;
                    }
                    if !visiting.insert(ty) {
                        results.push(ty);
                        continue;
                    }
                    match arena.get(ty).clone() {
                        TypeNode::Meta(meta) => return Err(TypeError::Ambiguous(meta)),
                        TypeNode::Bound(_) => {
                            return Err(TypeError::Internal(
                                "bound type escaped scheme instantiation".into(),
                            ));
                        }
                        TypeNode::Apply(left, right) => {
                            work.push(Work::Apply(ty));
                            work.push(Work::Visit(right));
                            work.push(Work::Visit(left));
                        }
                        TypeNode::Function(left, right) => {
                            work.push(Work::Function(ty));
                            work.push(Work::Visit(right));
                            work.push(Work::Visit(left));
                        }
                        TypeNode::RowCons { label, field, tail } => {
                            work.push(Work::Row(ty, label));
                            work.push(Work::Visit(tail));
                            work.push(Work::Visit(field));
                        }
                        _ => {
                            visiting.remove(&ty);
                            self.zonked.insert(ty, ty);
                            results.push(ty);
                        }
                    }
                }
                Work::Apply(original) => {
                    let right = results.pop().expect("type argument zonked");
                    let left = results.pop().expect("type function zonked");
                    visiting.remove(&original);
                    let zonked = arena.apply(left, right);
                    self.zonked.insert(original, zonked);
                    results.push(zonked);
                }
                Work::Function(original) => {
                    let right = results.pop().expect("function result zonked");
                    let left = results.pop().expect("function argument zonked");
                    visiting.remove(&original);
                    let zonked = arena.function(left, right);
                    self.zonked.insert(original, zonked);
                    results.push(zonked);
                }
                Work::Row(original, label) => {
                    let tail = results.pop().expect("row tail zonked");
                    let field = results.pop().expect("row field zonked");
                    visiting.remove(&original);
                    let zonked = arena.intern(TypeNode::RowCons { label, field, tail });
                    self.zonked.insert(original, zonked);
                    results.push(zonked);
                }
            }
        }
        Ok(ClosedTypeId(results.pop().expect("root type zonked")))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassId {
    Show,
    Eq,
    Ord,
    Monad,
    Functor,
    Applicative,
    Alternative,
    Monoid,
    Semigroup,
    FoldCase,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceImplementationId(pub u16);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidencePlan {
    Direct {
        class: ClassId,
        target: ClosedTypeId,
        implementation: InstanceImplementationId,
    },
    Entailed {
        class: ClassId,
        target: ClosedTypeId,
        implementation: InstanceImplementationId,
        premises: Arc<[EvidencePlan]>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_type_operations_use_heap_worklists() {
        const DEPTH: usize = 8_192;
        let kinds = KindArena::default();
        let mut types = TypeArena::default();
        let unit = types.constructor("()", KindArena::TYPE);
        let mut left = unit;
        let mut right = unit;
        for _ in 0..DEPTH {
            left = types.function(unit, left);
            right = types.function(unit, right);
        }

        assert_eq!(
            types.kind_of(&kinds, left, |_| KindArena::TYPE).unwrap(),
            KindArena::TYPE
        );
        let displayed = types.display(left);
        assert!(displayed.starts_with("() -> "));
        assert!(displayed.ends_with("()"));
        let mut unifier = Unifier::default();
        unifier.unify(&mut types, &kinds, left, right).unwrap();
        let meta = unifier.fresh(&mut types, KindArena::TYPE);
        unifier.unify(&mut types, &kinds, meta, left).unwrap();
        assert_eq!(unifier.zonk(&mut types, meta).unwrap().raw(), left);
    }

    #[test]
    fn deep_occurs_failure_remains_structured() {
        const DEPTH: usize = 8_192;
        let kinds = KindArena::default();
        let mut types = TypeArena::default();
        let mut unifier = Unifier::default();
        let meta = unifier.fresh(&mut types, KindArena::TYPE);
        let unit = types.constructor("()", KindArena::TYPE);
        let mut recursive = meta;
        for _ in 0..DEPTH {
            recursive = types.function(unit, recursive);
        }
        assert!(matches!(
            unifier.unify(&mut types, &kinds, meta, recursive),
            Err(TypeError::Occurs { .. })
        ));
    }
}
