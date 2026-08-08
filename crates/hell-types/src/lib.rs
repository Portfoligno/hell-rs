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
    pub fn kind_of(
        &self,
        kinds: &KindArena,
        ty: TypeId,
        meta_kinds: impl Fn(MetaId) -> KindId + Copy,
    ) -> Result<KindId, TypeError> {
        match self.get(ty) {
            TypeNode::Meta(meta) => Ok(meta_kinds(*meta)),
            TypeNode::Bound(_) => Err(TypeError::Internal("unsubstituted bound type".into())),
            TypeNode::Constructor { kind, .. } => Ok(*kind),
            TypeNode::Function(argument, result) => {
                let argument_kind = self.kind_of(kinds, *argument, meta_kinds)?;
                let result_kind = self.kind_of(kinds, *result, meta_kinds)?;
                if argument_kind != KindArena::TYPE {
                    return Err(TypeError::KindMismatch {
                        expected: KindArena::TYPE,
                        actual: argument_kind,
                    });
                }
                if result_kind != KindArena::TYPE {
                    return Err(TypeError::KindMismatch {
                        expected: KindArena::TYPE,
                        actual: result_kind,
                    });
                }
                Ok(KindArena::TYPE)
            }
            TypeNode::Symbol(_) => Ok(KindArena::SYMBOL),
            TypeNode::RowNil => Ok(KindArena::ROW),
            TypeNode::RowCons { field, tail, .. } => {
                let field_kind = self.kind_of(kinds, *field, meta_kinds)?;
                let tail_kind = self.kind_of(kinds, *tail, meta_kinds)?;
                if field_kind != KindArena::TYPE {
                    return Err(TypeError::KindMismatch {
                        expected: KindArena::TYPE,
                        actual: field_kind,
                    });
                }
                if tail_kind != KindArena::ROW {
                    return Err(TypeError::KindMismatch {
                        expected: KindArena::ROW,
                        actual: tail_kind,
                    });
                }
                Ok(KindArena::ROW)
            }
            TypeNode::Apply(function, argument) => {
                let function_kind = self.kind_of(kinds, *function, meta_kinds)?;
                let argument_kind = self.kind_of(kinds, *argument, meta_kinds)?;
                match kinds.get(function_kind) {
                    KindNode::Arrow(expected, result) if *expected == argument_kind => Ok(*result),
                    KindNode::Arrow(expected, _) => Err(TypeError::KindMismatch {
                        expected: *expected,
                        actual: argument_kind,
                    }),
                    _ => Err(TypeError::NotATypeConstructor(function_kind)),
                }
            }
        }
    }

    #[must_use]
    pub fn display(&self, ty: TypeId) -> String {
        fn go(arena: &TypeArena, ty: TypeId, precedence: u8, out: &mut String) {
            match arena.get(ty) {
                TypeNode::Meta(id) => write!(out, "t{}", id.0).expect("writing to String"),
                TypeNode::Bound(id) => write!(out, "a{id}").expect("writing to String"),
                TypeNode::Constructor { name, .. } => out.push_str(name),
                TypeNode::Symbol(value) => {
                    out.push('"');
                    out.push_str(value);
                    out.push('"');
                }
                TypeNode::RowNil => out.push_str("{}"),
                TypeNode::RowCons { label, field, tail } => {
                    out.push('{');
                    out.push_str(label);
                    out.push_str(" :: ");
                    go(arena, *field, 0, out);
                    if !matches!(arena.get(*tail), TypeNode::RowNil) {
                        out.push_str(", ..");
                    }
                    out.push('}');
                }
                TypeNode::Function(argument, result) => {
                    let paren = precedence > 0;
                    if paren {
                        out.push('(');
                    }
                    go(arena, *argument, 1, out);
                    out.push_str(" -> ");
                    go(arena, *result, 0, out);
                    if paren {
                        out.push(')');
                    }
                }
                TypeNode::Apply(function, argument) => {
                    if let TypeNode::Constructor { name, .. } = arena.get(*function)
                        && name.as_ref() == "[]"
                    {
                        out.push('[');
                        go(arena, *argument, 0, out);
                        out.push(']');
                        return;
                    }
                    let paren = precedence > 1;
                    if paren {
                        out.push('(');
                    }
                    go(arena, *function, 1, out);
                    out.push(' ');
                    go(arena, *argument, 2, out);
                    if paren {
                        out.push(')');
                    }
                }
            }
        }
        let mut result = String::new();
        go(self, ty, 0, &mut result);
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
        let TypeNode::Meta(meta) = arena.get(ty).clone() else {
            return ty;
        };
        let Some(bound) = self.metas[meta.0 as usize].binding else {
            return ty;
        };
        let pruned = self.prune(arena, bound);
        self.metas[meta.0 as usize].binding = Some(pruned);
        pruned
    }

    fn occurs(&mut self, arena: &mut TypeArena, needle: MetaId, ty: TypeId) -> bool {
        let ty = self.prune(arena, ty);
        match arena.get(ty).clone() {
            TypeNode::Meta(meta) => meta == needle,
            TypeNode::Apply(left, right) | TypeNode::Function(left, right) => {
                self.occurs(arena, needle, left) || self.occurs(arena, needle, right)
            }
            TypeNode::RowCons { field, tail, .. } => {
                self.occurs(arena, needle, field) || self.occurs(arena, needle, tail)
            }
            _ => false,
        }
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
        let left = self.prune(arena, left);
        let right = self.prune(arena, right);
        if left == right {
            return Ok(());
        }
        match (arena.get(left).clone(), arena.get(right).clone()) {
            (TypeNode::Meta(meta), _) => self.bind(arena, kinds, meta, right),
            (_, TypeNode::Meta(meta)) => self.bind(arena, kinds, meta, left),
            (TypeNode::Function(a1, b1), TypeNode::Function(a2, b2))
            | (TypeNode::Apply(a1, b1), TypeNode::Apply(a2, b2)) => {
                self.unify(arena, kinds, a1, a2)?;
                self.unify(arena, kinds, b1, b2)
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
                self.unify(arena, kinds, f1, f2)?;
                self.unify(arena, kinds, t1, t2)
            }
            (l, r) if l == r => Ok(()),
            _ => Err(TypeError::Mismatch { left, right }),
        }
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
        self.metas[meta.0 as usize].binding = Some(ty);
        Ok(())
    }

    /// Resolves all metavariables and proves that `ty` is closed.
    ///
    /// # Errors
    ///
    /// Returns an ambiguity, escaped-bound, or cyclic-type error when a closed
    /// type cannot be produced.
    pub fn zonk(&mut self, arena: &mut TypeArena, ty: TypeId) -> Result<ClosedTypeId, TypeError> {
        fn go(
            unifier: &mut Unifier,
            arena: &mut TypeArena,
            ty: TypeId,
            visiting: &mut HashSet<TypeId>,
        ) -> Result<TypeId, TypeError> {
            let ty = unifier.prune(arena, ty);
            if !visiting.insert(ty) {
                return Ok(ty);
            }
            let node = arena.get(ty).clone();
            let result = match node {
                TypeNode::Meta(meta) => return Err(TypeError::Ambiguous(meta)),
                TypeNode::Bound(_) => {
                    return Err(TypeError::Internal(
                        "bound type escaped scheme instantiation".into(),
                    ));
                }
                TypeNode::Apply(left, right) => {
                    let left = go(unifier, arena, left, visiting)?;
                    let right = go(unifier, arena, right, visiting)?;
                    arena.apply(left, right)
                }
                TypeNode::Function(left, right) => {
                    let left = go(unifier, arena, left, visiting)?;
                    let right = go(unifier, arena, right, visiting)?;
                    arena.function(left, right)
                }
                TypeNode::RowCons { label, field, tail } => {
                    let field = go(unifier, arena, field, visiting)?;
                    let tail = go(unifier, arena, tail, visiting)?;
                    arena.intern(TypeNode::RowCons { label, field, tail })
                }
                _ => ty,
            };
            visiting.remove(&ty);
            Ok(result)
        }
        go(self, arena, ty, &mut HashSet::new()).map(ClosedTypeId)
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
