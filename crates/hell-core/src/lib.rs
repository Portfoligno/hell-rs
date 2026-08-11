//! Typed core and the independent verification boundary consumed by runtime.

use std::fmt;
use std::sync::Arc;

use hell_builtins::{BuiltinId, TypeClass};
use hell_source::Span;
use hell_types::{ClosedTypeId, TypeArena, TypeId, TypeNode};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CoreId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Projection {
    Identity,
    TupleElement { arity: u8, index: u8 },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Constant {
    Unit,
    Bool(bool),
    Int(i64),
    Double(f64),
    Character(char),
    Text(Arc<str>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecordFieldLayout {
    pub name: Arc<str>,
    pub ty: ClosedTypeId,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecordLayout {
    pub type_name: Arc<str>,
    pub constructor: Arc<str>,
    pub fields: Arc<[RecordFieldLayout]>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VariantConstructorLayout {
    pub name: Arc<str>,
    pub payload: Option<ClosedTypeId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VariantLayout {
    pub type_name: Arc<str>,
    pub constructors: Arc<[VariantConstructorLayout]>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaseBranch {
    pub constructor_index: u16,
    pub payload_type: Option<ClosedTypeId>,
    pub body: CoreId,
}

/// Closed dictionary evidence attached to a constrained primitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassEvidence {
    pub class: TypeClass,
    pub head: ClosedTypeId,
    pub plan: InstanceEvidencePlanId,
}

/// Index of one compiler-retained class-instance evidence plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceEvidencePlanId(pub u32);

/// One immutable node in the exact class-instance evidence graph selected by
/// the compiler for a constrained primitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceEvidencePlan {
    pub class: TypeClass,
    pub head: TypeId,
    pub resolution: hell_builtins::InstanceResolution,
    pub premises: Arc<[InstanceEvidencePlanId]>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CoreKind {
    BoundVar {
        de_bruijn: u32,
        projection: Projection,
    },
    Lambda {
        parameter_type: ClosedTypeId,
        body: CoreId,
    },
    Apply {
        function: CoreId,
        argument: CoreId,
    },
    Constant(Constant),
    Builtin {
        builtin: BuiltinId,
        evidence: Option<ClassEvidence>,
    },
    Tuple {
        elements: Arc<[CoreId]>,
    },
    List {
        elements: Arc<[CoreId]>,
    },
    Record {
        layout: Arc<RecordLayout>,
        fields: Arc<[CoreId]>,
    },
    RecordGet {
        layout: Arc<RecordLayout>,
        field_index: u16,
        record: CoreId,
    },
    RecordSet {
        layout: Arc<RecordLayout>,
        field_index: u16,
        value: CoreId,
        record: CoreId,
    },
    RecordModify {
        layout: Arc<RecordLayout>,
        field_index: u16,
        function: CoreId,
        record: CoreId,
    },
    Variant {
        layout: Arc<VariantLayout>,
        constructor_index: u16,
        payload: Option<CoreId>,
    },
    Case {
        scrutinee: CoreId,
        layout: Arc<VariantLayout>,
        branches: Arc<[CaseBranch]>,
        default: Option<CoreId>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoreNode {
    pub ty: ClosedTypeId,
    pub span: Span,
    pub kind: CoreKind,
}

#[derive(Clone, Debug)]
pub struct CoreProgram {
    pub root: CoreId,
    pub nodes: Vec<CoreNode>,
    pub types: TypeArena,
    pub main_type: ClosedTypeId,
    pub instance_evidence: Vec<InstanceEvidencePlan>,
    pub compiler_evidence: CompilerBuiltinEvidence,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompilerBuiltinEvidence {
    pub parsed: Vec<BuiltinId>,
    pub resolved: Vec<BuiltinId>,
    pub specialized: Vec<BuiltinId>,
}

#[derive(Clone, Debug)]
pub struct ExecutableProgram {
    root: CoreId,
    nodes: Arc<[CoreNode]>,
    types: Arc<TypeArena>,
    main_type: ClosedTypeId,
    instance_evidence: Arc<[InstanceEvidencePlan]>,
    #[cfg(feature = "compat-tracing")]
    compiler_evidence: CompilerBuiltinEvidence,
}

/// The only program handle accepted by `hell-runtime`. Its fields are private;
/// callers obtain it exclusively through the independent checker below.
#[derive(Clone, Debug)]
pub struct VerifiedProgram {
    executable: Arc<ExecutableProgram>,
}

impl VerifiedProgram {
    #[must_use]
    pub fn executable(&self) -> &ExecutableProgram {
        &self.executable
    }
}

impl ExecutableProgram {
    #[must_use]
    pub const fn root(&self) -> CoreId {
        self.root
    }

    #[must_use]
    pub fn node(&self, id: CoreId) -> Option<&CoreNode> {
        self.nodes.get(id.0 as usize)
    }

    #[must_use]
    pub fn nodes(&self) -> &[CoreNode] {
        &self.nodes
    }

    #[must_use]
    pub fn types(&self) -> &TypeArena {
        &self.types
    }

    #[must_use]
    pub const fn main_type(&self) -> ClosedTypeId {
        self.main_type
    }

    #[must_use]
    pub fn instance_evidence(&self, id: InstanceEvidencePlanId) -> Option<&InstanceEvidencePlan> {
        self.instance_evidence.get(id.0 as usize)
    }

    #[must_use]
    pub fn instance_evidence_plans(&self) -> &[InstanceEvidencePlan] {
        &self.instance_evidence
    }

    /// Builtins whose source names were parsed, resolved to registry IDs, and
    /// retained in the independently verified typed core.
    #[must_use]
    #[cfg(feature = "compat-tracing")]
    pub const fn compiler_evidence(&self) -> &CompilerBuiltinEvidence {
        &self.compiler_evidence
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationError {
    pub code: &'static str,
    pub message: Arc<str>,
    pub node: Option<CoreId>,
    pub span: Option<Span>,
}

impl VerificationError {
    fn at(id: CoreId, node: &CoreNode, message: impl Into<Arc<str>>) -> Self {
        Self {
            code: "H0703",
            message: message.into(),
            node: Some(id),
            span: Some(node.span),
        }
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for VerificationError {}

fn constructor_name(types: &TypeArena, ty: TypeId) -> Option<&str> {
    match types.get(ty) {
        TypeNode::Constructor { name, .. } => Some(name),
        _ => None,
    }
}

fn type_head_name(types: &TypeArena, mut ty: TypeId) -> Option<&str> {
    while let TypeNode::Apply(function, _) = types.get(ty) {
        ty = *function;
    }
    constructor_name(types, ty)
}

fn type_is_closed(types: &TypeArena, root: TypeId) -> bool {
    let mut stack = vec![root];
    let mut visited = std::collections::HashSet::new();
    while let Some(ty) = stack.pop() {
        if !visited.insert(ty) {
            continue;
        }
        match types.get(ty) {
            TypeNode::Meta(_) | TypeNode::Bound(_) => return false,
            TypeNode::Apply(left, right) | TypeNode::Function(left, right) => {
                stack.push(*left);
                stack.push(*right);
            }
            TypeNode::RowCons { field, tail, .. } => {
                stack.push(*field);
                stack.push(*tail);
            }
            TypeNode::Constructor { .. } | TypeNode::Symbol(_) | TypeNode::RowNil => {}
        }
    }
    true
}

fn constant_has_type(types: &TypeArena, constant: &Constant, ty: TypeId) -> bool {
    let expected = match constant {
        Constant::Unit => "()",
        Constant::Bool(_) => "Bool",
        Constant::Int(_) => "Int",
        Constant::Double(_) => "Double",
        Constant::Character(_) => "Char",
        Constant::Text(_) => "Text",
    };
    constructor_name(types, ty) == Some(expected)
}

/// Recomputes every core-node type without consulting the inference unifier.
/// Independently validates typed core and seals it for runtime execution.
///
/// # Errors
///
/// Returns [`VerificationError`] for cyclic/shared nodes, invalid de Bruijn
/// references, inconsistent node types, unavailable builtins, or a `main`
/// expression whose type is not exactly `IO ()`.
#[allow(clippy::too_many_lines)]
pub fn verify(program: CoreProgram) -> Result<VerifiedProgram, VerificationError> {
    let node_count = program.nodes.len();
    if program.root.0 as usize >= node_count {
        return Err(VerificationError {
            code: "H0703",
            message: "root core id is out of bounds".into(),
            node: Some(program.root),
            span: None,
        });
    }
    let mut record_layouts = std::collections::HashMap::<&str, &RecordLayout>::new();
    let mut variant_layouts = std::collections::HashMap::<&str, &VariantLayout>::new();
    for (index, node) in program.nodes.iter().enumerate() {
        let id = CoreId(u32::try_from(index).unwrap_or(u32::MAX));
        let record_layout = match &node.kind {
            CoreKind::Record { layout, .. }
            | CoreKind::RecordGet { layout, .. }
            | CoreKind::RecordSet { layout, .. }
            | CoreKind::RecordModify { layout, .. } => Some(layout.as_ref()),
            _ => None,
        };
        if let Some(layout) = record_layout
            && record_layouts
                .insert(layout.type_name.as_ref(), layout)
                .is_some_and(|previous| previous != layout)
        {
            return Err(VerificationError::at(
                id,
                node,
                "conflicting record layouts share one nominal type",
            ));
        }
        let variant_layout = match &node.kind {
            CoreKind::Variant { layout, .. } | CoreKind::Case { layout, .. } => {
                Some(layout.as_ref())
            }
            _ => None,
        };
        if let Some(layout) = variant_layout
            && variant_layouts
                .insert(layout.type_name.as_ref(), layout)
                .is_some_and(|previous| previous != layout)
        {
            return Err(VerificationError::at(
                id,
                node,
                "conflicting variant layouts share one nominal type",
            ));
        }
    }
    // Executable core is deliberately a tree. Rejecting sharing keeps local
    // environment meaning unambiguous and prevents malformed cycles from
    // entering the evaluator. Post-verification lowering may introduce safe
    // code sharing with an explicit capture key.
    let mut incoming = vec![0_u32; node_count];
    let mut colors = vec![0_u8; node_count];
    let mut graph_stack = vec![(program.root, false)];
    while let Some((id, exiting)) = graph_stack.pop() {
        let Some(node) = program.nodes.get(id.0 as usize) else {
            return Err(VerificationError {
                code: "H0703",
                message: "core edge is out of bounds".into(),
                node: Some(id),
                span: None,
            });
        };
        if exiting {
            colors[id.0 as usize] = 2;
            continue;
        }
        match colors[id.0 as usize] {
            1 => return Err(VerificationError::at(id, node, "cyclic core graph")),
            2 => continue,
            _ => {}
        }
        colors[id.0 as usize] = 1;
        graph_stack.push((id, true));
        let mut push_child = |child: CoreId| -> Result<(), VerificationError> {
            let Some(count) = incoming.get_mut(child.0 as usize) else {
                return Err(VerificationError::at(
                    id,
                    node,
                    "core edge is out of bounds",
                ));
            };
            *count = count.saturating_add(1);
            if *count > 1 {
                return Err(VerificationError::at(
                    child,
                    &program.nodes[child.0 as usize],
                    "shared core node lacks an environment capture key",
                ));
            }
            graph_stack.push((child, false));
            Ok(())
        };
        match &node.kind {
            CoreKind::Lambda { body, .. } => push_child(*body)?,
            CoreKind::Apply { function, argument } => {
                push_child(*argument)?;
                push_child(*function)?;
            }
            CoreKind::Tuple { elements } | CoreKind::List { elements } => {
                for child in elements.iter().rev() {
                    push_child(*child)?;
                }
            }
            CoreKind::Record { fields, .. } => {
                for child in fields.iter().rev() {
                    push_child(*child)?;
                }
            }
            CoreKind::RecordGet { record, .. } => push_child(*record)?,
            CoreKind::RecordSet { value, record, .. } => {
                push_child(*record)?;
                push_child(*value)?;
            }
            CoreKind::RecordModify {
                function, record, ..
            } => {
                push_child(*record)?;
                push_child(*function)?;
            }
            CoreKind::Variant { payload, .. } => {
                if let Some(payload) = payload {
                    push_child(*payload)?;
                }
            }
            CoreKind::Case {
                scrutinee,
                branches,
                default,
                ..
            } => {
                if let Some(default) = default {
                    push_child(*default)?;
                }
                for branch in branches.iter().rev() {
                    push_child(branch.body)?;
                }
                push_child(*scrutinee)?;
            }
            CoreKind::BoundVar { .. } | CoreKind::Constant(_) | CoreKind::Builtin { .. } => {}
        }
    }
    let mut computed: Vec<Option<TypeId>> = vec![None; node_count];
    let mut stack = vec![(program.root, false, Vec::<TypeId>::new())];
    while let Some((id, visited, locals)) = stack.pop() {
        let Some(node) = program.nodes.get(id.0 as usize) else {
            return Err(VerificationError {
                code: "H0703",
                message: "core edge is out of bounds".into(),
                node: Some(id),
                span: None,
            });
        };
        if !type_is_closed(&program.types, node.ty.raw()) {
            return Err(VerificationError::at(
                id,
                node,
                "core node carries an open type",
            ));
        }
        if !visited {
            stack.push((id, true, locals.clone()));
            match &node.kind {
                CoreKind::Lambda {
                    parameter_type,
                    body,
                } => {
                    let mut body_locals = locals;
                    body_locals.push(parameter_type.raw());
                    stack.push((*body, false, body_locals));
                }
                CoreKind::Apply { function, argument } => {
                    stack.push((*argument, false, locals.clone()));
                    stack.push((*function, false, locals));
                }
                CoreKind::Tuple { elements } | CoreKind::List { elements } => {
                    for child in elements.iter().rev() {
                        stack.push((*child, false, locals.clone()));
                    }
                }
                CoreKind::Record { fields, .. } => {
                    for child in fields.iter().rev() {
                        stack.push((*child, false, locals.clone()));
                    }
                }
                CoreKind::RecordGet { record, .. } => {
                    stack.push((*record, false, locals));
                }
                CoreKind::RecordSet { value, record, .. } => {
                    stack.push((*record, false, locals.clone()));
                    stack.push((*value, false, locals));
                }
                CoreKind::RecordModify {
                    function, record, ..
                } => {
                    stack.push((*record, false, locals.clone()));
                    stack.push((*function, false, locals));
                }
                CoreKind::Variant { payload, .. } => {
                    if let Some(payload) = payload {
                        stack.push((*payload, false, locals));
                    }
                }
                CoreKind::Case {
                    scrutinee,
                    branches,
                    default,
                    ..
                } => {
                    if let Some(default) = default {
                        stack.push((*default, false, locals.clone()));
                    }
                    for branch in branches.iter().rev() {
                        let mut branch_locals = locals.clone();
                        if let Some(payload_type) = branch.payload_type {
                            branch_locals.push(payload_type.raw());
                        }
                        stack.push((branch.body, false, branch_locals));
                    }
                    stack.push((*scrutinee, false, locals));
                }
                CoreKind::BoundVar { .. } | CoreKind::Constant(_) | CoreKind::Builtin { .. } => {}
            }
            continue;
        }
        let inferred = match &node.kind {
            CoreKind::BoundVar {
                de_bruijn,
                projection,
            } => {
                let Some(index) = locals.len().checked_sub(*de_bruijn as usize + 1) else {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "de Bruijn index is out of scope",
                    ));
                };
                let local = locals[index];
                match projection {
                    Projection::Identity => local,
                    Projection::TupleElement { arity, index } => {
                        let mut arguments = Vec::new();
                        let mut current = local;
                        while let TypeNode::Apply(function, argument) = program.types.get(current) {
                            arguments.push(*argument);
                            current = *function;
                        }
                        arguments.reverse();
                        let expected_name = match arity {
                            2 => "(,)",
                            3 => "(,,)",
                            4 => "(,,,)",
                            _ => {
                                return Err(VerificationError::at(
                                    id,
                                    node,
                                    "tuple projection arity is invalid",
                                ));
                            }
                        };
                        if constructor_name(&program.types, current) != Some(expected_name)
                            || arguments.len() != usize::from(*arity)
                            || usize::from(*index) >= arguments.len()
                        {
                            return Err(VerificationError::at(
                                id,
                                node,
                                "tuple projection does not match local type",
                            ));
                        }
                        arguments[usize::from(*index)]
                    }
                }
            }
            CoreKind::Lambda {
                parameter_type,
                body,
            } => {
                let Some(body_type) = computed.get(body.0 as usize).and_then(|value| *value) else {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "lambda body was not verified",
                    ));
                };
                match program.types.get(node.ty.raw()) {
                    TypeNode::Function(parameter, result)
                        if *parameter == parameter_type.raw() && *result == body_type =>
                    {
                        node.ty.raw()
                    }
                    _ => {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "lambda type is inconsistent",
                        ));
                    }
                }
            }
            CoreKind::Apply { function, argument } => {
                let function_type = computed[function.0 as usize].ok_or_else(|| {
                    VerificationError::at(id, node, "application function was not verified")
                })?;
                let argument_type = computed[argument.0 as usize].ok_or_else(|| {
                    VerificationError::at(id, node, "application argument was not verified")
                })?;
                match program.types.get(function_type) {
                    TypeNode::Function(expected, result)
                        if *expected == argument_type && *result == node.ty.raw() =>
                    {
                        *result
                    }
                    _ => {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "application edge does not reconstruct its stored type",
                        ));
                    }
                }
            }
            CoreKind::Constant(constant) => {
                if !constant_has_type(&program.types, constant, node.ty.raw()) {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "constant type is inconsistent",
                    ));
                }
                node.ty.raw()
            }
            CoreKind::Builtin { builtin, evidence } => {
                let Some(spec) = hell_builtins::registry().get(builtin.0 as usize) else {
                    return Err(VerificationError::at(id, node, "unknown built-in id"));
                };
                if spec.implementation.is_none() || spec.scheme.is_none() {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "unavailable built-in entered executable core",
                    ));
                }
                if !builtin_type_is_plausible(&program.types, spec.name, node.ty.raw()) {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "built-in type does not instantiate its registry scheme",
                    ));
                }
                match (spec.type_class, evidence) {
                    (None, None) => {}
                    (Some(expected), Some(actual))
                        if expected == actual.class
                            && builtin_instance_head(&program.types, spec.name, node.ty.raw())
                                == Some(actual.head.raw())
                            && validate_instance_evidence_plan(
                                &program.types,
                                &program.instance_evidence,
                                *actual,
                            ) => {}
                    _ => {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "built-in class evidence is absent, mismatched, or unresolved",
                        ));
                    }
                }
                node.ty.raw()
            }
            CoreKind::Tuple { elements } => {
                if !(2..=4).contains(&elements.len()) {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "tuple arity invariant failed",
                    ));
                }
                let mut arguments = Vec::new();
                let mut constructor = node.ty.raw();
                while let TypeNode::Apply(function, argument) = program.types.get(constructor) {
                    arguments.push(*argument);
                    constructor = *function;
                }
                arguments.reverse();
                let expected_name = match elements.len() {
                    2 => "(,)",
                    3 => "(,,)",
                    4 => "(,,,)",
                    _ => unreachable!(),
                };
                if constructor_name(&program.types, constructor) != Some(expected_name)
                    || arguments.len() != elements.len()
                {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "tuple node has non-tuple type",
                    ));
                }
                for (child, argument) in elements.iter().zip(arguments) {
                    if computed[child.0 as usize] != Some(argument) {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "tuple element type mismatch",
                        ));
                    }
                }
                node.ty.raw()
            }
            CoreKind::List { elements } => {
                let TypeNode::Apply(constructor, item) = program.types.get(node.ty.raw()) else {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "list node has non-list type",
                    ));
                };
                if constructor_name(&program.types, *constructor) != Some("[]") {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "list node has non-list type",
                    ));
                }
                for child in elements.iter() {
                    if computed[child.0 as usize] != Some(*item) {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "list element type mismatch",
                        ));
                    }
                }
                node.ty.raw()
            }
            CoreKind::Record { layout, fields } => {
                if type_head_name(&program.types, node.ty.raw()) != Some(&layout.type_name)
                    || fields.len() != layout.fields.len()
                {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "record layout does not match its nominal type",
                    ));
                }
                for (child, field) in fields.iter().zip(layout.fields.iter()) {
                    if computed[child.0 as usize] != Some(field.ty.raw()) {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "record field type mismatch",
                        ));
                    }
                }
                node.ty.raw()
            }
            CoreKind::RecordGet {
                layout,
                field_index,
                record,
            } => {
                let Some(field) = layout.fields.get(usize::from(*field_index)) else {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "record field index is out of bounds",
                    ));
                };
                if computed[record.0 as usize].and_then(|ty| type_head_name(&program.types, ty))
                    != Some(&layout.type_name)
                    || node.ty != field.ty
                {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "record getter is inconsistent with its layout",
                    ));
                }
                node.ty.raw()
            }
            CoreKind::RecordSet {
                layout,
                field_index,
                value,
                record,
            } => {
                let Some(field) = layout.fields.get(usize::from(*field_index)) else {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "record field index is out of bounds",
                    ));
                };
                if computed[record.0 as usize] != Some(node.ty.raw())
                    || type_head_name(&program.types, node.ty.raw()) != Some(&layout.type_name)
                    || computed[value.0 as usize] != Some(field.ty.raw())
                {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "record setter is inconsistent with its layout",
                    ));
                }
                node.ty.raw()
            }
            CoreKind::RecordModify {
                layout,
                field_index,
                function,
                record,
            } => {
                let Some(field) = layout.fields.get(usize::from(*field_index)) else {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "record field index is out of bounds",
                    ));
                };
                let function_type = computed[function.0 as usize];
                let valid_function = function_type.is_some_and(|ty| {
                    matches!(
                        program.types.get(ty),
                        TypeNode::Function(argument, result)
                            if *argument == field.ty.raw() && *result == field.ty.raw()
                    )
                });
                if computed[record.0 as usize] != Some(node.ty.raw())
                    || type_head_name(&program.types, node.ty.raw()) != Some(&layout.type_name)
                    || !valid_function
                {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "record modifier is inconsistent with its layout",
                    ));
                }
                node.ty.raw()
            }
            CoreKind::Variant {
                layout,
                constructor_index,
                payload,
            } => {
                if type_head_name(&program.types, node.ty.raw()) != Some(&layout.type_name) {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "variant layout does not match its nominal type",
                    ));
                }
                let Some(constructor) = layout.constructors.get(usize::from(*constructor_index))
                else {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "variant constructor index is out of bounds",
                    ));
                };
                let actual_payload = payload.map(|payload| computed[payload.0 as usize]);
                match (constructor.payload, actual_payload) {
                    (None, None) => {}
                    (Some(expected), Some(Some(actual))) if expected.raw() == actual => {}
                    _ => {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "variant payload type mismatch",
                        ));
                    }
                }
                node.ty.raw()
            }
            CoreKind::Case {
                scrutinee,
                layout,
                branches,
                default,
            } => {
                let Some(scrutinee_type) = computed[scrutinee.0 as usize] else {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "case scrutinee was not verified",
                    ));
                };
                if type_head_name(&program.types, scrutinee_type) != Some(&layout.type_name) {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "case scrutinee does not match its variant layout",
                    ));
                }
                let mut seen = std::collections::HashSet::new();
                for branch in branches.iter() {
                    let Some(constructor) = layout
                        .constructors
                        .get(usize::from(branch.constructor_index))
                    else {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "case constructor index is out of bounds",
                        ));
                    };
                    if !seen.insert(branch.constructor_index)
                        || constructor.payload != branch.payload_type
                        || computed[branch.body.0 as usize] != Some(node.ty.raw())
                    {
                        return Err(VerificationError::at(
                            id,
                            node,
                            "case branch is inconsistent with its layout",
                        ));
                    }
                }
                if let Some(default) = default
                    && computed[default.0 as usize] != Some(node.ty.raw())
                {
                    return Err(VerificationError::at(
                        id,
                        node,
                        "case default branch type mismatch",
                    ));
                }
                if default.is_none() && seen.len() != layout.constructors.len() {
                    return Err(VerificationError::at(id, node, "non-exhaustive user case"));
                }
                node.ty.raw()
            }
        };
        if inferred != node.ty.raw() {
            return Err(VerificationError::at(
                id,
                node,
                "stored type differs from recomputed type",
            ));
        }
        computed[id.0 as usize] = Some(inferred);
    }
    if computed[program.root.0 as usize] != Some(program.main_type.raw()) {
        let root = &program.nodes[program.root.0 as usize];
        return Err(VerificationError::at(
            program.root,
            root,
            "program root differs from declared main type",
        ));
    }
    if !instance_evidence_inventory_is_exact(&program) {
        let root = &program.nodes[program.root.0 as usize];
        return Err(VerificationError::at(
            program.root,
            root,
            "class-instance evidence inventory is noncanonical or contains unused plans",
        ));
    }
    let TypeNode::Apply(io, unit) = program.types.get(program.main_type.raw()) else {
        let root = &program.nodes[program.root.0 as usize];
        return Err(VerificationError::at(
            program.root,
            root,
            "main is not `IO ()`",
        ));
    };
    if constructor_name(&program.types, *io) != Some("IO")
        || constructor_name(&program.types, *unit) != Some("()")
    {
        let root = &program.nodes[program.root.0 as usize];
        return Err(VerificationError::at(
            program.root,
            root,
            "main is not `IO ()`",
        ));
    }
    #[cfg(feature = "compat-tracing")]
    validate_compiler_evidence(&program)?;
    Ok(VerifiedProgram {
        executable: Arc::new(ExecutableProgram {
            root: program.root,
            nodes: program.nodes.into(),
            types: Arc::new(program.types),
            main_type: program.main_type,
            instance_evidence: program.instance_evidence.into(),
            #[cfg(feature = "compat-tracing")]
            compiler_evidence: program.compiler_evidence,
        }),
    })
}

#[cfg(feature = "compat-tracing")]
fn validate_compiler_evidence(program: &CoreProgram) -> Result<(), VerificationError> {
    let mut present = program
        .nodes
        .iter()
        .filter_map(|node| match node.kind {
            CoreKind::Builtin { builtin, .. } => Some(builtin),
            _ => None,
        })
        .collect::<Vec<_>>();
    for node in &program.nodes {
        let mut retain = |name| {
            if let Some(spec) = hell_builtins::lookup(name) {
                present.push(spec.id);
            }
        };
        match &node.kind {
            CoreKind::Tuple { elements } => match elements.len() {
                2 => retain("Tuple.(,)"),
                3 => retain("Tuple.(,,)"),
                4 => retain("Tuple.(,,,)"),
                _ => {}
            },
            CoreKind::Record { fields, .. } => {
                retain("hell:Hell.NilR");
                if !fields.is_empty() {
                    retain("hell:Hell.ConsR");
                }
            }
            CoreKind::RecordGet { .. } => retain("Record.get"),
            CoreKind::RecordSet { .. } => retain("Record.set"),
            CoreKind::RecordModify { .. } => retain("Record.modify"),
            CoreKind::Variant {
                constructor_index,
                payload,
                ..
            } => {
                retain("hell:Hell.LeftV");
                if *constructor_index != 0 {
                    retain("hell:Hell.RightV");
                }
                retain("hell:Hell.Tagged");
                if payload.is_none() {
                    retain("hell:Hell.Nullary");
                }
            }
            CoreKind::Case {
                branches, default, ..
            } => {
                retain("hell:Hell.NilA");
                if !branches.is_empty() {
                    retain("hell:Hell.ConsA");
                }
                if default.is_some() {
                    retain("hell:Hell.WildA");
                }
                retain("hell:Hell.runAccessor");
            }
            _ => {}
        }
    }
    for evidence in [
        &program.compiler_evidence.parsed,
        &program.compiler_evidence.resolved,
        &program.compiler_evidence.specialized,
    ] {
        if evidence.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || evidence.iter().any(|builtin| !present.contains(builtin))
        {
            let root = &program.nodes[program.root.0 as usize];
            return Err(VerificationError::at(
                program.root,
                root,
                "compiler builtin evidence is unsorted or not retained in typed core",
            ));
        }
    }
    if program.compiler_evidence.parsed != program.compiler_evidence.resolved
        || program.compiler_evidence.resolved != program.compiler_evidence.specialized
    {
        let root = &program.nodes[program.root.0 as usize];
        return Err(VerificationError::at(
            program.root,
            root,
            "compiler builtin phase evidence is incomplete",
        ));
    }
    Ok(())
}

fn validate_instance_evidence_plan(
    types: &TypeArena,
    plans: &[InstanceEvidencePlan],
    evidence: ClassEvidence,
) -> bool {
    plans
        .get(evidence.plan.0 as usize)
        .is_some_and(|root| root.class == evidence.class && root.head == evidence.head.raw())
        && validate_instance_evidence_graph(types, plans, evidence.plan).is_some()
}

fn validate_instance_evidence_graph(
    types: &TypeArena,
    plans: &[InstanceEvidencePlan],
    root: InstanceEvidencePlanId,
) -> Option<std::collections::BTreeSet<InstanceEvidencePlanId>> {
    enum Work {
        Enter(InstanceEvidencePlanId),
        Leave(InstanceEvidencePlanId),
    }
    let mut work = vec![Work::Enter(root)];
    let mut active = std::collections::BTreeSet::new();
    let mut visited = std::collections::BTreeSet::new();
    while let Some(item) = work.pop() {
        match item {
            Work::Leave(id) => {
                if !active.remove(&id) {
                    return None;
                }
            }
            Work::Enter(id) => {
                if active.contains(&id) {
                    return None;
                }
                if visited.contains(&id) {
                    continue;
                }
                let plan = plans.get(id.0 as usize)?;
                let (target, arguments) = instance_head(types, plan.head)?;
                let instance = hell_builtins::instance(plan.class, target)?;
                let premise_count = usize::from(instance.resolution.premise_count());
                if plan.resolution != instance.resolution
                    || usize::from(instance.resolution.head_arity()) != arguments.len()
                    || plan.premises.len() != premise_count
                {
                    return None;
                }
                for (index, premise) in plan.premises.iter().copied().enumerate() {
                    let child = plans.get(premise.0 as usize)?;
                    if child.class != plan.class || child.head != arguments[index] {
                        return None;
                    }
                }
                active.insert(id);
                visited.insert(id);
                work.push(Work::Leave(id));
                work.extend(plan.premises.iter().rev().copied().map(Work::Enter));
            }
        }
    }
    Some(visited)
}

fn instance_head(types: &TypeArena, mut ty: TypeId) -> Option<(&str, Vec<TypeId>)> {
    let mut arguments = Vec::new();
    while let TypeNode::Apply(function, argument) = types.get(ty) {
        arguments.push(*argument);
        ty = *function;
    }
    arguments.reverse();
    let TypeNode::Constructor { name, .. } = types.get(ty) else {
        return None;
    };
    Some((name, arguments))
}

fn builtin_instance_head(types: &TypeArena, name: &str, ty: TypeId) -> Option<TypeId> {
    use hell_builtins::InstanceHeadProjection::{
        ApplyArgument, ApplyFunction, FunctionArgument, FunctionResult,
    };
    let mut current = ty;
    for projection in hell_builtins::instance_head_projection(name)? {
        current = match projection {
            FunctionArgument(index) => function_type_parts(types, current)
                .0
                .get(usize::from(*index))
                .copied()?,
            FunctionResult => function_type_parts(types, current).1,
            ApplyFunction => match types.get(current) {
                TypeNode::Apply(function, _) => *function,
                _ => return None,
            },
            ApplyArgument => match types.get(current) {
                TypeNode::Apply(_, argument) => *argument,
                _ => return None,
            },
        };
    }
    Some(current)
}

fn function_type_parts(types: &TypeArena, mut ty: TypeId) -> (Vec<TypeId>, TypeId) {
    let mut arguments = Vec::new();
    while let TypeNode::Function(argument, result) = types.get(ty) {
        arguments.push(*argument);
        ty = *result;
    }
    (arguments, ty)
}

fn instance_evidence_inventory_is_exact(program: &CoreProgram) -> bool {
    let mut roots = program.nodes.iter().filter_map(|node| match node.kind {
        CoreKind::Builtin {
            evidence: Some(evidence),
            ..
        } => Some(evidence.plan),
        _ => None,
    });
    let Some(first) = roots.next() else {
        return program.instance_evidence.is_empty();
    };
    let mut reachable =
        validate_instance_evidence_graph(&program.types, &program.instance_evidence, first)
            .unwrap_or_default();
    for root in roots {
        let Some(nodes) =
            validate_instance_evidence_graph(&program.types, &program.instance_evidence, root)
        else {
            return false;
        };
        reachable.extend(nodes);
    }
    if reachable.len() != program.instance_evidence.len() {
        return false;
    }
    let mut identities = std::collections::BTreeSet::new();
    program
        .instance_evidence
        .iter()
        .all(|plan| identities.insert((plan.class, plan.head)))
}

fn builtin_type_is_plausible(types: &TypeArena, name: &str, ty: TypeId) -> bool {
    let arrow = |ty| match types.get(ty) {
        TypeNode::Function(argument, result) => Some((*argument, *result)),
        _ => None,
    };
    let displayed = types.display(ty);
    match name {
        "Bool.False" | "Bool.True" => displayed == "Bool",
        "Bool.not" => displayed == "Bool -> Bool",
        "Int.plus" | "Int.subtract" | "Int.mult" => displayed == "Int -> Int -> Int",
        "Int.eq" => displayed == "Int -> Int -> Bool",
        "Eq.eq" | "Ord.lt" | "Ord.gt" => arrow(ty).is_some_and(|(left, rest)| {
            arrow(rest).is_some_and(|(right, result)| {
                left == right && constructor_name(types, result) == Some("Bool")
            })
        }),
        "Int.show" => displayed == "Int -> Text",
        "Text.eq" => displayed == "Text -> Text -> Bool",
        "Text.length" => displayed == "Text -> Int",
        "Text.reverse" => displayed == "Text -> Text",
        "Text.putStr" | "Text.putStrLn" => displayed == "Text -> IO ()",
        "Function.id" => arrow(ty).is_some_and(|(argument, result)| argument == result),
        "Function.fix" => arrow(ty).is_some_and(|(function, result)| {
            arrow(function).is_some_and(|(argument, function_result)| {
                argument == result && function_result == result
            })
        }),
        "Error.error" => {
            arrow(ty).is_some_and(|(argument, _)| constructor_name(types, argument) == Some("Text"))
        }
        "hell:Hell.NilR" => type_head_name(types, ty) == Some("hell:Hell.Record"),
        "hell:Hell.ConsR" => arrow(ty).is_some_and(|(_, rest)| {
            arrow(rest).is_some_and(|(tail, result)| {
                type_head_name(types, tail) == Some("hell:Hell.Record")
                    && type_head_name(types, result) == Some("hell:Hell.Record")
            })
        }),
        "hell:Hell.LeftV" => arrow(ty)
            .is_some_and(|(_, result)| type_head_name(types, result) == Some("hell:Hell.Variant")),
        "hell:Hell.RightV" => arrow(ty).is_some_and(|(variant, result)| {
            type_head_name(types, variant) == Some("hell:Hell.Variant")
                && type_head_name(types, result) == Some("hell:Hell.Variant")
        }),
        "hell:Hell.NilA" => type_head_name(types, ty) == Some("hell:Hell.Accessor"),
        "hell:Hell.WildA" => arrow(ty)
            .is_some_and(|(_, result)| type_head_name(types, result) == Some("hell:Hell.Accessor")),
        "hell:Hell.ConsA" => arrow(ty).is_some_and(|(handler, rest)| {
            arrow(handler).is_some()
                && arrow(rest).is_some_and(|(tail, result)| {
                    type_head_name(types, tail) == Some("hell:Hell.Accessor")
                        && type_head_name(types, result) == Some("hell:Hell.Accessor")
                })
        }),
        "hell:Hell.runAccessor" => arrow(ty).is_some_and(|(tagged, rest)| {
            type_head_name(types, tagged) == Some("hell:Hell.Tagged")
                && arrow(rest).is_some_and(|(accessor, _)| {
                    type_head_name(types, accessor) == Some("hell:Hell.Accessor")
                })
        }),
        "hell:Hell.Tagged" => arrow(ty)
            .is_some_and(|(_, result)| type_head_name(types, result) == Some("hell:Hell.Tagged")),
        "hell:Hell.Nullary" => constructor_name(types, ty) == Some("hell:Hell.Nullary"),
        _ => {
            let expected_arity =
                hell_builtins::lookup(name).map_or(usize::MAX, |spec| spec.arity as usize);
            let mut actual_arity = 0_usize;
            let mut current = ty;
            while let TypeNode::Function(_, result) = types.get(current) {
                actual_arity += 1;
                current = *result;
            }
            actual_arity == expected_arity
        }
    }
}

#[cfg(test)]
mod instance_evidence_tests {
    use super::*;
    use hell_types::KindArena;

    #[test]
    fn constrained_builtin_projection_selects_the_instantiated_head() {
        let mut types = TypeArena::default();
        let int = types.constructor("Int", KindArena::TYPE);
        let boolean = types.constructor("Bool", KindArena::TYPE);
        let tail = types.function(int, boolean);
        let eq = types.function(int, tail);
        assert_eq!(builtin_instance_head(&types, "Eq.eq", eq), Some(int));
    }
}
