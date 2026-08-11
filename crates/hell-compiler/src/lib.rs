//! Resolution, global-template expansion, inference, and verified-core output.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hell_core::{
    CaseBranch, ClassEvidence, CompilerBuiltinEvidence, Constant, CoreId, CoreKind, CoreNode,
    CoreProgram, InstanceEvidencePlan, InstanceEvidencePlanId, Projection, RecordFieldLayout,
    RecordLayout, VariantConstructorLayout, VariantLayout, VerifiedProgram,
};
use hell_source::{SourceFile, SourceMap, SourceName, Span};
use hell_syntax::{
    BindingPattern, CaseAlternative, CasePattern, Declaration, DoStatement, Expr, ExprId, Literal,
    ParsedFile, RecordFieldExpr, TypeExpr, TypeExprId,
};
use hell_types::{ClosedTypeId, KindArena, TypeArena, TypeError, TypeId, TypeNode, Unifier};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilerProfile {
    Upstream,
    Sandboxed,
    DeterministicTest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit<T> {
    Unlimited,
    At(T),
}

impl<T: Copy> Limit<T> {
    const fn value(self) -> Option<T> {
        match self {
            Self::Unlimited => None,
            Self::At(value) => Some(value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompilerLimits {
    pub parser: hell_syntax::ParserLimits,
    pub source_bytes: Limit<u64>,
    pub tokens: Limit<u64>,
    pub syntax_nodes: Limit<u64>,
    pub nesting: Limit<u32>,
    pub type_constraints: Limit<u64>,
    pub core_nodes: Limit<u64>,
    pub max_expansion_depth: Option<usize>,
    pub max_elaborated_nodes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompilerConfig {
    pub id: Arc<str>,
    pub profile: CompilerProfile,
    pub limits: CompilerLimits,
    pub collect_stats: bool,
}

impl CompilerConfig {
    #[must_use]
    pub fn upstream() -> Self {
        Self {
            id: Arc::from("upstream"),
            profile: CompilerProfile::Upstream,
            limits: CompilerLimits {
                parser: hell_syntax::ParserLimits::upstream(),
                source_bytes: Limit::Unlimited,
                tokens: Limit::Unlimited,
                syntax_nodes: Limit::Unlimited,
                nesting: Limit::Unlimited,
                type_constraints: Limit::Unlimited,
                core_nodes: Limit::Unlimited,
                max_expansion_depth: None,
                max_elaborated_nodes: None,
            },
            collect_stats: false,
        }
    }

    #[must_use]
    pub fn sandboxed() -> Self {
        Self {
            id: Arc::from("sandboxed"),
            profile: CompilerProfile::Sandboxed,
            limits: CompilerLimits {
                parser: hell_syntax::ParserLimits::sandboxed(),
                source_bytes: Limit::At(64 * 1024 * 1024),
                tokens: Limit::At(1_000_000),
                syntax_nodes: Limit::At(1_000_000),
                nesting: Limit::At(64),
                type_constraints: Limit::At(1_000_000),
                core_nodes: Limit::At(1_000_000),
                max_expansion_depth: Some(256),
                max_elaborated_nodes: Some(1_000_000),
            },
            collect_stats: false,
        }
    }

    #[must_use]
    pub fn deterministic_test() -> Self {
        let mut config = Self::sandboxed();
        config.id = Arc::from("deterministic-test");
        config.profile = CompilerProfile::DeterministicTest;
        config
    }
}

#[derive(Clone, Debug, Default)]
pub struct CompilerStats {
    enabled: bool,
    pub parsed_declarations: usize,
    pub elaborated_nodes: usize,
    pub global_expansions: usize,
    pub timings: Vec<CompilerTiming>,
}

impl CompilerStats {
    fn begin_run(&mut self) {
        let enabled = self.enabled;
        *self = Self {
            enabled,
            ..Self::default()
        };
    }

    fn record_timing(&mut self, depth: u16, label: &'static str, started: Instant) {
        self.record_elapsed(depth, label, started.elapsed());
    }

    fn record_elapsed(&mut self, depth: u16, label: &'static str, elapsed: Duration) {
        if self.enabled {
            self.timings.push(CompilerTiming {
                depth,
                label,
                elapsed,
            });
        }
    }

    fn set_parsed_declarations(&mut self, declarations: usize) {
        if self.enabled {
            self.parsed_declarations = declarations;
        }
    }

    fn record_elaborated_node(&mut self) {
        if self.enabled {
            self.elaborated_nodes += 1;
        }
    }

    fn record_global_expansion(&mut self) {
        if self.enabled {
            self.global_expansions += 1;
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompilerTiming {
    pub depth: u16,
    pub label: &'static str,
    pub elapsed: Duration,
}

#[derive(Clone, Debug)]
pub struct CompilerSession {
    pub sources: SourceMap,
    pub kinds: KindArena,
    pub types: TypeArena,
    pub config: CompilerConfig,
    pub stats: CompilerStats,
}

impl Default for CompilerSession {
    fn default() -> Self {
        Self {
            sources: SourceMap::new(),
            kinds: KindArena::default(),
            types: TypeArena::default(),
            config: CompilerConfig::sandboxed(),
            stats: CompilerStats::default(),
        }
    }
}

impl CompilerSession {
    /// Uses the compatibility profile without the sandbox parser nesting cap.
    #[must_use]
    pub fn upstream() -> Self {
        Self {
            config: CompilerConfig::upstream(),
            ..Self::default()
        }
    }

    /// Enables timing and counter collection for the next compilation.
    pub fn enable_stats(&mut self) {
        self.config.collect_stats = true;
        self.stats.enabled = true;
    }

    fn record_timing(&mut self, depth: u16, label: &'static str, started: Instant) {
        self.stats.record_timing(depth, label, started);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub message: Arc<str>,
    pub span: Option<Span>,
    pub notes: Vec<Arc<str>>,
}

impl Diagnostic {
    fn new(
        code: &'static str,
        message: impl Into<Arc<str>>,
        span: impl Into<Option<Span>>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            span: span.into(),
            notes: Vec::new(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error[{}]: {}", self.code, self.message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticBundle(pub Vec<Diagnostic>);

impl fmt::Display for DiagnosticBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, diagnostic) in self.0.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "{diagnostic}")?;
        }
        Ok(())
    }
}

impl std::error::Error for DiagnosticBundle {}

#[derive(Clone)]
struct UserField {
    name: Arc<str>,
    ty: TypeExprId,
}

#[derive(Clone)]
struct UserConstructor {
    name: Arc<str>,
    payload: Option<TypeExprId>,
    span: Span,
}

#[derive(Clone)]
enum UserTypeShape {
    Record {
        constructor: Arc<str>,
        fields: Vec<UserField>,
    },
    Variant {
        constructors: Vec<UserConstructor>,
    },
}

#[derive(Clone)]
struct UserType {
    qualified_name: Arc<str>,
    shape: UserTypeShape,
    span: Span,
}

#[derive(Clone, Copy)]
enum ConstructorOwner {
    Record {
        type_index: usize,
    },
    Variant {
        type_index: usize,
        constructor_index: usize,
    },
}

#[derive(Default)]
struct UserTypes {
    definitions: Vec<UserType>,
    by_name: HashMap<Arc<str>, usize>,
    constructors: HashMap<Arc<str>, ConstructorOwner>,
}

/// Compiles and independently verifies one UTF-8 Hell source file.
///
/// # Errors
///
/// Returns diagnostics for filesystem/UTF-8 failures or any rejected language,
/// type, lowering, or verification condition.
pub fn compile_file(
    session: &mut CompilerSession,
    path: &Path,
) -> Result<VerifiedProgram, DiagnosticBundle> {
    compile_file_current(session, path)
}

fn compile_file_current(
    session: &mut CompilerSession,
    path: &Path,
) -> Result<VerifiedProgram, DiagnosticBundle> {
    session.stats.begin_run();
    let started = Instant::now();
    let source = session.sources.read_file(path).map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::InvalidData {
            "H0002"
        } else {
            "H0001"
        };
        DiagnosticBundle(vec![Diagnostic::new(code, error.to_string(), None)])
    })?;
    session.record_timing(1, "read_file", started);
    compile_source_file(session, &source)
}

/// Compiles and independently verifies one in-memory Hell source.
///
/// # Errors
///
/// Returns diagnostics for invalid source, resolution, inference, lowering, or
/// independent core verification failures.
pub fn compile_source(
    session: &mut CompilerSession,
    name: impl Into<Arc<str>>,
    source: impl Into<Arc<str>>,
) -> Result<VerifiedProgram, DiagnosticBundle> {
    let name = name.into();
    let source = source.into();
    compile_source_current(session, &name, &source)
}

fn compile_source_current(
    session: &mut CompilerSession,
    name: &Arc<str>,
    source: &Arc<str>,
) -> Result<VerifiedProgram, DiagnosticBundle> {
    session.stats.begin_run();
    let file = session
        .sources
        .add_bytes(
            SourceName::Virtual(Arc::clone(name)),
            Arc::<[u8]>::from(source.as_bytes()),
        )
        .map_err(|error| {
            DiagnosticBundle(vec![Diagnostic::new("H0002", error.to_string(), None)])
        })?;
    compile_source_file(session, &file)
}

fn compiler_limit_error(
    operation: &str,
    profile: &str,
    configured: u64,
    observed: u64,
    span: impl Into<Option<Span>>,
) -> DiagnosticBundle {
    DiagnosticBundle(vec![Diagnostic::new(
        "H0802",
        format!(
            "compiler resource limit exceeded: operation={operation} profile={profile} configured={configured} observed={observed}"
        ),
        span,
    )])
}

#[allow(clippy::too_many_lines)]
fn compile_source_file(
    session: &mut CompilerSession,
    source: &SourceFile,
) -> Result<VerifiedProgram, DiagnosticBundle> {
    let profile_id = Arc::clone(&session.config.id);
    let profile = profile_id.as_ref();
    let source_bytes = u64::try_from(source.bytes.len()).unwrap_or(u64::MAX);
    if let Some(configured) = session.config.limits.source_bytes.value()
        && source_bytes > configured
    {
        return Err(compiler_limit_error(
            "read_source",
            profile,
            configured,
            source_bytes,
            source.eof_span(),
        ));
    }
    let mut parser_limits = session.config.limits.parser;
    parser_limits.profile_id = match session.config.profile {
        CompilerProfile::Upstream => "upstream",
        CompilerProfile::Sandboxed => "sandboxed",
        CompilerProfile::DeterministicTest => "deterministic-test",
    };
    if let Some(configured) = session.config.limits.tokens.value() {
        parser_limits.max_tokens = Some(usize::try_from(configured).unwrap_or(usize::MAX));
    }
    if let Some(configured) = session.config.limits.nesting.value() {
        parser_limits.max_nesting_depth = Some(usize::try_from(configured).unwrap_or(usize::MAX));
    }
    let parse_started = Instant::now();
    let parsed = hell_syntax::parse_with_limits(source, parser_limits).map_err(|errors| {
        DiagnosticBundle(
            errors
                .into_iter()
                .map(|error| Diagnostic::new(error.code, error.message, error.span))
                .collect(),
        )
    })?;
    let syntax_nodes = parsed
        .declarations
        .len()
        .saturating_add(parsed.expressions.len())
        .saturating_add(parsed.types.len());
    let syntax_nodes = u64::try_from(syntax_nodes).unwrap_or(u64::MAX);
    if let Some(configured) = session.config.limits.syntax_nodes.value()
        && syntax_nodes > configured
    {
        return Err(compiler_limit_error(
            "build_syntax",
            profile,
            configured,
            syntax_nodes,
            parsed.span,
        ));
    }
    session.record_timing(1, "parse_module_with_mode", parse_started);
    session
        .stats
        .set_parsed_declarations(parsed.declarations.len());
    let resolve_started = Instant::now();
    let desugar_started = Instant::now();
    let user_types = collect_user_types(&parsed)?;
    let globals = collect_globals(&parsed, &user_types)?;
    validate_all_names(&parsed, &globals, &user_types)?;
    session.record_timing(1, "resolve_module", resolve_started);
    session.record_timing(0, "parse", parse_started);
    let desugar_elapsed = desugar_started.elapsed();
    let cycle_started = Instant::now();
    reject_type_cycles(&parsed, &user_types)?;
    reject_cycles(&parsed, &globals)?;
    session.record_timing(0, "cycle_detect", cycle_started);
    session.stats.record_elapsed(0, "desugar", desugar_elapsed);
    let Some(main) = globals.get("main").copied() else {
        return Err(DiagnosticBundle(vec![Diagnostic::new(
            "H0701",
            "script does not define `main`",
            Some(parsed.span),
        )]));
    };

    // Each compilation owns a fresh type universe, making closed IDs
    // deterministic and preventing cross-program type identity leaks.
    session.kinds = KindArena::default();
    session.types = TypeArena::default();
    let infer_started = Instant::now();
    let mut context = InferContext {
        parsed: &parsed,
        globals: &globals,
        user_types: &user_types,
        kinds: &mut session.kinds,
        types: &mut session.types,
        unifier: Unifier::default(),
        show_wanteds: Vec::new(),
        eq_wanteds: Vec::new(),
        ord_wanteds: Vec::new(),
        semigroup_wanteds: Vec::new(),
        class_wanteds: Vec::new(),
        record_wanteds: Vec::new(),
        temporary: Vec::new(),
        expansion_stack: Vec::new(),
        preinferred: HashMap::new(),
        preinferred_bindings: HashMap::new(),
        worklist_bypass: HashSet::new(),
        #[cfg(feature = "compat-tracing")]
        parsed_builtins: HashSet::new(),
        #[cfg(feature = "compat-tracing")]
        resolved_builtins: HashSet::new(),
        #[cfg(feature = "compat-tracing")]
        specialized_builtins: HashSet::new(),
        type_constraints: 0,
        profile_id,
        stats: &mut session.stats,
        limits: &session.config.limits,
    };
    let elaborate_started = Instant::now();
    let root = context.expand_global(main, &mut Vec::new())?;
    context
        .stats
        .record_timing(1, "elaborate", elaborate_started);
    let unit = context.types.constructor("()", KindArena::TYPE);
    let main_expected = context.types.io(unit, context.kinds);

    let unify_started = Instant::now();
    for (selected, declared, wanted_span) in context.record_wanteds.clone() {
        let selected =
            context
                .unifier
                .zonk(context.types, selected)
                .map_err(|error| match error {
                    TypeError::Ambiguous(_) => DiagnosticBundle(vec![Diagnostic::new(
                        "H0602",
                        "record field type is ambiguous; supply the second visible type argument",
                        wanted_span,
                    )]),
                    other => context.type_diagnostic(other, wanted_span, None, Some(selected)),
                })?;
        let declared = context
            .unifier
            .zonk(context.types, declared)
            .map_err(|error| context.type_diagnostic(error, wanted_span, None, Some(declared)))?;
        if selected != declared {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0502",
                format!(
                    "record field type mismatch: selected `{}`, declared `{}`",
                    context.types.display(selected.raw()),
                    context.types.display(declared.raw())
                ),
                wanted_span,
            )]));
        }
    }
    context.stats.record_timing(1, "unify", unify_started);

    let zonk_started = Instant::now();
    let mut closed_types = Vec::with_capacity(context.temporary.len());
    let mut closed_by_type = HashMap::new();
    for temporary in &context.temporary {
        let closed = context
            .unifier
            .zonk(context.types, temporary.ty)
            .map_err(|error| {
                context.type_diagnostic(error, temporary.span, None, Some(temporary.ty))
            })?;
        closed_by_type.insert(temporary.ty, closed);
        if let TemporaryKind::Lambda { parameter_type, .. } = temporary.kind {
            let parameter_closed = context
                .unifier
                .zonk(context.types, parameter_type)
                .map_err(|error| {
                    context.type_diagnostic(error, temporary.span, None, Some(parameter_type))
                })?;
            closed_by_type.insert(parameter_type, parameter_closed);
        }
        closed_types.push(closed);
    }
    let layout_types: Vec<(TypeId, Span)> = context
        .temporary
        .iter()
        .flat_map(|temporary| {
            let types: Vec<TypeId> = match &temporary.kind {
                TemporaryKind::Record { layout, .. }
                | TemporaryKind::RecordGet { layout, .. }
                | TemporaryKind::RecordSet { layout, .. }
                | TemporaryKind::RecordModify { layout, .. } => {
                    layout.fields.iter().map(|(_, ty)| *ty).collect()
                }
                TemporaryKind::Variant { layout, .. } | TemporaryKind::Case { layout, .. } => {
                    layout
                        .constructors
                        .iter()
                        .filter_map(|(_, payload)| *payload)
                        .collect()
                }
                TemporaryKind::Builtin {
                    evidence: Some((_, head)),
                    ..
                } => vec![*head],
                _ => Vec::new(),
            };
            types.into_iter().map(|ty| (ty, temporary.span))
        })
        .collect();
    for (ty, span) in layout_types {
        if closed_by_type.contains_key(&ty) {
            continue;
        }
        let closed = context
            .unifier
            .zonk(context.types, ty)
            .map_err(|error| context.type_diagnostic(error, span, None, Some(ty)))?;
        closed_by_type.insert(ty, closed);
    }
    let main_type = context
        .unifier
        .zonk(context.types, main_expected)
        .map_err(|error| context.type_diagnostic(error, root.span, None, Some(main_expected)))?;
    if closed_types[root.node.0 as usize] != main_type {
        return Err(DiagnosticBundle(vec![Diagnostic::new(
            "H0702",
            format!(
                "`main` must have type `IO ()`; inferred `{}`",
                context
                    .types
                    .display(closed_types[root.node.0 as usize].raw())
            ),
            root.span,
        )]));
    }
    for (wanted, wanted_span) in context.show_wanteds.clone() {
        let closed = context
            .unifier
            .zonk(context.types, wanted)
            .map_err(|error| context.type_diagnostic(error, wanted_span, None, Some(wanted)))?;
        if !has_show_instance(context.types, closed.raw()) {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0507",
                format!(
                    "no `Show` instance for `{}`",
                    context.types.display(closed.raw())
                ),
                wanted_span,
            )]));
        }
    }
    for (wanted, wanted_span) in context.eq_wanteds.clone() {
        let closed = context
            .unifier
            .zonk(context.types, wanted)
            .map_err(|error| context.type_diagnostic(error, wanted_span, None, Some(wanted)))?;
        if !has_eq_instance(context.types, closed.raw()) {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0507",
                format!(
                    "no `Eq` instance for `{}`",
                    context.types.display(closed.raw())
                ),
                wanted_span,
            )]));
        }
    }
    for (wanted, wanted_span) in context.ord_wanteds.clone() {
        let closed = context
            .unifier
            .zonk(context.types, wanted)
            .map_err(|error| context.type_diagnostic(error, wanted_span, None, Some(wanted)))?;
        if !has_instance(context.types, hell_builtins::TypeClass::Ord, closed.raw()) {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0507",
                format!(
                    "no `Ord` instance for `{}`",
                    context.types.display(closed.raw())
                ),
                wanted_span,
            )]));
        }
    }
    for (wanted, wanted_span) in context.semigroup_wanteds.clone() {
        let closed = context
            .unifier
            .zonk(context.types, wanted)
            .map_err(|error| context.type_diagnostic(error, wanted_span, None, Some(wanted)))?;
        if !has_semigroup_instance(context.types, closed.raw()) {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0507",
                format!(
                    "no `Semigroup` instance for `{}`",
                    context.types.display(closed.raw())
                ),
                wanted_span,
            )]));
        }
    }
    for (class, wanted, wanted_span) in context.class_wanteds.clone() {
        let closed = context
            .unifier
            .zonk(context.types, wanted)
            .map_err(|error| context.type_diagnostic(error, wanted_span, None, Some(wanted)))?;
        if !has_instance(context.types, class, closed.raw()) {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0507",
                format!(
                    "no `{}` instance for `{}`",
                    class.as_str(),
                    context.types.display(closed.raw())
                ),
                wanted_span,
            )]));
        }
    }
    let mut instance_evidence = InstanceEvidencePlans::default();
    for temporary in &context.temporary {
        let TemporaryKind::Builtin {
            evidence: Some((class, head)),
            ..
        } = temporary.kind
        else {
            continue;
        };
        let closed_head = closed_by_type[&head].raw();
        if instance_evidence
            .retain(context.types, class, closed_head)
            .is_none()
        {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0507",
                format!(
                    "no `{}` instance evidence for `{}`",
                    class.as_str(),
                    context.types.display(closed_head)
                ),
                temporary.span,
            )]));
        }
    }
    let nodes = context
        .temporary
        .iter()
        .zip(closed_types.iter().copied())
        .map(|(temporary, ty)| CoreNode {
            ty,
            span: temporary.span,
            kind: temporary
                .kind
                .clone()
                .close(&closed_by_type, &instance_evidence.identities),
        })
        .collect();
    let program = CoreProgram {
        root: root.node,
        nodes,
        types: context.types.clone(),
        main_type,
        instance_evidence: instance_evidence.plans,
        compiler_evidence: compiler_builtin_evidence(&context),
    };
    context.stats.record_timing(1, "zonk", zonk_started);
    context.stats.record_timing(0, "infer", infer_started);
    let check_started = Instant::now();
    let verified = hell_core::verify(program).map_err(|error| {
        DiagnosticBundle(vec![Diagnostic::new(error.code, error.message, error.span)])
    })?;
    context.stats.record_timing(0, "check", check_started);
    Ok(verified)
}

#[cfg(feature = "compat-tracing")]
fn compiler_builtin_evidence(context: &InferContext<'_>) -> CompilerBuiltinEvidence {
    let mut parsed = context.parsed_builtins.clone();
    let mut resolved = context.resolved_builtins.clone();
    let mut specialized = context.specialized_builtins.clone();
    for node in &context.temporary {
        retain_generated_builtin_evidence(&node.kind, &mut parsed);
        retain_generated_builtin_evidence(&node.kind, &mut resolved);
        retain_generated_builtin_evidence(&node.kind, &mut specialized);
    }
    CompilerBuiltinEvidence {
        parsed: sorted_builtin_ids(&parsed),
        resolved: sorted_builtin_ids(&resolved),
        specialized: sorted_builtin_ids(&specialized),
    }
}

#[cfg(feature = "compat-tracing")]
fn retain_generated_builtin_evidence(
    kind: &TemporaryKind,
    evidence: &mut HashSet<hell_builtins::BuiltinId>,
) {
    let mut retain = |name| {
        evidence.insert(
            hell_builtins::lookup(name)
                .expect("generated builtin is registered")
                .id,
        );
    };
    match kind {
        TemporaryKind::Tuple { elements } => match elements.len() {
            2 => retain("Tuple.(,)"),
            3 => retain("Tuple.(,,)"),
            4 => retain("Tuple.(,,,)"),
            _ => {}
        },
        TemporaryKind::Record { fields, .. } => {
            retain("hell:Hell.NilR");
            if !fields.is_empty() {
                retain("hell:Hell.ConsR");
            }
        }
        TemporaryKind::RecordGet { .. } => retain("Record.get"),
        TemporaryKind::RecordSet { .. } => retain("Record.set"),
        TemporaryKind::RecordModify { .. } => retain("Record.modify"),
        TemporaryKind::Variant {
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
        TemporaryKind::Case {
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

#[cfg(not(feature = "compat-tracing"))]
fn compiler_builtin_evidence(_context: &InferContext<'_>) -> CompilerBuiltinEvidence {
    CompilerBuiltinEvidence::default()
}

#[cfg(feature = "compat-tracing")]
fn sorted_builtin_ids(
    builtins: &HashSet<hell_builtins::BuiltinId>,
) -> Vec<hell_builtins::BuiltinId> {
    let mut builtins = builtins.iter().copied().collect::<Vec<_>>();
    builtins.sort_by_key(|builtin| builtin.0);
    builtins
}

#[allow(clippy::too_many_lines)]
fn collect_user_types(parsed: &ParsedFile) -> Result<UserTypes, DiagnosticBundle> {
    let mut result = UserTypes::default();
    for declaration in &parsed.declarations {
        let (type_name, shape, declaration_span) = match declaration {
            Declaration::Value(_) => continue,
            Declaration::Record(record) => {
                let mut seen = HashMap::<Arc<str>, Span>::new();
                let mut fields = Vec::new();
                for field in &record.fields {
                    if let Some(first) = seen.insert(Arc::clone(&field.name), field.span) {
                        return Err(DiagnosticBundle(vec![Diagnostic {
                            code: "H0304",
                            message: format!("duplicate record field `{}`", field.name).into(),
                            span: Some(field.span),
                            notes: vec![
                                format!("first declaration starts at byte {}", first.start).into(),
                            ],
                        }]));
                    }
                    fields.push(UserField {
                        name: Arc::clone(&field.name),
                        ty: field.ty,
                    });
                }
                fields.sort_by(|left, right| left.name.cmp(&right.name));
                (
                    Arc::clone(&record.type_name),
                    UserTypeShape::Record {
                        constructor: Arc::clone(&record.constructor),
                        fields,
                    },
                    record.span,
                )
            }
            Declaration::Sum(sum) => {
                // The pinned front end normalizes repeated constructors within
                // one declaration through a last-wins map before namespace checks.
                let mut normalized = HashMap::<Arc<str>, UserConstructor>::new();
                for constructor in &sum.constructors {
                    normalized.insert(
                        Arc::clone(&constructor.name),
                        UserConstructor {
                            name: Arc::clone(&constructor.name),
                            payload: constructor.payload,
                            span: constructor.span,
                        },
                    );
                }
                let mut constructors: Vec<_> = normalized.into_values().collect();
                constructors.sort_by(|left, right| left.name.cmp(&right.name));
                (
                    Arc::clone(&sum.type_name),
                    UserTypeShape::Variant { constructors },
                    sum.span,
                )
            }
        };
        let qualified_name: Arc<str> = format!("Main.{type_name}").into();
        if let Some(previous) = result
            .by_name
            .insert(Arc::clone(&qualified_name), result.definitions.len())
        {
            return Err(DiagnosticBundle(vec![Diagnostic {
                code: "H0302",
                message: format!("duplicate user type `{qualified_name}`").into(),
                span: Some(declaration_span),
                notes: vec![
                    format!(
                        "first declaration starts at byte {}",
                        result.definitions[previous].span.start
                    )
                    .into(),
                ],
            }]));
        }
        result.definitions.push(UserType {
            qualified_name,
            shape,
            span: declaration_span,
        });
    }
    for (type_index, definition) in result.definitions.iter().enumerate() {
        match &definition.shape {
            UserTypeShape::Record { constructor, .. } => {
                if result
                    .constructors
                    .insert(
                        Arc::clone(constructor),
                        ConstructorOwner::Record { type_index },
                    )
                    .is_some()
                {
                    return Err(DiagnosticBundle(vec![Diagnostic::new(
                        "H0303",
                        format!("duplicate constructor `{constructor}`"),
                        definition.span,
                    )]));
                }
            }
            UserTypeShape::Variant { constructors } => {
                for (constructor_index, constructor) in constructors.iter().enumerate() {
                    if result
                        .constructors
                        .insert(
                            Arc::clone(&constructor.name),
                            ConstructorOwner::Variant {
                                type_index,
                                constructor_index,
                            },
                        )
                        .is_some()
                    {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0303",
                            format!("duplicate constructor `{}`", constructor.name),
                            constructor.span,
                        )]));
                    }
                }
            }
        }
    }
    Ok(result)
}

fn collect_globals(
    parsed: &ParsedFile,
    user_types: &UserTypes,
) -> Result<HashMap<Arc<str>, usize>, DiagnosticBundle> {
    let mut globals = HashMap::new();
    for (index, declaration) in parsed.declarations.iter().enumerate() {
        let Declaration::Value(declaration) = declaration else {
            continue;
        };
        if user_types.constructors.contains_key(&declaration.name) {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0303",
                format!(
                    "top-level term `{}` collides with a constructor",
                    declaration.name
                ),
                declaration.span,
            )]));
        }
        if let Some(previous) = globals.insert(Arc::clone(&declaration.name), index) {
            let Declaration::Value(previous) = &parsed.declarations[previous] else {
                unreachable!("global map contains value declarations only")
            };
            return Err(DiagnosticBundle(vec![Diagnostic {
                code: "H0301",
                message: format!("duplicate top-level term `{}`", declaration.name).into(),
                span: Some(declaration.span),
                notes: vec![
                    format!("first definition starts at byte {}", previous.span.start).into(),
                ],
            }]));
        }
    }
    Ok(globals)
}

fn validate_all_names(
    parsed: &ParsedFile,
    globals: &HashMap<Arc<str>, usize>,
    user_types: &UserTypes,
) -> Result<(), DiagnosticBundle> {
    let mut errors = Vec::new();
    for declaration in &parsed.declarations {
        match declaration {
            Declaration::Value(declaration) => {
                let mut locals = Vec::new();
                validate_expression(
                    parsed,
                    declaration.value,
                    globals,
                    user_types,
                    &mut locals,
                    &mut errors,
                );
                if let Some(annotation) = declaration.annotation {
                    validate_type(parsed, annotation, user_types, &mut errors);
                }
            }
            Declaration::Record(record) => {
                for field in &record.fields {
                    validate_type(parsed, field.ty, user_types, &mut errors);
                }
            }
            Declaration::Sum(sum) => {
                for constructor in &sum.constructors {
                    if let Some(payload) = constructor.payload {
                        validate_type(parsed, payload, user_types, &mut errors);
                    }
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(DiagnosticBundle(errors))
    }
}

#[allow(clippy::too_many_lines)]
fn validate_expression(
    parsed: &ParsedFile,
    id: ExprId,
    globals: &HashMap<Arc<str>, usize>,
    user_types: &UserTypes,
    locals: &mut Vec<Arc<str>>,
    errors: &mut Vec<Diagnostic>,
) {
    enum Work {
        Expression(ExprId),
        Type(TypeExprId),
        RestoreLocals(usize),
        DoNext {
            expression: ExprId,
            index: usize,
        },
        DoBind {
            expression: ExprId,
            index: usize,
            pattern: BindingPattern,
        },
        CaseNext {
            expression: ExprId,
            index: usize,
        },
        CaseContinue {
            expression: ExprId,
            index: usize,
            base: usize,
        },
    }

    let mut work = vec![Work::Expression(id)];
    while let Some(step) = work.pop() {
        match step {
            Work::Type(id) => validate_type(parsed, id, user_types, errors),
            Work::RestoreLocals(base) => locals.truncate(base),
            Work::DoNext { expression, index } => {
                let Expr::Do { statements, .. } = &parsed.expressions[expression.0 as usize] else {
                    unreachable!("do continuation references a do expression")
                };
                let Some(statement) = statements.get(index) else {
                    continue;
                };
                match statement {
                    DoStatement::Bind(pattern, child, _) | DoStatement::Let(pattern, child, _) => {
                        work.push(Work::DoBind {
                            expression,
                            index: index + 1,
                            pattern: pattern.clone(),
                        });
                        work.push(Work::Expression(*child));
                    }
                    DoStatement::Then(child, _) => {
                        work.push(Work::DoNext {
                            expression,
                            index: index + 1,
                        });
                        work.push(Work::Expression(*child));
                    }
                }
            }
            Work::DoBind {
                expression,
                index,
                pattern,
            } => {
                push_pattern_names(&pattern, locals, errors);
                work.push(Work::DoNext { expression, index });
            }
            Work::CaseNext { expression, index } => {
                let Expr::Case { alternatives, .. } = &parsed.expressions[expression.0 as usize]
                else {
                    unreachable!("case continuation references a case expression")
                };
                let Some(alternative) = alternatives.get(index) else {
                    continue;
                };
                let base = locals.len();
                match &alternative.pattern {
                    CasePattern::UserConstructor { binder, .. } => {
                        if let Some(binder) = binder {
                            locals.push(Arc::clone(binder));
                        }
                    }
                    CasePattern::PrimitiveConstructor { binders, .. } => {
                        locals.extend(binders.iter().cloned());
                    }
                    CasePattern::Wildcard(_) => {}
                }
                work.push(Work::CaseContinue {
                    expression,
                    index: index + 1,
                    base,
                });
                work.push(Work::Expression(alternative.expression));
            }
            Work::CaseContinue {
                expression,
                index,
                base,
            } => {
                locals.truncate(base);
                work.push(Work::CaseNext { expression, index });
            }
            Work::Expression(id) => match &parsed.expressions[id.0 as usize] {
                Expr::Name(name, span) => {
                    if let Some(global) = name.strip_prefix("Main.") {
                        if !globals.contains_key(global)
                            && !user_types.constructors.contains_key(global)
                        {
                            errors.push(Diagnostic::new(
                                "H0402",
                                format!("unknown global `{name}`"),
                                *span,
                            ));
                        }
                    } else if name.contains('.') || is_operator(name) {
                        if matches!(name.as_ref(), "Record.get" | "Record.set" | "Record.modify") {
                            continue;
                        }
                        match hell_builtins::lookup(name) {
                            None => errors.push(Diagnostic::new(
                                "H0403",
                                format!("unknown primitive `{name}`"),
                                *span,
                            )),
                            Some(spec) if spec.implementation.is_none() => {
                                errors.push(Diagnostic::new(
                                    "H0004",
                                    format!("primitive `{name}` is not available in this build"),
                                    *span,
                                ));
                            }
                            Some(_) => {}
                        }
                    } else if !locals.iter().rev().any(|local| local == name) {
                        let message = if globals.contains_key(name) {
                            format!("global `{name}` must be referenced as `Main.{name}`")
                        } else if user_types.constructors.contains_key(name) {
                            format!("constructor `{name}` must be qualified as `Main.{name}`")
                        } else {
                            format!("unbound local `{name}`")
                        };
                        errors.push(Diagnostic::new("H0401", message, *span));
                    }
                }
                Expr::Literal(_, _) => {}
                Expr::Apply {
                    function, argument, ..
                } => {
                    work.push(Work::Expression(*argument));
                    work.push(Work::Expression(*function));
                }
                Expr::TypeApply {
                    function, argument, ..
                } => {
                    work.push(Work::Type(*argument));
                    work.push(Work::Expression(*function));
                }
                Expr::Lambda {
                    parameters, body, ..
                } => {
                    let base = locals.len();
                    for pattern in parameters {
                        push_pattern_names(pattern, locals, errors);
                    }
                    work.push(Work::RestoreLocals(base));
                    work.push(Work::Expression(*body));
                }
                Expr::If {
                    condition,
                    then_branch,
                    else_branch,
                    ..
                } => {
                    work.push(Work::Expression(*else_branch));
                    work.push(Work::Expression(*then_branch));
                    work.push(Work::Expression(*condition));
                }
                Expr::Do { .. } => {
                    let base = locals.len();
                    work.push(Work::RestoreLocals(base));
                    work.push(Work::DoNext {
                        expression: id,
                        index: 0,
                    });
                }
                Expr::Tuple { elements, .. } | Expr::List { elements, .. } => {
                    work.extend(elements.iter().rev().copied().map(Work::Expression));
                }
                Expr::RecordConstruction {
                    constructor,
                    fields,
                    span,
                } => {
                    let known_user_record = constructor.strip_prefix("Main.").is_some_and(|name| {
                        matches!(
                            user_types.constructors.get(name),
                            Some(ConstructorOwner::Record { .. })
                        )
                    });
                    let known_fallback = hell_builtins::lookup(constructor).is_some();
                    if !known_user_record && !known_fallback {
                        errors.push(Diagnostic::new(
                            "H0403",
                            format!("unknown record-construction function `{constructor}`"),
                            *span,
                        ));
                    }
                    let mut supplied = HashSet::new();
                    for field in fields {
                        if !supplied.insert(field.name.as_ref()) {
                            errors.push(Diagnostic::new(
                                "H0603",
                                format!("duplicate record initializer `{}`", field.name),
                                field.span,
                            ));
                        }
                    }
                    work.extend(
                        fields
                            .iter()
                            .rev()
                            .map(|field| Work::Expression(field.value)),
                    );
                }
                Expr::Case { scrutinee, .. } => {
                    work.push(Work::CaseNext {
                        expression: id,
                        index: 0,
                    });
                    work.push(Work::Expression(*scrutinee));
                }
                Expr::Annotation { expression, ty, .. } => {
                    work.push(Work::Type(*ty));
                    work.push(Work::Expression(*expression));
                }
            },
        }
    }
}

fn push_pattern_names(
    pattern: &BindingPattern,
    locals: &mut Vec<Arc<str>>,
    errors: &mut Vec<Diagnostic>,
) {
    let mut pattern = pattern;
    while let BindingPattern::Annotated(inner, _, _) = pattern {
        pattern = inner;
    }
    match pattern {
        BindingPattern::Variable(name, _) => locals.push(Arc::clone(name)),
        BindingPattern::Wildcard(_) => locals.push("_".into()),
        BindingPattern::Tuple(names, span) => {
            let mut unique = HashSet::new();
            for name in names {
                if !unique.insert(name.as_ref()) {
                    errors.push(Diagnostic::new(
                        "H0205",
                        format!("duplicate tuple binder `{name}`"),
                        *span,
                    ));
                }
                locals.push(Arc::clone(name));
            }
        }
        BindingPattern::Annotated(_, _, _) => unreachable!("annotations were stripped above"),
    }
}

fn validate_type(
    parsed: &ParsedFile,
    id: TypeExprId,
    user_types: &UserTypes,
    errors: &mut Vec<Diagnostic>,
) {
    let mut work = vec![id];
    while let Some(id) = work.pop() {
        match &parsed.types[id.0 as usize] {
            TypeExpr::Name(name, span) => {
                if !is_public_type_name(name) && !user_types.by_name.contains_key(name) {
                    errors.push(Diagnostic::new(
                        "H0404",
                        format!("unknown or unavailable type `{name}`"),
                        *span,
                    ));
                }
            }
            TypeExpr::Unit(_) | TypeExpr::Promoted(_, _) => {}
            TypeExpr::List(item, _) => work.push(*item),
            TypeExpr::Tuple(items, _) => work.extend(items.iter().rev().copied()),
            TypeExpr::Function(left, right, _) | TypeExpr::Apply(left, right, _) => {
                work.push(*right);
                work.push(*left);
            }
        }
    }
}

fn reject_type_cycles(parsed: &ParsedFile, user_types: &UserTypes) -> Result<(), DiagnosticBundle> {
    fn collect(
        parsed: &ParsedFile,
        id: TypeExprId,
        user_types: &UserTypes,
        output: &mut Vec<usize>,
    ) {
        let mut work = vec![id];
        while let Some(id) = work.pop() {
            match &parsed.types[id.0 as usize] {
                TypeExpr::Name(name, _) => {
                    if let Some(index) = user_types.by_name.get(name) {
                        output.push(*index);
                    }
                }
                TypeExpr::List(item, _) => work.push(*item),
                TypeExpr::Tuple(items, _) => work.extend(items.iter().rev().copied()),
                TypeExpr::Function(left, right, _) | TypeExpr::Apply(left, right, _) => {
                    work.push(*right);
                    work.push(*left);
                }
                TypeExpr::Unit(_) | TypeExpr::Promoted(_, _) => {}
            }
        }
    }
    let dependencies: Vec<Vec<usize>> = user_types
        .definitions
        .iter()
        .map(|definition| {
            let mut output = Vec::new();
            match &definition.shape {
                UserTypeShape::Record { fields, .. } => {
                    for field in fields {
                        collect(parsed, field.ty, user_types, &mut output);
                    }
                }
                UserTypeShape::Variant { constructors } => {
                    for constructor in constructors {
                        if let Some(payload) = constructor.payload {
                            collect(parsed, payload, user_types, &mut output);
                        }
                    }
                }
            }
            output.sort_unstable();
            output.dedup();
            output
        })
        .collect();
    if let Some(cycle) = cyclic_nodes(&dependencies).into_iter().next() {
        return Err(DiagnosticBundle(vec![Diagnostic::new(
            "H0311",
            format!(
                "cyclic user type declaration involving `{}`",
                user_types.definitions[cycle].qualified_name
            ),
            user_types.definitions[cycle].span,
        )]));
    }
    Ok(())
}

fn reject_cycles(
    parsed: &ParsedFile,
    globals: &HashMap<Arc<str>, usize>,
) -> Result<(), DiagnosticBundle> {
    let dependencies: Vec<Vec<usize>> = parsed
        .declarations
        .iter()
        .map(|declaration| {
            let mut result = Vec::new();
            if let Declaration::Value(declaration) = declaration {
                collect_dependencies(parsed, declaration.value, globals, &mut result);
            }
            result.sort_unstable();
            result.dedup();
            result
        })
        .collect();
    let cycle = cyclic_nodes(&dependencies);
    if let Some(node) = cycle.first().copied() {
        let names = cycle
            .iter()
            .filter_map(|index| match &parsed.declarations[*index] {
                Declaration::Value(declaration) => Some(format!("Main.{}", declaration.name)),
                Declaration::Record(_) | Declaration::Sum(_) => None,
            })
            .collect::<Vec<_>>()
            .join(" -> ");
        return Err(DiagnosticBundle(vec![Diagnostic::new(
            "H0310",
            format!("cyclic term declarations are unsupported: {names}"),
            parsed.declarations[node].span(),
        )]));
    }
    Ok(())
}

/// Returns nodes that could not be removed by a stack-safe topological sweep.
/// This includes every cycle and nodes whose resolution is blocked by one.
fn cyclic_nodes(dependencies: &[Vec<usize>]) -> Vec<usize> {
    let mut unresolved: Vec<_> = dependencies.iter().map(Vec::len).collect();
    let mut dependents = vec![Vec::new(); dependencies.len()];
    for (node, edges) in dependencies.iter().enumerate() {
        for dependency in edges {
            if let Some(reverse) = dependents.get_mut(*dependency) {
                reverse.push(node);
            }
        }
    }
    let mut ready: VecDeque<_> = unresolved
        .iter()
        .enumerate()
        .filter_map(|(node, count)| (*count == 0).then_some(node))
        .collect();
    while let Some(node) = ready.pop_front() {
        for dependent in &dependents[node] {
            unresolved[*dependent] -= 1;
            if unresolved[*dependent] == 0 {
                ready.push_back(*dependent);
            }
        }
    }
    unresolved
        .into_iter()
        .enumerate()
        .filter_map(|(node, count)| (count > 0).then_some(node))
        .collect()
}

fn collect_dependencies(
    parsed: &ParsedFile,
    id: ExprId,
    globals: &HashMap<Arc<str>, usize>,
    output: &mut Vec<usize>,
) {
    let mut work = vec![id];
    while let Some(id) = work.pop() {
        match &parsed.expressions[id.0 as usize] {
            Expr::Name(name, _) => {
                if let Some(global) = name.strip_prefix("Main.")
                    && let Some(index) = globals.get(global)
                {
                    output.push(*index);
                }
            }
            Expr::Apply {
                function, argument, ..
            } => {
                work.push(*argument);
                work.push(*function);
            }
            Expr::TypeApply { function, .. }
            | Expr::Annotation {
                expression: function,
                ..
            }
            | Expr::Lambda { body: function, .. } => work.push(*function),
            Expr::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                work.push(*else_branch);
                work.push(*then_branch);
                work.push(*condition);
            }
            Expr::Do { statements, .. } => {
                work.extend(statements.iter().rev().map(|statement| match statement {
                    DoStatement::Bind(_, child, _)
                    | DoStatement::Let(_, child, _)
                    | DoStatement::Then(child, _) => *child,
                }));
            }
            Expr::Tuple { elements, .. } | Expr::List { elements, .. } => {
                work.extend(elements.iter().rev().copied());
            }
            Expr::RecordConstruction { fields, .. } => {
                work.extend(fields.iter().rev().map(|field| field.value));
            }
            Expr::Case {
                scrutinee,
                alternatives,
                ..
            } => {
                work.extend(
                    alternatives
                        .iter()
                        .rev()
                        .map(|alternative| alternative.expression),
                );
                work.push(*scrutinee);
            }
            Expr::Literal(_, _) => {}
        }
    }
}

fn is_operator(name: &str) -> bool {
    matches!(name, "$" | "." | "<$>" | "<*>" | "<**>" | "<>")
}

fn public_type_arity(name: &str) -> Option<u8> {
    hell_builtins::public_type_arity(name)
}

fn is_public_type_name(name: &str) -> bool {
    public_type_arity(name).is_some()
}

fn primitive_case_constructor(name: &str) -> Option<(&'static str, usize, usize, usize)> {
    Some(match name {
        "Maybe.Nothing" => ("Maybe", 0, 0, 2),
        "Maybe.Just" => ("Maybe", 1, 1, 2),
        "Either.Left" => ("Either", 0, 1, 2),
        "Either.Right" => ("Either", 1, 1, 2),
        "Exit.ExitSuccess" => ("Exit", 0, 0, 2),
        "Exit.ExitFailure" => ("Exit", 1, 1, 2),
        "Bool.False" => ("Bool", 0, 0, 2),
        "Bool.True" => ("Bool", 1, 0, 2),
        "These.This" => ("These", 0, 1, 3),
        "These.That" => ("These", 1, 1, 3),
        "These.These" => ("These", 2, 2, 3),
        "Json.Null" => ("Json", 0, 0, 6),
        "Json.Bool" => ("Json", 1, 1, 6),
        "Json.String" => ("Json", 2, 1, 6),
        "Json.Number" => ("Json", 3, 1, 6),
        "Json.Array" => ("Json", 4, 1, 6),
        "Json.Object" => ("Json", 5, 1, 6),
        _ => return None,
    })
}

#[derive(Clone)]
struct TemporaryNode {
    ty: TypeId,
    span: Span,
    kind: TemporaryKind,
}

#[derive(Clone)]
enum TemporaryKind {
    BoundVar {
        de_bruijn: u32,
        projection: Projection,
    },
    Lambda {
        parameter_type: TypeId,
        body: CoreId,
    },
    Apply {
        function: CoreId,
        argument: CoreId,
    },
    Constant(Constant),
    Builtin {
        builtin: hell_builtins::BuiltinId,
        evidence: Option<(hell_builtins::TypeClass, TypeId)>,
    },
    Tuple {
        elements: Arc<[CoreId]>,
    },
    List {
        elements: Arc<[CoreId]>,
    },
    Record {
        layout: TemporaryRecordLayout,
        fields: Arc<[CoreId]>,
    },
    RecordGet {
        layout: TemporaryRecordLayout,
        field_index: u16,
        record: CoreId,
    },
    RecordSet {
        layout: TemporaryRecordLayout,
        field_index: u16,
        value: CoreId,
        record: CoreId,
    },
    RecordModify {
        layout: TemporaryRecordLayout,
        field_index: u16,
        function: CoreId,
        record: CoreId,
    },
    Variant {
        layout: TemporaryVariantLayout,
        constructor_index: u16,
        payload: Option<CoreId>,
    },
    Case {
        scrutinee: CoreId,
        layout: TemporaryVariantLayout,
        branches: Arc<[TemporaryCaseBranch]>,
        default: Option<CoreId>,
    },
}

#[derive(Clone)]
struct TemporaryRecordLayout {
    type_name: Arc<str>,
    constructor: Arc<str>,
    fields: Arc<[(Arc<str>, TypeId)]>,
}

#[derive(Clone)]
struct TemporaryVariantLayout {
    type_name: Arc<str>,
    constructors: Arc<[(Arc<str>, Option<TypeId>)]>,
}

#[derive(Clone)]
struct TemporaryCaseBranch {
    constructor_index: u16,
    payload_type: Option<TypeId>,
    body: CoreId,
}

impl TemporaryKind {
    fn close(
        &self,
        closed: &HashMap<TypeId, ClosedTypeId>,
        evidence_plans: &HashMap<(hell_builtins::TypeClass, TypeId), InstanceEvidencePlanId>,
    ) -> CoreKind {
        match self {
            Self::BoundVar {
                de_bruijn,
                projection,
            } => CoreKind::BoundVar {
                de_bruijn: *de_bruijn,
                projection: *projection,
            },
            Self::Lambda {
                parameter_type,
                body,
            } => CoreKind::Lambda {
                parameter_type: closed[parameter_type],
                body: *body,
            },
            Self::Apply { function, argument } => CoreKind::Apply {
                function: *function,
                argument: *argument,
            },
            Self::Constant(value) => CoreKind::Constant(value.clone()),
            Self::Builtin { builtin, evidence } => CoreKind::Builtin {
                builtin: *builtin,
                evidence: evidence.map(|(class, head)| ClassEvidence {
                    class,
                    head: closed[&head],
                    plan: evidence_plans[&(class, closed[&head].raw())],
                }),
            },
            Self::Tuple { elements } => CoreKind::Tuple {
                elements: Arc::clone(elements),
            },
            Self::List { elements } => CoreKind::List {
                elements: Arc::clone(elements),
            },
            Self::Record { layout, fields } => CoreKind::Record {
                layout: Arc::new(close_record_layout(layout, closed)),
                fields: Arc::clone(fields),
            },
            Self::RecordGet {
                layout,
                field_index,
                record,
            } => CoreKind::RecordGet {
                layout: Arc::new(close_record_layout(layout, closed)),
                field_index: *field_index,
                record: *record,
            },
            Self::RecordSet {
                layout,
                field_index,
                value,
                record,
            } => CoreKind::RecordSet {
                layout: Arc::new(close_record_layout(layout, closed)),
                field_index: *field_index,
                value: *value,
                record: *record,
            },
            Self::RecordModify {
                layout,
                field_index,
                function,
                record,
            } => CoreKind::RecordModify {
                layout: Arc::new(close_record_layout(layout, closed)),
                field_index: *field_index,
                function: *function,
                record: *record,
            },
            Self::Variant {
                layout,
                constructor_index,
                payload,
            } => CoreKind::Variant {
                layout: Arc::new(close_variant_layout(layout, closed)),
                constructor_index: *constructor_index,
                payload: *payload,
            },
            Self::Case {
                scrutinee,
                layout,
                branches,
                default,
            } => CoreKind::Case {
                scrutinee: *scrutinee,
                layout: Arc::new(close_variant_layout(layout, closed)),
                branches: branches
                    .iter()
                    .map(|branch| CaseBranch {
                        constructor_index: branch.constructor_index,
                        payload_type: branch.payload_type.map(|ty| closed[&ty]),
                        body: branch.body,
                    })
                    .collect::<Vec<_>>()
                    .into(),
                default: *default,
            },
        }
    }
}

fn close_record_layout(
    layout: &TemporaryRecordLayout,
    closed: &HashMap<TypeId, ClosedTypeId>,
) -> RecordLayout {
    RecordLayout {
        type_name: Arc::clone(&layout.type_name),
        constructor: Arc::clone(&layout.constructor),
        fields: layout
            .fields
            .iter()
            .map(|(name, ty)| RecordFieldLayout {
                name: Arc::clone(name),
                ty: closed[ty],
            })
            .collect::<Vec<_>>()
            .into(),
    }
}

fn close_variant_layout(
    layout: &TemporaryVariantLayout,
    closed: &HashMap<TypeId, ClosedTypeId>,
) -> VariantLayout {
    VariantLayout {
        type_name: Arc::clone(&layout.type_name),
        constructors: layout
            .constructors
            .iter()
            .map(|(name, payload)| VariantConstructorLayout {
                name: Arc::clone(name),
                payload: payload.map(|ty| closed[&ty]),
            })
            .collect::<Vec<_>>()
            .into(),
    }
}

#[derive(Clone)]
struct Inferred {
    node: CoreId,
    ty: TypeId,
    span: Span,
    visible: Vec<(TypeId, hell_types::KindId)>,
    visible_used: usize,
}

#[derive(Clone)]
struct Local {
    name: Arc<str>,
    ty: TypeId,
    slot: usize,
    projection: Projection,
}

struct InferContext<'a> {
    parsed: &'a ParsedFile,
    globals: &'a HashMap<Arc<str>, usize>,
    user_types: &'a UserTypes,
    kinds: &'a mut KindArena,
    types: &'a mut TypeArena,
    unifier: Unifier,
    show_wanteds: Vec<(TypeId, Span)>,
    eq_wanteds: Vec<(TypeId, Span)>,
    ord_wanteds: Vec<(TypeId, Span)>,
    semigroup_wanteds: Vec<(TypeId, Span)>,
    class_wanteds: Vec<(hell_builtins::TypeClass, TypeId, Span)>,
    record_wanteds: Vec<(TypeId, TypeId, Span)>,
    temporary: Vec<TemporaryNode>,
    expansion_stack: Vec<usize>,
    preinferred: HashMap<ExprId, VecDeque<Inferred>>,
    preinferred_bindings: HashMap<ExprId, VecDeque<Vec<TypeId>>>,
    worklist_bypass: HashSet<ExprId>,
    #[cfg(feature = "compat-tracing")]
    parsed_builtins: HashSet<hell_builtins::BuiltinId>,
    #[cfg(feature = "compat-tracing")]
    resolved_builtins: HashSet<hell_builtins::BuiltinId>,
    #[cfg(feature = "compat-tracing")]
    specialized_builtins: HashSet<hell_builtins::BuiltinId>,
    type_constraints: u64,
    profile_id: Arc<str>,
    stats: &'a mut CompilerStats,
    limits: &'a CompilerLimits,
}

impl InferContext<'_> {
    fn charge_type_constraint(&mut self, span: Span) -> Result<(), DiagnosticBundle> {
        self.type_constraints = self.type_constraints.saturating_add(1);
        if let Some(configured) = self.limits.type_constraints.value()
            && self.type_constraints > configured
        {
            return Err(compiler_limit_error(
                "solve_type_constraint",
                &self.profile_id,
                configured,
                self.type_constraints,
                span,
            ));
        }
        Ok(())
    }

    fn put_preinferred(&mut self, id: ExprId, inferred: Inferred) {
        self.preinferred.entry(id).or_default().push_back(inferred);
    }

    fn take_preinferred(&mut self, id: ExprId) -> Option<Inferred> {
        let queue = self.preinferred.get_mut(&id)?;
        let inferred = queue.pop_front();
        if queue.is_empty() {
            self.preinferred.remove(&id);
        }
        inferred
    }

    fn peek_preinferred(&self, id: ExprId) -> Option<Inferred> {
        self.preinferred.get(&id)?.front().cloned()
    }

    fn put_preinferred_bindings(&mut self, id: ExprId, bindings: Vec<TypeId>) {
        self.preinferred_bindings
            .entry(id)
            .or_default()
            .push_back(bindings);
    }

    fn take_preinferred_bindings(&mut self, id: ExprId) -> Option<Vec<TypeId>> {
        let queue = self.preinferred_bindings.get_mut(&id)?;
        let bindings = queue.pop_front();
        if queue.is_empty() {
            self.preinferred_bindings.remove(&id);
        }
        bindings
    }

    #[allow(clippy::needless_pass_by_value)]
    fn type_diagnostic(
        &self,
        error: TypeError,
        span: Span,
        expected: Option<TypeId>,
        actual: Option<TypeId>,
    ) -> DiagnosticBundle {
        let code = match error {
            TypeError::KindMismatch { .. } | TypeError::NotATypeConstructor(_) => "H0501",
            TypeError::Occurs { .. } => "H0503",
            TypeError::Ambiguous(_) => "H0504",
            TypeError::Mismatch { .. } => "H0502",
            TypeError::Internal(_) => "H9000",
        };
        let message = match (expected, actual) {
            (Some(expected), Some(actual)) => format!(
                "{}: expected `{}`, found `{}`",
                error,
                self.types.display(expected),
                self.types.display(actual)
            ),
            _ => error.to_string(),
        };
        DiagnosticBundle(vec![Diagnostic::new(code, message, span)])
    }

    fn alloc(
        &mut self,
        ty: TypeId,
        span: Span,
        kind: TemporaryKind,
    ) -> Result<CoreId, DiagnosticBundle> {
        let observed = u64::try_from(self.temporary.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if let Some(configured) = self.limits.core_nodes.value()
            && observed > configured
        {
            return Err(compiler_limit_error(
                "elaborate_core",
                &self.profile_id,
                configured,
                observed,
                span,
            ));
        }
        if self
            .limits
            .max_elaborated_nodes
            .is_some_and(|limit| self.temporary.len() >= limit)
        {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0407",
                format!(
                    "global expansion exceeded the configured node budget: operation=elaborate_core profile={} configured={} observed={}",
                    self.profile_id,
                    self.limits
                        .max_elaborated_nodes
                        .expect("finite elaborated-node limit checked"),
                    self.temporary.len().saturating_add(1)
                ),
                span,
            )]));
        }
        let id = CoreId(u32::try_from(self.temporary.len()).map_err(|_| {
            compiler_limit_error(
                "allocate_core_id",
                &self.profile_id,
                u64::from(u32::MAX),
                u64::try_from(self.temporary.len()).unwrap_or(u64::MAX),
                span,
            )
        })?);
        self.temporary.push(TemporaryNode { ty, span, kind });
        self.stats.record_elaborated_node();
        Ok(id)
    }

    fn expand_global(
        &mut self,
        index: usize,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        let mut index = index;
        let mut aliases = Vec::new();
        let result = loop {
            if self
                .limits
                .max_expansion_depth
                .is_some_and(|limit| self.expansion_stack.len() >= limit)
            {
                return Err(DiagnosticBundle(vec![Diagnostic::new(
                    "H0407",
                    format!(
                        "global expansion depth exceeded: operation=expand_global profile={} configured={} observed={}",
                        self.profile_id,
                        self.limits
                            .max_expansion_depth
                            .expect("finite expansion limit checked"),
                        self.expansion_stack.len().saturating_add(1)
                    ),
                    self.parsed.declarations[index].span(),
                )]));
            }
            self.expansion_stack.push(index);
            self.stats.record_global_expansion();
            let Declaration::Value(declaration) = &self.parsed.declarations[index] else {
                return Err(DiagnosticBundle(vec![Diagnostic::new(
                    "H9000",
                    "global symbol did not point to a value declaration",
                    self.parsed.declarations[index].span(),
                )]));
            };
            aliases.push((declaration.annotation, declaration.span));
            let Expr::Name(name, _) = &self.parsed.expressions[declaration.value.0 as usize] else {
                break self.infer_expr(declaration.value, locals)?;
            };
            let Some(global) = name.strip_prefix("Main.") else {
                break self.infer_expr(declaration.value, locals)?;
            };
            let Some(next) = self.globals.get(global).copied() else {
                break self.infer_expr(declaration.value, locals)?;
            };
            index = next;
        };
        for (annotation, span) in aliases.into_iter().rev() {
            if let Some(annotation) = annotation {
                let annotation = self.lower_type(annotation)?;
                self.charge_type_constraint(span)?;
                self.unifier
                    .unify(self.types, self.kinds, result.ty, annotation)
                    .map_err(|error| {
                        self.type_diagnostic(error, span, Some(annotation), Some(result.ty))
                    })?;
            }
            self.expansion_stack.pop();
        }
        Ok(result)
    }

    #[allow(clippy::too_many_lines)]
    fn infer_expr(
        &mut self,
        id: ExprId,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        if let Some(inferred) = self.take_preinferred(id) {
            if let Some(prepared) = self.take_preinferred_bindings(id) {
                let actual = locals
                    .get(locals.len().saturating_sub(prepared.len())..)
                    .expect("prepared case bindings fit the local scope");
                for (prepared, actual) in prepared.into_iter().zip(actual) {
                    let span = self.parsed.expressions[id.0 as usize].span();
                    self.charge_type_constraint(span)?;
                    self.unifier
                        .unify(self.types, self.kinds, prepared, actual.ty)
                        .map_err(|error| {
                            self.type_diagnostic(
                                error,
                                self.parsed.expressions[id.0 as usize].span(),
                                Some(actual.ty),
                                Some(prepared),
                            )
                        })?;
                }
            }
            return Ok(inferred);
        }
        let worklist_bypass = self.worklist_bypass.remove(&id);
        if let Some(intrinsic) = self.infer_record_intrinsic(id, locals)? {
            return Ok(intrinsic);
        }
        let expression = self.parsed.expressions[id.0 as usize].clone();
        match expression {
            Expr::Name(name, span) => self.infer_name(&name, span, locals),
            Expr::Literal(literal, span) => self.infer_literal(literal, span),
            Expr::Apply {
                function: _,
                argument: _,
                span: _,
            } => self.infer_application_tree(id, locals),
            Expr::TypeApply {
                function,
                argument,
                span,
            } => {
                let mut applications = vec![(argument, span)];
                let mut head = function;
                while let Expr::TypeApply {
                    function,
                    argument,
                    span,
                } = self.parsed.expressions[head.0 as usize]
                {
                    applications.push((argument, span));
                    head = function;
                }
                let mut function = self.infer_expr(head, locals)?;
                for (argument, span) in applications.into_iter().rev() {
                    let Some((binder, kind)) = function.visible.get(function.visible_used).copied()
                    else {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0505",
                            "visible type application has no remaining binder",
                            span,
                        )]));
                    };
                    let explicit = self.lower_type(argument)?;
                    let actual_kind = self
                        .types
                        .kind_of(self.kinds, explicit, |meta| self.unifier.meta_kind(meta))
                        .map_err(|error| self.type_diagnostic(error, span, None, None))?;
                    if actual_kind != kind {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0506",
                            "visible type argument has the wrong kind",
                            span,
                        )]));
                    }
                    self.charge_type_constraint(span)?;
                    self.unifier
                        .unify(self.types, self.kinds, binder, explicit)
                        .map_err(|error| {
                            self.type_diagnostic(error, span, Some(binder), Some(explicit))
                        })?;
                    function.visible_used += 1;
                }
                Ok(function)
            }
            Expr::Lambda {
                parameters,
                body,
                span,
            } => {
                let base = locals.len();
                let mut groups = vec![(parameters, span)];
                let mut body = body;
                while let Expr::Lambda {
                    parameters,
                    body: nested_body,
                    span,
                } = self.parsed.expressions[body.0 as usize].clone()
                {
                    groups.push((parameters, span));
                    body = nested_body;
                }
                let mut group_types = Vec::with_capacity(groups.len());
                for (parameters, _) in &groups {
                    let mut parameter_types = Vec::with_capacity(parameters.len());
                    for parameter in parameters {
                        parameter_types.push(self.bind_pattern(parameter, locals)?);
                    }
                    group_types.push(parameter_types);
                }
                let mut result = self.infer_expr(body, locals)?;
                locals.truncate(base);
                for ((_, span), parameter_types) in groups.into_iter().zip(group_types).rev() {
                    for parameter_type in parameter_types.into_iter().rev() {
                        let ty = self.types.function(parameter_type, result.ty);
                        let node = self.alloc(
                            ty,
                            span,
                            TemporaryKind::Lambda {
                                parameter_type,
                                body: result.node,
                            },
                        )?;
                        result = Inferred {
                            node,
                            ty,
                            span,
                            visible: Vec::new(),
                            visible_used: 0,
                        };
                    }
                }
                Ok(result)
            }
            Expr::If {
                condition,
                then_branch,
                else_branch,
                span,
            } => {
                if !worklist_bypass {
                    return self.infer_expression_tree(id, locals);
                }
                let builtin = self.infer_name("Bool.bool", span, locals)?;
                let else_branch = self.infer_expr(else_branch, locals)?;
                let then_branch = self.infer_expr(then_branch, locals)?;
                let condition = self.infer_expr(condition, locals)?;
                let applied_false = self.apply_inferred(builtin, else_branch, span)?;
                let applied_true = self.apply_inferred(applied_false, then_branch, span)?;
                self.apply_inferred(applied_true, condition, span)
            }
            Expr::Do { statements, span } => {
                if worklist_bypass {
                    self.infer_do(&statements, span, locals)
                } else {
                    self.infer_expression_tree(id, locals)
                }
            }
            Expr::Case {
                scrutinee: _,
                alternatives: _,
                span: _,
            } => self.infer_case_tree(id, locals),
            Expr::Tuple { elements, span } => {
                if !worklist_bypass {
                    return self.infer_expression_tree(id, locals);
                }
                let mut nodes = Vec::new();
                let mut types = Vec::new();
                for element in elements {
                    let element = self.infer_expr(element, locals)?;
                    nodes.push(element.node);
                    types.push(element.ty);
                }
                let ty = self.types.tuple(&types, self.kinds);
                let node = self.alloc(
                    ty,
                    span,
                    TemporaryKind::Tuple {
                        elements: nodes.into(),
                    },
                )?;
                Ok(Inferred {
                    node,
                    ty,
                    span,
                    visible: Vec::new(),
                    visible_used: 0,
                })
            }
            Expr::List { elements, span } => {
                if !worklist_bypass {
                    return self.infer_expression_tree(id, locals);
                }
                let item = self.unifier.fresh(self.types, KindArena::TYPE);
                let mut nodes = Vec::new();
                for element in elements {
                    let element = self.infer_expr(element, locals)?;
                    self.charge_type_constraint(span)?;
                    self.unifier
                        .unify(self.types, self.kinds, item, element.ty)
                        .map_err(|error| {
                            self.type_diagnostic(error, span, Some(item), Some(element.ty))
                        })?;
                    nodes.push(element.node);
                }
                let ty = self.types.list(item, self.kinds);
                let node = self.alloc(
                    ty,
                    span,
                    TemporaryKind::List {
                        elements: nodes.into(),
                    },
                )?;
                Ok(Inferred {
                    node,
                    ty,
                    span,
                    visible: Vec::new(),
                    visible_used: 0,
                })
            }
            Expr::RecordConstruction {
                constructor: _,
                fields: _,
                span: _,
            } => self.infer_record_tree(id, locals),
            Expr::Annotation {
                expression,
                ty,
                span,
            } => {
                if !worklist_bypass {
                    return self.infer_expression_tree(id, locals);
                }
                let expression = self.infer_expr(expression, locals)?;
                let annotation = self.lower_type(ty)?;
                self.charge_type_constraint(span)?;
                self.unifier
                    .unify(self.types, self.kinds, expression.ty, annotation)
                    .map_err(|error| {
                        self.type_diagnostic(error, span, Some(annotation), Some(expression.ty))
                    })?;
                Ok(expression)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn infer_expression_tree(
        &mut self,
        root: ExprId,
        locals: &[Local],
    ) -> Result<Inferred, DiagnosticBundle> {
        enum Work {
            Infer {
                id: ExprId,
                locals: Vec<Local>,
                prepared: Vec<TypeId>,
            },
            Finish {
                id: ExprId,
                locals: Vec<Local>,
                prepared: Vec<TypeId>,
            },
            DoNext {
                id: ExprId,
                statements: Arc<[DoStatement]>,
                index: usize,
                base: usize,
                root_locals: Vec<Local>,
                locals: Vec<Local>,
                prepared: Vec<TypeId>,
            },
            DoAfter {
                id: ExprId,
                statements: Arc<[DoStatement]>,
                index: usize,
                base: usize,
                root_locals: Vec<Local>,
                locals: Vec<Local>,
                prepared: Vec<TypeId>,
            },
        }

        let mut work = vec![Work::Infer {
            id: root,
            locals: locals.to_owned(),
            prepared: Vec::new(),
        }];
        while let Some(next) = work.pop() {
            match next {
                Work::Infer {
                    id,
                    mut locals,
                    prepared,
                } => {
                    let expression = self.parsed.expressions[id.0 as usize].clone();
                    let mut children = Vec::new();
                    match expression {
                        Expr::If {
                            condition,
                            then_branch,
                            else_branch,
                            ..
                        } => {
                            children.push((else_branch, locals.clone(), prepared.clone()));
                            children.push((then_branch, locals.clone(), prepared.clone()));
                            children.push((condition, locals.clone(), prepared.clone()));
                        }
                        Expr::Tuple { elements, .. } | Expr::List { elements, .. } => {
                            children.extend(
                                elements
                                    .into_iter()
                                    .map(|child| (child, locals.clone(), prepared.clone())),
                            );
                        }
                        Expr::Annotation { expression, .. } => {
                            children.push((expression, locals.clone(), prepared.clone()));
                        }
                        Expr::Do { statements, .. } => {
                            let base = locals.len();
                            work.push(Work::DoNext {
                                id,
                                statements: statements.into(),
                                index: 0,
                                base,
                                root_locals: locals.clone(),
                                locals,
                                prepared,
                            });
                            continue;
                        }
                        _ => {
                            let inferred = self.infer_expr(id, &mut locals)?;
                            if !prepared.is_empty() {
                                self.put_preinferred_bindings(id, prepared);
                            }
                            self.put_preinferred(id, inferred);
                            continue;
                        }
                    }
                    work.push(Work::Finish {
                        id,
                        locals,
                        prepared,
                    });
                    work.extend(children.into_iter().rev().map(|(id, locals, prepared)| {
                        Work::Infer {
                            id,
                            locals,
                            prepared,
                        }
                    }));
                }
                Work::Finish {
                    id,
                    mut locals,
                    prepared,
                } => {
                    self.worklist_bypass.insert(id);
                    let inferred = self.infer_expr(id, &mut locals)?;
                    if !prepared.is_empty() {
                        self.put_preinferred_bindings(id, prepared);
                    }
                    self.put_preinferred(id, inferred);
                }
                Work::DoNext {
                    id,
                    statements,
                    index,
                    base,
                    root_locals,
                    locals,
                    prepared,
                } => {
                    let Some(statement) = statements.get(index) else {
                        work.push(Work::Finish {
                            id,
                            locals: root_locals,
                            prepared,
                        });
                        continue;
                    };
                    let expression = match statement {
                        DoStatement::Then(expression, _)
                        | DoStatement::Let(_, expression, _)
                        | DoStatement::Bind(_, expression, _) => *expression,
                    };
                    let bindings = locals[base..].iter().map(|local| local.ty).collect();
                    work.push(Work::DoAfter {
                        id,
                        statements,
                        index,
                        base,
                        root_locals,
                        locals: locals.clone(),
                        prepared,
                    });
                    work.push(Work::Infer {
                        id: expression,
                        locals,
                        prepared: bindings,
                    });
                }
                Work::DoAfter {
                    id,
                    statements,
                    index,
                    base,
                    root_locals,
                    mut locals,
                    prepared,
                } => {
                    let statement = &statements[index];
                    let (pattern, expression, span, is_bind) = match statement {
                        DoStatement::Then(expression, span) => (None, *expression, *span, false),
                        DoStatement::Let(pattern, expression, span) => {
                            (Some(pattern), *expression, *span, false)
                        }
                        DoStatement::Bind(pattern, expression, span) => {
                            (Some(pattern), *expression, *span, true)
                        }
                    };
                    if let Some(pattern) = pattern {
                        let value = self
                            .peek_preinferred(expression)
                            .expect("do statement expression inferred");
                        let parameter_type = self.bind_pattern(pattern, &mut locals)?;
                        let expected = if is_bind {
                            let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                                KindArena::TYPE,
                                KindArena::TYPE,
                            ));
                            let constructor = self.unifier.fresh(self.types, constructor_kind);
                            self.types.apply(constructor, parameter_type)
                        } else {
                            parameter_type
                        };
                        self.unifier
                            .unify(self.types, self.kinds, value.ty, expected)
                            .map_err(|error| {
                                self.type_diagnostic(error, span, Some(expected), Some(value.ty))
                            })?;
                    }
                    work.push(Work::DoNext {
                        id,
                        statements,
                        index: index + 1,
                        base,
                        root_locals,
                        locals,
                        prepared,
                    });
                }
            }
        }
        Ok(self
            .take_preinferred(root)
            .expect("expression root inferred"))
    }

    fn infer_application_tree(
        &mut self,
        root: ExprId,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        enum Work {
            Infer(ExprId),
            Apply(Span),
        }

        let mut work = vec![Work::Infer(root)];
        let mut inferred = Vec::new();
        while let Some(next) = work.pop() {
            match next {
                Work::Infer(id) => {
                    if let Some(intrinsic) = self.infer_record_intrinsic(id, locals)? {
                        inferred.push(intrinsic);
                        continue;
                    }
                    match self.parsed.expressions[id.0 as usize] {
                        Expr::Apply {
                            function,
                            argument,
                            span,
                        } => {
                            work.push(Work::Apply(span));
                            work.push(Work::Infer(argument));
                            work.push(Work::Infer(function));
                        }
                        _ => inferred.push(self.infer_expr(id, locals)?),
                    }
                }
                Work::Apply(span) => {
                    let argument = inferred.pop().expect("application argument inferred");
                    let function = inferred.pop().expect("application function inferred");
                    inferred.push(self.apply_inferred(function, argument, span)?);
                }
            }
        }
        Ok(inferred.pop().expect("application root inferred"))
    }

    fn infer_record_tree(
        &mut self,
        root: ExprId,
        locals: &mut [Local],
    ) -> Result<Inferred, DiagnosticBundle> {
        enum Work {
            Infer(ExprId),
            Finish(ExprId),
        }

        let mut task_locals = locals.to_owned();
        let mut work = vec![Work::Infer(root)];
        while let Some(next) = work.pop() {
            match next {
                Work::Infer(id) => {
                    let Expr::RecordConstruction { fields, .. } =
                        &self.parsed.expressions[id.0 as usize]
                    else {
                        let inferred = self.infer_expr(id, &mut task_locals)?;
                        self.put_preinferred(id, inferred);
                        continue;
                    };
                    work.push(Work::Finish(id));
                    work.extend(fields.iter().rev().map(|field| Work::Infer(field.value)));
                }
                Work::Finish(id) => {
                    let Expr::RecordConstruction {
                        constructor,
                        fields,
                        span,
                    } = self.parsed.expressions[id.0 as usize].clone()
                    else {
                        unreachable!("record continuation references a record")
                    };
                    let inferred = self.infer_record_construction(
                        &constructor,
                        &fields,
                        span,
                        &mut task_locals,
                    )?;
                    self.put_preinferred(id, inferred);
                }
            }
        }
        Ok(self.take_preinferred(root).expect("record root inferred"))
    }

    #[allow(clippy::too_many_lines)]
    fn infer_case_tree(
        &mut self,
        root: ExprId,
        locals: &[Local],
    ) -> Result<Inferred, DiagnosticBundle> {
        enum Work {
            Infer(ExprId, Vec<Local>),
            Finish(ExprId, Vec<Local>),
        }

        let mut work = vec![Work::Infer(root, locals.to_owned())];
        while let Some(next) = work.pop() {
            match next {
                Work::Infer(id, mut task_locals) => {
                    let Expr::Case {
                        scrutinee,
                        alternatives,
                        ..
                    } = self.parsed.expressions[id.0 as usize].clone()
                    else {
                        let inferred = self.infer_expr(id, &mut task_locals)?;
                        self.put_preinferred(id, inferred);
                        continue;
                    };
                    let primitive = alternatives.iter().any(|alternative| {
                        matches!(
                            alternative.pattern,
                            CasePattern::PrimitiveConstructor { .. }
                        )
                    });
                    let primitive_constructor_count = alternatives
                        .iter()
                        .find_map(|alternative| {
                            let CasePattern::PrimitiveConstructor { name, .. } =
                                &alternative.pattern
                            else {
                                return None;
                            };
                            primitive_case_constructor(name).map(|(_, _, _, count)| count)
                        })
                        .unwrap_or(1);
                    let explicit_primitive_count = alternatives
                        .iter()
                        .filter(|alternative| {
                            matches!(
                                alternative.pattern,
                                CasePattern::PrimitiveConstructor { .. }
                            )
                        })
                        .count();
                    work.push(Work::Finish(id, task_locals.clone()));
                    let mut branches = Vec::with_capacity(alternatives.len());
                    for alternative in &alternatives {
                        let mut branch_locals = task_locals.clone();
                        let names: Vec<Arc<str>> = match &alternative.pattern {
                            CasePattern::UserConstructor {
                                binder: Some(binder),
                                ..
                            } => vec![Arc::clone(binder)],
                            CasePattern::PrimitiveConstructor { binders, .. } => binders.clone(),
                            CasePattern::Wildcard(_)
                            | CasePattern::UserConstructor { binder: None, .. } => Vec::new(),
                        };
                        let mut prepared = Vec::with_capacity(names.len());
                        for name in names {
                            let ty = self.unifier.fresh(self.types, KindArena::TYPE);
                            branch_locals.push(Local {
                                name,
                                ty,
                                slot: local_slot_count(&branch_locals),
                                projection: Projection::Identity,
                            });
                            prepared.push(ty);
                        }
                        if !prepared.is_empty() {
                            self.put_preinferred_bindings(alternative.expression, prepared);
                        }
                        let repeats = if primitive
                            && matches!(alternative.pattern, CasePattern::Wildcard(_))
                        {
                            primitive_constructor_count.saturating_sub(explicit_primitive_count)
                        } else {
                            1
                        };
                        for _ in 0..repeats {
                            branches
                                .push(Work::Infer(alternative.expression, branch_locals.clone()));
                        }
                    }
                    work.extend(branches.into_iter().rev());
                    work.push(Work::Infer(scrutinee, task_locals));
                }
                Work::Finish(id, mut task_locals) => {
                    let Expr::Case {
                        scrutinee,
                        alternatives,
                        span,
                    } = self.parsed.expressions[id.0 as usize].clone()
                    else {
                        unreachable!("case continuation references a case")
                    };
                    let inferred =
                        self.infer_case(scrutinee, &alternatives, span, &mut task_locals)?;
                    self.put_preinferred(id, inferred);
                }
            }
        }
        Ok(self.take_preinferred(root).expect("case root inferred"))
    }

    #[allow(clippy::too_many_lines)]
    fn infer_record_intrinsic(
        &mut self,
        id: ExprId,
        locals: &mut Vec<Local>,
    ) -> Result<Option<Inferred>, DiagnosticBundle> {
        let mut expression = id;
        let mut arguments = Vec::new();
        let mut type_arguments = Vec::new();
        if let Expr::Apply {
            function: dollar_application,
            argument,
            ..
        } = &self.parsed.expressions[expression.0 as usize]
            && let Expr::Apply {
                function: operator,
                argument: left,
                ..
            } = &self.parsed.expressions[dollar_application.0 as usize]
            && matches!(
                &self.parsed.expressions[operator.0 as usize],
                Expr::Name(name, _) if name.as_ref() == "$"
            )
        {
            arguments.push(*argument);
            expression = *left;
        }
        loop {
            match &self.parsed.expressions[expression.0 as usize] {
                Expr::Apply {
                    function, argument, ..
                } => {
                    arguments.push(*argument);
                    expression = *function;
                }
                Expr::TypeApply {
                    function, argument, ..
                } => {
                    type_arguments.push(*argument);
                    expression = *function;
                }
                _ => break,
            }
        }
        let Expr::Name(name, _) = &self.parsed.expressions[expression.0 as usize] else {
            return Ok(None);
        };
        let expected_arguments = match name.as_ref() {
            "Record.get" => 1,
            "Record.set" | "Record.modify" => 2,
            _ => return Ok(None),
        };
        if arguments.len() != expected_arguments || type_arguments.is_empty() {
            return Ok(None);
        }
        arguments.reverse();
        type_arguments.reverse();
        let span = self.parsed.expressions[id.0 as usize].span();
        let TypeExpr::Promoted(field_name, _) = &self.parsed.types[type_arguments[0].0 as usize]
        else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0506",
                "the first record intrinsic type argument must be a promoted field name",
                span,
            )]));
        };
        let record_id = *arguments.last().expect("record intrinsic arity checked");
        let record = self.infer_expr(record_id, locals)?;
        let resolved_record = match self.unifier.zonk(self.types, record.ty) {
            Ok(closed) => closed.raw(),
            Err(TypeError::Ambiguous(_)) => {
                return Err(DiagnosticBundle(vec![Diagnostic::new(
                    "H0602",
                    format!("cannot infer the record type containing field `{field_name}`"),
                    span,
                )]));
            }
            Err(error) => return Err(self.type_diagnostic(error, span, None, Some(record.ty))),
        };
        let TypeNode::Constructor {
            name: record_type_name,
            ..
        } = self.types.get(resolved_record)
        else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0602",
                format!("cannot infer the record type containing field `{field_name}`"),
                span,
            )]));
        };
        let Some(type_index) = self.user_types.by_name.get(record_type_name).copied() else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0601",
                format!("type `{record_type_name}` is not a user record"),
                span,
            )]));
        };
        let definition = self.user_types.definitions[type_index].clone();
        let UserTypeShape::Record {
            constructor,
            fields,
        } = definition.shape
        else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0601",
                format!("type `{record_type_name}` is not a record"),
                span,
            )]));
        };
        let mut layout_fields = Vec::new();
        for field in &fields {
            layout_fields.push((Arc::clone(&field.name), self.lower_type(field.ty)?));
        }
        let Some(field_index) = fields.iter().position(|field| field.name == *field_name) else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0601",
                format!(
                    "record `{}` has no field `{field_name}`",
                    definition.qualified_name
                ),
                span,
            )]));
        };
        let declared_field_type = layout_fields[field_index].1;
        let field_type = if let Some(explicit) = type_arguments.get(1) {
            self.lower_type(*explicit)?
        } else {
            self.unifier.fresh(self.types, KindArena::TYPE)
        };
        self.record_wanteds
            .push((field_type, declared_field_type, span));
        let layout = TemporaryRecordLayout {
            type_name: definition.qualified_name,
            constructor,
            fields: layout_fields.into(),
        };
        let field_index = u16::try_from(field_index).unwrap_or(u16::MAX);
        let (node, ty) = match name.as_ref() {
            "Record.get" => (
                self.alloc(
                    field_type,
                    span,
                    TemporaryKind::RecordGet {
                        layout,
                        field_index,
                        record: record.node,
                    },
                )?,
                field_type,
            ),
            "Record.set" => {
                let value = self.infer_expr(arguments[0], locals)?;
                self.charge_type_constraint(span)?;
                self.unifier
                    .unify(self.types, self.kinds, field_type, value.ty)
                    .map_err(|error| {
                        self.type_diagnostic(error, span, Some(field_type), Some(value.ty))
                    })?;
                (
                    self.alloc(
                        record.ty,
                        span,
                        TemporaryKind::RecordSet {
                            layout,
                            field_index,
                            value: value.node,
                            record: record.node,
                        },
                    )?,
                    record.ty,
                )
            }
            "Record.modify" => {
                let function = self.infer_expr(arguments[0], locals)?;
                let expected = self.types.function(field_type, field_type);
                self.charge_type_constraint(span)?;
                self.unifier
                    .unify(self.types, self.kinds, expected, function.ty)
                    .map_err(|error| {
                        self.type_diagnostic(error, span, Some(expected), Some(function.ty))
                    })?;
                (
                    self.alloc(
                        record.ty,
                        span,
                        TemporaryKind::RecordModify {
                            layout,
                            field_index,
                            function: function.node,
                            record: record.node,
                        },
                    )?,
                    record.ty,
                )
            }
            _ => unreachable!(),
        };
        Ok(Some(Inferred {
            node,
            ty,
            span,
            visible: Vec::new(),
            visible_used: 0,
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn infer_record_construction(
        &mut self,
        constructor: &str,
        fields: &[RecordFieldExpr],
        span: Span,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        let Some(name) = constructor.strip_prefix("Main.") else {
            return self.infer_generic_record_construction(constructor, fields, span, locals);
        };
        let Some(ConstructorOwner::Record { type_index }) =
            self.user_types.constructors.get(name).copied()
        else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0402",
                format!("unknown user record constructor `{constructor}`"),
                span,
            )]));
        };
        let definition = self.user_types.definitions[type_index].clone();
        let UserTypeShape::Record {
            constructor: declared_constructor,
            fields: declared_fields,
        } = definition.shape
        else {
            unreachable!("record constructor owner points to record type")
        };
        let mut supplied = HashMap::new();
        for field in fields {
            if supplied.insert(field.name.as_ref(), field).is_some() {
                return Err(DiagnosticBundle(vec![Diagnostic::new(
                    "H0603",
                    format!("duplicate record initializer `{}`", field.name),
                    field.span,
                )]));
            }
        }
        let expected: HashSet<&str> = declared_fields
            .iter()
            .map(|field| field.name.as_ref())
            .collect();
        let mut missing: Vec<_> = expected
            .iter()
            .filter(|field| !supplied.contains_key(**field))
            .copied()
            .collect();
        missing.sort_unstable();
        if !missing.is_empty() {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0604",
                format!(
                    "record construction is missing fields: {}",
                    missing.join(", ")
                ),
                span,
            )]));
        }
        let mut unexpected: Vec<_> = supplied
            .keys()
            .filter(|field| !expected.contains(**field))
            .copied()
            .collect();
        unexpected.sort_unstable();
        if !unexpected.is_empty() {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0605",
                format!(
                    "record construction has unexpected fields: {}",
                    unexpected.join(", ")
                ),
                span,
            )]));
        }
        let mut nodes = Vec::new();
        let mut layout_fields = Vec::new();
        for field in declared_fields {
            let expected_type = self.lower_type(field.ty)?;
            let supplied_field = supplied[field.name.as_ref()];
            let inferred = self.infer_expr(supplied_field.value, locals)?;
            self.charge_type_constraint(supplied_field.span)?;
            self.unifier
                .unify(self.types, self.kinds, inferred.ty, expected_type)
                .map_err(|error| {
                    self.type_diagnostic(
                        error,
                        supplied_field.span,
                        Some(expected_type),
                        Some(inferred.ty),
                    )
                })?;
            nodes.push(inferred.node);
            layout_fields.push((field.name, expected_type));
        }
        let ty = self
            .types
            .constructor(Arc::clone(&definition.qualified_name), KindArena::TYPE);
        let node = self.alloc(
            ty,
            span,
            TemporaryKind::Record {
                layout: TemporaryRecordLayout {
                    type_name: definition.qualified_name,
                    constructor: declared_constructor,
                    fields: layout_fields.into(),
                },
                fields: nodes.into(),
            },
        )?;
        Ok(Inferred {
            node,
            ty,
            span,
            visible: Vec::new(),
            visible_used: 0,
        })
    }

    fn infer_generic_record_construction(
        &mut self,
        constructor: &str,
        fields: &[RecordFieldExpr],
        span: Span,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        if constructor != "Maybe.Just" {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0004",
                format!(
                    "generic record construction through `{constructor}` is not available in this build"
                ),
                span,
            )]));
        }
        let mut sorted = fields.to_vec();
        sorted.sort_by(|left, right| left.name.cmp(&right.name));
        let mut seen = HashSet::new();
        let mut nodes = Vec::new();
        let mut layout_fields = Vec::new();
        for field in sorted {
            if !seen.insert(Arc::clone(&field.name)) {
                return Err(DiagnosticBundle(vec![Diagnostic::new(
                    "H0603",
                    format!("duplicate record initializer `{}`", field.name),
                    field.span,
                )]));
            }
            let value = self.infer_expr(field.value, locals)?;
            nodes.push(value.node);
            layout_fields.push((field.name, value.ty));
        }
        let mut row = self.types.intern(TypeNode::RowNil);
        for (name, ty) in layout_fields.iter().rev() {
            row = self.types.intern(TypeNode::RowCons {
                label: Arc::clone(name),
                field: *ty,
                tail: row,
            });
        }
        let record_kind = self
            .kinds
            .intern(hell_types::KindNode::Arrow(KindArena::ROW, KindArena::TYPE));
        let record_constructor = self.types.constructor("hell:Hell.Record", record_kind);
        let record_type = self.types.apply(record_constructor, row);
        let record = self.alloc(
            record_type,
            span,
            TemporaryKind::Record {
                layout: TemporaryRecordLayout {
                    type_name: "hell:Hell.Record".into(),
                    constructor: "hell:Hell.Record".into(),
                    fields: layout_fields.into(),
                },
                fields: nodes.into(),
            },
        )?;
        let just = self.infer_name("Maybe.Just", span, locals)?;
        self.apply_inferred(
            just,
            Inferred {
                node: record,
                ty: record_type,
                span,
                visible: Vec::new(),
                visible_used: 0,
            },
            span,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn infer_case(
        &mut self,
        scrutinee: ExprId,
        alternatives: &[CaseAlternative],
        span: Span,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        if alternatives.iter().any(|alternative| {
            matches!(
                alternative.pattern,
                CasePattern::PrimitiveConstructor { .. }
            )
        }) {
            return self.infer_primitive_case(scrutinee, alternatives, span, locals);
        }
        let scrutinee = self.infer_expr(scrutinee, locals)?;
        let mut selected_type = None;
        for alternative in alternatives {
            let CasePattern::UserConstructor { name, .. } = &alternative.pattern else {
                continue;
            };
            let Some(ConstructorOwner::Variant { type_index, .. }) =
                self.user_types.constructors.get(name).copied()
            else {
                return Err(DiagnosticBundle(vec![Diagnostic::new(
                    "H0610",
                    format!("unknown variant constructor `{name}`"),
                    alternative.pattern.span(),
                )]));
            };
            if selected_type
                .replace(type_index)
                .is_some_and(|old| old != type_index)
            {
                return Err(DiagnosticBundle(vec![Diagnostic::new(
                    "H0611",
                    "case alternatives belong to different user variants",
                    alternative.pattern.span(),
                )]));
            }
        }
        if selected_type.is_none()
            && let TypeNode::Constructor { name, .. } = self.types.get(scrutinee.ty)
        {
            selected_type = self.user_types.by_name.get(name).copied();
        }
        let Some(type_index) = selected_type else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0610",
                "a wildcard-only user case requires a known nominal variant scrutinee",
                span,
            )]));
        };
        let definition = self.user_types.definitions[type_index].clone();
        let UserTypeShape::Variant { constructors } = definition.shape else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0610",
                "case scrutinee is not a user variant",
                span,
            )]));
        };
        let scrutinee_expected = self
            .types
            .constructor(Arc::clone(&definition.qualified_name), KindArena::TYPE);
        self.charge_type_constraint(span)?;
        self.unifier
            .unify(self.types, self.kinds, scrutinee.ty, scrutinee_expected)
            .map_err(|error| {
                self.type_diagnostic(error, span, Some(scrutinee_expected), Some(scrutinee.ty))
            })?;

        let mut explicit = Vec::new();
        let mut wildcard = None;
        let mut seen = HashSet::new();
        for alternative in alternatives {
            match &alternative.pattern {
                CasePattern::UserConstructor { name, binder, .. } => {
                    if !seen.insert(name.as_ref()) {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0612",
                            format!("duplicate case constructor `{name}`"),
                            alternative.pattern.span(),
                        )]));
                    }
                    let Some((constructor_index, constructor)) = constructors
                        .iter()
                        .enumerate()
                        .find(|(_, constructor)| constructor.name == *name)
                    else {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0610",
                            format!(
                                "constructor `{name}` is not part of `{}`",
                                definition.qualified_name
                            ),
                            alternative.pattern.span(),
                        )]));
                    };
                    if constructor.payload.is_some() != binder.is_some() {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0611",
                            format!("constructor `{name}` has the wrong payload binder arity"),
                            alternative.pattern.span(),
                        )]));
                    }
                    explicit.push((
                        constructor_index,
                        constructor.clone(),
                        binder.clone(),
                        alternative,
                    ));
                }
                CasePattern::Wildcard(_) => {
                    if wildcard.replace(alternative).is_some() {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0613",
                            "a case may contain at most one wildcard",
                            alternative.pattern.span(),
                        )]));
                    }
                }
                CasePattern::PrimitiveConstructor { .. } => unreachable!(),
            }
        }
        explicit.sort_by_key(|(index, _, _, _)| *index);
        let explicit_names: Vec<&str> = explicit
            .iter()
            .map(|(_, constructor, _, _)| constructor.name.as_ref())
            .collect();
        let expected_names: Vec<&str> = constructors
            .iter()
            .take(explicit.len())
            .map(|constructor| constructor.name.as_ref())
            .collect();
        if wildcard.is_some() && explicit_names != expected_names {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0502",
                "explicit user alternatives before a wildcard must form the canonical constructor prefix",
                span,
            )]));
        }
        if wildcard.is_none() && explicit.len() != constructors.len() {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0502",
                format!("non-exhaustive case over `{}`", definition.qualified_name),
                span,
            )]));
        }

        let mut layout_constructors = Vec::new();
        for constructor in &constructors {
            layout_constructors.push((
                Arc::clone(&constructor.name),
                constructor
                    .payload
                    .map(|payload| self.lower_type(payload))
                    .transpose()?,
            ));
        }
        let result_type = self.unifier.fresh(self.types, KindArena::TYPE);
        let mut branches = Vec::new();
        for (constructor_index, constructor, binder, alternative) in explicit {
            let base = locals.len();
            let payload_type = constructor
                .payload
                .map(|payload| self.lower_type(payload))
                .transpose()?;
            if let (Some(name), Some(payload_type)) = (binder, payload_type) {
                locals.push(Local {
                    name,
                    ty: payload_type,
                    slot: local_slot_count(locals),
                    projection: Projection::Identity,
                });
            }
            let branch = self.infer_expr(alternative.expression, locals)?;
            locals.truncate(base);
            self.charge_type_constraint(alternative.span)?;
            self.unifier
                .unify(self.types, self.kinds, result_type, branch.ty)
                .map_err(|error| {
                    self.type_diagnostic(
                        error,
                        alternative.span,
                        Some(result_type),
                        Some(branch.ty),
                    )
                })?;
            branches.push(TemporaryCaseBranch {
                constructor_index: u16::try_from(constructor_index).unwrap_or(u16::MAX),
                payload_type,
                body: branch.node,
            });
        }
        let default = if let Some(alternative) = wildcard {
            let branch = self.infer_expr(alternative.expression, locals)?;
            self.charge_type_constraint(alternative.span)?;
            self.unifier
                .unify(self.types, self.kinds, result_type, branch.ty)
                .map_err(|error| {
                    self.type_diagnostic(
                        error,
                        alternative.span,
                        Some(result_type),
                        Some(branch.ty),
                    )
                })?;
            Some(branch.node)
        } else {
            None
        };
        let node = self.alloc(
            result_type,
            span,
            TemporaryKind::Case {
                scrutinee: scrutinee.node,
                layout: TemporaryVariantLayout {
                    type_name: definition.qualified_name,
                    constructors: layout_constructors.into(),
                },
                branches: branches.into(),
                default,
            },
        )?;
        Ok(Inferred {
            node,
            ty: result_type,
            span,
            visible: Vec::new(),
            visible_used: 0,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn infer_primitive_case(
        &mut self,
        scrutinee: ExprId,
        alternatives: &[CaseAlternative],
        span: Span,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        let mut wildcard = None;
        let mut family = None;
        let mut constructor_count = 0;
        let mut seen = HashSet::new();
        for alternative in alternatives {
            match &alternative.pattern {
                CasePattern::PrimitiveConstructor { name, binders, .. } => {
                    let Some((current_family, constructor_index, arity, count)) =
                        primitive_case_constructor(name)
                    else {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0610",
                            format!("unknown primitive case constructor `{name}`"),
                            alternative.pattern.span(),
                        )]));
                    };
                    if family.is_some_and(|family| family != current_family) {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0614",
                            "primitive constructors from different case families cannot be mixed",
                            alternative.pattern.span(),
                        )]));
                    }
                    family = Some(current_family);
                    constructor_count = count;
                    if binders.len() != arity {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0611",
                            format!("primitive constructor `{name}` has the wrong payload arity"),
                            alternative.pattern.span(),
                        )]));
                    }
                    if !seen.insert(constructor_index) {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0612",
                            format!("duplicate case constructor `{name}`"),
                            alternative.pattern.span(),
                        )]));
                    }
                }
                CasePattern::Wildcard(_) => {
                    if wildcard.replace(alternative).is_some() {
                        return Err(DiagnosticBundle(vec![Diagnostic::new(
                            "H0613",
                            "a case may contain at most one wildcard",
                            alternative.pattern.span(),
                        )]));
                    }
                }
                CasePattern::UserConstructor { .. } => {
                    return Err(DiagnosticBundle(vec![Diagnostic::new(
                        "H0614",
                        "primitive and user case constructors cannot be mixed",
                        alternative.pattern.span(),
                    )]));
                }
            }
        }
        if wildcard.is_none() && seen.len() != constructor_count {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0615",
                "non-exhaustive primitive case",
                span,
            )]));
        }
        self.infer_registered_primitive_case(
            family.expect("a primitive case has a primitive constructor"),
            scrutinee,
            alternatives,
            wildcard,
            span,
            locals,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn infer_registered_primitive_case(
        &mut self,
        family: &str,
        scrutinee: ExprId,
        alternatives: &[CaseAlternative],
        wildcard: Option<&CaseAlternative>,
        span: Span,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        let eliminator_name = match family {
            "Bool" => "Bool.bool",
            "Maybe" => "Maybe.maybe",
            "Either" => "Either.either",
            "Exit" => "Exit.exitCode",
            "These" => "These.these",
            "Json" => "Json.value",
            _ => unreachable!("primitive case family validated"),
        };
        let mut eliminator = self.infer_name(eliminator_name, span, locals)?;
        let visible = eliminator.visible.clone();
        let int = self.types.constructor("Int", KindArena::TYPE);
        let bool_ = self.types.constructor("Bool", KindArena::TYPE);
        let text = self.types.constructor("Text", KindArena::TYPE);
        let double = self.types.constructor("Double", KindArena::TYPE);
        let value = self.types.constructor("Value", KindArena::TYPE);
        let unary_kind = self.kinds.intern(hell_types::KindNode::Arrow(
            KindArena::TYPE,
            KindArena::TYPE,
        ));
        let binary_result_kind = self.kinds.intern(hell_types::KindNode::Arrow(
            KindArena::TYPE,
            KindArena::TYPE,
        ));
        let binary_kind = self.kinds.intern(hell_types::KindNode::Arrow(
            KindArena::TYPE,
            binary_result_kind,
        ));
        let vector = self.types.constructor("Vector", unary_kind);
        let vector_value = self.types.apply(vector, value);
        let map = self.types.constructor("Map", binary_kind);
        let map_text = self.types.apply(map, text);
        let map_text_value = self.types.apply(map_text, value);
        let payloads: Vec<Vec<TypeId>> = match family {
            "Bool" => vec![vec![], vec![]],
            "Maybe" => vec![vec![], vec![visible[0].0]],
            "Either" => vec![vec![visible[0].0], vec![visible[1].0]],
            "Exit" => vec![vec![], vec![int]],
            "These" => vec![
                vec![visible[0].0],
                vec![visible[1].0],
                vec![visible[0].0, visible[1].0],
            ],
            "Json" => vec![
                vec![],
                vec![bool_],
                vec![text],
                vec![double],
                vec![vector_value],
                vec![map_text_value],
            ],
            _ => unreachable!("primitive case family validated"),
        };
        for (constructor_index, payload_types) in payloads.iter().enumerate() {
            let explicit = alternatives.iter().find(|alternative| {
                let CasePattern::PrimitiveConstructor { name, .. } = &alternative.pattern else {
                    return false;
                };
                primitive_case_constructor(name)
                    .is_some_and(|(_, index, _, _)| index == constructor_index)
            });
            let alternative = explicit
                .or(wildcard)
                .expect("primitive case coverage validated");
            let binders = if let Some(CaseAlternative {
                pattern: CasePattern::PrimitiveConstructor { binders, .. },
                ..
            }) = explicit
            {
                binders.clone()
            } else {
                (0..payload_types.len())
                    .map(|index| Arc::<str>::from(format!("$wildcard{index}")))
                    .collect()
            };
            let base = locals.len();
            for (binder, payload_type) in binders.into_iter().zip(payload_types.iter().copied()) {
                locals.push(Local {
                    name: binder,
                    ty: payload_type,
                    slot: local_slot_count(locals),
                    projection: Projection::Identity,
                });
            }
            let body = self.infer_expr(alternative.expression, locals)?;
            locals.truncate(base);
            let mut handler_node = body.node;
            let mut handler_type = body.ty;
            for payload_type in payload_types.iter().rev().copied() {
                handler_type = self.types.function(payload_type, handler_type);
                handler_node = self.alloc(
                    handler_type,
                    alternative.span,
                    TemporaryKind::Lambda {
                        parameter_type: payload_type,
                        body: handler_node,
                    },
                )?;
            }
            let handler = Inferred {
                node: handler_node,
                ty: handler_type,
                span: alternative.span,
                visible: Vec::new(),
                visible_used: 0,
            };
            eliminator = self.apply_inferred(eliminator, handler, span)?;
        }
        let scrutinee = self.infer_expr(scrutinee, locals)?;
        self.apply_inferred(eliminator, scrutinee, span)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn apply_inferred(
        &mut self,
        function: Inferred,
        argument: Inferred,
        span: Span,
    ) -> Result<Inferred, DiagnosticBundle> {
        let result = self.unifier.fresh(self.types, KindArena::TYPE);
        let expected = self.types.function(argument.ty, result);
        self.charge_type_constraint(span)?;
        self.unifier
            .unify(self.types, self.kinds, function.ty, expected)
            .map_err(|error| {
                self.type_diagnostic(error, span, Some(expected), Some(function.ty))
            })?;
        let node = self.alloc(
            result,
            span,
            TemporaryKind::Apply {
                function: function.node,
                argument: argument.node,
            },
        )?;
        Ok(Inferred {
            node,
            ty: result,
            span,
            visible: Vec::new(),
            visible_used: 0,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn infer_do(
        &mut self,
        statements: &[DoStatement],
        span: Span,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        enum Frame {
            Then {
                action: Inferred,
                span: Span,
            },
            Let {
                value: Inferred,
                parameter_type: TypeId,
                locals_base: usize,
                span: Span,
            },
            Bind {
                action: Inferred,
                parameter_type: TypeId,
                locals_base: usize,
                span: Span,
            },
        }

        let Some((last, prefix)) = statements.split_last() else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0210",
                "empty do block",
                span,
            )]));
        };
        let mut frames = Vec::with_capacity(prefix.len());
        for statement in prefix {
            match statement {
                DoStatement::Then(expression, statement_span) => {
                    frames.push(Frame::Then {
                        action: self.infer_expr(*expression, locals)?,
                        span: *statement_span,
                    });
                }
                DoStatement::Let(pattern, expression, statement_span) => {
                    let value = self.infer_expr(*expression, locals)?;
                    let locals_base = locals.len();
                    let parameter_type = self.bind_pattern(pattern, locals)?;
                    self.charge_type_constraint(*statement_span)?;
                    self.unifier
                        .unify(self.types, self.kinds, parameter_type, value.ty)
                        .map_err(|error| {
                            self.type_diagnostic(
                                error,
                                *statement_span,
                                Some(parameter_type),
                                Some(value.ty),
                            )
                        })?;
                    frames.push(Frame::Let {
                        value,
                        parameter_type,
                        locals_base,
                        span: *statement_span,
                    });
                }
                DoStatement::Bind(pattern, expression, statement_span) => {
                    let action = self.infer_expr(*expression, locals)?;
                    let locals_base = locals.len();
                    let parameter_type = self.bind_pattern(pattern, locals)?;
                    let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                        KindArena::TYPE,
                        KindArena::TYPE,
                    ));
                    let constructor = self.unifier.fresh(self.types, constructor_kind);
                    let expected_action = self.types.apply(constructor, parameter_type);
                    self.charge_type_constraint(*statement_span)?;
                    self.unifier
                        .unify(self.types, self.kinds, action.ty, expected_action)
                        .map_err(|error| {
                            self.type_diagnostic(
                                error,
                                *statement_span,
                                Some(expected_action),
                                Some(action.ty),
                            )
                        })?;
                    frames.push(Frame::Bind {
                        action,
                        parameter_type,
                        locals_base,
                        span: *statement_span,
                    });
                }
            }
        }
        let DoStatement::Then(expression, _) = last else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0210",
                "a do block must end with an expression",
                span,
            )]));
        };
        let mut body = self.infer_expr(*expression, locals)?;
        for frame in frames.into_iter().rev() {
            match frame {
                Frame::Then { action, span } => {
                    let then = self.infer_name("Monad.then", span, locals)?;
                    let applied = self.apply_inferred(then, action, span)?;
                    body = self.apply_inferred(applied, body, span)?;
                }
                Frame::Let {
                    value,
                    parameter_type,
                    locals_base,
                    span,
                } => {
                    locals.truncate(locals_base);
                    let function_type = self.types.function(parameter_type, body.ty);
                    let lambda = self.alloc(
                        function_type,
                        span,
                        TemporaryKind::Lambda {
                            parameter_type,
                            body: body.node,
                        },
                    )?;
                    body = self.apply_inferred(
                        Inferred {
                            node: lambda,
                            ty: function_type,
                            span,
                            visible: Vec::new(),
                            visible_used: 0,
                        },
                        value,
                        span,
                    )?;
                }
                Frame::Bind {
                    action,
                    parameter_type,
                    locals_base,
                    span,
                } => {
                    locals.truncate(locals_base);
                    let function_type = self.types.function(parameter_type, body.ty);
                    let lambda = self.alloc(
                        function_type,
                        span,
                        TemporaryKind::Lambda {
                            parameter_type,
                            body: body.node,
                        },
                    )?;
                    let bind = self.infer_name("Monad.bind", span, locals)?;
                    let bind = self.apply_inferred(bind, action, span)?;
                    body = self.apply_inferred(
                        bind,
                        Inferred {
                            node: lambda,
                            ty: function_type,
                            span,
                            visible: Vec::new(),
                            visible_used: 0,
                        },
                        span,
                    )?;
                }
            }
        }
        Ok(body)
    }

    fn bind_pattern(
        &mut self,
        pattern: &BindingPattern,
        locals: &mut Vec<Local>,
    ) -> Result<TypeId, DiagnosticBundle> {
        let slot = local_slot_count(locals);
        match pattern {
            BindingPattern::Variable(name, _) => {
                let ty = self.unifier.fresh(self.types, KindArena::TYPE);
                locals.push(Local {
                    name: Arc::clone(name),
                    ty,
                    slot,
                    projection: Projection::Identity,
                });
                Ok(ty)
            }
            BindingPattern::Wildcard(_) => {
                let ty = self.unifier.fresh(self.types, KindArena::TYPE);
                locals.push(Local {
                    name: "$wildcard".into(),
                    ty,
                    slot,
                    projection: Projection::Identity,
                });
                Ok(ty)
            }
            BindingPattern::Tuple(names, _) => {
                let items: Vec<_> = names
                    .iter()
                    .map(|_| self.unifier.fresh(self.types, KindArena::TYPE))
                    .collect();
                for (index, (name, ty)) in names.iter().zip(items.iter()).enumerate() {
                    locals.push(Local {
                        name: Arc::clone(name),
                        ty: *ty,
                        slot,
                        projection: Projection::TupleElement {
                            arity: u8::try_from(names.len()).unwrap_or(u8::MAX),
                            index: u8::try_from(index).unwrap_or(u8::MAX),
                        },
                    });
                }
                Ok(self.types.tuple(&items, self.kinds))
            }
            BindingPattern::Annotated(inner, annotation, span) => {
                let base = locals.len();
                let inferred = self.bind_pattern(inner, locals)?;
                let annotation = self.lower_type(*annotation)?;
                self.charge_type_constraint(*span)?;
                self.unifier
                    .unify(self.types, self.kinds, inferred, annotation)
                    .map_err(|error| {
                        self.type_diagnostic(error, *span, Some(annotation), Some(inferred))
                    })?;
                // Component bindings keep their projected types; a simple
                // variable binding adopts the concrete annotation.
                if locals.len() == base + 1
                    && matches!(locals[base].projection, Projection::Identity)
                {
                    locals[base].ty = annotation;
                }
                Ok(annotation)
            }
        }
    }

    fn infer_name(
        &mut self,
        name: &str,
        span: Span,
        locals: &mut Vec<Local>,
    ) -> Result<Inferred, DiagnosticBundle> {
        if let Some(global) = name.strip_prefix("Main.") {
            if let Some(index) = self.globals.get(global) {
                return self.expand_global(*index, locals);
            }
            if let Some(owner) = self.user_types.constructors.get(global).copied() {
                return self.infer_user_constructor(owner, span);
            }
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0402",
                format!("unknown global `{name}`"),
                span,
            )]));
        }
        if name.contains('.') || is_operator(name) {
            return self.instantiate_builtin(name, span);
        }
        let Some((_, local)) = locals
            .iter()
            .enumerate()
            .rev()
            .find(|(_, local)| local.name.as_ref() == name)
        else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0401",
                format!("unbound local `{name}`"),
                span,
            )]));
        };
        let slot_count = local_slot_count(locals);
        let de_bruijn = u32::try_from(slot_count - local.slot - 1).unwrap_or(u32::MAX);
        let ty = local.ty;
        let projection = local.projection;
        let node = self.alloc(
            ty,
            span,
            TemporaryKind::BoundVar {
                de_bruijn,
                projection,
            },
        )?;
        Ok(Inferred {
            node,
            ty,
            span,
            visible: Vec::new(),
            visible_used: 0,
        })
    }

    fn infer_user_constructor(
        &mut self,
        owner: ConstructorOwner,
        span: Span,
    ) -> Result<Inferred, DiagnosticBundle> {
        let ConstructorOwner::Variant {
            type_index,
            constructor_index,
        } = owner
        else {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0406",
                "record constructors must use named record-construction syntax",
                span,
            )]));
        };
        let definition = self.user_types.definitions[type_index].clone();
        let UserTypeShape::Variant { constructors } = definition.shape else {
            unreachable!("variant constructor owner points to variant type")
        };
        let mut layout_constructors = Vec::new();
        for constructor in &constructors {
            layout_constructors.push((
                Arc::clone(&constructor.name),
                constructor
                    .payload
                    .map(|payload| self.lower_type(payload))
                    .transpose()?,
            ));
        }
        let result_type = self
            .types
            .constructor(Arc::clone(&definition.qualified_name), KindArena::TYPE);
        let payload_type = layout_constructors[constructor_index].1;
        let layout = TemporaryVariantLayout {
            type_name: definition.qualified_name,
            constructors: layout_constructors.into(),
        };
        if let Some(payload_type) = payload_type {
            let payload = self.alloc(
                payload_type,
                span,
                TemporaryKind::BoundVar {
                    de_bruijn: 0,
                    projection: Projection::Identity,
                },
            )?;
            let variant = self.alloc(
                result_type,
                span,
                TemporaryKind::Variant {
                    layout,
                    constructor_index: u16::try_from(constructor_index).unwrap_or(u16::MAX),
                    payload: Some(payload),
                },
            )?;
            let ty = self.types.function(payload_type, result_type);
            let node = self.alloc(
                ty,
                span,
                TemporaryKind::Lambda {
                    parameter_type: payload_type,
                    body: variant,
                },
            )?;
            Ok(Inferred {
                node,
                ty,
                span,
                visible: Vec::new(),
                visible_used: 0,
            })
        } else {
            let node = self.alloc(
                result_type,
                span,
                TemporaryKind::Variant {
                    layout,
                    constructor_index: u16::try_from(constructor_index).unwrap_or(u16::MAX),
                    payload: None,
                },
            )?;
            Ok(Inferred {
                node,
                ty: result_type,
                span,
                visible: Vec::new(),
                visible_used: 0,
            })
        }
    }

    #[allow(clippy::too_many_lines)]
    fn instantiate_builtin(
        &mut self,
        name: &str,
        span: Span,
    ) -> Result<Inferred, DiagnosticBundle> {
        let spec = hell_builtins::lookup(name).ok_or_else(|| {
            DiagnosticBundle(vec![Diagnostic::new(
                "H0403",
                format!("unknown primitive `{name}`"),
                span,
            )])
        })?;
        #[cfg(feature = "compat-tracing")]
        self.parsed_builtins.insert(spec.id);
        if spec.implementation.is_none() {
            return Err(DiagnosticBundle(vec![Diagnostic::new(
                "H0004",
                format!("primitive `{name}` is not available in this build"),
                span,
            )]));
        }
        #[cfg(feature = "compat-tracing")]
        self.resolved_builtins.insert(spec.id);
        let int = self.types.constructor("Int", KindArena::TYPE);
        let integer = self.types.constructor("Integer", KindArena::TYPE);
        let bool_ = self.types.constructor("Bool", KindArena::TYPE);
        let text = self.types.constructor("Text", KindArena::TYPE);
        let double = self.types.constructor("Double", KindArena::TYPE);
        let bytes = self.types.constructor("ByteString", KindArena::TYPE);
        let handle = self.types.constructor("Handle", KindArena::TYPE);
        let buffer_mode = self.types.constructor("BufferMode", KindArena::TYPE);
        let file_mode = self.types.constructor("FileMode", KindArena::TYPE);
        let process = self.types.constructor("Process", KindArena::TYPE);
        let exit_code = self.types.constructor("ExitCode", KindArena::TYPE);
        let json_value = self.types.constructor("Value", KindArena::TYPE);
        let day = self.types.constructor("Day", KindArena::TYPE);
        let day_of_week = self.types.constructor("DayOfWeek", KindArena::TYPE);
        let utc_time = self.types.constructor("UTCTime", KindArena::TYPE);
        let time_of_day = self.types.constructor("TimeOfDay", KindArena::TYPE);
        let builder = self.types.constructor("Builder", KindArena::TYPE);
        let http_status = self.types.constructor("Http.Status", KindArena::TYPE);
        let http_file_part = self.types.constructor("Http.FilePart", KindArena::TYPE);
        let http_request = self.types.constructor("Http.Request", KindArena::TYPE);
        let http_response = self.types.constructor("Http.Response", KindArena::TYPE);
        let http_response_received = self
            .types
            .constructor("Http.ResponseReceived", KindArena::TYPE);
        let unit = self.types.constructor("()", KindArena::TYPE);
        let mut binders = Vec::new();
        let mut evidence = None;
        let ty = match name {
            "Bool.False" | "Bool.True" => bool_,
            "Bool.not" => self.types.function(bool_, bool_),
            "Bool.bool" => {
                let a = self.fresh_binder(&mut binders);
                let final_ = self.types.function(bool_, a);
                let true_ = self.types.function(a, final_);
                self.types.function(a, true_)
            }
            "Function.id" => {
                let a = self.fresh_binder(&mut binders);
                self.types.function(a, a)
            }
            "Function.fix" => {
                let a = self.fresh_binder(&mut binders);
                let function = self.types.function(a, a);
                self.types.function(function, a)
            }
            "Error.error" => {
                let a = self.fresh_binder(&mut binders);
                self.types.function(text, a)
            }
            "Int.plus" | "Int.subtract" | "Int.mult" => {
                let result = self.types.function(int, int);
                self.types.function(int, result)
            }
            "Int.eq" => {
                let result = self.types.function(int, bool_);
                self.types.function(int, result)
            }
            "Eq.eq" => {
                let a = self.fresh_binder(&mut binders);
                self.eq_wanteds.push((a, span));
                evidence = Some((hell_builtins::TypeClass::Eq, a));
                let result = self.types.function(a, bool_);
                self.types.function(a, result)
            }
            "Ord.lt" | "Ord.gt" => {
                let a = self.fresh_binder(&mut binders);
                self.ord_wanteds.push((a, span));
                evidence = Some((hell_builtins::TypeClass::Ord, a));
                let result = self.types.function(a, bool_);
                self.types.function(a, result)
            }
            "Int.show" => self.types.function(int, text),
            "Int.readMaybe" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let result = self.types.apply(maybe, int);
                self.types.function(text, result)
            }
            "Int.toInteger" => self.types.function(int, integer),
            "Int.fromInteger" => self.types.function(integer, int),
            "Integer.plus" | "Integer.subtract" | "Integer.mult" => {
                let result = self.types.function(integer, integer);
                self.types.function(integer, result)
            }
            "Integer.readMaybe" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let result = self.types.apply(maybe, integer);
                self.types.function(text, result)
            }
            "Double.eq" => {
                let result = self.types.function(double, bool_);
                self.types.function(double, result)
            }
            "Double.plus" | "Double.subtract" | "Double.mult" => {
                let result = self.types.function(double, double);
                self.types.function(double, result)
            }
            "Double.fromInt" => self.types.function(int, double),
            "Double.readMaybe" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let result = self.types.apply(maybe, double);
                self.types.function(text, result)
            }
            "Double.show" => self.types.function(double, text),
            "Double.showEFloat" | "Double.showFFloat" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let precision = self.types.apply(maybe, int);
                let suffix = self.types.function(text, text);
                let number = self.types.function(double, suffix);
                self.types.function(precision, number)
            }
            "Show.show" => {
                let a = self.fresh_binder(&mut binders);
                self.show_wanteds.push((a, span));
                evidence = Some((hell_builtins::TypeClass::Show, a));
                self.types.function(a, text)
            }
            "Text.eq" | "Text.isInfixOf" | "Text.isPrefixOf" | "Text.isSuffixOf" => {
                let result = self.types.function(text, bool_);
                self.types.function(text, result)
            }
            "Text.all" | "Text.any" => {
                let character = self.types.constructor("Char", KindArena::TYPE);
                let predicate = self.types.function(character, bool_);
                let tail = self.types.function(text, bool_);
                self.types.function(predicate, tail)
            }
            "Text.filter" => {
                let character = self.types.constructor("Char", KindArena::TYPE);
                let predicate = self.types.function(character, bool_);
                let tail = self.types.function(text, text);
                self.types.function(predicate, tail)
            }
            "Text.breakOn" => {
                let pair = self.types.tuple(&[text, text], self.kinds);
                let tail = self.types.function(text, pair);
                self.types.function(text, tail)
            }
            "Text.length" => self.types.function(text, int),
            "Text.reverse" | "Text.strip" | "Text.toLower" | "Text.toUpper" => {
                self.types.function(text, text)
            }
            "Text.concat" | "Text.unlines" | "Text.unwords" => {
                let texts = self.types.list(text, self.kinds);
                self.types.function(texts, text)
            }
            "Text.lines" | "Text.words" => {
                let texts = self.types.list(text, self.kinds);
                self.types.function(text, texts)
            }
            "Text.pack" => {
                let character = self.types.constructor("Char", KindArena::TYPE);
                let characters = self.types.list(character, self.kinds);
                self.types.function(characters, text)
            }
            "Text.unpack" => {
                let character = self.types.constructor("Char", KindArena::TYPE);
                let characters = self.types.list(character, self.kinds);
                self.types.function(text, characters)
            }
            "Text.getLine" | "Text.getContents" => self.types.io(text, self.kinds),
            "Text.interact" => {
                let transform = self.types.function(text, text);
                let action = self.types.io(unit, self.kinds);
                self.types.function(transform, action)
            }
            "Text.take" | "Text.drop" | "Text.takeEnd" | "Text.dropEnd" => {
                let tail = self.types.function(text, text);
                self.types.function(int, tail)
            }
            "Text.stripPrefix" | "Text.stripSuffix" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let result = self.types.apply(maybe, text);
                let tail = self.types.function(text, result);
                self.types.function(text, tail)
            }
            "Text.replace" => {
                let result = self.types.function(text, text);
                let source = self.types.function(text, result);
                self.types.function(text, source)
            }
            "Text.splitOn" => {
                let texts = self.types.list(text, self.kinds);
                let source = self.types.function(text, texts);
                self.types.function(text, source)
            }
            "Text.intercalate" => {
                let texts = self.types.list(text, self.kinds);
                let tail = self.types.function(texts, text);
                self.types.function(text, tail)
            }
            "Text.putStr"
            | "Text.putStrLn"
            | "Directory.createDirectory"
            | "Directory.removeDirectory"
            | "Directory.removeFile"
            | "Directory.setCurrentDirectory" => {
                let io_unit = self.types.io(unit, self.kinds);
                self.types.function(text, io_unit)
            }
            "Text.readFile" | "Environment.getEnv" | "Directory.getSymbolicLinkTarget" => {
                let io_text = self.types.io(text, self.kinds);
                self.types.function(text, io_text)
            }
            "Text.writeFile"
            | "Text.appendFile"
            | "Directory.copyFile"
            | "Directory.renameFile" => {
                let io_unit = self.types.io(unit, self.kinds);
                let contents = self.types.function(text, io_unit);
                self.types.function(text, contents)
            }
            "Text.hPutStr" => {
                let io_unit = self.types.io(unit, self.kinds);
                let contents = self.types.function(text, io_unit);
                self.types.function(handle, contents)
            }
            "Text.readProcess" => {
                let output = self.types.tuple(&[exit_code, text, text], self.kinds);
                let output = self.types.io(output, self.kinds);
                self.types.function(process, output)
            }
            "Text.readProcess_" => {
                let output = self.types.tuple(&[text, text], self.kinds);
                let output = self.types.io(output, self.kinds);
                self.types.function(process, output)
            }
            "Text.readProcessStdout_" => {
                let output = self.types.io(text, self.kinds);
                self.types.function(process, output)
            }
            "Text.setStdin" | "Process.setWorkingDir" => {
                let configured = self.types.function(process, process);
                self.types.function(text, configured)
            }
            "Text.encodeUtf8" => self.types.function(text, bytes),
            "Text.decodeUtf8" => self.types.function(bytes, text),
            "Builder.byteString" => self.types.function(bytes, builder),
            "Http.mkStatus" => {
                let reason = self.types.function(text, http_status);
                self.types.function(int, reason)
            }
            "Http.FilePart" => {
                let size = self.types.function(integer, http_file_part);
                let count = self.types.function(integer, size);
                self.types.function(integer, count)
            }
            "Http.pathInfo" => {
                let path = self.types.list(text, self.kinds);
                self.types.function(http_request, path)
            }
            "Http.requestHeaders" => {
                let ci_bytes = self.apply_named_type("CI", &[bytes]);
                let header = self.types.tuple(&[ci_bytes, bytes], self.kinds);
                let headers = self.types.list(header, self.kinds);
                self.types.function(http_request, headers)
            }
            "Http.queryString" => {
                let maybe_bytes = self.apply_named_type("Maybe", &[bytes]);
                let parameter = self.types.tuple(&[bytes, maybe_bytes], self.kinds);
                let query = self.types.list(parameter, self.kinds);
                self.types.function(http_request, query)
            }
            "Http.getRequestBodyChunk" | "Http.consumeRequestBodyStrict" => {
                let result = self.types.io(bytes, self.kinds);
                self.types.function(http_request, result)
            }
            "Http.responseBuilder" => {
                let ci_bytes = self.apply_named_type("CI", &[bytes]);
                let header = self.types.tuple(&[ci_bytes, bytes], self.kinds);
                let headers = self.types.list(header, self.kinds);
                let body = self.types.function(builder, http_response);
                let with_headers = self.types.function(headers, body);
                self.types.function(http_status, with_headers)
            }
            "Http.responseFile" => {
                let ci_bytes = self.apply_named_type("CI", &[bytes]);
                let header = self.types.tuple(&[ci_bytes, bytes], self.kinds);
                let headers = self.types.list(header, self.kinds);
                let maybe_part = self.apply_named_type("Maybe", &[http_file_part]);
                let part = self.types.function(maybe_part, http_response);
                let path = self.types.function(text, part);
                let with_headers = self.types.function(headers, path);
                self.types.function(http_status, with_headers)
            }
            "Http.responseStream" => {
                let ci_bytes = self.apply_named_type("CI", &[bytes]);
                let header = self.types.tuple(&[ci_bytes, bytes], self.kinds);
                let headers = self.types.list(header, self.kinds);
                let io_unit = self.types.io(unit, self.kinds);
                let write = self.types.function(builder, io_unit);
                let flush = self.types.function(io_unit, io_unit);
                let streaming = self.types.function(write, flush);
                let callback = self.types.function(streaming, http_response);
                let with_headers = self.types.function(headers, callback);
                self.types.function(http_status, with_headers)
            }
            "Http.run" => {
                let received = self.types.io(http_response_received, self.kinds);
                let responder = self.types.function(http_response, received);
                let application_result = self.types.function(responder, received);
                let application = self.types.function(http_request, application_result);
                let result = self.types.io(unit, self.kinds);
                let callback = self.types.function(application, result);
                self.types.function(int, callback)
            }
            "IO.stdin" | "IO.stdout" | "IO.stderr" | "Process.nullStream" => handle,
            "IO.NoBuffering" | "IO.LineBuffering" | "IO.BlockBuffering" => buffer_mode,
            "IO.ReadMode" | "IO.WriteMode" | "IO.AppendMode" | "IO.ReadWriteMode" => file_mode,
            "IO.openFile" => {
                let action = self.types.io(handle, self.kinds);
                let mode = self.types.function(file_mode, action);
                self.types.function(text, mode)
            }
            "IO.hClose" => {
                let action = self.types.io(unit, self.kinds);
                self.types.function(handle, action)
            }
            "IO.hSetBuffering" => {
                let action = self.types.io(unit, self.kinds);
                let mode = self.types.function(buffer_mode, action);
                self.types.function(handle, mode)
            }
            "Temp.withSystemTempDirectory" => {
                let result = self.fresh_binder(&mut binders);
                let action = self.types.io(result, self.kinds);
                let callback = self.types.function(text, action);
                let callback = self.types.function(callback, action);
                self.types.function(text, callback)
            }
            "Temp.withSystemTempFile" => {
                let result = self.fresh_binder(&mut binders);
                let action = self.types.io(result, self.kinds);
                let handle_callback = self.types.function(handle, action);
                let callback = self.types.function(text, handle_callback);
                let callback = self.types.function(callback, action);
                self.types.function(text, callback)
            }
            "IO.print" => {
                let a = self.fresh_binder(&mut binders);
                self.show_wanteds.push((a, span));
                evidence = Some((hell_builtins::TypeClass::Show, a));
                let io_unit = self.types.io(unit, self.kinds);
                self.types.function(a, io_unit)
            }
            "Functor.fmap" | "<$>" => {
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                let input = self.fresh_binder(&mut binders);
                let output = self.fresh_binder(&mut binders);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Functor, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Functor, constructor));
                let input_container = self.types.apply(constructor, input);
                let output_container = self.types.apply(constructor, output);
                let function = self.types.function(input, output);
                let tail = self.types.function(input_container, output_container);
                self.types.function(function, tail)
            }
            "IO.pure" => {
                let a = self.fresh_binder(&mut binders);
                let io_a = self.types.io(a, self.kinds);
                self.types.function(a, io_a)
            }
            "Applicative.pure" => {
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                let a = self.fresh_binder(&mut binders);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Applicative, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Applicative, constructor));
                let result = self.types.apply(constructor, a);
                self.types.function(a, result)
            }
            "Monad.return" => {
                let a = self.fresh_binder(&mut binders);
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Monad, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Monad, constructor));
                let result = self.types.apply(constructor, a);
                self.types.function(a, result)
            }
            "<*>" | "<**>" => {
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Applicative, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Applicative, constructor));
                let a_container = self.types.apply(constructor, a);
                let function = self.types.function(a, b);
                let function_container = self.types.apply(constructor, function);
                let result = self.types.apply(constructor, b);
                let tail = if name == "<*>" {
                    self.types.function(a_container, result)
                } else {
                    self.types.function(function_container, result)
                };
                if name == "<*>" {
                    self.types.function(function_container, tail)
                } else {
                    self.types.function(a_container, tail)
                }
            }
            "Alternative.optional" | "Alternative.many" => {
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                let a = self.fresh_binder(&mut binders);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Alternative, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Alternative, constructor));
                let input = self.types.apply(constructor, a);
                let item = if name == "Alternative.optional" {
                    self.apply_named_type("Maybe", &[a])
                } else {
                    self.types.list(a, self.kinds)
                };
                let result = self.types.apply(constructor, item);
                self.types.function(input, result)
            }
            "Monad.then" => {
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Monad, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Monad, constructor));
                let monad_a = self.types.apply(constructor, a);
                let monad_b = self.types.apply(constructor, b);
                let result = self.types.function(monad_b, monad_b);
                self.types.function(monad_a, result)
            }
            "Monad.bind" => {
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Monad, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Monad, constructor));
                let monad_a = self.types.apply(constructor, a);
                let monad_b = self.types.apply(constructor, b);
                let continuation = self.types.function(a, monad_b);
                let result = self.types.function(continuation, monad_b);
                self.types.function(monad_a, result)
            }
            "Concurrent.threadDelay" => {
                let io_unit = self.types.io(unit, self.kinds);
                self.types.function(int, io_unit)
            }
            "Timeout.timeout" => {
                let item = self.fresh_binder(&mut binders);
                let io_item = self.types.io(item, self.kinds);
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let maybe_item = self.types.apply(maybe, item);
                let io_maybe = self.types.io(maybe_item, self.kinds);
                let action_tail = self.types.function(io_item, io_maybe);
                self.types.function(int, action_tail)
            }
            "Day.fromGregorianValid" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let maybe_day = self.types.apply(maybe, day);
                let day_argument = self.types.function(int, maybe_day);
                let month = self.types.function(int, day_argument);
                self.types.function(integer, month)
            }
            "Day.toGregorian" => {
                let parts = self.types.tuple(&[integer, int, int], self.kinds);
                self.types.function(day, parts)
            }
            "Day.addDays" => {
                let date = self.types.function(day, day);
                self.types.function(integer, date)
            }
            "Day.diffDays" => {
                let right = self.types.function(day, integer);
                self.types.function(day, right)
            }
            "Day.dayOfWeek" => self.types.function(day, day_of_week),
            "Day.iso8601Show" => self.types.function(day, text),
            "Day.iso8601ParseM" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let maybe_day = self.types.apply(maybe, day);
                self.types.function(text, maybe_day)
            }
            "UTCTime.UTCTime" => {
                let seconds = self.types.function(double, utc_time);
                self.types.function(day, seconds)
            }
            "UTCTime.utctDay" => self.types.function(utc_time, day),
            "UTCTime.utctDayTime" | "UTCTime.diffUTCTime" => {
                let result = self.types.function(utc_time, double);
                if name == "UTCTime.diffUTCTime" {
                    self.types.function(utc_time, result)
                } else {
                    result
                }
            }
            "UTCTime.addUTCTime" => {
                let instant = self.types.function(utc_time, utc_time);
                self.types.function(double, instant)
            }
            "UTCTime.getCurrentTime" => self.types.io(utc_time, self.kinds),
            "UTCTime.iso8601Show" => self.types.function(utc_time, text),
            "UTCTime.iso8601ParseM" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let maybe_time = self.types.apply(maybe, utc_time);
                self.types.function(text, maybe_time)
            }
            "TimeOfDay.timeToTimeOfDay" => self.types.function(double, time_of_day),
            "TimeOfDay.todHour" | "TimeOfDay.todMin" => self.types.function(time_of_day, int),
            "TimeOfDay.todSec" | "TimeOfDay.timeOfDayToTime" => {
                self.types.function(time_of_day, double)
            }
            "TimeOfDay.midnight" | "TimeOfDay.midday" => time_of_day,
            "TimeOfDay.makeTimeOfDayValid" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let maybe_time = self.types.apply(maybe, time_of_day);
                let seconds = self.types.function(double, maybe_time);
                let minute = self.types.function(int, seconds);
                self.types.function(int, minute)
            }
            "Async.concurrently" => {
                let left = self.fresh_binder(&mut binders);
                let right = self.fresh_binder(&mut binders);
                let io_left = self.types.io(left, self.kinds);
                let io_right = self.types.io(right, self.kinds);
                let pair = self.types.tuple(&[left, right], self.kinds);
                let io_pair = self.types.io(pair, self.kinds);
                let right_tail = self.types.function(io_right, io_pair);
                self.types.function(io_left, right_tail)
            }
            "Async.race" => {
                let left = self.fresh_binder(&mut binders);
                let right = self.fresh_binder(&mut binders);
                let io_left = self.types.io(left, self.kinds);
                let io_right = self.types.io(right, self.kinds);
                let kind1 = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let kind2 = self
                    .kinds
                    .intern(hell_types::KindNode::Arrow(KindArena::TYPE, kind1));
                let either = self.types.constructor("Either", kind2);
                let either_left = self.types.apply(either, left);
                let either_value = self.types.apply(either_left, right);
                let io_either = self.types.io(either_value, self.kinds);
                let right_tail = self.types.function(io_right, io_either);
                self.types.function(io_left, right_tail)
            }
            "Async.pooledMapConcurrently" | "Async.pooledForConcurrently" => {
                let item = self.fresh_binder(&mut binders);
                let result = self.fresh_binder(&mut binders);
                let io_result = self.types.io(result, self.kinds);
                let callback = self.types.function(item, io_result);
                let items = self.types.list(item, self.kinds);
                let results = self.types.list(result, self.kinds);
                let io_results = self.types.io(results, self.kinds);
                if name == "Async.pooledMapConcurrently" {
                    let items_tail = self.types.function(items, io_results);
                    self.types.function(callback, items_tail)
                } else {
                    let callback_tail = self.types.function(callback, io_results);
                    self.types.function(items, callback_tail)
                }
            }
            "Async.pooledMapConcurrently_" | "Async.pooledForConcurrently_" => {
                let item = self.fresh_binder(&mut binders);
                let io_unit = self.types.io(unit, self.kinds);
                let callback = self.types.function(item, io_unit);
                let items = self.types.list(item, self.kinds);
                if name == "Async.pooledMapConcurrently_" {
                    let items_tail = self.types.function(items, io_unit);
                    self.types.function(callback, items_tail)
                } else {
                    let callback_tail = self.types.function(callback, io_unit);
                    self.types.function(items, callback_tail)
                }
            }
            "List.break" | "List.span" | "List.partition" => {
                let item = self.fresh_binder(&mut binders);
                let predicate = self.types.function(item, bool_);
                let items = self.types.list(item, self.kinds);
                let pair = self.types.tuple(&[items, items], self.kinds);
                let tail = self.types.function(items, pair);
                self.types.function(predicate, tail)
            }
            "List.concatMap" => {
                let input = self.fresh_binder(&mut binders);
                let output = self.fresh_binder(&mut binders);
                let outputs = self.types.list(output, self.kinds);
                let callback = self.types.function(input, outputs);
                let inputs = self.types.list(input, self.kinds);
                let tail = self.types.function(inputs, outputs);
                self.types.function(callback, tail)
            }
            "List.deleteBy" => {
                let item = self.fresh_binder(&mut binders);
                let comparison_tail = self.types.function(item, bool_);
                let comparison = self.types.function(item, comparison_tail);
                let items = self.types.list(item, self.kinds);
                let list_tail = self.types.function(items, items);
                let item_tail = self.types.function(item, list_tail);
                self.types.function(comparison, item_tail)
            }
            "List.foldr" | "List.scanr" => {
                let item = self.fresh_binder(&mut binders);
                let accumulator = self.fresh_binder(&mut binders);
                let step_tail = self.types.function(accumulator, accumulator);
                let step = self.types.function(item, step_tail);
                let items = self.types.list(item, self.kinds);
                let result = if name == "List.scanr" {
                    self.types.list(accumulator, self.kinds)
                } else {
                    accumulator
                };
                let list_tail = self.types.function(items, result);
                let seed_tail = self.types.function(accumulator, list_tail);
                self.types.function(step, seed_tail)
            }
            "List.group" => {
                let item = self.fresh_binder(&mut binders);
                self.eq_wanteds.push((item, span));
                evidence = Some((hell_builtins::TypeClass::Eq, item));
                let items = self.types.list(item, self.kinds);
                let groups = self.types.list(items, self.kinds);
                self.types.function(items, groups)
            }
            "List.groupBy" => {
                let item = self.fresh_binder(&mut binders);
                let comparison_tail = self.types.function(item, bool_);
                let comparison = self.types.function(item, comparison_tail);
                let items = self.types.list(item, self.kinds);
                let groups = self.types.list(items, self.kinds);
                let tail = self.types.function(items, groups);
                self.types.function(comparison, tail)
            }
            "List.inits" | "List.permutations" | "List.subsequences" | "List.tails" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                let results = self.types.list(items, self.kinds);
                self.types.function(items, results)
            }
            "List.intercalate" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                let groups = self.types.list(items, self.kinds);
                let tail = self.types.function(groups, items);
                self.types.function(items, tail)
            }
            "List.nubOrd" | "List.sort" => {
                let item = self.fresh_binder(&mut binders);
                self.ord_wanteds.push((item, span));
                evidence = Some((hell_builtins::TypeClass::Ord, item));
                let items = self.types.list(item, self.kinds);
                self.types.function(items, items)
            }
            "List.scanl'" => {
                let item = self.fresh_binder(&mut binders);
                let accumulator = self.fresh_binder(&mut binders);
                let step_tail = self.types.function(item, accumulator);
                let step = self.types.function(accumulator, step_tail);
                let items = self.types.list(item, self.kinds);
                let results = self.types.list(accumulator, self.kinds);
                let list_tail = self.types.function(items, results);
                let seed_tail = self.types.function(accumulator, list_tail);
                self.types.function(step, seed_tail)
            }
            "List.splitAt" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                let pair = self.types.tuple(&[items, items], self.kinds);
                let tail = self.types.function(items, pair);
                self.types.function(int, tail)
            }
            "List.transpose" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                let rows = self.types.list(items, self.kinds);
                self.types.function(rows, rows)
            }
            "List.unfoldr" => {
                let item = self.fresh_binder(&mut binders);
                let seed = self.fresh_binder(&mut binders);
                let pair = self.types.tuple(&[item, seed], self.kinds);
                let result = self.apply_named_type("Maybe", &[pair]);
                let callback = self.types.function(seed, result);
                let items = self.types.list(item, self.kinds);
                let tail = self.types.function(seed, items);
                self.types.function(callback, tail)
            }
            "List.all" | "List.any" => {
                let item = self.fresh_binder(&mut binders);
                let predicate = self.types.function(item, bool_);
                let items = self.types.list(item, self.kinds);
                let tail = self.types.function(items, bool_);
                self.types.function(predicate, tail)
            }
            "List.concat" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                let nested = self.types.list(items, self.kinds);
                self.types.function(nested, items)
            }
            "List.dropWhile" | "List.dropWhileEnd" | "List.filter" | "List.takeWhile" => {
                let item = self.fresh_binder(&mut binders);
                let predicate = self.types.function(item, bool_);
                let items = self.types.list(item, self.kinds);
                let tail = self.types.function(items, items);
                self.types.function(predicate, tail)
            }
            "List.elem" | "List.notElem" => {
                let item = self.fresh_binder(&mut binders);
                self.eq_wanteds.push((item, span));
                evidence = Some((hell_builtins::TypeClass::Eq, item));
                let items = self.types.list(item, self.kinds);
                let tail = self.types.function(items, bool_);
                self.types.function(item, tail)
            }
            "List.elemIndex" => {
                let item = self.fresh_binder(&mut binders);
                self.eq_wanteds.push((item, span));
                evidence = Some((hell_builtins::TypeClass::Eq, item));
                let items = self.types.list(item, self.kinds);
                let result = self.apply_named_type("Maybe", &[int]);
                let tail = self.types.function(items, result);
                self.types.function(item, tail)
            }
            "List.elemIndices" => {
                let item = self.fresh_binder(&mut binders);
                self.eq_wanteds.push((item, span));
                evidence = Some((hell_builtins::TypeClass::Eq, item));
                let items = self.types.list(item, self.kinds);
                let indices = self.types.list(int, self.kinds);
                let tail = self.types.function(items, indices);
                self.types.function(item, tail)
            }
            "List.find" => {
                let item = self.fresh_binder(&mut binders);
                let predicate = self.types.function(item, bool_);
                let items = self.types.list(item, self.kinds);
                let result = self.apply_named_type("Maybe", &[item]);
                let tail = self.types.function(items, result);
                self.types.function(predicate, tail)
            }
            "List.findIndex" | "List.findIndices" => {
                let item = self.fresh_binder(&mut binders);
                let predicate = self.types.function(item, bool_);
                let items = self.types.list(item, self.kinds);
                let result = if name == "List.findIndex" {
                    self.apply_named_type("Maybe", &[int])
                } else {
                    self.types.list(int, self.kinds)
                };
                let tail = self.types.function(items, result);
                self.types.function(predicate, tail)
            }
            "List.isInfixOf" | "List.isPrefixOf" | "List.isSubsequenceOf" | "List.isSuffixOf" => {
                let item = self.fresh_binder(&mut binders);
                self.eq_wanteds.push((item, span));
                evidence = Some((hell_builtins::TypeClass::Eq, item));
                let items = self.types.list(item, self.kinds);
                let tail = self.types.function(items, bool_);
                self.types.function(items, tail)
            }
            "List.null" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                self.types.function(items, bool_)
            }
            "List.repeat" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                self.types.function(item, items)
            }
            "List.uncons" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                let pair = self.types.tuple(&[item, items], self.kinds);
                let result = self.apply_named_type("Maybe", &[pair]);
                self.types.function(items, result)
            }
            "List.zipWith" => {
                let left = self.fresh_binder(&mut binders);
                let right = self.fresh_binder(&mut binders);
                let result = self.fresh_binder(&mut binders);
                let callback_tail = self.types.function(right, result);
                let callback = self.types.function(left, callback_tail);
                let lefts = self.types.list(left, self.kinds);
                let rights = self.types.list(right, self.kinds);
                let results = self.types.list(result, self.kinds);
                let right_tail = self.types.function(rights, results);
                let left_tail = self.types.function(lefts, right_tail);
                self.types.function(callback, left_tail)
            }
            "List.nil" => {
                let a = self.fresh_binder(&mut binders);
                self.types.list(a, self.kinds)
            }
            "List.cons" | "List.intersperse" => {
                let a = self.fresh_binder(&mut binders);
                let list = self.types.list(a, self.kinds);
                let result = self.types.function(list, list);
                self.types.function(a, result)
            }
            "List.take" | "List.drop" => {
                let a = self.fresh_binder(&mut binders);
                let list = self.types.list(a, self.kinds);
                let result = self.types.function(list, list);
                self.types.function(int, result)
            }
            "List.iterate'" => {
                let a = self.fresh_binder(&mut binders);
                let list = self.types.list(a, self.kinds);
                let seed = self.types.function(a, list);
                let step = self.types.function(a, a);
                self.types.function(step, seed)
            }
            "List.map" => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let list_a = self.types.list(a, self.kinds);
                let list_b = self.types.list(b, self.kinds);
                let tail = self.types.function(list_a, list_b);
                let mapper = self.types.function(a, b);
                self.types.function(mapper, tail)
            }
            "List.mapAccumL" | "List.mapAccumR" => {
                let accumulator = self.fresh_binder(&mut binders);
                let item = self.fresh_binder(&mut binders);
                let mapped = self.fresh_binder(&mut binders);
                let result_pair = self.types.tuple(&[accumulator, mapped], self.kinds);
                let step_item = self.types.function(item, result_pair);
                let step = self.types.function(accumulator, step_item);
                let items = self.types.list(item, self.kinds);
                let mapped_items = self.types.list(mapped, self.kinds);
                let result = self.types.tuple(&[accumulator, mapped_items], self.kinds);
                let list_tail = self.types.function(items, result);
                let seed_tail = self.types.function(accumulator, list_tail);
                self.types.function(step, seed_tail)
            }
            "List.sortOn" => {
                let item = self.fresh_binder(&mut binders);
                let key = self.fresh_binder(&mut binders);
                self.ord_wanteds.push((key, span));
                evidence = Some((hell_builtins::TypeClass::Ord, key));
                let function = self.types.function(item, key);
                let list = self.types.list(item, self.kinds);
                let tail = self.types.function(list, list);
                self.types.function(function, tail)
            }
            "List.foldl'" => {
                let item = self.fresh_binder(&mut binders);
                let accumulator = self.fresh_binder(&mut binders);
                let list = self.types.list(item, self.kinds);
                let step_tail = self.types.function(item, accumulator);
                let step = self.types.function(accumulator, step_tail);
                let list_tail = self.types.function(list, accumulator);
                let seed_tail = self.types.function(accumulator, list_tail);
                self.types.function(step, seed_tail)
            }
            "List.zip" => {
                let left = self.fresh_binder(&mut binders);
                let right = self.fresh_binder(&mut binders);
                let left_list = self.types.list(left, self.kinds);
                let right_list = self.types.list(right, self.kinds);
                let pair = self.types.tuple(&[left, right], self.kinds);
                let pairs = self.types.list(pair, self.kinds);
                let tail = self.types.function(right_list, pairs);
                self.types.function(left_list, tail)
            }
            "List.cycle" | "List.reverse" => {
                let item = self.fresh_binder(&mut binders);
                let list = self.types.list(item, self.kinds);
                self.types.function(list, list)
            }
            "List.length" => {
                let a = self.fresh_binder(&mut binders);
                let list = self.types.list(a, self.kinds);
                self.types.function(list, int)
            }
            "List.lookup" => {
                let key = self.fresh_binder(&mut binders);
                let value = self.fresh_binder(&mut binders);
                self.eq_wanteds.push((key, span));
                evidence = Some((hell_builtins::TypeClass::Eq, key));
                let pair = self.types.tuple(&[key, value], self.kinds);
                let pairs = self.types.list(pair, self.kinds);
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let result = self.types.apply(maybe, value);
                let tail = self.types.function(pairs, result);
                self.types.function(key, tail)
            }
            "List.and" | "List.or" => {
                let list = self.types.list(bool_, self.kinds);
                self.types.function(list, bool_)
            }
            "Vector.fromList" | "Vector.toList" => {
                let item = self.fresh_binder(&mut binders);
                let vector_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let vector = self.types.constructor("Vector", vector_kind);
                let vector = self.types.apply(vector, item);
                let list = self.types.list(item, self.kinds);
                if name == "Vector.fromList" {
                    self.types.function(list, vector)
                } else {
                    self.types.function(vector, list)
                }
            }
            "Map.fromList" | "Map.toList" | "Map.lookup" | "Map.insert" | "Map.delete"
            | "Map.singleton" | "Map.size" | "Map.filter" | "Map.filterWithKey" | "Map.any"
            | "Map.all" | "Map.insertWith" | "Map.adjust" | "Map.unionWith" | "Map.map"
            | "Map.keys" | "Map.elems" => {
                let key = self.fresh_binder(&mut binders);
                let item = self.fresh_binder(&mut binders);
                let map = self.apply_named_type("Map", &[key, item]);
                let pair = self.types.tuple(&[key, item], self.kinds);
                let pairs = self.types.list(pair, self.kinds);
                if matches!(
                    name,
                    "Map.fromList"
                        | "Map.lookup"
                        | "Map.insert"
                        | "Map.delete"
                        | "Map.singleton"
                        | "Map.insertWith"
                        | "Map.adjust"
                        | "Map.unionWith"
                ) {
                    self.ord_wanteds.push((key, span));
                    evidence = Some((hell_builtins::TypeClass::Ord, key));
                }
                match name {
                    "Map.fromList" => self.types.function(pairs, map),
                    "Map.toList" => self.types.function(map, pairs),
                    "Map.lookup" => {
                        let maybe = self.apply_named_type("Maybe", &[item]);
                        let tail = self.types.function(map, maybe);
                        self.types.function(key, tail)
                    }
                    "Map.insert" => {
                        let with_map = self.types.function(map, map);
                        let with_item = self.types.function(item, with_map);
                        self.types.function(key, with_item)
                    }
                    "Map.delete" => {
                        let tail = self.types.function(map, map);
                        self.types.function(key, tail)
                    }
                    "Map.singleton" => {
                        let tail = self.types.function(item, map);
                        self.types.function(key, tail)
                    }
                    "Map.size" => self.types.function(map, int),
                    "Map.filter" => {
                        let predicate = self.types.function(item, bool_);
                        let tail = self.types.function(map, map);
                        self.types.function(predicate, tail)
                    }
                    "Map.filterWithKey" => {
                        let item_predicate = self.types.function(item, bool_);
                        let predicate = self.types.function(key, item_predicate);
                        let tail = self.types.function(map, map);
                        self.types.function(predicate, tail)
                    }
                    "Map.any" | "Map.all" => {
                        let predicate = self.types.function(item, bool_);
                        let tail = self.types.function(map, bool_);
                        self.types.function(predicate, tail)
                    }
                    "Map.insertWith" => {
                        let combine_tail = self.types.function(item, item);
                        let combine = self.types.function(item, combine_tail);
                        let with_map = self.types.function(map, map);
                        let with_item = self.types.function(item, with_map);
                        let with_key = self.types.function(key, with_item);
                        self.types.function(combine, with_key)
                    }
                    "Map.adjust" => {
                        let adjust = self.types.function(item, item);
                        let with_map = self.types.function(map, map);
                        let with_key = self.types.function(key, with_map);
                        self.types.function(adjust, with_key)
                    }
                    "Map.unionWith" => {
                        let combine_tail = self.types.function(item, item);
                        let combine = self.types.function(item, combine_tail);
                        let right = self.types.function(map, map);
                        let left = self.types.function(map, right);
                        self.types.function(combine, left)
                    }
                    "Map.map" => {
                        let output = self.fresh_binder(&mut binders);
                        let output_map = self.apply_named_type("Map", &[key, output]);
                        let function = self.types.function(item, output);
                        let tail = self.types.function(map, output_map);
                        self.types.function(function, tail)
                    }
                    "Map.keys" => {
                        let keys = self.types.list(key, self.kinds);
                        self.types.function(map, keys)
                    }
                    "Map.elems" => {
                        let items = self.types.list(item, self.kinds);
                        self.types.function(map, items)
                    }
                    _ => unreachable!("Map builtin matched"),
                }
            }
            "Set.fromList" | "Set.toList" | "Set.insert" | "Set.member" | "Set.delete"
            | "Set.union" | "Set.difference" | "Set.intersection" | "Set.size"
            | "Set.singleton" => {
                let item = self.fresh_binder(&mut binders);
                let set = self.apply_named_type("Set", &[item]);
                if matches!(
                    name,
                    "Set.fromList"
                        | "Set.insert"
                        | "Set.member"
                        | "Set.delete"
                        | "Set.union"
                        | "Set.difference"
                        | "Set.intersection"
                        | "Set.singleton"
                ) {
                    self.ord_wanteds.push((item, span));
                    evidence = Some((hell_builtins::TypeClass::Ord, item));
                }
                match name {
                    "Set.fromList" => {
                        let list = self.types.list(item, self.kinds);
                        self.types.function(list, set)
                    }
                    "Set.toList" => {
                        let list = self.types.list(item, self.kinds);
                        self.types.function(set, list)
                    }
                    "Set.insert" | "Set.delete" => {
                        let tail = self.types.function(set, set);
                        self.types.function(item, tail)
                    }
                    "Set.member" => {
                        let tail = self.types.function(set, bool_);
                        self.types.function(item, tail)
                    }
                    "Set.union" | "Set.difference" | "Set.intersection" => {
                        let tail = self.types.function(set, set);
                        self.types.function(set, tail)
                    }
                    "Set.size" => self.types.function(set, int),
                    "Set.singleton" => self.types.function(item, set),
                    _ => unreachable!("Set builtin matched"),
                }
            }
            "Maybe.Nothing" => {
                let item = self.fresh_binder(&mut binders);
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                self.types.apply(maybe, item)
            }
            "Maybe.Just" => {
                let item = self.fresh_binder(&mut binders);
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let result = self.types.apply(maybe, item);
                self.types.function(item, result)
            }
            "Maybe.maybe" => {
                let item = self.fresh_binder(&mut binders);
                let result = self.fresh_binder(&mut binders);
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let maybe_item = self.types.apply(maybe, item);
                let just = self.types.function(item, result);
                let maybe_tail = self.types.function(maybe_item, result);
                let just_tail = self.types.function(just, maybe_tail);
                self.types.function(result, just_tail)
            }
            "Maybe.listToMaybe" => {
                let item = self.fresh_binder(&mut binders);
                let items = self.types.list(item, self.kinds);
                let result = self.apply_named_type("Maybe", &[item]);
                self.types.function(items, result)
            }
            "Maybe.mapMaybe" => {
                let input = self.fresh_binder(&mut binders);
                let output = self.fresh_binder(&mut binders);
                let maybe_output = self.apply_named_type("Maybe", &[output]);
                let function = self.types.function(input, maybe_output);
                let inputs = self.types.list(input, self.kinds);
                let outputs = self.types.list(output, self.kinds);
                let tail = self.types.function(inputs, outputs);
                self.types.function(function, tail)
            }
            "Either.Left" | "Either.Right" | "Either.either" => {
                let left = self.fresh_binder(&mut binders);
                let right = self.fresh_binder(&mut binders);
                let kind1 = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let kind2 = self
                    .kinds
                    .intern(hell_types::KindNode::Arrow(KindArena::TYPE, kind1));
                let either = self.types.constructor("Either", kind2);
                let either_left = self.types.apply(either, left);
                let either_value = self.types.apply(either_left, right);
                match name {
                    "Either.Left" => self.types.function(left, either_value),
                    "Either.Right" => self.types.function(right, either_value),
                    "Either.either" => {
                        let result = self.fresh_binder(&mut binders);
                        let left_handler = self.types.function(left, result);
                        let right_handler = self.types.function(right, result);
                        let scrutinee_tail = self.types.function(either_value, result);
                        let right_tail = self.types.function(right_handler, scrutinee_tail);
                        self.types.function(left_handler, right_tail)
                    }
                    _ => unreachable!("Either builtin matched"),
                }
            }
            "CI.mk" => {
                let item = self.fresh_binder(&mut binders);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::FoldCase, item, span));
                evidence = Some((hell_builtins::TypeClass::FoldCase, item));
                let ci = self.apply_named_type("CI", &[item]);
                self.types.function(item, ci)
            }
            "CI.foldedCase" => {
                let item = self.fresh_binder(&mut binders);
                let ci = self.apply_named_type("CI", &[item]);
                self.types.function(ci, item)
            }
            "Tree.Node" => {
                let item = self.fresh_binder(&mut binders);
                let tree = self.apply_named_type("Tree", &[item]);
                let children = self.types.list(tree, self.kinds);
                let tail = self.types.function(children, tree);
                self.types.function(item, tail)
            }
            "Tree.map" => {
                let input = self.fresh_binder(&mut binders);
                let output = self.fresh_binder(&mut binders);
                let function = self.types.function(input, output);
                let input_tree = self.apply_named_type("Tree", &[input]);
                let output_tree = self.apply_named_type("Tree", &[output]);
                let tail = self.types.function(input_tree, output_tree);
                self.types.function(function, tail)
            }
            "Tree.foldTree" => {
                let item = self.fresh_binder(&mut binders);
                let result = self.fresh_binder(&mut binders);
                let results = self.types.list(result, self.kinds);
                let children_tail = self.types.function(results, result);
                let folder = self.types.function(item, children_tail);
                let tree = self.apply_named_type("Tree", &[item]);
                let tree_tail = self.types.function(tree, result);
                self.types.function(folder, tree_tail)
            }
            "Tree.flatten" | "Tree.levels" => {
                let item = self.fresh_binder(&mut binders);
                let tree = self.apply_named_type("Tree", &[item]);
                let list = self.types.list(item, self.kinds);
                let result = if name == "Tree.levels" {
                    self.types.list(list, self.kinds)
                } else {
                    list
                };
                self.types.function(tree, result)
            }
            "Tree.unfoldTree" => {
                let item = self.fresh_binder(&mut binders);
                let seed = self.fresh_binder(&mut binders);
                let seeds = self.types.list(seed, self.kinds);
                let pair = self.types.tuple(&[item, seeds], self.kinds);
                let function = self.types.function(seed, pair);
                let tree = self.apply_named_type("Tree", &[item]);
                let tail = self.types.function(seed, tree);
                self.types.function(function, tail)
            }
            "Exit.ExitSuccess" => self.types.constructor("ExitCode", KindArena::TYPE),
            "Exit.ExitFailure" => {
                let exit = self.types.constructor("ExitCode", KindArena::TYPE);
                self.types.function(int, exit)
            }
            "Exit.exitCode" => {
                let result = self.fresh_binder(&mut binders);
                let exit = self.types.constructor("ExitCode", KindArena::TYPE);
                let failure = self.types.function(int, result);
                let exit_tail = self.types.function(exit, result);
                let failure_tail = self.types.function(failure, exit_tail);
                self.types.function(result, failure_tail)
            }
            "Exit.die" => {
                let result = self.fresh_binder(&mut binders);
                let action = self.types.io(result, self.kinds);
                self.types.function(text, action)
            }
            "Exit.exitWith" => {
                let result = self.fresh_binder(&mut binders);
                let exit = self.types.constructor("ExitCode", KindArena::TYPE);
                let action = self.types.io(result, self.kinds);
                self.types.function(exit, action)
            }
            "These.This" | "These.That" | "These.These" | "These.these" => {
                let left = self.fresh_binder(&mut binders);
                let right = self.fresh_binder(&mut binders);
                let kind1 = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let kind2 = self
                    .kinds
                    .intern(hell_types::KindNode::Arrow(KindArena::TYPE, kind1));
                let these = self.types.constructor("These", kind2);
                let these_left = self.types.apply(these, left);
                let these_value = self.types.apply(these_left, right);
                match name {
                    "These.This" => self.types.function(left, these_value),
                    "These.That" => self.types.function(right, these_value),
                    "These.These" => {
                        let right_tail = self.types.function(right, these_value);
                        self.types.function(left, right_tail)
                    }
                    "These.these" => {
                        let result = self.fresh_binder(&mut binders);
                        let left_handler = self.types.function(left, result);
                        let right_handler = self.types.function(right, result);
                        let both_tail = self.types.function(right, result);
                        let both_handler = self.types.function(left, both_tail);
                        let scrutinee_tail = self.types.function(these_value, result);
                        let both_tail = self.types.function(both_handler, scrutinee_tail);
                        let right_tail = self.types.function(right_handler, both_tail);
                        self.types.function(left_handler, right_tail)
                    }
                    _ => unreachable!("These builtin matched"),
                }
            }
            "Json.Null" => json_value,
            "Json.Bool" => self.types.function(bool_, json_value),
            "Json.String" => self.types.function(text, json_value),
            "Json.Number" => self.types.function(double, json_value),
            "Json.Array" => {
                let kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let vector = self.types.constructor("Vector", kind);
                let array = self.types.apply(vector, json_value);
                self.types.function(array, json_value)
            }
            "Json.Object" => {
                let kind1 = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let kind2 = self
                    .kinds
                    .intern(hell_types::KindNode::Arrow(KindArena::TYPE, kind1));
                let map = self.types.constructor("Map", kind2);
                let map_text = self.types.apply(map, text);
                let object = self.types.apply(map_text, json_value);
                self.types.function(object, json_value)
            }
            "Json.value" => {
                let result = self.fresh_binder(&mut binders);
                let kind1 = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let kind2 = self
                    .kinds
                    .intern(hell_types::KindNode::Arrow(KindArena::TYPE, kind1));
                let vector = self.types.constructor("Vector", kind1);
                let array = self.types.apply(vector, json_value);
                let map = self.types.constructor("Map", kind2);
                let map_text = self.types.apply(map, text);
                let object = self.types.apply(map_text, json_value);
                let bool_handler = self.types.function(bool_, result);
                let text_handler = self.types.function(text, result);
                let number_handler = self.types.function(double, result);
                let array_handler = self.types.function(array, result);
                let object_handler = self.types.function(object, result);
                let value_tail = self.types.function(json_value, result);
                let object_tail = self.types.function(object_handler, value_tail);
                let array_tail = self.types.function(array_handler, object_tail);
                let number_tail = self.types.function(number_handler, array_tail);
                let text_tail = self.types.function(text_handler, number_tail);
                let bool_tail = self.types.function(bool_handler, text_tail);
                self.types.function(result, bool_tail)
            }
            "Json.encode" => self.types.function(json_value, bytes),
            "Json.decode" => {
                let maybe_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let maybe = self.types.constructor("Maybe", maybe_kind);
                let decoded = self.types.apply(maybe, json_value);
                self.types.function(bytes, decoded)
            }
            "IO.mapM_" => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let io_b = self.types.io(b, self.kinds);
                let callback = self.types.function(a, io_b);
                let list = self.types.list(a, self.kinds);
                let io_unit = self.types.io(unit, self.kinds);
                let tail = self.types.function(list, io_unit);
                self.types.function(callback, tail)
            }
            "IO.forM_" => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let list = self.types.list(a, self.kinds);
                let io_b = self.types.io(b, self.kinds);
                let callback = self.types.function(a, io_b);
                let io_unit = self.types.io(unit, self.kinds);
                let tail = self.types.function(callback, io_unit);
                self.types.function(list, tail)
            }
            "Monad.mapM" | "Monad.mapM_" | "Monad.forM" | "Monad.forM_" => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Monad, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Monad, constructor));
                let callback_result = if name.ends_with('_') {
                    self.types.apply(constructor, unit)
                } else {
                    self.types.apply(constructor, b)
                };
                let callback = self.types.function(a, callback_result);
                let input = self.types.list(a, self.kinds);
                let result_item = if name.ends_with('_') {
                    unit
                } else {
                    self.types.list(b, self.kinds)
                };
                let result = self.types.apply(constructor, result_item);
                if matches!(name, "Monad.mapM" | "Monad.mapM_") {
                    let tail = self.types.function(input, result);
                    self.types.function(callback, tail)
                } else {
                    let tail = self.types.function(callback, result);
                    self.types.function(input, tail)
                }
            }
            "Monad.sequence" => {
                let a = self.fresh_binder(&mut binders);
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Monad, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Monad, constructor));
                let monadic_item = self.types.apply(constructor, a);
                let input = self.types.list(monadic_item, self.kinds);
                let items = self.types.list(a, self.kinds);
                let result = self.types.apply(constructor, items);
                self.types.function(input, result)
            }
            "Monad.when" => {
                let constructor_kind = self.kinds.intern(hell_types::KindNode::Arrow(
                    KindArena::TYPE,
                    KindArena::TYPE,
                ));
                let constructor = self.fresh_binder_with_kind(&mut binders, constructor_kind);
                self.class_wanteds
                    .push((hell_builtins::TypeClass::Monad, constructor, span));
                evidence = Some((hell_builtins::TypeClass::Monad, constructor));
                let monad_unit = self.types.apply(constructor, unit);
                let tail = self.types.function(monad_unit, monad_unit);
                self.types.function(bool_, tail)
            }
            "Flag.long" | "Flag.help" | "Option.long" | "Option.help" | "Argument.metavar"
            | "Argument.help" => {
                let item = self.fresh_binder(&mut binders);
                let fields_name = if name.starts_with("Flag.") {
                    "Options.FlagFields"
                } else if name.starts_with("Option.") {
                    "Options.OptionFields"
                } else {
                    "Options.ArgumentFields"
                };
                let fields = self.types.constructor(fields_name, KindArena::TYPE);
                let modifier = self.apply_named_type("Options.Mod", &[fields, item]);
                self.types.function(text, modifier)
            }
            "Option.value" | "Argument.value" => {
                let item = self.fresh_binder(&mut binders);
                let fields_name = if name.starts_with("Option.") {
                    "Options.OptionFields"
                } else {
                    "Options.ArgumentFields"
                };
                let fields = self.types.constructor(fields_name, KindArena::TYPE);
                let modifier = self.apply_named_type("Options.Mod", &[fields, item]);
                self.types.function(item, modifier)
            }
            "Options.flag" | "Options.flag'" => {
                let item = self.fresh_binder(&mut binders);
                let fields = self
                    .types
                    .constructor("Options.FlagFields", KindArena::TYPE);
                let modifier = self.apply_named_type("Options.Mod", &[fields, item]);
                let parser = self.apply_named_type("Options.Parser", &[item]);
                let modifier_tail = self.types.function(modifier, parser);
                let active_tail = self.types.function(item, modifier_tail);
                if name == "Options.flag" {
                    self.types.function(item, active_tail)
                } else {
                    active_tail
                }
            }
            "Options.switch" => {
                let fields = self
                    .types
                    .constructor("Options.FlagFields", KindArena::TYPE);
                let modifier = self.apply_named_type("Options.Mod", &[fields, bool_]);
                let parser = self.apply_named_type("Options.Parser", &[bool_]);
                self.types.function(modifier, parser)
            }
            "Options.strOption" | "Options.strArgument" => {
                let fields_name = if name == "Options.strOption" {
                    "Options.OptionFields"
                } else {
                    "Options.ArgumentFields"
                };
                let fields = self.types.constructor(fields_name, KindArena::TYPE);
                let modifier = self.apply_named_type("Options.Mod", &[fields, text]);
                let parser = self.apply_named_type("Options.Parser", &[text]);
                self.types.function(modifier, parser)
            }
            "Options.helper" => {
                let item = self.fresh_binder(&mut binders);
                let identity = self.types.function(item, item);
                self.apply_named_type("Options.Parser", &[identity])
            }
            "Options.fullDesc" => {
                let item = self.fresh_binder(&mut binders);
                self.apply_named_type("Options.InfoMod", &[item])
            }
            "Options.progDesc" | "Options.header" => {
                let item = self.fresh_binder(&mut binders);
                let info = self.apply_named_type("Options.InfoMod", &[item]);
                self.types.function(text, info)
            }
            "Options.info" => {
                let item = self.fresh_binder(&mut binders);
                let parser = self.apply_named_type("Options.Parser", &[item]);
                let info = self.apply_named_type("Options.InfoMod", &[item]);
                let parser_info = self.apply_named_type("Options.ParserInfo", &[item]);
                let tail = self.types.function(info, parser_info);
                self.types.function(parser, tail)
            }
            "Options.execParser" => {
                let item = self.fresh_binder(&mut binders);
                let parser_info = self.apply_named_type("Options.ParserInfo", &[item]);
                let result = self.types.io(item, self.kinds);
                self.types.function(parser_info, result)
            }
            "Options.command" => {
                let item = self.fresh_binder(&mut binders);
                let parser_info = self.apply_named_type("Options.ParserInfo", &[item]);
                let fields = self
                    .types
                    .constructor("Options.CommandFields", KindArena::TYPE);
                let modifier = self.apply_named_type("Options.Mod", &[fields, item]);
                let tail = self.types.function(parser_info, modifier);
                self.types.function(text, tail)
            }
            "Options.hsubparser" => {
                let item = self.fresh_binder(&mut binders);
                let fields = self
                    .types
                    .constructor("Options.CommandFields", KindArena::TYPE);
                let modifier = self.apply_named_type("Options.Mod", &[fields, item]);
                let parser = self.apply_named_type("Options.Parser", &[item]);
                self.types.function(modifier, parser)
            }
            "Environment.getArgs" => {
                let list = self.types.list(text, self.kinds);
                self.types.io(list, self.kinds)
            }
            "Environment.getEnvironment" => {
                let pair = self.types.tuple(&[text, text], self.kinds);
                let environment = self.types.list(pair, self.kinds);
                self.types.io(environment, self.kinds)
            }
            "Directory.getCurrentDirectory" | "Directory.getHomeDirectory" => {
                self.types.io(text, self.kinds)
            }
            "Directory.getFileSize" => {
                let result = self.types.io(integer, self.kinds);
                self.types.function(text, result)
            }
            "Directory.listDirectory" => {
                let entries = self.types.list(text, self.kinds);
                let result = self.types.io(entries, self.kinds);
                self.types.function(text, result)
            }
            "Directory.doesDirectoryExist"
            | "Directory.doesFileExist"
            | "Directory.pathIsSymbolicLink" => {
                let result = self.types.io(bool_, self.kinds);
                self.types.function(text, result)
            }
            "Directory.createDirectoryIfMissing" => {
                let result = self.types.io(unit, self.kinds);
                let path = self.types.function(text, result);
                self.types.function(bool_, path)
            }
            "ByteString.hPutStr" => {
                let io_unit = self.types.io(unit, self.kinds);
                let contents = self.types.function(bytes, io_unit);
                self.types.function(handle, contents)
            }
            "ByteString.getContents" => self.types.io(bytes, self.kinds),
            "ByteString.interact" => {
                let transform = self.types.function(bytes, bytes);
                let action = self.types.io(unit, self.kinds);
                self.types.function(transform, action)
            }
            "ByteString.hGet" => {
                let result = self.types.io(bytes, self.kinds);
                let amount = self.types.function(int, result);
                self.types.function(handle, amount)
            }
            "ByteString.readFile" => {
                let result = self.types.io(bytes, self.kinds);
                self.types.function(text, result)
            }
            "ByteString.writeFile" => {
                let result = self.types.io(unit, self.kinds);
                let contents = self.types.function(bytes, result);
                self.types.function(text, contents)
            }
            "ByteString.readProcess" => {
                let output = self.types.tuple(&[exit_code, bytes, bytes], self.kinds);
                let output = self.types.io(output, self.kinds);
                self.types.function(process, output)
            }
            "ByteString.readProcess_" => {
                let output = self.types.tuple(&[bytes, bytes], self.kinds);
                let output = self.types.io(output, self.kinds);
                self.types.function(process, output)
            }
            "ByteString.readProcessStdout_" => {
                let output = self.types.io(bytes, self.kinds);
                self.types.function(process, output)
            }
            "Process.proc" => {
                let arguments = self.types.list(text, self.kinds);
                let arguments = self.types.function(arguments, process);
                self.types.function(text, arguments)
            }
            "Process.runProcess" => {
                let action = self.types.io(exit_code, self.kinds);
                self.types.function(process, action)
            }
            "Process.runProcess_" => {
                let action = self.types.io(unit, self.kinds);
                self.types.function(process, action)
            }
            "Process.setEnv" => {
                let pair = self.types.tuple(&[text, text], self.kinds);
                let environment = self.types.list(pair, self.kinds);
                let configured = self.types.function(process, process);
                self.types.function(environment, configured)
            }
            "Process.setStderr" | "Process.setStdin" | "Process.setStdout" => {
                let configured = self.types.function(process, process);
                self.types.function(handle, configured)
            }
            "Process.useHandleClose" | "Process.useHandleOpen" => {
                self.types.function(handle, handle)
            }
            "Tuple.(,)" => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let tuple = self.types.tuple(&[a, b], self.kinds);
                let tail = self.types.function(b, tuple);
                self.types.function(a, tail)
            }
            "Tuple.(,,)" => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let c = self.fresh_binder(&mut binders);
                let tuple = self.types.tuple(&[a, b, c], self.kinds);
                let c_tail = self.types.function(c, tuple);
                let b_tail = self.types.function(b, c_tail);
                self.types.function(a, b_tail)
            }
            "Tuple.(,,,)" => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let c = self.fresh_binder(&mut binders);
                let d = self.fresh_binder(&mut binders);
                let tuple = self.types.tuple(&[a, b, c, d], self.kinds);
                let d_tail = self.types.function(d, tuple);
                let c_tail = self.types.function(c, d_tail);
                let b_tail = self.types.function(b, c_tail);
                self.types.function(a, b_tail)
            }
            "$" => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let function = self.types.function(a, b);
                let tail = self.types.function(a, b);
                self.types.function(function, tail)
            }
            "." => {
                let a = self.fresh_binder(&mut binders);
                let b = self.fresh_binder(&mut binders);
                let c = self.fresh_binder(&mut binders);
                let bc = self.types.function(b, c);
                let ab = self.types.function(a, b);
                let ac = self.types.function(a, c);
                let tail = self.types.function(ab, ac);
                self.types.function(bc, tail)
            }
            "<>" => {
                let a = self.fresh_binder(&mut binders);
                self.semigroup_wanteds.push((a, span));
                evidence = Some((hell_builtins::TypeClass::Semigroup, a));
                let result = self.types.function(a, a);
                self.types.function(a, result)
            }
            _ => {
                return Err(DiagnosticBundle(vec![Diagnostic::new(
                    "H0004",
                    format!("primitive `{name}` has no compiler scheme in this build"),
                    span,
                )]));
            }
        };
        let node = self.alloc(
            ty,
            span,
            TemporaryKind::Builtin {
                builtin: spec.id,
                evidence,
            },
        )?;
        #[cfg(feature = "compat-tracing")]
        self.specialized_builtins.insert(spec.id);
        Ok(Inferred {
            node,
            ty,
            span,
            visible: binders,
            visible_used: 0,
        })
    }

    fn fresh_binder(&mut self, binders: &mut Vec<(TypeId, hell_types::KindId)>) -> TypeId {
        self.fresh_binder_with_kind(binders, KindArena::TYPE)
    }

    fn fresh_binder_with_kind(
        &mut self,
        binders: &mut Vec<(TypeId, hell_types::KindId)>,
        kind: hell_types::KindId,
    ) -> TypeId {
        let ty = self.unifier.fresh(self.types, kind);
        binders.push((ty, kind));
        ty
    }

    fn apply_named_type(&mut self, name: &str, arguments: &[TypeId]) -> TypeId {
        let mut kind = KindArena::TYPE;
        for _ in arguments {
            kind = self
                .kinds
                .intern(hell_types::KindNode::Arrow(KindArena::TYPE, kind));
        }
        let mut ty = self.types.constructor(name, kind);
        for argument in arguments {
            ty = self.types.apply(ty, *argument);
        }
        ty
    }

    fn infer_literal(
        &mut self,
        literal: Literal,
        span: Span,
    ) -> Result<Inferred, DiagnosticBundle> {
        let (constant, ty) = match literal {
            Literal::Unit => (
                Constant::Unit,
                self.types.constructor("()", KindArena::TYPE),
            ),
            Literal::Character(value) => (
                Constant::Character(value),
                self.types.constructor("Char", KindArena::TYPE),
            ),
            Literal::Text(value) => (
                Constant::Text(value),
                self.types.constructor("Text", KindArena::TYPE),
            ),
            Literal::Double(raw) => {
                let value = raw.parse::<f64>().map_err(|_| {
                    DiagnosticBundle(vec![Diagnostic::new(
                        "H0206",
                        "invalid Double literal",
                        span,
                    )])
                })?;
                (
                    Constant::Double(value),
                    self.types.constructor("Double", KindArena::TYPE),
                )
            }
            Literal::Integer(raw) => (
                Constant::Int(parse_wrapping_int(&raw).ok_or_else(|| {
                    DiagnosticBundle(vec![Diagnostic::new("H0206", "invalid Int literal", span)])
                })?),
                self.types.constructor("Int", KindArena::TYPE),
            ),
        };
        let node = self.alloc(ty, span, TemporaryKind::Constant(constant))?;
        Ok(Inferred {
            node,
            ty,
            span,
            visible: Vec::new(),
            visible_used: 0,
        })
    }

    fn lower_type(&mut self, id: TypeExprId) -> Result<TypeId, DiagnosticBundle> {
        enum Work {
            Parse(TypeExprId),
            FinishList,
            FinishTuple(usize),
            FinishFunction,
            FinishApply(Span),
        }

        let mut work = vec![Work::Parse(id)];
        let mut output = Vec::new();
        while let Some(step) = work.pop() {
            match step {
                Work::Parse(id) => match self.parsed.types[id.0 as usize].clone() {
                    TypeExpr::Name(name, span) => {
                        let kind = if let Some(arity) = public_type_arity(&name) {
                            let mut kind = KindArena::TYPE;
                            for _ in 0..arity {
                                kind = self
                                    .kinds
                                    .intern(hell_types::KindNode::Arrow(KindArena::TYPE, kind));
                            }
                            kind
                        } else if self.user_types.by_name.contains_key(&name) {
                            KindArena::TYPE
                        } else {
                            return Err(DiagnosticBundle(vec![Diagnostic::new(
                                "H0404",
                                format!("unknown type `{name}`"),
                                span,
                            )]));
                        };
                        output.push(self.types.constructor(name, kind));
                    }
                    TypeExpr::Unit(_) => {
                        output.push(self.types.constructor("()", KindArena::TYPE));
                    }
                    TypeExpr::List(item, _) => {
                        work.push(Work::FinishList);
                        work.push(Work::Parse(item));
                    }
                    TypeExpr::Tuple(items, _) => {
                        work.push(Work::FinishTuple(items.len()));
                        work.extend(items.into_iter().rev().map(Work::Parse));
                    }
                    TypeExpr::Function(argument, result, _) => {
                        work.push(Work::FinishFunction);
                        work.push(Work::Parse(result));
                        work.push(Work::Parse(argument));
                    }
                    TypeExpr::Apply(function, argument, span) => {
                        work.push(Work::FinishApply(span));
                        work.push(Work::Parse(argument));
                        work.push(Work::Parse(function));
                    }
                    TypeExpr::Promoted(value, _) => {
                        output.push(self.types.intern(TypeNode::Symbol(value)));
                    }
                },
                Work::FinishList => {
                    let item = output.pop().expect("list type item was lowered");
                    output.push(self.types.list(item, self.kinds));
                }
                Work::FinishTuple(count) => {
                    let items = output.split_off(output.len() - count);
                    output.push(self.types.tuple(&items, self.kinds));
                }
                Work::FinishFunction => {
                    let result = output.pop().expect("function result type was lowered");
                    let argument = output.pop().expect("function argument type was lowered");
                    output.push(self.types.function(argument, result));
                }
                Work::FinishApply(span) => {
                    let argument = output.pop().expect("type application argument was lowered");
                    let function = output.pop().expect("type application function was lowered");
                    let result = self.types.apply(function, argument);
                    self.types
                        .kind_of(self.kinds, result, |meta| self.unifier.meta_kind(meta))
                        .map_err(|error| self.type_diagnostic(error, span, None, None))?;
                    output.push(result);
                }
            }
        }
        Ok(output
            .pop()
            .expect("iterative type lowering produced a value"))
    }
}

fn local_slot_count(locals: &[Local]) -> usize {
    locals.iter().map(|local| local.slot + 1).max().unwrap_or(0)
}

fn has_show_instance(types: &TypeArena, ty: TypeId) -> bool {
    has_instance(types, hell_builtins::TypeClass::Show, ty)
}

fn has_eq_instance(types: &TypeArena, ty: TypeId) -> bool {
    has_instance(types, hell_builtins::TypeClass::Eq, ty)
}

fn has_semigroup_instance(types: &TypeArena, ty: TypeId) -> bool {
    has_instance(types, hell_builtins::TypeClass::Semigroup, ty)
}

#[derive(Default)]
struct InstanceEvidencePlans {
    plans: Vec<InstanceEvidencePlan>,
    identities: HashMap<(hell_builtins::TypeClass, TypeId), InstanceEvidencePlanId>,
}

impl InstanceEvidencePlans {
    fn retain(
        &mut self,
        types: &TypeArena,
        class: hell_builtins::TypeClass,
        root: TypeId,
    ) -> Option<InstanceEvidencePlanId> {
        enum Work {
            Enter(TypeId),
            Leave(TypeId),
        }
        let mut work = vec![Work::Enter(root)];
        let mut active = HashSet::new();
        while let Some(item) = work.pop() {
            match item {
                Work::Leave(head) => {
                    let (target, arguments) = instance_head(types, head)?;
                    let instance = hell_builtins::instance(class, target)?;
                    let premise_count = usize::from(instance.resolution.premise_count());
                    let premises = arguments
                        .iter()
                        .take(premise_count)
                        .map(|premise| self.identities.get(&(class, *premise)).copied())
                        .collect::<Option<Vec<_>>>()?;
                    let plan = InstanceEvidencePlanId(u32::try_from(self.plans.len()).ok()?);
                    self.plans.push(InstanceEvidencePlan {
                        class,
                        head,
                        resolution: instance.resolution,
                        premises: premises.into(),
                    });
                    self.identities.insert((class, head), plan);
                    if !active.remove(&head) {
                        return None;
                    }
                }
                Work::Enter(head) => {
                    if self.identities.contains_key(&(class, head)) {
                        continue;
                    }
                    if !active.insert(head) {
                        return None;
                    }
                    let (target, arguments) = instance_head(types, head)?;
                    let instance = hell_builtins::instance(class, target)?;
                    let premise_count = usize::from(instance.resolution.premise_count());
                    if usize::from(instance.resolution.head_arity()) != arguments.len() {
                        return None;
                    }
                    work.push(Work::Leave(head));
                    work.extend(
                        arguments
                            .into_iter()
                            .take(premise_count)
                            .rev()
                            .map(Work::Enter),
                    );
                }
            }
        }
        self.identities.get(&(class, root)).copied()
    }
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

fn has_instance(types: &TypeArena, class: hell_builtins::TypeClass, ty: TypeId) -> bool {
    InstanceEvidencePlans::default()
        .retain(types, class, ty)
        .is_some()
}

fn parse_wrapping_int(raw: &str) -> Option<i64> {
    let (radix, digits) = if let Some(value) = raw.strip_prefix("0x").or(raw.strip_prefix("0X")) {
        (16_u32, value)
    } else if let Some(value) = raw.strip_prefix("0o").or(raw.strip_prefix("0O")) {
        (8_u32, value)
    } else {
        (10_u32, raw)
    };
    if digits.is_empty() {
        return None;
    }
    let mut value = 0_u64;
    for digit in digits.chars() {
        let digit = u64::from(digit.to_digit(radix)?);
        value = value.wrapping_mul(u64::from(radix)).wrapping_add(digit);
    }
    Some(value.cast_signed())
}
