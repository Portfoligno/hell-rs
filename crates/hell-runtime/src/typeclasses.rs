//! Runtime representations shared by manifest-driven class adapters.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::sync::Arc;

use hell_core::ClassEvidence;
use hell_types::TypeNode;

#[cfg(feature = "compat-tracing")]
use crate::AdapterCausalIdentity;
use crate::{
    Evaluator, ForceOutcome, FunctionValue, HostFunction, IoAction, ListCell, PrimitiveFamily,
    PrimitiveVariantValue, RuntimeError, RuntimeResult, Suspension, Thunk, ThunkRef, Value,
    list_from_values,
};

#[derive(Clone, Debug)]
pub struct TreeValue {
    pub(crate) root: ThunkRef,
    pub(crate) children: ThunkRef,
}

#[derive(Clone, Debug)]
pub struct CaseInsensitiveValue {
    pub(crate) original: ThunkRef,
    pub(crate) folded: ThunkRef,
}

#[derive(Clone, Debug)]
pub enum OptionModifier {
    Long(Arc<str>),
    Help(Arc<str>),
    Metavar(Arc<str>),
    Default(ThunkRef),
    Command { name: Arc<str>, parser: ParserInfo },
}

#[derive(Clone, Debug, Default)]
pub struct OptionModifiers(pub(crate) Arc<[OptionModifier]>);

#[derive(Clone, Debug)]
pub enum OptionParser {
    Pure(ThunkRef),
    Helper,
    Map {
        function: ThunkRef,
        parser: Arc<Self>,
        #[cfg(feature = "compat-tracing")]
        callback_parent: Option<AdapterCausalIdentity>,
    },
    Apply {
        function: Arc<Self>,
        argument: Arc<Self>,
        flipped: bool,
        #[cfg(feature = "compat-tracing")]
        callback_parent: Option<AdapterCausalIdentity>,
        #[cfg(feature = "compat-tracing")]
        callback_argument: u16,
    },
    Optional(Arc<Self>),
    Many(Arc<Self>),
    Switch(OptionModifiers),
    Flag {
        inactive: Option<ThunkRef>,
        active: ThunkRef,
        modifiers: OptionModifiers,
    },
    StringOption(OptionModifiers),
    StringArgument(OptionModifiers),
    Commands(OptionModifiers),
}

#[derive(Clone, Debug, Default)]
pub struct InfoModifiers {
    pub(crate) full_description: bool,
    pub(crate) program_description: Option<Arc<str>>,
    pub(crate) header: Option<Arc<str>>,
}

#[derive(Clone, Debug)]
pub struct ParserInfo {
    pub(crate) parser: Arc<OptionParser>,
    pub(crate) modifiers: InfoModifiers,
}

#[allow(clippy::too_many_lines)]
pub(super) fn apply_native(
    implementation: &str,
    arguments: &[ThunkRef],
    evidence: Option<ClassEvidence>,
    evaluator: &mut Evaluator,
) -> Option<RuntimeResult<ForceOutcome>> {
    let target = evidence.and_then(|evidence| instance_target(evaluator, evidence).ok());
    Some(match implementation {
        "functor_map" => map_value(evaluator, target.as_deref(), &arguments[0], &arguments[1]),
        "applicative_pure" => pure_value(evaluator, target.as_deref(), &arguments[0]),
        "io_pure" if evidence.is_some() => pure_value(evaluator, target.as_deref(), &arguments[0]),
        "applicative_apply" => apply_value(
            evaluator,
            target.as_deref(),
            &arguments[0],
            &arguments[1],
            false,
        ),
        "applicative_apply_flipped" => apply_value(
            evaluator,
            target.as_deref(),
            &arguments[1],
            &arguments[0],
            true,
        ),
        "alternative_optional" => optional_value(evaluator, target.as_deref(), &arguments[0]),
        "alternative_many" => many_value(evaluator, target.as_deref(), &arguments[0]),
        "io_bind" if evidence.is_some() => {
            bind_value(evaluator, target.as_deref(), &arguments[0], &arguments[1])
        }
        "io_then" if evidence.is_some() => {
            then_value(evaluator, target.as_deref(), &arguments[0], &arguments[1])
        }
        "monad_map_m" | "monad_map_m_discard" | "monad_for_m" | "monad_for_m_discard" => {
            let (callback, list, callback_argument) = if implementation.starts_with("monad_map") {
                (&arguments[0], &arguments[1], 0)
            } else {
                (&arguments[1], &arguments[0], 1)
            };
            traverse_value(
                evaluator,
                target.as_deref(),
                list,
                Some(callback),
                Some(callback_argument),
                implementation.ends_with("discard"),
            )
        }
        "monad_sequence" => traverse_value(
            evaluator,
            target.as_deref(),
            &arguments[0],
            None,
            None,
            false,
        ),
        "monad_when" => {
            let selected = evaluator.force_bool(&arguments[0]);
            match selected {
                Ok(true) => Ok(ForceOutcome::Alias(Arc::clone(&arguments[1]))),
                Ok(false) => {
                    pure_value(evaluator, target.as_deref(), &Thunk::evaluated(Value::Unit))
                }
                Err(error) => Err(error),
            }
        }
        "ci_mk" => case_insensitive(evaluator, &arguments[0]),
        "ci_folded_case" => folded_case(evaluator, &arguments[0]),
        "tree_node" => Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
            root: Arc::clone(&arguments[0]),
            children: Arc::clone(&arguments[1]),
        })))),
        "tree_map" => map_tree(evaluator, &arguments[0], &arguments[1]),
        "tree_fold" => fold_tree(evaluator, &arguments[0], &arguments[1]),
        "tree_flatten" => flatten_tree(evaluator, &arguments[0]),
        "tree_levels" => tree_levels(evaluator, &arguments[0]),
        "tree_unfold" => unfold_tree(evaluator, &arguments[0], &arguments[1]),
        "maybe_list_to_maybe" => list_to_maybe(evaluator, &arguments[0]),
        "maybe_map_maybe" => Ok(ForceOutcome::Alias(map_maybe_list(
            &arguments[0],
            &arguments[1],
        ))),
        "list_sort_on" => sort_list_on(evaluator, &arguments[0], &arguments[1]),
        "list_map_accum_l_compat" => {
            map_accum_l_compat(evaluator, &arguments[0], &arguments[1], &arguments[2])
        }
        "options_long" | "options_help" | "options_metavar" => {
            option_text_modifier(evaluator, implementation, &arguments[0])
        }
        "options_switch" | "options_str_option" | "options_str_argument" => {
            option_leaf_parser(evaluator, implementation, &arguments[0])
        }
        "options_default" => Ok(ForceOutcome::Value(Arc::new(Value::OptionsMod(
            OptionModifiers(Arc::from([OptionModifier::Default(Arc::clone(
                &arguments[0],
            ))])),
        )))),
        "options_flag" => option_flag(evaluator, Some(&arguments[0]), &arguments[1], &arguments[2]),
        "options_flag_prime" => option_flag(evaluator, None, &arguments[0], &arguments[1]),
        "options_helper" => Ok(ForceOutcome::Value(Arc::new(Value::OptionsParser(
            Arc::new(OptionParser::Helper),
        )))),
        "options_full_desc" => Ok(ForceOutcome::Value(Arc::new(Value::OptionsInfoMod(
            InfoModifiers {
                full_description: true,
                ..InfoModifiers::default()
            },
        )))),
        "options_prog_desc" | "options_header" => {
            option_info_text(evaluator, implementation, &arguments[0])
        }
        "options_info" => option_info(evaluator, &arguments[0], &arguments[1]),
        "options_exec_parser" => option_exec(evaluator, &arguments[0]),
        "options_command" => option_command(evaluator, &arguments[0], &arguments[1]),
        "options_hsubparser" => option_subparser(evaluator, &arguments[0]),
        _ => return None,
    })
}

pub(crate) fn instance_target(
    evaluator: &Evaluator,
    evidence: ClassEvidence,
) -> RuntimeResult<Arc<str>> {
    let plan = evaluator
        .program
        .instance_evidence(evidence.plan)
        .ok_or_else(|| RuntimeError::internal("class evidence plan disappeared"))?;
    if plan.class != evidence.class || plan.head != evidence.head.raw() {
        return Err(RuntimeError::internal(
            "class evidence root does not match its retained plan",
        ));
    }
    instance_target_from_type(evaluator, plan.head)
}

#[cfg(feature = "compat-tracing")]
pub(crate) struct RetainedInstanceEvidence {
    pub(crate) target: Arc<str>,
    pub(crate) premises: Vec<(Arc<str>, u8)>,
}

#[cfg(feature = "compat-tracing")]
pub(crate) fn retained_instance_evidence(
    evaluator: &Evaluator,
    evidence: ClassEvidence,
) -> RuntimeResult<RetainedInstanceEvidence> {
    enum Work {
        Enter(hell_core::InstanceEvidencePlanId, bool),
        Leave(hell_core::InstanceEvidencePlanId),
    }
    let root = evaluator
        .program
        .instance_evidence(evidence.plan)
        .ok_or_else(|| RuntimeError::internal("class evidence plan disappeared"))?;
    if root.class != evidence.class || root.head != evidence.head.raw() {
        return Err(RuntimeError::internal(
            "class evidence root does not match its retained plan",
        ));
    }
    let target = instance_target(evaluator, evidence)?;
    let mut premises = Vec::new();
    let mut active = BTreeSet::new();
    let mut work = vec![Work::Enter(evidence.plan, true)];
    while let Some(item) = work.pop() {
        match item {
            Work::Leave(id) => {
                if !active.remove(&id) {
                    return Err(RuntimeError::internal(
                        "class evidence plan leave is unbalanced",
                    ));
                }
            }
            Work::Enter(id, is_root) => {
                if !active.insert(id) {
                    return Err(RuntimeError::internal(
                        "class evidence plan contains a cycle",
                    ));
                }
                let plan = evaluator
                    .program
                    .instance_evidence(id)
                    .ok_or_else(|| RuntimeError::internal("class evidence premise disappeared"))?;
                let premise_target = instance_target_from_type(evaluator, plan.head)?;
                if !is_root {
                    premises.push((premise_target, plan.resolution.premise_count()));
                }
                work.push(Work::Leave(id));
                work.extend(
                    plan.premises
                        .iter()
                        .rev()
                        .copied()
                        .map(|premise| Work::Enter(premise, false)),
                );
            }
        }
    }
    Ok(RetainedInstanceEvidence { target, premises })
}

fn instance_target_from_type(
    evaluator: &Evaluator,
    head: hell_types::TypeId,
) -> RuntimeResult<Arc<str>> {
    let mut current = head;
    while let TypeNode::Apply(function, _) = evaluator.program.types().get(current) {
        current = *function;
    }
    match evaluator.program.types().get(current) {
        TypeNode::Constructor { name, .. } => Ok(Arc::clone(name)),
        _ => Err(RuntimeError::internal(
            "class evidence premise does not have a constructor head",
        )),
    }
}

fn pure_value(
    _evaluator: &mut Evaluator,
    target: Option<&str>,
    argument: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let value = match target {
        Some("IO") => {
            let result = Arc::clone(argument);
            Value::Io(IoAction::new(move |_, _| Ok(Arc::clone(&result))))
        }
        Some("Maybe") => Value::Maybe(Some(Arc::clone(argument))),
        Some("[]") => {
            return Ok(ForceOutcome::Alias(list_from_values(vec![Arc::clone(
                argument,
            )])));
        }
        Some("Either") => Value::PrimitiveVariant(PrimitiveVariantValue {
            family: PrimitiveFamily::Either,
            constructor_index: 1,
            payloads: Arc::from([Arc::clone(argument)]),
        }),
        Some("Tree") => Value::Tree(TreeValue {
            root: Arc::clone(argument),
            children: Thunk::evaluated(Value::List(ListCell::Nil)),
        }),
        Some("Options.Parser") => {
            Value::OptionsParser(Arc::new(OptionParser::Pure(Arc::clone(argument))))
        }
        Some(other) => {
            return Err(RuntimeError::internal(format!(
                "manifest Applicative/Monad target `{other}` has no pure adapter"
            )));
        }
        None => {
            return Err(RuntimeError::internal(
                "class primitive is missing evidence",
            ));
        }
    };
    Ok(ForceOutcome::Value(Arc::new(value)))
}

fn map_value(
    evaluator: &mut Evaluator,
    target: Option<&str>,
    function: &ThunkRef,
    container: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    #[cfg(feature = "compat-tracing")]
    let callback_parent = evaluator.active_adapter_identity_optional()?;
    match target {
        Some("[]") => Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::ListMap {
            function: Arc::clone(function),
            list: Arc::clone(container),
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        }))),
        Some("IO") => Ok(map_io(
            function,
            container,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        )),
        Some("Options.Parser") => map_option_parser(
            evaluator,
            function,
            container,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        ),
        Some("Tree") => map_tree(evaluator, function, container),
        Some("Maybe") => map_maybe(
            evaluator,
            function,
            container,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        ),
        Some("Either") => map_either(
            evaluator,
            function,
            container,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        ),
        Some("(,)") => map_pair(
            evaluator,
            function,
            container,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        ),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Functor target `{other}` has no runtime adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Functor primitive is missing evidence",
        )),
    }
}

fn map_io(
    function: &ThunkRef,
    container: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> ForceOutcome {
    let action = Arc::clone(container);
    let function = Arc::clone(function);
    ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
        move |evaluator, context| {
            let action = evaluator.force_io(&action)?;
            let value = action.run(evaluator, context)?;
            #[cfg(feature = "compat-tracing")]
            let mapped = Evaluator::callback_application_for_optional_parent(
                callback_parent,
                Arc::clone(&function),
                &[value],
                0,
                "io-result",
            );
            #[cfg(not(feature = "compat-tracing"))]
            let mapped = Thunk::suspended(Suspension::Apply {
                function: Arc::clone(&function),
                argument: value,
            });
            Ok(mapped)
        },
    ))))
}

fn map_option_parser(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    container: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> RuntimeResult<ForceOutcome> {
    let container = evaluator.force(container)?;
    let Value::OptionsParser(parser) = container.as_ref() else {
        return Err(RuntimeError::internal(
            "Functor Options.Parser value mismatch",
        ));
    };
    Ok(ForceOutcome::Value(Arc::new(Value::OptionsParser(
        Arc::new(OptionParser::Map {
            function: Arc::clone(function),
            parser: Arc::clone(parser),
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        }),
    ))))
}

fn map_maybe(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    container: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> RuntimeResult<ForceOutcome> {
    match evaluator.force(container)?.as_ref() {
        Value::Maybe(None) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None)))),
        Value::Maybe(Some(value)) => {
            #[cfg(feature = "compat-tracing")]
            let mapped = Evaluator::callback_application_for_optional_parent(
                callback_parent,
                Arc::clone(function),
                &[Arc::clone(value)],
                0,
                "just",
            );
            #[cfg(not(feature = "compat-tracing"))]
            let mapped = Thunk::suspended(Suspension::Apply {
                function: Arc::clone(function),
                argument: Arc::clone(value),
            });
            Ok(ForceOutcome::Value(Arc::new(Value::Maybe(Some(mapped)))))
        }
        _ => Err(RuntimeError::internal("Functor Maybe value mismatch")),
    }
}

fn map_either(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    container: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> RuntimeResult<ForceOutcome> {
    match evaluator.force(container)?.as_ref() {
        Value::PrimitiveVariant(variant)
            if variant.family == PrimitiveFamily::Either && variant.constructor_index == 0 =>
        {
            Ok(ForceOutcome::Alias(Arc::clone(container)))
        }
        Value::PrimitiveVariant(variant)
            if variant.family == PrimitiveFamily::Either && variant.constructor_index == 1 =>
        {
            let payload = variant
                .payloads
                .first()
                .ok_or_else(|| RuntimeError::internal("Either.Right payload is missing"))?;
            #[cfg(feature = "compat-tracing")]
            let mapped = Evaluator::callback_application_for_optional_parent(
                callback_parent,
                Arc::clone(function),
                &[Arc::clone(payload)],
                0,
                "right",
            );
            #[cfg(not(feature = "compat-tracing"))]
            let mapped = Thunk::suspended(Suspension::Apply {
                function: Arc::clone(function),
                argument: Arc::clone(payload),
            });
            Ok(ForceOutcome::Value(Arc::new(Value::PrimitiveVariant(
                PrimitiveVariantValue {
                    family: PrimitiveFamily::Either,
                    constructor_index: 1,
                    payloads: Arc::from([mapped]),
                },
            ))))
        }
        _ => Err(RuntimeError::internal("Functor Either value mismatch")),
    }
}

fn map_pair(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    container: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> RuntimeResult<ForceOutcome> {
    match evaluator.force(container)?.as_ref() {
        Value::Tuple(elements) if elements.len() == 2 => {
            #[cfg(feature = "compat-tracing")]
            let mapped = Evaluator::callback_application_for_optional_parent(
                callback_parent,
                Arc::clone(function),
                &[Arc::clone(&elements[1])],
                0,
                "second",
            );
            #[cfg(not(feature = "compat-tracing"))]
            let mapped = Thunk::suspended(Suspension::Apply {
                function: Arc::clone(function),
                argument: Arc::clone(&elements[1]),
            });
            Ok(ForceOutcome::Value(Arc::new(Value::Tuple(
                [Arc::clone(&elements[0]), mapped].into(),
            ))))
        }
        _ => Err(RuntimeError::internal("Functor pair value mismatch")),
    }
}

#[allow(clippy::too_many_lines)]
fn apply_value(
    evaluator: &mut Evaluator,
    target: Option<&str>,
    functions: &ThunkRef,
    arguments: &ThunkRef,
    flipped: bool,
) -> RuntimeResult<ForceOutcome> {
    #[cfg(feature = "compat-tracing")]
    let callback_parent = evaluator.active_adapter_identity_optional()?;
    #[cfg(feature = "compat-tracing")]
    let callback_argument = u16::from(flipped);
    match target {
        Some("Options.Parser") => {
            let functions = evaluator.force(functions)?;
            let Value::OptionsParser(function) = functions.as_ref() else {
                return Err(RuntimeError::internal(
                    "Applicative Options.Parser function mismatch",
                ));
            };
            let arguments = evaluator.force(arguments)?;
            let Value::OptionsParser(argument) = arguments.as_ref() else {
                return Err(RuntimeError::internal(
                    "Applicative Options.Parser argument mismatch",
                ));
            };
            Ok(ForceOutcome::Value(Arc::new(Value::OptionsParser(
                Arc::new(OptionParser::Apply {
                    function: Arc::clone(function),
                    argument: Arc::clone(argument),
                    flipped,
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                    #[cfg(feature = "compat-tracing")]
                    callback_argument,
                }),
            ))))
        }
        Some("IO") => {
            let functions = Arc::clone(functions);
            let arguments = Arc::clone(arguments);
            Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
                move |evaluator, context| {
                    let (function, argument) = if flipped {
                        let argument_action = evaluator.force_io(&arguments)?;
                        let argument = argument_action.run(evaluator, context)?;
                        let function_action = evaluator.force_io(&functions)?;
                        (function_action.run(evaluator, context)?, argument)
                    } else {
                        let function_action = evaluator.force_io(&functions)?;
                        let function = function_action.run(evaluator, context)?;
                        let argument_action = evaluator.force_io(&arguments)?;
                        (function, argument_action.run(evaluator, context)?)
                    };
                    #[cfg(feature = "compat-tracing")]
                    let applied = Evaluator::callback_application_for_optional_parent(
                        callback_parent,
                        function,
                        &[argument],
                        callback_argument,
                        "application",
                    );
                    #[cfg(not(feature = "compat-tracing"))]
                    let applied = Thunk::suspended(Suspension::Apply { function, argument });
                    Ok(applied)
                },
            )))))
        }
        Some("Maybe") => {
            let (function, argument) = if flipped {
                let Some(argument) = force_maybe_payload(evaluator, arguments)? else {
                    return Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None))));
                };
                let Some(function) = force_maybe_payload(evaluator, functions)? else {
                    return Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None))));
                };
                (function, argument)
            } else {
                let Some(function) = force_maybe_payload(evaluator, functions)? else {
                    return Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None))));
                };
                let Some(argument) = force_maybe_payload(evaluator, arguments)? else {
                    return Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None))));
                };
                (function, argument)
            };
            #[cfg(feature = "compat-tracing")]
            let applied = Evaluator::callback_application_for_optional_parent(
                callback_parent,
                function,
                &[argument],
                callback_argument,
                "application",
            );
            #[cfg(not(feature = "compat-tracing"))]
            let applied = Thunk::suspended(Suspension::Apply { function, argument });
            Ok(ForceOutcome::Value(Arc::new(Value::Maybe(Some(applied)))))
        }
        Some("Either") => {
            let (function, argument) = if flipped {
                let argument = force_applicative_either(evaluator, arguments)?;
                let ApplicativeEither::Right(argument) = argument else {
                    return Ok(argument.into_outcome());
                };
                let function = force_applicative_either(evaluator, functions)?;
                let ApplicativeEither::Right(function) = function else {
                    return Ok(function.into_outcome());
                };
                (function, argument)
            } else {
                let function = force_applicative_either(evaluator, functions)?;
                let ApplicativeEither::Right(function) = function else {
                    return Ok(function.into_outcome());
                };
                let argument = force_applicative_either(evaluator, arguments)?;
                let ApplicativeEither::Right(argument) = argument else {
                    return Ok(argument.into_outcome());
                };
                (function, argument)
            };
            #[cfg(feature = "compat-tracing")]
            let applied = Evaluator::callback_application_for_optional_parent(
                callback_parent,
                function,
                &[argument],
                callback_argument,
                "application",
            );
            #[cfg(not(feature = "compat-tracing"))]
            let applied = Thunk::suspended(Suspension::Apply { function, argument });
            Ok(ForceOutcome::Value(Arc::new(Value::PrimitiveVariant(
                PrimitiveVariantValue {
                    family: PrimitiveFamily::Either,
                    constructor_index: 1,
                    payloads: Arc::from([applied]),
                },
            ))))
        }
        Some("[]") => {
            let (functions, arguments) = if flipped {
                let arguments = evaluator.force_list_elements(arguments)?;
                if arguments.is_empty() {
                    return Ok(ForceOutcome::Alias(list_from_values(Vec::new())));
                }
                (evaluator.force_list_elements(functions)?, arguments)
            } else {
                let functions = evaluator.force_list_elements(functions)?;
                if functions.is_empty() {
                    return Ok(ForceOutcome::Alias(list_from_values(Vec::new())));
                }
                (functions, evaluator.force_list_elements(arguments)?)
            };
            let mut results = Vec::with_capacity(functions.len().saturating_mul(arguments.len()));
            let pairs = if flipped {
                arguments
                    .iter()
                    .flat_map(|argument| functions.iter().map(move |function| (function, argument)))
                    .collect::<Vec<_>>()
            } else {
                functions
                    .iter()
                    .flat_map(|function| arguments.iter().map(move |argument| (function, argument)))
                    .collect::<Vec<_>>()
            };
            for (function, argument) in pairs {
                #[cfg(feature = "compat-tracing")]
                results.push(Evaluator::callback_application_for_optional_parent(
                    callback_parent,
                    Arc::clone(function),
                    &[Arc::clone(argument)],
                    callback_argument,
                    "application",
                ));
                #[cfg(not(feature = "compat-tracing"))]
                results.push(Thunk::suspended(Suspension::Apply {
                    function: Arc::clone(function),
                    argument: Arc::clone(argument),
                }));
            }
            Ok(ForceOutcome::Alias(list_from_values(results)))
        }
        Some("Tree") if flipped => apply_tree_flipped(
            evaluator,
            arguments,
            functions,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
            #[cfg(feature = "compat-tracing")]
            callback_argument,
        ),
        Some("Tree") => apply_tree(
            evaluator,
            functions,
            arguments,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
            #[cfg(feature = "compat-tracing")]
            callback_argument,
        ),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Applicative target `{other}` has no apply adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Applicative primitive is missing evidence",
        )),
    }
}

fn force_maybe_payload(
    evaluator: &mut Evaluator,
    value: &ThunkRef,
) -> RuntimeResult<Option<ThunkRef>> {
    match evaluator.force(value)?.as_ref() {
        Value::Maybe(payload) => Ok(payload.as_ref().map(Arc::clone)),
        _ => Err(RuntimeError::internal("Applicative Maybe value mismatch")),
    }
}

enum ApplicativeEither {
    Left(PrimitiveVariantValue),
    Right(ThunkRef),
}

impl ApplicativeEither {
    fn into_outcome(self) -> ForceOutcome {
        let Self::Left(value) = self else {
            unreachable!("only a Left short-circuits Applicative Either")
        };
        ForceOutcome::Value(Arc::new(Value::PrimitiveVariant(value)))
    }
}

fn force_applicative_either(
    evaluator: &mut Evaluator,
    value: &ThunkRef,
) -> RuntimeResult<ApplicativeEither> {
    let value = evaluator.force(value)?;
    let Value::PrimitiveVariant(variant) = value.as_ref() else {
        return Err(RuntimeError::internal("Applicative Either value mismatch"));
    };
    if variant.family != PrimitiveFamily::Either {
        return Err(RuntimeError::internal("Applicative Either family mismatch"));
    }
    match variant.constructor_index {
        0 => Ok(ApplicativeEither::Left(variant.clone())),
        1 => variant
            .payloads
            .first()
            .map(|payload| ApplicativeEither::Right(Arc::clone(payload)))
            .ok_or_else(|| RuntimeError::internal("Either.Right payload is missing")),
        _ => Err(RuntimeError::internal(
            "Applicative Either constructor mismatch",
        )),
    }
}

fn traverse_tree(
    evaluator: &mut Evaluator,
    items: Vec<ThunkRef>,
    callback: Option<&ThunkRef>,
    discard: bool,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")] callback_argument: Option<u16>,
) -> RuntimeResult<ForceOutcome> {
    let empty_children = || Thunk::evaluated(Value::List(ListCell::Nil));
    let mut accumulated = Thunk::evaluated(Value::Tree(TreeValue {
        root: empty_children(),
        children: empty_children(),
    }));
    for item in items {
        let action = traversal_action(
            callback,
            &item,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
            #[cfg(feature = "compat-tracing")]
            callback_argument,
        );
        let continuation = Thunk::evaluated(Value::Function(FunctionValue::Host(
            HostFunction::new(move |values| {
                let action = Arc::clone(&action);
                let append = Thunk::evaluated(Value::Function(FunctionValue::Host(
                    HostFunction::new(move |value| {
                        let root = Thunk::suspended(Suspension::SemigroupAppend {
                            left: Arc::clone(&values),
                            right: list_from_values(vec![value]),
                        });
                        Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
                            root,
                            children: Thunk::evaluated(Value::List(ListCell::Nil)),
                        }))))
                    }),
                )));
                Ok(ForceOutcome::Alias(Thunk::deferred(move |evaluator| {
                    let outcome = bind_tree(evaluator, &action, &append)?;
                    outcome_value(evaluator, outcome)
                })))
            }),
        )));
        let previous = accumulated;
        accumulated = Thunk::deferred(move |evaluator| {
            let outcome = bind_tree(evaluator, &previous, &continuation)?;
            outcome_value(evaluator, outcome)
        });
    }
    if discard {
        let discard = Thunk::evaluated(Value::Function(FunctionValue::Host(HostFunction::new(
            |_| Ok(ForceOutcome::Value(Arc::new(Value::Unit))),
        ))));
        map_tree(evaluator, &discard, &accumulated)
    } else {
        Ok(ForceOutcome::Alias(accumulated))
    }
}

fn optional_value(
    evaluator: &mut Evaluator,
    target: Option<&str>,
    argument: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    match target {
        Some("Options.Parser") => {
            let argument = evaluator.force(argument)?;
            let Value::OptionsParser(parser) = argument.as_ref() else {
                return Err(RuntimeError::internal(
                    "Alternative Options.Parser value mismatch",
                ));
            };
            Ok(ForceOutcome::Value(Arc::new(Value::OptionsParser(
                Arc::new(OptionParser::Optional(Arc::clone(parser))),
            ))))
        }
        Some("Maybe") => match evaluator.force(argument)?.as_ref() {
            Value::Maybe(None) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(Some(
                Thunk::evaluated(Value::Maybe(None)),
            ))))),
            Value::Maybe(Some(value)) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(Some(
                Thunk::evaluated(Value::Maybe(Some(Arc::clone(value)))),
            ))))),
            _ => Err(RuntimeError::internal("Alternative Maybe value mismatch")),
        },
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Alternative target `{other}` has no optional adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Alternative primitive is missing evidence",
        )),
    }
}

fn many_value(
    evaluator: &mut Evaluator,
    target: Option<&str>,
    argument: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    match target {
        Some("Options.Parser") => {
            let argument = evaluator.force(argument)?;
            let Value::OptionsParser(parser) = argument.as_ref() else {
                return Err(RuntimeError::internal(
                    "Alternative Options.Parser value mismatch",
                ));
            };
            Ok(ForceOutcome::Value(Arc::new(Value::OptionsParser(
                Arc::new(OptionParser::Many(Arc::clone(parser))),
            ))))
        }
        Some("Maybe") => match evaluator.force(argument)?.as_ref() {
            Value::Maybe(None) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(Some(
                Thunk::evaluated(Value::List(ListCell::Nil)),
            ))))),
            Value::Maybe(Some(_)) => Err(RuntimeError::internal(
                "Alternative.many on a successful Maybe is non-productive",
            )),
            _ => Err(RuntimeError::internal("Alternative Maybe value mismatch")),
        },
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Alternative target `{other}` has no many adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Alternative primitive is missing evidence",
        )),
    }
}

fn bind_value(
    evaluator: &mut Evaluator,
    target: Option<&str>,
    monad: &ThunkRef,
    continuation: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    #[cfg(feature = "compat-tracing")]
    let callback_parent = evaluator.active_adapter_identity_optional()?;
    match target {
        Some("IO") => {
            let action = Arc::clone(monad);
            let continuation = Arc::clone(continuation);
            Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
                move |evaluator, context| {
                    let action = evaluator.force_io(&action)?;
                    let result = action.run(evaluator, context)?;
                    #[cfg(feature = "compat-tracing")]
                    let applied = Evaluator::callback_application_for_optional_parent(
                        callback_parent,
                        Arc::clone(&continuation),
                        &[result],
                        1,
                        "continuation",
                    );
                    #[cfg(not(feature = "compat-tracing"))]
                    let applied = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&continuation),
                        argument: result,
                    });
                    let next = evaluator.force_io(&applied)?;
                    next.run(evaluator, context)
                },
            )))))
        }
        Some("Maybe") => match evaluator.force(monad)?.as_ref() {
            Value::Maybe(None) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None)))),
            Value::Maybe(Some(value)) => {
                #[cfg(feature = "compat-tracing")]
                let applied = Evaluator::callback_application_for_optional_parent(
                    callback_parent,
                    Arc::clone(continuation),
                    &[Arc::clone(value)],
                    1,
                    "continuation",
                );
                #[cfg(not(feature = "compat-tracing"))]
                let applied = Thunk::suspended(Suspension::Apply {
                    function: Arc::clone(continuation),
                    argument: Arc::clone(value),
                });
                Ok(ForceOutcome::Alias(applied))
            }
            _ => Err(RuntimeError::internal("Monad Maybe value mismatch")),
        },
        Some("Either") => match evaluator.force(monad)?.as_ref() {
            Value::PrimitiveVariant(variant) if variant.constructor_index == 0 => {
                Ok(ForceOutcome::Alias(Arc::clone(monad)))
            }
            Value::PrimitiveVariant(variant) if variant.constructor_index == 1 => {
                let value = variant
                    .payloads
                    .first()
                    .ok_or_else(|| RuntimeError::internal("Either.Right payload is missing"))?;
                #[cfg(feature = "compat-tracing")]
                let applied = Evaluator::callback_application_for_optional_parent(
                    callback_parent,
                    Arc::clone(continuation),
                    &[Arc::clone(value)],
                    1,
                    "continuation",
                );
                #[cfg(not(feature = "compat-tracing"))]
                let applied = Thunk::suspended(Suspension::Apply {
                    function: Arc::clone(continuation),
                    argument: Arc::clone(value),
                });
                Ok(ForceOutcome::Alias(applied))
            }
            _ => Err(RuntimeError::internal("Monad Either value mismatch")),
        },
        Some("[]") => Ok(ForceOutcome::Alias(bind_list(
            monad,
            continuation,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        ))),
        Some("Tree") => bind_tree_with_parent(
            evaluator,
            monad,
            continuation,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        ),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Monad target `{other}` has no bind adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Monad primitive is missing evidence",
        )),
    }
}

fn bind_list(
    list: &ThunkRef,
    continuation: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> ThunkRef {
    let list = Arc::clone(list);
    let continuation = Arc::clone(continuation);
    Thunk::deferred(move |evaluator| match evaluator.force(&list)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            #[cfg(feature = "compat-tracing")]
            let first = Evaluator::callback_application_for_optional_parent(
                callback_parent,
                Arc::clone(&continuation),
                &[Arc::clone(head)],
                1,
                "continuation",
            );
            #[cfg(not(feature = "compat-tracing"))]
            let first = Thunk::suspended(Suspension::Apply {
                function: Arc::clone(&continuation),
                argument: Arc::clone(head),
            });
            let rest = bind_list(
                tail,
                &continuation,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            );
            evaluator.force(&Thunk::suspended(Suspension::SemigroupAppend {
                left: first,
                right: rest,
            }))
        }
        _ => Err(RuntimeError::internal("Monad list value mismatch")),
    })
}

fn then_value(
    evaluator: &mut Evaluator,
    target: Option<&str>,
    first: &ThunkRef,
    second: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    match target {
        Some("IO") => {
            let first = Arc::clone(first);
            let second = Arc::clone(second);
            Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
                move |evaluator, context| {
                    let first_action = evaluator.force_io(&first)?;
                    let _discarded = first_action.run(evaluator, context)?;
                    let second_action = evaluator.force_io(&second)?;
                    second_action.run(evaluator, context)
                },
            )))))
        }
        Some("Maybe") => match evaluator.force(first)?.as_ref() {
            Value::Maybe(None) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None)))),
            Value::Maybe(Some(_)) => Ok(ForceOutcome::Alias(Arc::clone(second))),
            _ => Err(RuntimeError::internal("Monad Maybe value mismatch")),
        },
        Some("Either") => match evaluator.force(first)?.as_ref() {
            Value::PrimitiveVariant(variant) if variant.constructor_index == 0 => {
                Ok(ForceOutcome::Alias(Arc::clone(first)))
            }
            Value::PrimitiveVariant(variant) if variant.constructor_index == 1 => {
                Ok(ForceOutcome::Alias(Arc::clone(second)))
            }
            _ => Err(RuntimeError::internal("Monad Either value mismatch")),
        },
        Some("[]") => Ok(ForceOutcome::Alias(then_list(first, second))),
        Some("Tree") => then_tree(evaluator, first, second),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Monad target `{other}` has no then adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Monad primitive is missing evidence",
        )),
    }
}

fn then_list(first: &ThunkRef, second: &ThunkRef) -> ThunkRef {
    let first = Arc::clone(first);
    let second = Arc::clone(second);
    Thunk::deferred(move |evaluator| match evaluator.force(&first)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { tail, .. }) => {
            let rest = then_list(tail, &second);
            evaluator.force(&Thunk::suspended(Suspension::SemigroupAppend {
                left: Arc::clone(&second),
                right: rest,
            }))
        }
        _ => Err(RuntimeError::internal("Monad list value mismatch")),
    })
}

#[allow(clippy::too_many_lines)]
fn traverse_value(
    evaluator: &mut Evaluator,
    target: Option<&str>,
    list: &ThunkRef,
    callback: Option<&ThunkRef>,
    callback_argument: Option<u16>,
    discard: bool,
) -> RuntimeResult<ForceOutcome> {
    #[cfg(not(feature = "compat-tracing"))]
    let _ = callback_argument;
    #[cfg(feature = "compat-tracing")]
    let callback_parent = if callback.is_some() {
        evaluator.active_adapter_identity_optional()?
    } else {
        None
    };
    let items = evaluator.force_list_elements(list)?;
    match target {
        Some("IO") => {
            let callback = callback.cloned();
            Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
                move |evaluator, context| {
                    let mut results = Vec::with_capacity(items.len());
                    for item in &items {
                        let action = traversal_action(
                            callback.as_ref(),
                            item,
                            #[cfg(feature = "compat-tracing")]
                            callback_parent,
                            #[cfg(feature = "compat-tracing")]
                            callback_argument,
                        );
                        let action = evaluator.force_io(&action)?;
                        results.push(action.run(evaluator, context)?);
                    }
                    if discard {
                        Ok(Thunk::evaluated(Value::Unit))
                    } else {
                        Ok(list_from_values(results))
                    }
                },
            )))))
        }
        Some("Maybe") => {
            let mut results = Vec::with_capacity(items.len());
            for item in items {
                let action = traversal_action(
                    callback,
                    &item,
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                    #[cfg(feature = "compat-tracing")]
                    callback_argument,
                );
                match evaluator.force(&action)?.as_ref() {
                    Value::Maybe(None) => {
                        return Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None))));
                    }
                    Value::Maybe(Some(value)) => results.push(Arc::clone(value)),
                    _ => return Err(RuntimeError::internal("Monad Maybe traversal mismatch")),
                }
            }
            let result = if discard {
                Thunk::evaluated(Value::Unit)
            } else {
                list_from_values(results)
            };
            Ok(ForceOutcome::Value(Arc::new(Value::Maybe(Some(result)))))
        }
        Some("Either") => {
            let mut results = Vec::with_capacity(items.len());
            for item in items {
                let action = traversal_action(
                    callback,
                    &item,
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                    #[cfg(feature = "compat-tracing")]
                    callback_argument,
                );
                let action_value = evaluator.force(&action)?;
                let Value::PrimitiveVariant(variant) = action_value.as_ref() else {
                    return Err(RuntimeError::internal("Monad Either traversal mismatch"));
                };
                match variant.constructor_index {
                    0 => return Ok(ForceOutcome::Alias(action)),
                    1 => results.push(Arc::clone(variant.payloads.first().ok_or_else(|| {
                        RuntimeError::internal("Either.Right payload is missing")
                    })?)),
                    _ => {
                        return Err(RuntimeError::internal(
                            "Either traversal constructor is out of bounds",
                        ));
                    }
                }
            }
            let result = if discard {
                Thunk::evaluated(Value::Unit)
            } else {
                list_from_values(results)
            };
            Ok(ForceOutcome::Value(Arc::new(Value::PrimitiveVariant(
                PrimitiveVariantValue {
                    family: PrimitiveFamily::Either,
                    constructor_index: 1,
                    payloads: Arc::from([result]),
                },
            ))))
        }
        Some("[]") => {
            let mut combinations = vec![Vec::new()];
            for item in items {
                let action = traversal_action(
                    callback,
                    &item,
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                    #[cfg(feature = "compat-tracing")]
                    callback_argument,
                );
                let alternatives = evaluator.force_list_elements(&action)?;
                let mut next =
                    Vec::with_capacity(combinations.len().saturating_mul(alternatives.len()));
                for combination in combinations {
                    for alternative in &alternatives {
                        let mut combination = combination.clone();
                        combination.push(Arc::clone(alternative));
                        next.push(combination);
                    }
                }
                combinations = next;
            }
            let results = combinations
                .into_iter()
                .map(|combination| {
                    if discard {
                        Thunk::evaluated(Value::Unit)
                    } else {
                        list_from_values(combination)
                    }
                })
                .collect();
            Ok(ForceOutcome::Alias(list_from_values(results)))
        }
        Some("Tree") => traverse_tree(
            evaluator,
            items,
            callback,
            discard,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
            #[cfg(feature = "compat-tracing")]
            callback_argument,
        ),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Monad target `{other}` has no traversal adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Monad traversal is missing evidence",
        )),
    }
}

fn traversal_action(
    callback: Option<&ThunkRef>,
    item: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")] callback_argument: Option<u16>,
) -> ThunkRef {
    callback.map_or_else(
        || Arc::clone(item),
        |callback| {
            #[cfg(feature = "compat-tracing")]
            return Evaluator::callback_application_for_optional_parent(
                callback_parent,
                Arc::clone(callback),
                &[Arc::clone(item)],
                callback_argument.expect("traversal callback has an argument index"),
                "element",
            );
            #[cfg(not(feature = "compat-tracing"))]
            Thunk::suspended(Suspension::Apply {
                function: Arc::clone(callback),
                argument: Arc::clone(item),
            })
        },
    )
}

fn map_accum_l_compat(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    initial: &ThunkRef,
    list: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut accumulator = Arc::clone(initial);
    let mut current = Arc::clone(list);
    let mut mapped = Vec::new();
    loop {
        match evaluator.force(&current)?.as_ref() {
            Value::List(ListCell::Nil) => {
                return Ok(ForceOutcome::Value(Arc::new(Value::Tuple(Arc::from([
                    accumulator,
                    list_from_values(mapped),
                ])))));
            }
            Value::List(ListCell::Cons { head, tail }) => {
                #[cfg(feature = "compat-tracing")]
                let apply_item = evaluator.callback_application(
                    Arc::clone(function),
                    &[Arc::clone(&accumulator), Arc::clone(head)],
                    0,
                    "accumulate",
                )?;
                #[cfg(not(feature = "compat-tracing"))]
                let apply_accumulator = Thunk::suspended(Suspension::Apply {
                    function: Arc::clone(function),
                    argument: accumulator,
                });
                #[cfg(not(feature = "compat-tracing"))]
                let apply_item = Thunk::suspended(Suspension::Apply {
                    function: apply_accumulator,
                    argument: Arc::clone(head),
                });
                let pair = evaluator.force(&apply_item)?;
                let Value::Tuple(elements) = pair.as_ref() else {
                    return Err(RuntimeError::internal(
                        "List.mapAccumR compatibility callback returned a non-pair",
                    ));
                };
                let [next_accumulator, item] = elements.as_ref() else {
                    return Err(RuntimeError::internal(
                        "List.mapAccumR compatibility callback returned a non-pair",
                    ));
                };
                accumulator = Arc::clone(next_accumulator);
                mapped.push(Arc::clone(item));
                current = Arc::clone(tail);
            }
            _ => {
                return Err(RuntimeError::internal(
                    "List.mapAccumR compatibility adapter received a non-list",
                ));
            }
        }
    }
}

fn case_insensitive(evaluator: &mut Evaluator, argument: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let folded = match evaluator.force(argument)?.as_ref() {
        Value::Text(text) => Thunk::evaluated(Value::Text(text.to_lowercase().into())),
        Value::ByteString(bytes) => Thunk::evaluated(Value::ByteString(
            bytes.iter().map(u8::to_ascii_lowercase).collect(),
        )),
        _ => return Err(RuntimeError::internal("FoldCase evidence/value mismatch")),
    };
    Ok(ForceOutcome::Value(Arc::new(Value::CaseInsensitive(
        CaseInsensitiveValue {
            original: Arc::clone(argument),
            folded,
        },
    ))))
}

fn folded_case(evaluator: &mut Evaluator, value: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    match evaluator.force(value)?.as_ref() {
        Value::CaseInsensitive(value) => Ok(ForceOutcome::Alias(Arc::clone(&value.folded))),
        _ => Err(RuntimeError::internal(
            "CI.foldedCase received a non-CI value",
        )),
    }
}

fn map_tree(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    tree: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    #[cfg(feature = "compat-tracing")]
    let callback_parent = evaluator.active_adapter_identity_optional()?;
    map_tree_with_parent(
        evaluator,
        function,
        tree,
        #[cfg(feature = "compat-tracing")]
        callback_parent,
        #[cfg(feature = "compat-tracing")]
        0,
        #[cfg(feature = "compat-tracing")]
        "node",
    )
}

fn map_tree_with_parent(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    tree: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")] callback_argument: u16,
    #[cfg(feature = "compat-tracing")] callback_branch: &'static str,
) -> RuntimeResult<ForceOutcome> {
    let tree_value = evaluator.force(tree)?;
    let Value::Tree(tree) = tree_value.as_ref() else {
        return Err(RuntimeError::internal("Tree.map received a non-Tree value"));
    };
    #[cfg(feature = "compat-tracing")]
    let root = Evaluator::callback_application_for_optional_parent(
        callback_parent,
        Arc::clone(function),
        &[Arc::clone(&tree.root)],
        callback_argument,
        callback_branch,
    );
    #[cfg(not(feature = "compat-tracing"))]
    let root = Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(&tree.root),
    });
    let mapper = Arc::clone(function);
    let children = evaluator.force_list_elements(&tree.children)?;
    let children = children
        .into_iter()
        .map(|child| {
            let mapper = Arc::clone(&mapper);
            Thunk::deferred(move |evaluator| {
                match map_tree_with_parent(
                    evaluator,
                    &mapper,
                    &child,
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                    #[cfg(feature = "compat-tracing")]
                    callback_argument,
                    #[cfg(feature = "compat-tracing")]
                    callback_branch,
                )? {
                    ForceOutcome::Value(value) => Ok(value),
                    ForceOutcome::Alias(value) => evaluator.force(&value),
                }
            })
        })
        .collect();
    Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
        root,
        children: list_from_values(children),
    }))))
}

fn fold_tree(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    tree: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    #[cfg(feature = "compat-tracing")]
    let callback_parent = evaluator.active_adapter_identity_optional()?;
    fold_tree_with_parent(
        evaluator,
        function,
        tree,
        #[cfg(feature = "compat-tracing")]
        callback_parent,
    )
}

fn fold_tree_with_parent(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    tree: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> RuntimeResult<ForceOutcome> {
    let tree_value = evaluator.force(tree)?;
    let Value::Tree(tree) = tree_value.as_ref() else {
        return Err(RuntimeError::internal(
            "Tree.foldTree received a non-Tree value",
        ));
    };
    let children = evaluator.force_list_elements(&tree.children)?;
    let folded = children
        .into_iter()
        .map(|child| {
            let function = Arc::clone(function);
            Thunk::deferred(move |evaluator| {
                match fold_tree_with_parent(
                    evaluator,
                    &function,
                    &child,
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                )? {
                    ForceOutcome::Value(value) => Ok(value),
                    ForceOutcome::Alias(value) => evaluator.force(&value),
                }
            })
        })
        .collect();
    let folded = list_from_values(folded);
    #[cfg(feature = "compat-tracing")]
    let application = Evaluator::callback_application_for_optional_parent(
        callback_parent,
        Arc::clone(function),
        &[Arc::clone(&tree.root), folded],
        0,
        "node",
    );
    #[cfg(not(feature = "compat-tracing"))]
    let application = {
        let with_root = Thunk::suspended(Suspension::Apply {
            function: Arc::clone(function),
            argument: Arc::clone(&tree.root),
        });
        Thunk::suspended(Suspension::Apply {
            function: with_root,
            argument: folded,
        })
    };
    Ok(ForceOutcome::Alias(application))
}

fn flatten_tree(evaluator: &mut Evaluator, tree: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    fn collect(
        evaluator: &mut Evaluator,
        tree: &ThunkRef,
        output: &mut Vec<ThunkRef>,
    ) -> RuntimeResult<()> {
        let tree_value = evaluator.force(tree)?;
        let Value::Tree(tree) = tree_value.as_ref() else {
            return Err(RuntimeError::internal(
                "Tree.flatten received a non-Tree value",
            ));
        };
        output.push(Arc::clone(&tree.root));
        for child in evaluator.force_list_elements(&tree.children)? {
            collect(evaluator, &child, output)?;
        }
        Ok(())
    }
    let mut output = Vec::new();
    collect(evaluator, tree, &mut output)?;
    Ok(ForceOutcome::Alias(list_from_values(output)))
}

fn tree_levels(evaluator: &mut Evaluator, tree: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let mut current = vec![Arc::clone(tree)];
    let mut levels = Vec::new();
    while !current.is_empty() {
        let mut roots = Vec::with_capacity(current.len());
        let mut next = Vec::new();
        for tree in current {
            let tree_value = evaluator.force(&tree)?;
            let Value::Tree(tree) = tree_value.as_ref() else {
                return Err(RuntimeError::internal(
                    "Tree.levels received a non-Tree value",
                ));
            };
            roots.push(Arc::clone(&tree.root));
            next.extend(evaluator.force_list_elements(&tree.children)?);
        }
        levels.push(list_from_values(roots));
        current = next;
    }
    Ok(ForceOutcome::Alias(list_from_values(levels)))
}

fn apply_tree(
    evaluator: &mut Evaluator,
    functions: &ThunkRef,
    arguments: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")] callback_argument: u16,
) -> RuntimeResult<ForceOutcome> {
    let function_value = evaluator.force(functions)?;
    let Value::Tree(functions) = function_value.as_ref() else {
        return Err(RuntimeError::internal(
            "Applicative Tree function value mismatch",
        ));
    };
    let mapped = outcome_thunk(map_tree_with_parent(
        evaluator,
        &functions.root,
        arguments,
        #[cfg(feature = "compat-tracing")]
        callback_parent,
        #[cfg(feature = "compat-tracing")]
        callback_argument,
        #[cfg(feature = "compat-tracing")]
        "application",
    )?);
    let mapped_value = evaluator.force(&mapped)?;
    let Value::Tree(mapped) = mapped_value.as_ref() else {
        return Err(RuntimeError::internal(
            "Applicative Tree mapped value mismatch",
        ));
    };
    let mut children = evaluator.force_list_elements(&mapped.children)?;
    for function_child in evaluator.force_list_elements(&functions.children)? {
        let arguments = Arc::clone(arguments);
        children.push(Thunk::deferred(move |evaluator| {
            let outcome = apply_tree(
                evaluator,
                &function_child,
                &arguments,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
                #[cfg(feature = "compat-tracing")]
                callback_argument,
            )?;
            outcome_value(evaluator, outcome)
        }));
    }
    Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
        root: Arc::clone(&mapped.root),
        children: list_from_values(children),
    }))))
}

fn apply_tree_flipped(
    evaluator: &mut Evaluator,
    values: &ThunkRef,
    functions: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")] callback_argument: u16,
) -> RuntimeResult<ForceOutcome> {
    let value = evaluator.force(values)?;
    let Value::Tree(values) = value.as_ref() else {
        return Err(RuntimeError::internal(
            "Applicative Tree argument value mismatch",
        ));
    };
    let mapped = outcome_thunk(apply_value_to_function_tree(
        evaluator,
        &values.root,
        functions,
        #[cfg(feature = "compat-tracing")]
        callback_parent,
        #[cfg(feature = "compat-tracing")]
        callback_argument,
    )?);
    let mapped = evaluator.force(&mapped)?;
    let Value::Tree(mapped) = mapped.as_ref() else {
        return Err(RuntimeError::internal(
            "Applicative flipped Tree mapped value mismatch",
        ));
    };
    let mut children = evaluator.force_list_elements(&mapped.children)?;
    for value_child in evaluator.force_list_elements(&values.children)? {
        let functions = Arc::clone(functions);
        children.push(Thunk::deferred(move |evaluator| {
            let outcome = apply_tree_flipped(
                evaluator,
                &value_child,
                &functions,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
                #[cfg(feature = "compat-tracing")]
                callback_argument,
            )?;
            outcome_value(evaluator, outcome)
        }));
    }
    Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
        root: Arc::clone(&mapped.root),
        children: list_from_values(children),
    }))))
}

fn apply_value_to_function_tree(
    evaluator: &mut Evaluator,
    value: &ThunkRef,
    functions: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")] callback_argument: u16,
) -> RuntimeResult<ForceOutcome> {
    let function_value = evaluator.force(functions)?;
    let Value::Tree(functions) = function_value.as_ref() else {
        return Err(RuntimeError::internal(
            "Applicative flipped Tree function value mismatch",
        ));
    };
    #[cfg(feature = "compat-tracing")]
    let root = Evaluator::callback_application_for_optional_parent(
        callback_parent,
        Arc::clone(&functions.root),
        &[Arc::clone(value)],
        callback_argument,
        "application",
    );
    #[cfg(not(feature = "compat-tracing"))]
    let root = Thunk::suspended(Suspension::Apply {
        function: Arc::clone(&functions.root),
        argument: Arc::clone(value),
    });
    let children = evaluator
        .force_list_elements(&functions.children)?
        .into_iter()
        .map(|function_child| {
            let value = Arc::clone(value);
            Thunk::deferred(move |evaluator| {
                let outcome = apply_value_to_function_tree(
                    evaluator,
                    &value,
                    &function_child,
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                    #[cfg(feature = "compat-tracing")]
                    callback_argument,
                )?;
                outcome_value(evaluator, outcome)
            })
        })
        .collect();
    Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
        root,
        children: list_from_values(children),
    }))))
}

fn bind_tree(
    evaluator: &mut Evaluator,
    tree: &ThunkRef,
    continuation: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    bind_tree_inner(
        evaluator,
        tree,
        continuation,
        #[cfg(feature = "compat-tracing")]
        None,
    )
}

fn bind_tree_with_parent(
    evaluator: &mut Evaluator,
    tree: &ThunkRef,
    continuation: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> RuntimeResult<ForceOutcome> {
    bind_tree_inner(
        evaluator,
        tree,
        continuation,
        #[cfg(feature = "compat-tracing")]
        callback_parent,
    )
}

fn bind_tree_inner(
    evaluator: &mut Evaluator,
    tree: &ThunkRef,
    continuation: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> RuntimeResult<ForceOutcome> {
    let tree_value = evaluator.force(tree)?;
    let Value::Tree(tree) = tree_value.as_ref() else {
        return Err(RuntimeError::internal("Monad Tree value mismatch"));
    };
    #[cfg(feature = "compat-tracing")]
    let applied = callback_parent.map_or_else(
        || {
            Thunk::suspended(Suspension::Apply {
                function: Arc::clone(continuation),
                argument: Arc::clone(&tree.root),
            })
        },
        |parent| {
            Evaluator::callback_application_for_parent(
                parent,
                Arc::clone(continuation),
                &[Arc::clone(&tree.root)],
                1,
                "continuation",
            )
        },
    );
    #[cfg(not(feature = "compat-tracing"))]
    let applied = Thunk::suspended(Suspension::Apply {
        function: Arc::clone(continuation),
        argument: Arc::clone(&tree.root),
    });
    let applied_value = evaluator.force(&applied)?;
    let Value::Tree(applied) = applied_value.as_ref() else {
        return Err(RuntimeError::internal(
            "Monad Tree continuation returned a non-Tree value",
        ));
    };
    let mut children = evaluator.force_list_elements(&applied.children)?;
    for child in evaluator.force_list_elements(&tree.children)? {
        let continuation = Arc::clone(continuation);
        children.push(Thunk::deferred(move |evaluator| {
            let outcome = bind_tree_inner(
                evaluator,
                &child,
                &continuation,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            )?;
            outcome_value(evaluator, outcome)
        }));
    }
    Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
        root: Arc::clone(&applied.root),
        children: list_from_values(children),
    }))))
}

fn then_tree(
    evaluator: &mut Evaluator,
    first: &ThunkRef,
    second: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let first_value = evaluator.force(first)?;
    let Value::Tree(first) = first_value.as_ref() else {
        return Err(RuntimeError::internal("Monad Tree value mismatch"));
    };
    let second_value = evaluator.force(second)?;
    let Value::Tree(second_value) = second_value.as_ref() else {
        return Err(RuntimeError::internal("Monad Tree value mismatch"));
    };
    let mut children = evaluator.force_list_elements(&second_value.children)?;
    for child in evaluator.force_list_elements(&first.children)? {
        let second = Arc::clone(second);
        children.push(Thunk::deferred(move |evaluator| {
            let outcome = then_tree(evaluator, &child, &second)?;
            outcome_value(evaluator, outcome)
        }));
    }
    Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
        root: Arc::clone(&second_value.root),
        children: list_from_values(children),
    }))))
}

fn outcome_thunk(outcome: ForceOutcome) -> ThunkRef {
    match outcome {
        ForceOutcome::Value(value) => Thunk::evaluated(value.as_ref().clone()),
        ForceOutcome::Alias(value) => value,
    }
}

fn outcome_value(
    evaluator: &mut Evaluator,
    outcome: ForceOutcome,
) -> RuntimeResult<crate::ValueRef> {
    match outcome {
        ForceOutcome::Value(value) => Ok(value),
        ForceOutcome::Alias(value) => evaluator.force(&value),
    }
}

fn sort_list_on(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    list: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut decorated = Vec::new();
    for value in evaluator.force_list_elements(list)? {
        evaluator.ensure_not_cancelled()?;
        #[cfg(feature = "compat-tracing")]
        let key = evaluator.callback_application(
            Arc::clone(function),
            std::slice::from_ref(&value),
            0,
            "key",
        )?;
        #[cfg(not(feature = "compat-tracing"))]
        let key = Thunk::suspended(Suspension::Apply {
            function: Arc::clone(function),
            argument: Arc::clone(&value),
        });
        decorated.push((key, value));
    }
    let mut runs = natural_keyed_runs(evaluator, decorated)?;
    while runs.len() > 1 {
        evaluator.ensure_not_cancelled()?;
        let mut merged = Vec::with_capacity(runs.len().div_ceil(2));
        let mut current = runs.into_iter();
        while let Some(left) = current.next() {
            if let Some(right) = current.next() {
                merged.push(merge_keyed_runs(evaluator, left, right)?);
            } else {
                merged.push(left);
            }
        }
        runs = merged;
    }
    Ok(ForceOutcome::Alias(list_from_values(
        runs.pop()
            .unwrap_or_default()
            .into_iter()
            .map(|(_, value)| value)
            .collect(),
    )))
}

fn natural_keyed_runs(
    evaluator: &mut Evaluator,
    items: Vec<(ThunkRef, ThunkRef)>,
) -> RuntimeResult<Vec<Vec<(ThunkRef, ThunkRef)>>> {
    let mut remaining = items.into_iter().peekable();
    let mut runs = Vec::new();
    while let Some(first) = remaining.next() {
        let Some(second) = remaining.next() else {
            runs.push(vec![first]);
            break;
        };
        let descending = keyed_greater_than(evaluator, &first.0, &second.0)?;
        let mut run = vec![first];
        let mut current = second;
        while let Some(next) = remaining.peek() {
            let next_descending = keyed_greater_than(evaluator, &current.0, &next.0)?;
            if next_descending != descending {
                break;
            }
            run.push(current);
            current = remaining.next().expect("peeked keyed sort item exists");
        }
        run.push(current);
        if descending {
            run.reverse();
        }
        runs.push(run);
    }
    Ok(runs)
}

fn keyed_greater_than(
    evaluator: &mut Evaluator,
    left: &ThunkRef,
    right: &ThunkRef,
) -> RuntimeResult<bool> {
    Ok(!evaluator.equal_values(left, right)? && !evaluator.less_values(left, right)?)
}

fn merge_keyed_runs(
    evaluator: &mut Evaluator,
    left: Vec<(ThunkRef, ThunkRef)>,
    right: Vec<(ThunkRef, ThunkRef)>,
) -> RuntimeResult<Vec<(ThunkRef, ThunkRef)>> {
    let mut output = Vec::with_capacity(left.len().saturating_add(right.len()));
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    while let (Some((left_key, _)), Some((right_key, _))) = (left.peek(), right.peek()) {
        evaluator.ensure_not_cancelled()?;
        if keyed_greater_than(evaluator, left_key, right_key)? {
            output.push(right.next().expect("peeked right keyed item exists"));
        } else {
            output.push(left.next().expect("peeked left keyed item exists"));
        }
    }
    output.extend(left);
    output.extend(right);
    Ok(output)
}

fn list_to_maybe(evaluator: &mut Evaluator, list: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    match evaluator.force(list)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None)))),
        Value::List(ListCell::Cons { head, .. }) => Ok(ForceOutcome::Value(Arc::new(
            Value::Maybe(Some(Arc::clone(head))),
        ))),
        _ => Err(RuntimeError::internal(
            "Maybe.listToMaybe received a non-list",
        )),
    }
}

fn map_maybe_list(function: &ThunkRef, list: &ThunkRef) -> ThunkRef {
    let function = Arc::clone(function);
    let list = Arc::clone(list);
    Thunk::deferred(move |evaluator| match evaluator.force(&list)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            #[cfg(feature = "compat-tracing")]
            let application = evaluator.callback_application(
                Arc::clone(&function),
                std::slice::from_ref(head),
                0,
                "element",
            )?;
            #[cfg(not(feature = "compat-tracing"))]
            let application = Thunk::suspended(Suspension::Apply {
                function: Arc::clone(&function),
                argument: Arc::clone(head),
            });
            let mapped = evaluator.force(&application)?;
            let rest = map_maybe_list(&function, tail);
            match mapped.as_ref() {
                Value::Maybe(None) => evaluator.force(&rest),
                Value::Maybe(Some(value)) => Ok(Arc::new(Value::List(ListCell::Cons {
                    head: Arc::clone(value),
                    tail: rest,
                }))),
                _ => Err(RuntimeError::internal(
                    "Maybe.mapMaybe callback returned a non-Maybe value",
                )),
            }
        }
        _ => Err(RuntimeError::internal(
            "Maybe.mapMaybe received a malformed list",
        )),
    })
}

fn unfold_tree(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    seed: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    #[cfg(feature = "compat-tracing")]
    let callback_parent = evaluator.active_adapter_identity_optional()?;
    unfold_tree_with_parent(
        evaluator,
        function,
        seed,
        #[cfg(feature = "compat-tracing")]
        callback_parent,
    )
}

fn unfold_tree_with_parent(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    seed: &ThunkRef,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> RuntimeResult<ForceOutcome> {
    #[cfg(feature = "compat-tracing")]
    let function_application = Evaluator::callback_application_for_optional_parent(
        callback_parent,
        Arc::clone(function),
        &[Arc::clone(seed)],
        0,
        "seed",
    );
    #[cfg(not(feature = "compat-tracing"))]
    let function_application = Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(seed),
    });
    let pair = evaluator.force(&function_application)?;
    let Value::Tuple(elements) = pair.as_ref() else {
        return Err(RuntimeError::internal(
            "Tree.unfoldTree callback returned a non-pair",
        ));
    };
    let [root, seeds] = elements.as_ref() else {
        return Err(RuntimeError::internal(
            "Tree.unfoldTree callback returned a non-pair",
        ));
    };
    let children = evaluator
        .force_list_elements(seeds)?
        .into_iter()
        .map(|seed| {
            let function = Arc::clone(function);
            Thunk::deferred(move |evaluator| {
                let outcome = unfold_tree_with_parent(
                    evaluator,
                    &function,
                    &seed,
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                )?;
                outcome_value(evaluator, outcome)
            })
        })
        .collect();
    Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
        root: Arc::clone(root),
        children: list_from_values(children),
    }))))
}

fn option_text_modifier(
    evaluator: &mut Evaluator,
    implementation: &str,
    argument: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let text = evaluator.force_text(argument)?;
    let modifier = match implementation {
        "options_long" => OptionModifier::Long(text),
        "options_help" => OptionModifier::Help(text),
        "options_metavar" => OptionModifier::Metavar(text),
        _ => unreachable!("Options text modifier implementation matched"),
    };
    Ok(ForceOutcome::Value(Arc::new(Value::OptionsMod(
        OptionModifiers(Arc::from([modifier])),
    ))))
}

fn option_leaf_parser(
    evaluator: &mut Evaluator,
    implementation: &str,
    modifiers: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let modifiers = evaluator.force(modifiers)?;
    let Value::OptionsMod(modifiers) = modifiers.as_ref() else {
        return Err(RuntimeError::internal(
            "Options leaf parser received non-modifier metadata",
        ));
    };
    validate_option_modifiers(
        modifiers,
        !matches!(implementation, "options_str_argument"),
        implementation,
    )?;
    let parser = match implementation {
        "options_switch" => OptionParser::Switch(modifiers.clone()),
        "options_str_option" => OptionParser::StringOption(modifiers.clone()),
        "options_str_argument" => OptionParser::StringArgument(modifiers.clone()),
        _ => unreachable!("Options leaf parser implementation matched"),
    };
    Ok(ForceOutcome::Value(Arc::new(Value::OptionsParser(
        Arc::new(parser),
    ))))
}

fn option_flag(
    evaluator: &mut Evaluator,
    inactive: Option<&ThunkRef>,
    active: &ThunkRef,
    modifiers: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let modifiers = evaluator.force(modifiers)?;
    let Value::OptionsMod(modifiers) = modifiers.as_ref() else {
        return Err(RuntimeError::internal(
            "Options.flag received non-modifier metadata",
        ));
    };
    validate_option_modifiers(modifiers, true, "Options.flag")?;
    Ok(ForceOutcome::Value(Arc::new(Value::OptionsParser(
        Arc::new(OptionParser::Flag {
            inactive: inactive.cloned(),
            active: Arc::clone(active),
            modifiers: modifiers.clone(),
        }),
    ))))
}

fn option_info_text(
    evaluator: &mut Evaluator,
    implementation: &str,
    argument: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let text = evaluator.force_text(argument)?;
    let mut modifiers = InfoModifiers::default();
    if implementation == "options_prog_desc" {
        modifiers.program_description = Some(text);
    } else {
        modifiers.header = Some(text);
    }
    Ok(ForceOutcome::Value(Arc::new(Value::OptionsInfoMod(
        modifiers,
    ))))
}

fn option_info(
    evaluator: &mut Evaluator,
    parser: &ThunkRef,
    modifiers: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let parser = evaluator.force(parser)?;
    let Value::OptionsParser(parser) = parser.as_ref() else {
        return Err(RuntimeError::internal(
            "Options.info received a non-parser value",
        ));
    };
    let modifiers = evaluator.force(modifiers)?;
    let Value::OptionsInfoMod(modifiers) = modifiers.as_ref() else {
        return Err(RuntimeError::internal(
            "Options.info received non-info modifiers",
        ));
    };
    Ok(ForceOutcome::Value(Arc::new(Value::OptionsParserInfo(
        ParserInfo {
            parser: Arc::clone(parser),
            modifiers: modifiers.clone(),
        },
    ))))
}

fn option_command(
    evaluator: &mut Evaluator,
    name: &ThunkRef,
    info: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let name = evaluator.force_text(name)?;
    let info = evaluator.force(info)?;
    let Value::OptionsParserInfo(info) = info.as_ref() else {
        return Err(RuntimeError::internal(
            "Options.command received non-parser info",
        ));
    };
    Ok(ForceOutcome::Value(Arc::new(Value::OptionsMod(
        OptionModifiers(Arc::from([OptionModifier::Command {
            name,
            parser: info.clone(),
        }])),
    ))))
}

fn option_subparser(
    evaluator: &mut Evaluator,
    modifiers: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let modifiers = evaluator.force(modifiers)?;
    let Value::OptionsMod(modifiers) = modifiers.as_ref() else {
        return Err(RuntimeError::internal(
            "Options.hsubparser received non-command modifiers",
        ));
    };
    validate_command_modifiers(modifiers)?;
    Ok(ForceOutcome::Value(Arc::new(Value::OptionsParser(
        Arc::new(OptionParser::Commands(modifiers.clone())),
    ))))
}

fn option_exec(evaluator: &mut Evaluator, info: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let info = evaluator.force(info)?;
    let Value::OptionsParserInfo(info) = info.as_ref() else {
        return Err(RuntimeError::internal(
            "Options.execParser received non-parser info",
        ));
    };
    let info = info.clone();
    Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
        move |evaluator, context| {
            let mut state = match tokenize_options(&info, &context.args)? {
                TokenizedOptions::State(state) => state,
                TokenizedOptions::Help {
                    info: help_info,
                    inherited_helper,
                } => {
                    let help = render_option_help(&help_info, inherited_helper)?;
                    context.write(help.as_bytes())?;
                    return Err(RuntimeError::exit(0));
                }
            };
            let value = match evaluate_option(evaluator, &info.parser, &mut state)? {
                OptionEvaluation::Success { value, .. } => value,
                OptionEvaluation::Missing { expected, .. } => {
                    return Err(RuntimeError::user(option_usage_error(
                        &info,
                        &format!("missing {expected}"),
                    )));
                }
            };
            ensure_no_option_leftovers(&info, &state)?;
            Ok(value)
        },
    )))))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PlannedOptionKind {
    Flag,
    Value,
}

#[derive(Default)]
struct ParserPlan {
    options: BTreeMap<Arc<str>, PlannedOptionKind>,
    commands: BTreeMap<Arc<str>, ParserInfo>,
    command_order: Vec<Arc<str>>,
    helper: bool,
}

enum TokenizedOptions {
    State(OptionParseState),
    Help {
        info: ParserInfo,
        inherited_helper: bool,
    },
}

struct OptionParseState {
    options: BTreeMap<Arc<str>, VecDeque<OptionOccurrence>>,
    positionals: VecDeque<OsString>,
    selected_command: Option<SelectedCommand>,
}

struct OptionOccurrence {
    position: usize,
    value: OptionOccurrenceValue,
}

enum OptionOccurrenceValue {
    Flag,
    Value(OsString),
}

struct SelectedCommand {
    info: ParserInfo,
    state: Box<OptionParseState>,
}

enum OptionEvaluation {
    Success { value: ThunkRef, consumed: usize },
    Missing { expected: Arc<str>, consumed: usize },
}

fn validate_option_modifiers(
    modifiers: &OptionModifiers,
    requires_long: bool,
    implementation: &str,
) -> RuntimeResult<()> {
    let mut long_count = 0usize;
    let mut metavar_count = 0usize;
    let mut default_count = 0usize;
    for modifier in modifiers.0.iter() {
        match modifier {
            OptionModifier::Long(long) => {
                long_count += 1;
                if long.is_empty()
                    || long.starts_with('-')
                    || long.contains('=')
                    || long.chars().any(char::is_whitespace)
                {
                    return Err(RuntimeError::user(format!(
                        "{implementation} has an invalid long option name `{long}`"
                    )));
                }
            }
            OptionModifier::Help(_) => {}
            OptionModifier::Metavar(_) => metavar_count += 1,
            OptionModifier::Default(_) => default_count += 1,
            OptionModifier::Command { .. } => {
                return Err(RuntimeError::user(format!(
                    "{implementation} cannot use a command modifier"
                )));
            }
        }
    }
    if requires_long && long_count == 0 {
        return Err(RuntimeError::user(format!(
            "{implementation} requires exactly one long modifier"
        )));
    }
    if !requires_long && long_count != 0 {
        return Err(RuntimeError::user(format!(
            "{implementation} cannot use a long modifier"
        )));
    }
    let accepts_value_metadata = matches!(
        implementation,
        "options_str_option" | "options_str_argument"
    );
    if !accepts_value_metadata && (metavar_count != 0 || default_count != 0) {
        return Err(RuntimeError::user(format!(
            "{implementation} cannot use metavar or default modifiers"
        )));
    }
    Ok(())
}

fn validate_command_modifiers(modifiers: &OptionModifiers) -> RuntimeResult<()> {
    let mut names = BTreeSet::new();
    for modifier in modifiers.0.iter() {
        let OptionModifier::Command { name, .. } = modifier else {
            return Err(RuntimeError::user(
                "Options.hsubparser accepts only command modifiers",
            ));
        };
        if name.is_empty() || name.chars().any(char::is_whitespace) {
            return Err(RuntimeError::user(format!(
                "Options.command has an invalid command name `{name}`"
            )));
        }
        if !names.insert(Arc::clone(name)) {
            return Err(RuntimeError::user(format!(
                "Options.hsubparser has duplicate command `{name}`"
            )));
        }
    }
    Ok(())
}

fn compile_option_plan(parser: &OptionParser, plan: &mut ParserPlan) -> RuntimeResult<()> {
    match parser {
        OptionParser::Pure(_) | OptionParser::StringArgument(_) => {}
        OptionParser::Helper => plan.helper = true,
        OptionParser::Map { parser, .. }
        | OptionParser::Optional(parser)
        | OptionParser::Many(parser) => compile_option_plan(parser, plan)?,
        OptionParser::Apply {
            function,
            argument,
            flipped,
            ..
        } => {
            if *flipped {
                compile_option_plan(argument, plan)?;
                compile_option_plan(function, plan)?;
            } else {
                compile_option_plan(function, plan)?;
                compile_option_plan(argument, plan)?;
            }
        }
        OptionParser::Switch(modifiers) | OptionParser::Flag { modifiers, .. } => {
            plan_option(modifiers, PlannedOptionKind::Flag, plan)?;
        }
        OptionParser::StringOption(modifiers) => {
            plan_option(modifiers, PlannedOptionKind::Value, plan)?;
        }
        OptionParser::Commands(modifiers) => {
            for modifier in modifiers.0.iter() {
                let OptionModifier::Command { name, parser } = modifier else {
                    return Err(RuntimeError::user(
                        "Options.hsubparser accepts only command modifiers",
                    ));
                };
                if plan
                    .commands
                    .insert(Arc::clone(name), parser.clone())
                    .is_some()
                {
                    return Err(RuntimeError::user(format!(
                        "ambiguous command `{name}` is declared more than once"
                    )));
                }
                plan.command_order.push(Arc::clone(name));
            }
        }
    }
    Ok(())
}

fn plan_option(
    modifiers: &OptionModifiers,
    kind: PlannedOptionKind,
    plan: &mut ParserPlan,
) -> RuntimeResult<()> {
    let mut aliases = BTreeSet::new();
    for long in modifier_longs(modifiers) {
        let long: Arc<str> = long.into();
        if !aliases.insert(Arc::clone(&long)) {
            continue;
        }
        if plan.options.insert(Arc::clone(&long), kind).is_some() {
            return Err(RuntimeError::user(format!(
                "ambiguous option `--{long}` is declared more than once"
            )));
        }
    }
    Ok(())
}

fn tokenize_options(info: &ParserInfo, arguments: &[OsString]) -> RuntimeResult<TokenizedOptions> {
    let mut plan = ParserPlan::default();
    compile_option_plan(&info.parser, &mut plan)?;
    tokenize_with_plan(info, &plan, arguments)
}

#[allow(clippy::too_many_lines)]
fn tokenize_with_plan(
    info: &ParserInfo,
    plan: &ParserPlan,
    arguments: &[OsString],
) -> RuntimeResult<TokenizedOptions> {
    let mut state = OptionParseState {
        options: BTreeMap::new(),
        positionals: VecDeque::new(),
        selected_command: None,
    };
    let mut option_mode = true;
    let mut index = 0usize;
    while let Some(token) = arguments.get(index) {
        if option_mode
            && token == "--"
            && !crate::semantic_mutant_active("options-parser-argument-binding")
        {
            option_mode = false;
            index += 1;
            continue;
        }
        if option_mode && plan.helper && matches!(token.to_str(), Some("--help" | "-h")) {
            return Ok(TokenizedOptions::Help {
                info: info.clone(),
                inherited_helper: plan.helper,
            });
        }
        if option_mode
            && let Some(long_token) = token.to_str().and_then(|token| token.strip_prefix("--"))
        {
            let (name, attached) = long_token
                .split_once('=')
                .map_or((long_token, None), |(name, value)| (name, Some(value)));
            let Some(kind) = plan.options.get(name) else {
                return Err(RuntimeError::user(option_usage_error(
                    info,
                    &format!("unknown option `--{name}`"),
                )));
            };
            let token_position = index;
            let value = match kind {
                PlannedOptionKind::Flag => {
                    if attached.is_some() {
                        return Err(RuntimeError::user(option_usage_error(
                            info,
                            &format!("flag `--{name}` does not take an argument"),
                        )));
                    }
                    OptionOccurrenceValue::Flag
                }
                PlannedOptionKind::Value => {
                    if let Some(value) = attached {
                        OptionOccurrenceValue::Value(OsString::from(value))
                    } else {
                        index += 1;
                        let Some(value) = arguments.get(index) else {
                            return Err(RuntimeError::user(option_usage_error(
                                info,
                                &format!("option `--{name}` requires an argument"),
                            )));
                        };
                        OptionOccurrenceValue::Value(value.clone())
                    }
                }
            };
            state
                .options
                .entry(Arc::<str>::from(name))
                .or_default()
                .push_back(OptionOccurrence {
                    position: token_position,
                    value,
                });
            index += 1;
            continue;
        }
        if option_mode
            && token
                .to_str()
                .is_some_and(|token| token.starts_with('-') && token != "-")
        {
            return Err(RuntimeError::user(option_usage_error(
                info,
                &format!("unknown option `{}`", token.to_string_lossy()),
            )));
        }
        if !plan.commands.is_empty() && state.selected_command.is_none() {
            let Some(command_name) = token.to_str() else {
                return Err(RuntimeError::user(option_usage_error(
                    info,
                    "command name is not valid Unicode",
                )));
            };
            let Some(command_info) = plan.commands.get(command_name) else {
                return Err(RuntimeError::user(option_usage_error(
                    info,
                    &format!("invalid command `{command_name}`"),
                )));
            };
            let mut command_plan = ParserPlan::default();
            compile_option_plan(&command_info.parser, &mut command_plan)?;
            command_plan.helper |= plan.helper;
            match tokenize_with_plan(command_info, &command_plan, &arguments[index + 1..])? {
                TokenizedOptions::State(command_state) => {
                    state.selected_command = Some(SelectedCommand {
                        info: command_info.clone(),
                        state: Box::new(command_state),
                    });
                    return Ok(TokenizedOptions::State(state));
                }
                TokenizedOptions::Help {
                    info: help_info,
                    inherited_helper,
                } => {
                    return Ok(TokenizedOptions::Help {
                        info: help_info,
                        inherited_helper,
                    });
                }
            }
        }
        state.positionals.push_back(token.clone());
        index += 1;
    }
    Ok(TokenizedOptions::State(state))
}

#[allow(clippy::only_used_in_recursion, clippy::too_many_lines)]
fn evaluate_option(
    evaluator: &mut Evaluator,
    parser: &OptionParser,
    state: &mut OptionParseState,
) -> RuntimeResult<OptionEvaluation> {
    match parser {
        OptionParser::Pure(value) => Ok(option_success(Arc::clone(value), 0)),
        OptionParser::Helper => {
            let identity = hell_builtins::lookup("Function.id")
                .ok_or_else(|| RuntimeError::internal("Function.id is missing from registry"))?;
            Ok(option_success(
                Thunk::evaluated(Value::Function(FunctionValue::Native {
                    builtin: identity.id,
                    arguments: Arc::from([]),
                    evidence: None,
                })),
                0,
            ))
        }
        OptionParser::Map {
            function,
            parser,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        } => {
            let result = evaluate_option(evaluator, parser, state)?;
            let OptionEvaluation::Success { value, consumed } = result else {
                return Ok(result);
            };
            #[cfg(feature = "compat-tracing")]
            let mapped = Evaluator::callback_application_for_optional_parent(
                *callback_parent,
                Arc::clone(function),
                &[value],
                0,
                "parser-result",
            );
            #[cfg(not(feature = "compat-tracing"))]
            let mapped = Thunk::suspended(Suspension::Apply {
                function: Arc::clone(function),
                argument: value,
            });
            Ok(option_success(mapped, consumed))
        }
        OptionParser::Apply {
            function,
            argument,
            flipped,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
            #[cfg(feature = "compat-tracing")]
            callback_argument,
        } => evaluate_option_application(
            evaluator,
            function,
            argument,
            state,
            *flipped,
            #[cfg(feature = "compat-tracing")]
            *callback_parent,
            #[cfg(feature = "compat-tracing")]
            *callback_argument,
        ),
        OptionParser::Optional(parser) => match evaluate_option(evaluator, parser, state)? {
            OptionEvaluation::Success { value, consumed } => Ok(option_success(
                Thunk::evaluated(Value::Maybe(Some(value))),
                consumed,
            )),
            OptionEvaluation::Missing { consumed: 0, .. } => {
                Ok(option_success(Thunk::evaluated(Value::Maybe(None)), 0))
            }
            missing @ OptionEvaluation::Missing { .. } => Ok(missing),
        },
        OptionParser::Many(parser) => {
            let mut values = Vec::new();
            let mut consumed = 0usize;
            loop {
                match evaluate_option(evaluator, parser, state)? {
                    OptionEvaluation::Success {
                        value,
                        consumed: item_consumed,
                    } => {
                        if item_consumed == 0 {
                            return Err(RuntimeError::user(
                                "Alternative.many parser accepted empty input",
                            ));
                        }
                        consumed = consumed.saturating_add(item_consumed);
                        values.push(value);
                    }
                    OptionEvaluation::Missing { consumed: 0, .. } => break,
                    OptionEvaluation::Missing {
                        expected,
                        consumed: item_consumed,
                    } => {
                        return Ok(OptionEvaluation::Missing {
                            expected,
                            consumed: consumed.saturating_add(item_consumed),
                        });
                    }
                }
            }
            Ok(option_success(list_from_values(values), consumed))
        }
        OptionParser::Switch(modifiers) => {
            let _ = required_long(modifiers)?;
            let found = take_option_occurrence(state, modifiers).is_some();
            Ok(option_success(
                Thunk::evaluated(Value::Bool(found)),
                usize::from(found),
            ))
        }
        OptionParser::Flag {
            inactive,
            active,
            modifiers,
        } => {
            let long = required_long(modifiers)?;
            if take_option_occurrence(state, modifiers).is_some() {
                Ok(option_success(Arc::clone(active), 1))
            } else if let Some(inactive) = inactive {
                Ok(option_success(Arc::clone(inactive), 0))
            } else {
                Ok(option_missing(format!("option `--{long}`"), 0))
            }
        }
        OptionParser::StringOption(modifiers) => {
            let long = required_long(modifiers)?;
            match take_option_occurrence(state, modifiers).map(|occurrence| occurrence.value) {
                Some(OptionOccurrenceValue::Value(value)) => Ok(option_success(
                    Thunk::evaluated(Value::Text(host_text(value)?)),
                    1,
                )),
                Some(OptionOccurrenceValue::Flag) => Err(RuntimeError::internal(
                    "value option was tokenized as a flag",
                )),
                None => match modifier_default(modifiers) {
                    Some(default) => Ok(option_success(default, 0)),
                    None => Ok(option_missing(format!("option `--{long}`"), 0)),
                },
            }
        }
        OptionParser::StringArgument(modifiers) => {
            if let Some(value) = state.positionals.pop_front() {
                return Ok(option_success(
                    Thunk::evaluated(Value::Text(host_text(value)?)),
                    1,
                ));
            }
            match modifier_default(modifiers) {
                Some(default) => Ok(option_success(default, 0)),
                None => Ok(option_missing(argument_metavar(modifiers), 0)),
            }
        }
        OptionParser::Commands(_) => {
            let Some(mut selected) = state.selected_command.take() else {
                return Ok(option_missing("command", 0));
            };
            let result = evaluate_option(evaluator, &selected.info.parser, &mut selected.state)?;
            match result {
                OptionEvaluation::Success { value, consumed } => {
                    ensure_no_option_leftovers(&selected.info, &selected.state)?;
                    Ok(option_success(value, consumed.saturating_add(1)))
                }
                OptionEvaluation::Missing { expected, .. } => Err(RuntimeError::user(
                    option_usage_error(&selected.info, &format!("missing {expected}")),
                )),
            }
        }
    }
}

fn evaluate_option_application(
    evaluator: &mut Evaluator,
    function_parser: &OptionParser,
    argument_parser: &OptionParser,
    state: &mut OptionParseState,
    flipped: bool,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")] callback_argument: u16,
) -> RuntimeResult<OptionEvaluation> {
    let (function, function_consumed, argument, argument_consumed) = if flipped {
        let argument_result = evaluate_option(evaluator, argument_parser, state)?;
        let OptionEvaluation::Success {
            value: argument,
            consumed: argument_consumed,
        } = argument_result
        else {
            return Ok(argument_result);
        };
        let function_result = evaluate_option(evaluator, function_parser, state)?;
        let OptionEvaluation::Success {
            value: function,
            consumed: function_consumed,
        } = function_result
        else {
            let OptionEvaluation::Missing { expected, consumed } = function_result else {
                unreachable!("option evaluation has two variants")
            };
            return Ok(OptionEvaluation::Missing {
                expected,
                consumed: argument_consumed.saturating_add(consumed),
            });
        };
        (function, function_consumed, argument, argument_consumed)
    } else {
        let function_result = evaluate_option(evaluator, function_parser, state)?;
        let OptionEvaluation::Success {
            value: function,
            consumed: function_consumed,
        } = function_result
        else {
            return Ok(function_result);
        };
        let argument_result = evaluate_option(evaluator, argument_parser, state)?;
        let OptionEvaluation::Success {
            value: argument,
            consumed: argument_consumed,
        } = argument_result
        else {
            let OptionEvaluation::Missing { expected, consumed } = argument_result else {
                unreachable!("option evaluation has two variants")
            };
            return Ok(OptionEvaluation::Missing {
                expected,
                consumed: function_consumed.saturating_add(consumed),
            });
        };
        (function, function_consumed, argument, argument_consumed)
    };
    #[cfg(feature = "compat-tracing")]
    let applied = Evaluator::callback_application_for_optional_parent(
        callback_parent,
        function,
        &[argument],
        callback_argument,
        "application",
    );
    #[cfg(not(feature = "compat-tracing"))]
    let applied = Thunk::suspended(Suspension::Apply { function, argument });
    Ok(option_success(
        applied,
        function_consumed.saturating_add(argument_consumed),
    ))
}

fn host_text(value: OsString) -> RuntimeResult<Arc<str>> {
    value
        .into_string()
        .map(Arc::<str>::from)
        .map_err(|_| RuntimeError::user("option argument is not valid Unicode"))
}

fn option_success(value: ThunkRef, consumed: usize) -> OptionEvaluation {
    OptionEvaluation::Success { value, consumed }
}

fn option_missing(expected: impl Into<Arc<str>>, consumed: usize) -> OptionEvaluation {
    OptionEvaluation::Missing {
        expected: expected.into(),
        consumed,
    }
}

fn required_long(modifiers: &OptionModifiers) -> RuntimeResult<&str> {
    modifier_long(modifiers)
        .ok_or_else(|| RuntimeError::user("option is missing its long modifier"))
}

fn take_option_occurrence(
    state: &mut OptionParseState,
    modifiers: &OptionModifiers,
) -> Option<OptionOccurrence> {
    let long = modifier_longs(modifiers)
        .filter_map(|long| {
            state
                .options
                .get(long)
                .and_then(VecDeque::front)
                .map(|occurrence| (occurrence.position, long))
        })
        .min_by_key(|(position, _)| *position)
        .map(|(_, long)| long)?;
    state.options.get_mut(long).and_then(VecDeque::pop_front)
}

fn argument_metavar(modifiers: &OptionModifiers) -> Arc<str> {
    modifiers
        .0
        .iter()
        .rev()
        .find_map(|modifier| match modifier {
            OptionModifier::Metavar(value) => Some(Arc::clone(value)),
            _ => None,
        })
        .unwrap_or_else(|| Arc::from("argument"))
}

fn ensure_no_option_leftovers(info: &ParserInfo, state: &OptionParseState) -> RuntimeResult<()> {
    if let Some((long, _)) = state
        .options
        .iter()
        .find(|(_, occurrences)| !occurrences.is_empty())
    {
        return Err(RuntimeError::user(option_usage_error(
            info,
            &format!("unexpected repeated option `--{long}`"),
        )));
    }
    if let Some(unexpected) = state.positionals.front() {
        return Err(RuntimeError::user(option_usage_error(
            info,
            &format!("unexpected argument `{}`", unexpected.to_string_lossy()),
        )));
    }
    if state.selected_command.is_some() {
        return Err(RuntimeError::user(option_usage_error(
            info,
            "unexpected command",
        )));
    }
    Ok(())
}

fn modifier_long(modifiers: &OptionModifiers) -> Option<&str> {
    modifier_longs(modifiers).next()
}

fn modifier_longs(modifiers: &OptionModifiers) -> impl Iterator<Item = &str> {
    modifiers.0.iter().filter_map(|modifier| match modifier {
        OptionModifier::Long(value) => Some(value.as_ref()),
        _ => None,
    })
}

fn modifier_default(modifiers: &OptionModifiers) -> Option<ThunkRef> {
    modifiers
        .0
        .iter()
        .rev()
        .find_map(|modifier| match modifier {
            OptionModifier::Default(value) => Some(Arc::clone(value)),
            _ => None,
        })
}

fn option_usage_error(info: &ParserInfo, message: &str) -> String {
    let mut output = message.to_owned();
    if let Some(header) = &info.modifiers.header {
        output.push_str("\n\n");
        output.push_str(header);
    }
    if let Some(description) = &info.modifiers.program_description {
        output.push_str("\n\n");
        output.push_str(description);
    }
    if info.modifiers.full_description {
        output.push_str("\n\nUse --help for usage details.");
    }
    if let Some(help) = parser_help(&info.parser) {
        output.push_str("\n\n");
        output.push_str(help);
    }
    output
}

fn render_option_help(info: &ParserInfo, inherited_helper: bool) -> RuntimeResult<String> {
    let mut plan = ParserPlan::default();
    compile_option_plan(&info.parser, &mut plan)?;
    plan.helper |= inherited_helper;
    let mut output = String::new();
    if let Some(header) = &info.modifiers.header {
        output.push_str(header);
        output.push_str("\n\n");
    }
    output.push_str("Usage:");
    if !plan.options.is_empty() || plan.helper {
        output.push_str(" [OPTIONS]");
    }
    if !plan.commands.is_empty() {
        output.push_str(" COMMAND");
    }
    if parser_has_positional(&info.parser) {
        output.push_str(" ARGUMENTS");
    }
    output.push('\n');
    if let Some(description) = &info.modifiers.program_description {
        output.push('\n');
        output.push_str(description);
        output.push('\n');
    }
    let mut entries = Vec::new();
    collect_option_help(&info.parser, &mut entries);
    if plan.helper {
        entries.push((
            "-h, --help".to_owned(),
            Some(Arc::from("Show this help text")),
        ));
    }
    if !entries.is_empty() {
        output.push_str("\nAvailable options:\n");
        for (syntax, help) in entries {
            output.push_str("  ");
            output.push_str(&syntax);
            if let Some(help) = help {
                output.push_str("  ");
                output.push_str(&help);
            }
            output.push('\n');
        }
    }
    if !plan.commands.is_empty() {
        output.push_str("\nAvailable commands:\n");
        for name in &plan.command_order {
            let command = plan
                .commands
                .get(name)
                .expect("planned command order references a command");
            output.push_str("  ");
            output.push_str(name);
            if let Some(description) = &command.modifiers.program_description {
                output.push_str("  ");
                output.push_str(description);
            }
            output.push('\n');
        }
    }
    Ok(output)
}

fn parser_has_positional(parser: &OptionParser) -> bool {
    match parser {
        OptionParser::StringArgument(_) => true,
        OptionParser::Map { parser, .. }
        | OptionParser::Optional(parser)
        | OptionParser::Many(parser) => parser_has_positional(parser),
        OptionParser::Apply {
            function, argument, ..
        } => parser_has_positional(function) || parser_has_positional(argument),
        _ => false,
    }
}

fn collect_option_help(parser: &OptionParser, entries: &mut Vec<(String, Option<Arc<str>>)>) {
    match parser {
        OptionParser::Map { parser, .. }
        | OptionParser::Optional(parser)
        | OptionParser::Many(parser) => collect_option_help(parser, entries),
        OptionParser::Apply {
            function,
            argument,
            flipped,
            ..
        } => {
            if *flipped {
                collect_option_help(argument, entries);
                collect_option_help(function, entries);
            } else {
                collect_option_help(function, entries);
                collect_option_help(argument, entries);
            }
        }
        OptionParser::Switch(modifiers) | OptionParser::Flag { modifiers, .. } => {
            if let Some(syntax) = option_long_syntax(modifiers) {
                entries.push((syntax, modifier_help(modifiers)));
            }
        }
        OptionParser::StringOption(modifiers) => {
            if let Some(mut syntax) = option_long_syntax(modifiers) {
                let metavar = argument_metavar(modifiers);
                syntax.push(' ');
                syntax.push_str(&metavar);
                entries.push((syntax, modifier_help(modifiers)));
            }
        }
        OptionParser::StringArgument(modifiers) => {
            entries.push((
                argument_metavar(modifiers).to_string(),
                modifier_help(modifiers),
            ));
        }
        OptionParser::Pure(_) | OptionParser::Helper | OptionParser::Commands(_) => {}
    }
}

fn option_long_syntax(modifiers: &OptionModifiers) -> Option<String> {
    let aliases = modifier_longs(modifiers)
        .map(|long| format!("--{long}"))
        .collect::<Vec<_>>();
    (!aliases.is_empty()).then(|| aliases.join("|"))
}

fn modifier_help(modifiers: &OptionModifiers) -> Option<Arc<str>> {
    modifiers
        .0
        .iter()
        .rev()
        .find_map(|modifier| match modifier {
            OptionModifier::Help(help) => Some(Arc::clone(help)),
            _ => None,
        })
}

fn parser_help(parser: &OptionParser) -> Option<&str> {
    match parser {
        OptionParser::Map { parser, .. }
        | OptionParser::Optional(parser)
        | OptionParser::Many(parser) => parser_help(parser),
        OptionParser::Apply {
            function, argument, ..
        } => parser_help(function).or_else(|| parser_help(argument)),
        OptionParser::Switch(modifiers)
        | OptionParser::Flag { modifiers, .. }
        | OptionParser::StringOption(modifiers)
        | OptionParser::StringArgument(modifiers)
        | OptionParser::Commands(modifiers) => {
            modifiers
                .0
                .iter()
                .rev()
                .find_map(|modifier| match modifier {
                    OptionModifier::Help(help) => Some(help.as_ref()),
                    _ => None,
                })
        }
        OptionParser::Pure(_) | OptionParser::Helper => None,
    }
}
