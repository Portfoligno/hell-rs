//! Runtime representations shared by manifest-driven class adapters.

use std::sync::Arc;

use hell_core::ClassEvidence;
use hell_types::TypeNode;

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
    },
    Apply {
        function: Arc<Self>,
        argument: Arc<Self>,
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
            let (callback, list) = if implementation.starts_with("monad_map") {
                (&arguments[0], &arguments[1])
            } else {
                (&arguments[1], &arguments[0])
            };
            traverse_value(
                evaluator,
                target.as_deref(),
                list,
                Some(callback),
                implementation.ends_with("discard"),
            )
        }
        "monad_sequence" => {
            traverse_value(evaluator, target.as_deref(), &arguments[0], None, false)
        }
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

fn instance_target(evaluator: &Evaluator, evidence: ClassEvidence) -> RuntimeResult<Arc<str>> {
    let mut current = evidence.head.raw();
    while let TypeNode::Apply(function, _) = evaluator.program.types().get(current) {
        current = *function;
    }
    match evaluator.program.types().get(current) {
        TypeNode::Constructor { name, .. } => Ok(Arc::clone(name)),
        _ => Err(RuntimeError::internal(
            "class evidence does not have a constructor head",
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
    match target {
        Some("[]") => Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::ListMap {
            function: Arc::clone(function),
            list: Arc::clone(container),
        }))),
        Some("IO") => {
            let action = Arc::clone(container);
            let function = Arc::clone(function);
            Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
                move |evaluator, context| {
                    let action = evaluator.force_io(&action)?;
                    let value = action.run(evaluator, context)?;
                    Ok(Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&function),
                        argument: value,
                    }))
                },
            )))))
        }
        Some("Options.Parser") => {
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
                }),
            ))))
        }
        Some("Tree") => map_tree(evaluator, function, container),
        Some("Maybe") => match evaluator.force(container)?.as_ref() {
            Value::Maybe(None) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None)))),
            Value::Maybe(Some(value)) => Ok(ForceOutcome::Value(Arc::new(Value::Maybe(Some(
                Thunk::suspended(Suspension::Apply {
                    function: Arc::clone(function),
                    argument: Arc::clone(value),
                }),
            ))))),
            _ => Err(RuntimeError::internal("Functor Maybe value mismatch")),
        },
        Some("Either") => match evaluator.force(container)?.as_ref() {
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
                Ok(ForceOutcome::Value(Arc::new(Value::PrimitiveVariant(
                    PrimitiveVariantValue {
                        family: PrimitiveFamily::Either,
                        constructor_index: 1,
                        payloads: Arc::from([Thunk::suspended(Suspension::Apply {
                            function: Arc::clone(function),
                            argument: Arc::clone(payload),
                        })]),
                    },
                ))))
            }
            _ => Err(RuntimeError::internal("Functor Either value mismatch")),
        },
        Some("(,)") => match evaluator.force(container)?.as_ref() {
            Value::Tuple(elements) if elements.len() == 2 => {
                Ok(ForceOutcome::Value(Arc::new(Value::Tuple(
                    [
                        Arc::clone(&elements[0]),
                        Thunk::suspended(Suspension::Apply {
                            function: Arc::clone(function),
                            argument: Arc::clone(&elements[1]),
                        }),
                    ]
                    .into(),
                ))))
            }
            _ => Err(RuntimeError::internal("Functor pair value mismatch")),
        },
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Functor target `{other}` has no runtime adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Functor primitive is missing evidence",
        )),
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
                    Ok(Thunk::suspended(Suspension::Apply { function, argument }))
                },
            )))))
        }
        Some("Maybe") => {
            let function = evaluator.force(functions)?;
            let argument = evaluator.force(arguments)?;
            match (function.as_ref(), argument.as_ref()) {
                (Value::Maybe(Some(function)), Value::Maybe(Some(argument))) => {
                    Ok(ForceOutcome::Value(Arc::new(Value::Maybe(Some(
                        Thunk::suspended(Suspension::Apply {
                            function: Arc::clone(function),
                            argument: Arc::clone(argument),
                        }),
                    )))))
                }
                (Value::Maybe(_), Value::Maybe(_)) => {
                    Ok(ForceOutcome::Value(Arc::new(Value::Maybe(None))))
                }
                _ => Err(RuntimeError::internal("Applicative Maybe value mismatch")),
            }
        }
        Some("Either") => {
            let function = evaluator.force(functions)?;
            let Value::PrimitiveVariant(function) = function.as_ref() else {
                return Err(RuntimeError::internal(
                    "Applicative Either function mismatch",
                ));
            };
            if function.constructor_index == 0 {
                return Ok(ForceOutcome::Alias(Thunk::evaluated(
                    Value::PrimitiveVariant(function.clone()),
                )));
            }
            let argument = evaluator.force(arguments)?;
            let Value::PrimitiveVariant(argument) = argument.as_ref() else {
                return Err(RuntimeError::internal(
                    "Applicative Either argument mismatch",
                ));
            };
            if argument.constructor_index == 0 {
                return Ok(ForceOutcome::Alias(Thunk::evaluated(
                    Value::PrimitiveVariant(argument.clone()),
                )));
            }
            let function = function.payloads.first().ok_or_else(|| {
                RuntimeError::internal("Either.Right function payload is missing")
            })?;
            let argument = argument.payloads.first().ok_or_else(|| {
                RuntimeError::internal("Either.Right argument payload is missing")
            })?;
            Ok(ForceOutcome::Value(Arc::new(Value::PrimitiveVariant(
                PrimitiveVariantValue {
                    family: PrimitiveFamily::Either,
                    constructor_index: 1,
                    payloads: Arc::from([Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(function),
                        argument: Arc::clone(argument),
                    })]),
                },
            ))))
        }
        Some("[]") => {
            let functions = evaluator.force_list_elements(functions)?;
            let arguments = evaluator.force_list_elements(arguments)?;
            let mut results = Vec::with_capacity(functions.len().saturating_mul(arguments.len()));
            for function in functions {
                for argument in &arguments {
                    results.push(Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&function),
                        argument: Arc::clone(argument),
                    }));
                }
            }
            Ok(ForceOutcome::Alias(list_from_values(results)))
        }
        Some("Tree") => apply_tree(evaluator, functions, arguments),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Applicative target `{other}` has no apply adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Applicative primitive is missing evidence",
        )),
    }
}

fn traverse_tree(
    evaluator: &mut Evaluator,
    items: Vec<ThunkRef>,
    callback: Option<&ThunkRef>,
    discard: bool,
) -> RuntimeResult<ForceOutcome> {
    let empty_children = || Thunk::evaluated(Value::List(ListCell::Nil));
    let mut accumulated = Thunk::evaluated(Value::Tree(TreeValue {
        root: empty_children(),
        children: empty_children(),
    }));
    for item in items {
        let action = traversal_action(callback, &item);
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
    match target {
        Some("IO") => {
            let action = Arc::clone(monad);
            let continuation = Arc::clone(continuation);
            Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
                move |evaluator, context| {
                    let action = evaluator.force_io(&action)?;
                    let result = action.run(evaluator, context)?;
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
                Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                    function: Arc::clone(continuation),
                    argument: Arc::clone(value),
                })))
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
                Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                    function: Arc::clone(continuation),
                    argument: Arc::clone(value),
                })))
            }
            _ => Err(RuntimeError::internal("Monad Either value mismatch")),
        },
        Some("[]") => Ok(ForceOutcome::Alias(bind_list(monad, continuation))),
        Some("Tree") => bind_tree(evaluator, monad, continuation),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Monad target `{other}` has no bind adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Monad primitive is missing evidence",
        )),
    }
}

fn bind_list(list: &ThunkRef, continuation: &ThunkRef) -> ThunkRef {
    let list = Arc::clone(list);
    let continuation = Arc::clone(continuation);
    Thunk::deferred(move |evaluator| match evaluator.force(&list)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            let first = Thunk::suspended(Suspension::Apply {
                function: Arc::clone(&continuation),
                argument: Arc::clone(head),
            });
            let rest = bind_list(tail, &continuation);
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
        Some("Tree") => then_tree(evaluator, first, second),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Monad target `{other}` has no then adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Monad primitive is missing evidence",
        )),
    }
}

#[allow(clippy::too_many_lines)]
fn traverse_value(
    evaluator: &mut Evaluator,
    target: Option<&str>,
    list: &ThunkRef,
    callback: Option<&ThunkRef>,
    discard: bool,
) -> RuntimeResult<ForceOutcome> {
    let items = evaluator.force_list_elements(list)?;
    match target {
        Some("IO") => {
            let callback = callback.cloned();
            Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
                move |evaluator, context| {
                    let mut results = Vec::with_capacity(items.len());
                    for item in &items {
                        let action = if let Some(callback) = &callback {
                            Thunk::suspended(Suspension::Apply {
                                function: Arc::clone(callback),
                                argument: Arc::clone(item),
                            })
                        } else {
                            Arc::clone(item)
                        };
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
                let action = traversal_action(callback, &item);
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
                let action = traversal_action(callback, &item);
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
                let action = traversal_action(callback, &item);
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
        Some("Tree") => traverse_tree(evaluator, items, callback, discard),
        Some(other) => Err(RuntimeError::internal(format!(
            "manifest Monad target `{other}` has no traversal adapter"
        ))),
        None => Err(RuntimeError::internal(
            "Monad traversal is missing evidence",
        )),
    }
}

fn traversal_action(callback: Option<&ThunkRef>, item: &ThunkRef) -> ThunkRef {
    callback.map_or_else(
        || Arc::clone(item),
        |callback| {
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
                let apply_accumulator = Thunk::suspended(Suspension::Apply {
                    function: Arc::clone(function),
                    argument: accumulator,
                });
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
    let tree_value = evaluator.force(tree)?;
    let Value::Tree(tree) = tree_value.as_ref() else {
        return Err(RuntimeError::internal("Tree.map received a non-Tree value"));
    };
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
            Thunk::deferred(
                move |evaluator| match map_tree(evaluator, &mapper, &child)? {
                    ForceOutcome::Value(value) => Ok(value),
                    ForceOutcome::Alias(value) => evaluator.force(&value),
                },
            )
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
            Thunk::deferred(
                move |evaluator| match fold_tree(evaluator, &function, &child)? {
                    ForceOutcome::Value(value) => Ok(value),
                    ForceOutcome::Alias(value) => evaluator.force(&value),
                },
            )
        })
        .collect();
    let with_root = Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(&tree.root),
    });
    Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
        function: with_root,
        argument: list_from_values(folded),
    })))
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
) -> RuntimeResult<ForceOutcome> {
    let function_value = evaluator.force(functions)?;
    let Value::Tree(functions) = function_value.as_ref() else {
        return Err(RuntimeError::internal(
            "Applicative Tree function value mismatch",
        ));
    };
    let mapped = outcome_thunk(map_tree(evaluator, &functions.root, arguments)?);
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
            let outcome = apply_tree(evaluator, &function_child, &arguments)?;
            outcome_value(evaluator, outcome)
        }));
    }
    Ok(ForceOutcome::Value(Arc::new(Value::Tree(TreeValue {
        root: Arc::clone(&mapped.root),
        children: list_from_values(children),
    }))))
}

fn bind_tree(
    evaluator: &mut Evaluator,
    tree: &ThunkRef,
    continuation: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let tree_value = evaluator.force(tree)?;
    let Value::Tree(tree) = tree_value.as_ref() else {
        return Err(RuntimeError::internal("Monad Tree value mismatch"));
    };
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
            let outcome = bind_tree(evaluator, &child, &continuation)?;
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
    let mut keyed = Vec::new();
    for value in evaluator.force_list_elements(list)? {
        let key = Thunk::suspended(Suspension::Apply {
            function: Arc::clone(function),
            argument: Arc::clone(&value),
        });
        keyed.push((key, value));
    }
    for index in 1..keyed.len() {
        let mut cursor = index;
        while cursor > 0 && evaluator.less_values(&keyed[cursor].0, &keyed[cursor - 1].0)? {
            keyed.swap(cursor, cursor - 1);
            cursor -= 1;
        }
    }
    Ok(ForceOutcome::Alias(list_from_values(
        keyed.into_iter().map(|(_, value)| value).collect(),
    )))
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
                let outcome = unfold_tree(evaluator, &function, &seed)?;
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
            let mut state = OptionParseState {
                arguments: Arc::clone(&context.args),
                used: vec![false; context.args.len()],
            };
            let value = parse_option(evaluator, &info.parser, &mut state)?.ok_or_else(|| {
                RuntimeError::user(option_usage_error(&info, "missing required option"))
            })?;
            if let Some((_, unexpected)) = state
                .used
                .iter()
                .zip(state.arguments.iter())
                .find(|(used, _)| !**used)
            {
                return Err(RuntimeError::user(option_usage_error(
                    &info,
                    &format!("unexpected argument `{unexpected}`"),
                )));
            }
            Ok(value)
        },
    )))))
}

struct OptionParseState {
    arguments: Arc<[Arc<str>]>,
    used: Vec<bool>,
}

#[allow(clippy::only_used_in_recursion, clippy::too_many_lines)]
fn parse_option(
    evaluator: &mut Evaluator,
    parser: &OptionParser,
    state: &mut OptionParseState,
) -> RuntimeResult<Option<ThunkRef>> {
    match parser {
        OptionParser::Pure(value) => Ok(Some(Arc::clone(value))),
        OptionParser::Helper => {
            let identity = hell_builtins::lookup("Function.id")
                .ok_or_else(|| RuntimeError::internal("Function.id is missing from registry"))?;
            Ok(Some(Thunk::evaluated(Value::Function(
                FunctionValue::Native {
                    builtin: identity.id,
                    arguments: Arc::from([]),
                    evidence: None,
                },
            ))))
        }
        OptionParser::Map { function, parser } => {
            let Some(argument) = parse_option(evaluator, parser, state)? else {
                return Ok(None);
            };
            Ok(Some(Thunk::suspended(Suspension::Apply {
                function: Arc::clone(function),
                argument,
            })))
        }
        OptionParser::Apply { function, argument } => {
            let Some(function) = parse_option(evaluator, function, state)? else {
                return Ok(None);
            };
            let Some(argument) = parse_option(evaluator, argument, state)? else {
                return Ok(None);
            };
            Ok(Some(Thunk::suspended(Suspension::Apply {
                function,
                argument,
            })))
        }
        OptionParser::Optional(parser) => Ok(Some(Thunk::evaluated(Value::Maybe(parse_option(
            evaluator, parser, state,
        )?)))),
        OptionParser::Many(parser) => {
            let mut values = Vec::new();
            loop {
                let before = state.used.iter().filter(|used| **used).count();
                let Some(value) = parse_option(evaluator, parser, state)? else {
                    break;
                };
                let after = state.used.iter().filter(|used| **used).count();
                if after == before {
                    return Err(RuntimeError::internal(
                        "Alternative.many parser accepted empty input",
                    ));
                }
                values.push(value);
            }
            Ok(Some(list_from_values(values)))
        }
        OptionParser::Switch(modifiers) => {
            let Some(long) = modifier_long(modifiers) else {
                return Err(RuntimeError::internal(
                    "Options.switch is missing Flag.long",
                ));
            };
            let needle = format!("--{long}");
            let found = state
                .arguments
                .iter()
                .enumerate()
                .find(|(index, value)| !state.used[*index] && value.as_ref() == needle)
                .map(|(index, _)| index);
            if let Some(index) = found {
                state.used[index] = true;
            }
            Ok(Some(Thunk::evaluated(Value::Bool(found.is_some()))))
        }
        OptionParser::Flag {
            inactive,
            active,
            modifiers,
        } => {
            let Some(long) = modifier_long(modifiers) else {
                return Err(RuntimeError::internal("Options.flag is missing Flag.long"));
            };
            let needle = format!("--{long}");
            let found = state
                .arguments
                .iter()
                .enumerate()
                .find(|(index, value)| !state.used[*index] && value.as_ref() == needle)
                .map(|(index, _)| index);
            if let Some(index) = found {
                state.used[index] = true;
                Ok(Some(Arc::clone(active)))
            } else {
                Ok(inactive.clone())
            }
        }
        OptionParser::StringOption(modifiers) => {
            let Some(long) = modifier_long(modifiers) else {
                return Err(RuntimeError::internal(
                    "Options.strOption is missing Option.long",
                ));
            };
            let needle = format!("--{long}");
            let found = state
                .arguments
                .iter()
                .enumerate()
                .find(|(index, value)| !state.used[*index] && value.as_ref() == needle)
                .map(|(index, _)| index);
            let Some(index) = found else {
                return Ok(modifier_default(modifiers));
            };
            let value_index = index + 1;
            let Some(value) = state.arguments.get(value_index).cloned() else {
                return Err(RuntimeError::user(format!(
                    "option `--{long}` requires an argument"
                )));
            };
            if state.used[value_index] {
                return Err(RuntimeError::user(format!(
                    "option `--{long}` has no available argument"
                )));
            }
            state.used[index] = true;
            state.used[value_index] = true;
            Ok(Some(Thunk::evaluated(Value::Text(value))))
        }
        OptionParser::StringArgument(modifiers) => {
            let found = state
                .arguments
                .iter()
                .enumerate()
                .find(|(index, value)| !state.used[*index] && !value.starts_with('-'))
                .map(|(index, value)| (index, Arc::clone(value)));
            let Some((index, value)) = found else {
                return Ok(modifier_default(modifiers));
            };
            state.used[index] = true;
            let _metavar = modifiers.0.iter().find_map(|modifier| match modifier {
                OptionModifier::Metavar(value) => Some(value),
                _ => None,
            });
            Ok(Some(Thunk::evaluated(Value::Text(value))))
        }
        OptionParser::Commands(modifiers) => {
            let found = state
                .arguments
                .iter()
                .enumerate()
                .find(|(index, _)| !state.used[*index])
                .map(|(index, value)| (index, Arc::clone(value)));
            let Some((index, command)) = found else {
                return Ok(None);
            };
            let parser = modifiers.0.iter().find_map(|modifier| match modifier {
                OptionModifier::Command { name, parser } if name == &command => Some(parser),
                _ => None,
            });
            let Some(parser) = parser else {
                return Err(RuntimeError::user(format!("unknown command `{command}`")));
            };
            state.used[index] = true;
            parse_option(evaluator, &parser.parser, state)
        }
    }
}

fn modifier_long(modifiers: &OptionModifiers) -> Option<&str> {
    modifiers.0.iter().find_map(|modifier| match modifier {
        OptionModifier::Long(value) => Some(value.as_ref()),
        _ => None,
    })
}

fn modifier_default(modifiers: &OptionModifiers) -> Option<ThunkRef> {
    modifiers.0.iter().find_map(|modifier| match modifier {
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

fn parser_help(parser: &OptionParser) -> Option<&str> {
    match parser {
        OptionParser::Map { parser, .. }
        | OptionParser::Optional(parser)
        | OptionParser::Many(parser) => parser_help(parser),
        OptionParser::Apply { function, argument } => {
            parser_help(function).or_else(|| parser_help(argument))
        }
        OptionParser::Switch(modifiers)
        | OptionParser::Flag { modifiers, .. }
        | OptionParser::StringOption(modifiers)
        | OptionParser::StringArgument(modifiers)
        | OptionParser::Commands(modifiers) => {
            modifiers.0.iter().find_map(|modifier| match modifier {
                OptionModifier::Help(help) => Some(help.as_ref()),
                _ => None,
            })
        }
        OptionParser::Pure(_) | OptionParser::Helper => None,
    }
}
