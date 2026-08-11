//! Lazy and finite-list native adapters.

use std::sync::Arc;

#[cfg(not(feature = "compat-tracing"))]
use crate::Suspension;
use crate::lazy_list::{Classifier, classify, drop_class, select_class, take_class};
use crate::{
    Evaluator, ForceOutcome, ListCell, RuntimeError, RuntimeResult, Thunk, ThunkRef, Value,
};

#[allow(clippy::too_many_lines)]
pub(crate) fn apply_native(
    implementation: &str,
    arguments: &[ThunkRef],
    evaluator: &mut Evaluator,
) -> Option<RuntimeResult<ForceOutcome>> {
    let result = match implementation {
        "list_all" | "list_any" => predicate_fold(
            evaluator,
            &arguments[0],
            &arguments[1],
            implementation == "list_all",
        )
        .map(|result| {
            if implementation == "list_all" && crate::semantic_mutant_active("all-constant-true") {
                value(Value::Bool(true))
            } else {
                value(result)
            }
        }),
        "list_break" | "list_span" => Ok(span(
            &arguments[0],
            &arguments[1],
            implementation == "list_break",
        )),
        "list_concat" => Ok(ForceOutcome::Alias(concat_lists(Arc::clone(&arguments[0])))),
        "list_concat_map" => Ok(ForceOutcome::Alias(concat_lists(map_to_lists(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        )))),
        "list_cycle" => Ok(ForceOutcome::Alias(cycle(Arc::clone(&arguments[0])))),
        "list_delete_by" => Ok(ForceOutcome::Alias(delete_by(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
            Arc::clone(&arguments[2]),
        ))),
        "list_drop" => drop_count(evaluator, &arguments[0], &arguments[1]),
        "list_drop_while" => drop_while(evaluator, &arguments[0], &arguments[1]),
        "list_drop_while_end" => Ok(ForceOutcome::Alias(drop_while_end(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        ))),
        "list_elem" | "list_not_elem" => contains(
            evaluator,
            &arguments[0],
            &arguments[1],
            implementation == "list_not_elem",
        )
        .map(value),
        "list_elem_index" => {
            find_index(evaluator, None, Some(&arguments[0]), &arguments[1]).map(value)
        }
        "list_elem_indices" => Ok(ForceOutcome::Alias(matching_indices(
            None,
            Some(Arc::clone(&arguments[0])),
            Arc::clone(&arguments[1]),
            0,
        ))),
        "list_filter" => Ok(ForceOutcome::Alias(filter(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        ))),
        "list_find" => find(evaluator, &arguments[0], &arguments[1]).map(value),
        "list_find_index" => {
            find_index(evaluator, Some(&arguments[0]), None, &arguments[1]).map(value)
        }
        "list_find_indices" => Ok(ForceOutcome::Alias(matching_indices(
            Some(Arc::clone(&arguments[0])),
            None,
            Arc::clone(&arguments[1]),
            0,
        ))),
        "list_foldr" => Ok(ForceOutcome::Alias(foldr(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
            Arc::clone(&arguments[2]),
        ))),
        "list_group" => Ok(ForceOutcome::Alias(group_by(
            None,
            Arc::clone(&arguments[0]),
        ))),
        "list_group_by" => Ok(ForceOutcome::Alias(group_by(
            Some(Arc::clone(&arguments[0])),
            Arc::clone(&arguments[1]),
        ))),
        "list_inits" => Ok(ForceOutcome::Alias(inits(Arc::clone(&arguments[0])))),
        "list_intercalate" => Ok(ForceOutcome::Alias(concat_lists(intersperse(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        )))),
        "list_intersperse" => Ok(ForceOutcome::Alias(intersperse(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        ))),
        "list_is_infix_of" => infix(evaluator, &arguments[0], &arguments[1]).map(value),
        "list_is_prefix_of" => prefix(evaluator, &arguments[0], &arguments[1]).map(value),
        "list_is_subsequence_of" => subsequence(evaluator, &arguments[0], &arguments[1]).map(value),
        "list_is_suffix_of" => suffix(evaluator, &arguments[0], &arguments[1]).map(value),
        "list_nub_ord" => Ok(ForceOutcome::Alias(nub_ord(
            Arc::clone(&arguments[0]),
            SeenTree::default(),
        ))),
        "list_null" => null(evaluator, &arguments[0]).map(value),
        "list_partition" => Ok(partition(&arguments[0], &arguments[1])),
        "list_permutations" => Ok(ForceOutcome::Alias(permutations(Arc::clone(&arguments[0])))),
        "list_repeat" => Ok(ForceOutcome::Alias(repeat(Arc::clone(&arguments[0])))),
        "list_scanl_strict" => Ok(ForceOutcome::Alias(scanl(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
            Arc::clone(&arguments[2]),
        ))),
        "list_scanr" => Ok(ForceOutcome::Alias(scanr(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
            Arc::clone(&arguments[2]),
        ))),
        "list_sort" => sort(evaluator, &arguments[0]).map(value),
        "list_split_at" => split_at(evaluator, &arguments[0], &arguments[1]),
        "list_subsequences" => Ok(ForceOutcome::Alias(subsequences(Arc::clone(&arguments[0])))),
        "list_tails" => Ok(ForceOutcome::Alias(tails(Arc::clone(&arguments[0])))),
        "list_take_while" => Ok(ForceOutcome::Alias(take_while(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        ))),
        "list_transpose" => Ok(ForceOutcome::Alias(transpose(Arc::clone(&arguments[0])))),
        "list_uncons" => uncons(evaluator, &arguments[0]).map(value),
        "list_unfoldr" => Ok(ForceOutcome::Alias(unfoldr(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        ))),
        "list_zip_with" => Ok(ForceOutcome::Alias(zip_with(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
            Arc::clone(&arguments[2]),
        ))),
        _ => return None,
    };
    Some(result)
}

fn value(value: Value) -> ForceOutcome {
    ForceOutcome::Value(Arc::new(value))
}

fn predicate_fold(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    input: &ThunkRef,
    all: bool,
) -> RuntimeResult<Value> {
    let mut list = Arc::clone(input);
    loop {
        match evaluator.force(&list)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(Value::Bool(all)),
            Value::List(ListCell::Cons { head, tail }) => {
                let matches =
                    evaluator.force_bool(&predicate_callback(evaluator, predicate, head))?;
                if matches != all {
                    return Ok(Value::Bool(!all));
                }
                list = Arc::clone(tail);
            }
            _ => return Err(non_list("List.all/any")),
        }
    }
}

#[cfg(feature = "compat-tracing")]
fn predicate_callback(
    evaluator: &Evaluator,
    predicate: &ThunkRef,
    argument: &ThunkRef,
) -> ThunkRef {
    evaluator
        .callback_application(
            Arc::clone(predicate),
            &[Arc::clone(argument)],
            0,
            "predicate",
        )
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn predicate_callback(
    _evaluator: &Evaluator,
    predicate: &ThunkRef,
    argument: &ThunkRef,
) -> ThunkRef {
    apply1(predicate, argument)
}

fn span(predicate: &ThunkRef, input: &ThunkRef, invert: bool) -> ForceOutcome {
    let matching = !invert;
    let classified = classify(
        Classifier::Predicate(Arc::clone(predicate)),
        Arc::clone(input),
        "List.span/break",
    );
    value(Value::Tuple(Arc::from([
        take_class(Arc::clone(&classified), matching, "List.span/break"),
        drop_class(classified, matching, "List.span/break"),
    ])))
}

fn map_to_lists(function: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: concat_map_callback(evaluator, &function, head),
            tail: map_to_lists(Arc::clone(&function), Arc::clone(tail)),
        }))),
        _ => Err(non_list("List.concatMap")),
    })
}

#[cfg(feature = "compat-tracing")]
fn concat_map_callback(evaluator: &Evaluator, function: &ThunkRef, item: &ThunkRef) -> ThunkRef {
    evaluator
        .callback_application(Arc::clone(function), &[Arc::clone(item)], 0, "element")
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn concat_map_callback(_evaluator: &Evaluator, function: &ThunkRef, item: &ThunkRef) -> ThunkRef {
    apply1(function, item)
}

fn cycle(input: ThunkRef) -> ThunkRef {
    cycle_from(Arc::clone(&input), input, false)
}

fn cycle_from(original: ThunkRef, current: ThunkRef, seen: bool) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&current)?.as_ref() {
        Value::List(ListCell::Cons { head, tail }) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(head),
            tail: cycle_from(Arc::clone(&original), Arc::clone(tail), true),
        }))),
        Value::List(ListCell::Nil) if seen => evaluator.force(&cycle_from(
            Arc::clone(&original),
            Arc::clone(&original),
            false,
        )),
        Value::List(ListCell::Nil) => Err(RuntimeError::user("List.cycle: empty list")),
        _ => Err(non_list("List.cycle")),
    })
}

fn delete_by(function: ThunkRef, needle: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            if evaluator.force_bool(&delete_by_callback(evaluator, &function, &needle, head))? {
                evaluator.force(tail)
            } else {
                Ok(Arc::new(Value::List(ListCell::Cons {
                    head: Arc::clone(head),
                    tail: delete_by(Arc::clone(&function), Arc::clone(&needle), Arc::clone(tail)),
                })))
            }
        }
        _ => Err(non_list("List.deleteBy")),
    })
}

#[cfg(feature = "compat-tracing")]
fn delete_by_callback(
    evaluator: &Evaluator,
    function: &ThunkRef,
    needle: &ThunkRef,
    item: &ThunkRef,
) -> ThunkRef {
    evaluator
        .callback_application(
            Arc::clone(function),
            &[Arc::clone(needle), Arc::clone(item)],
            0,
            "relation",
        )
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn delete_by_callback(
    _evaluator: &Evaluator,
    function: &ThunkRef,
    needle: &ThunkRef,
    item: &ThunkRef,
) -> ThunkRef {
    apply2(function, needle, item)
}

fn drop_while_end(predicate: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            let keep_tail = drop_while_end(Arc::clone(&predicate), Arc::clone(tail));
            if !evaluator.force_bool(&predicate_callback(evaluator, &predicate, head))? {
                return Ok(Arc::new(Value::List(ListCell::Cons {
                    head: Arc::clone(head),
                    tail: keep_tail,
                })));
            }
            match evaluator.force(&keep_tail)?.as_ref() {
                Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
                Value::List(ListCell::Cons { .. }) => Ok(Arc::new(Value::List(ListCell::Cons {
                    head: Arc::clone(head),
                    tail: keep_tail,
                }))),
                _ => Err(non_list("List.dropWhileEnd")),
            }
        }
        _ => Err(non_list("List.dropWhileEnd")),
    })
}

fn foldr(function: ThunkRef, seed: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => evaluator.force(&seed),
        Value::List(ListCell::Cons { head, tail }) => {
            let rest = foldr(Arc::clone(&function), Arc::clone(&seed), Arc::clone(tail));
            evaluator.force(&foldr_callback(evaluator, &function, head, &rest))
        }
        _ => Err(non_list("List.foldr")),
    })
}

#[cfg(feature = "compat-tracing")]
fn foldr_callback(
    evaluator: &Evaluator,
    function: &ThunkRef,
    item: &ThunkRef,
    accumulator: &ThunkRef,
) -> ThunkRef {
    evaluator
        .callback_application(
            Arc::clone(function),
            &[Arc::clone(item), Arc::clone(accumulator)],
            0,
            "fold",
        )
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn foldr_callback(
    _evaluator: &Evaluator,
    function: &ThunkRef,
    item: &ThunkRef,
    accumulator: &ThunkRef,
) -> ThunkRef {
    apply2(function, item, accumulator)
}

fn group_by(function: Option<ThunkRef>, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            let classified = classify(
                Classifier::Relation {
                    first: Arc::clone(head),
                    function: function.clone(),
                },
                Arc::clone(tail),
                "List.group/groupBy",
            );
            #[cfg(feature = "compat-tracing")]
            evaluator.register_current_adapter_child(&classified)?;
            let group_tail = take_class(Arc::clone(&classified), true, "List.group/groupBy");
            let suffix = drop_class(classified, true, "List.group/groupBy");
            Ok(Arc::new(Value::List(ListCell::Cons {
                head: Thunk::evaluated(Value::List(ListCell::Cons {
                    head: Arc::clone(head),
                    tail: group_tail,
                })),
                tail: group_by(function.clone(), suffix),
            })))
        }
        _ => Err(non_list("List.group/groupBy")),
    })
}

fn inits(input: ThunkRef) -> ThunkRef {
    inits_from(input, Vec::new(), true)
}

fn inits_from(input: ThunkRef, prefix: Vec<ThunkRef>, emit: bool) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        if emit {
            return Ok(Arc::new(Value::List(ListCell::Cons {
                head: list_from(prefix.clone()),
                tail: inits_from(Arc::clone(&input), prefix.clone(), false),
            })));
        }
        match evaluator.force(&input)?.as_ref() {
            Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
            Value::List(ListCell::Cons { head, tail }) => {
                let mut next = prefix.clone();
                next.push(Arc::clone(head));
                Ok(Arc::new(Value::List(ListCell::Cons {
                    head: list_from(next.clone()),
                    tail: inits_from(Arc::clone(tail), next, false),
                })))
            }
            _ => Err(non_list("List.inits")),
        }
    })
}

fn intersperse(separator: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(head),
            tail: intersperse_tail(Arc::clone(&separator), Arc::clone(tail)),
        }))),
        _ => Err(non_list("List.intersperse")),
    })
}

fn intersperse_tail(separator: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(&separator),
            tail: Thunk::evaluated(Value::List(ListCell::Cons {
                head: Arc::clone(head),
                tail: intersperse_tail(Arc::clone(&separator), Arc::clone(tail)),
            })),
        }))),
        _ => Err(non_list("List.intersperse")),
    })
}

fn concat_lists(outer: ThunkRef) -> ThunkRef {
    concat_from(outer, None)
}

fn concat_from(outer: ThunkRef, inner: Option<ThunkRef>) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let mut outer = Arc::clone(&outer);
        let mut inner = inner.clone();
        loop {
            if let Some(current) = inner.take() {
                match evaluator.force(&current)?.as_ref() {
                    Value::List(ListCell::Nil) => {}
                    Value::List(ListCell::Cons { head, tail }) => {
                        return Ok(Arc::new(Value::List(ListCell::Cons {
                            head: Arc::clone(head),
                            tail: concat_from(outer, Some(Arc::clone(tail))),
                        })));
                    }
                    _ => return Err(non_list("List.concat inner list")),
                }
            }
            match evaluator.force(&outer)?.as_ref() {
                Value::List(ListCell::Nil) => return Ok(Arc::new(Value::List(ListCell::Nil))),
                Value::List(ListCell::Cons { head, tail }) => {
                    inner = Some(Arc::clone(head));
                    outer = Arc::clone(tail);
                }
                _ => return Err(non_list("List.concat outer list")),
            }
        }
    })
}

fn drop_count(
    evaluator: &mut Evaluator,
    amount: &ThunkRef,
    input: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut remaining = evaluator.force_int(amount)?.max(0);
    let mut list = Arc::clone(input);
    while remaining > 0 {
        match evaluator.force(&list)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(ForceOutcome::Alias(list)),
            Value::List(ListCell::Cons { tail, .. }) => {
                remaining -= 1;
                list = Arc::clone(tail);
            }
            _ => return Err(non_list("List.drop")),
        }
    }
    Ok(ForceOutcome::Alias(list))
}

fn drop_while(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    input: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut list = Arc::clone(input);
    loop {
        match evaluator.force(&list)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(ForceOutcome::Alias(list)),
            Value::List(ListCell::Cons { head, tail }) => {
                if !evaluator.force_bool(&predicate_callback(evaluator, predicate, head))? {
                    return Ok(ForceOutcome::Alias(list));
                }
                list = Arc::clone(tail);
            }
            _ => return Err(non_list("List.dropWhile")),
        }
    }
}

fn contains(
    evaluator: &mut Evaluator,
    needle: &ThunkRef,
    input: &ThunkRef,
    invert: bool,
) -> RuntimeResult<Value> {
    let mut list = Arc::clone(input);
    loop {
        match evaluator.force(&list)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(Value::Bool(invert)),
            Value::List(ListCell::Cons { head, tail }) => {
                if evaluator.equal_values(needle, head)? {
                    return Ok(Value::Bool(!invert));
                }
                list = Arc::clone(tail);
            }
            _ => return Err(non_list("List.elem/notElem")),
        }
    }
}

fn find(evaluator: &mut Evaluator, predicate: &ThunkRef, input: &ThunkRef) -> RuntimeResult<Value> {
    let mut list = Arc::clone(input);
    loop {
        match evaluator.force(&list)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(Value::Maybe(None)),
            Value::List(ListCell::Cons { head, tail }) => {
                if evaluator.force_bool(&predicate_callback(evaluator, predicate, head))? {
                    return Ok(Value::Maybe(Some(Arc::clone(head))));
                }
                list = Arc::clone(tail);
            }
            _ => return Err(non_list("List.find")),
        }
    }
}

fn find_index(
    evaluator: &mut Evaluator,
    predicate: Option<&ThunkRef>,
    needle: Option<&ThunkRef>,
    input: &ThunkRef,
) -> RuntimeResult<Value> {
    let mut index = 0_i64;
    let mut list = Arc::clone(input);
    loop {
        match evaluator.force(&list)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(Value::Maybe(None)),
            Value::List(ListCell::Cons { head, tail }) => {
                let matches = if let Some(predicate) = predicate {
                    evaluator.force_bool(&predicate_callback(evaluator, predicate, head))?
                } else {
                    evaluator.equal_values(needle.expect("needle provided"), head)?
                };
                if matches {
                    return Ok(Value::Maybe(Some(Thunk::evaluated(Value::Int(index)))));
                }
                index = index.wrapping_add(1);
                list = Arc::clone(tail);
            }
            _ => return Err(non_list("List.findIndex/elemIndex")),
        }
    }
}

fn matching_indices(
    predicate: Option<ThunkRef>,
    needle: Option<ThunkRef>,
    input: ThunkRef,
    index: i64,
) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let mut list = Arc::clone(&input);
        let mut index = index;
        loop {
            match evaluator.force(&list)?.as_ref() {
                Value::List(ListCell::Nil) => return Ok(Arc::new(Value::List(ListCell::Nil))),
                Value::List(ListCell::Cons { head, tail }) => {
                    let matches = if let Some(predicate) = &predicate {
                        evaluator.force_bool(&predicate_callback(evaluator, predicate, head))?
                    } else {
                        evaluator.equal_values(needle.as_ref().expect("needle provided"), head)?
                    };
                    let next_index = index.wrapping_add(1);
                    if matches {
                        return Ok(Arc::new(Value::List(ListCell::Cons {
                            head: Thunk::evaluated(Value::Int(index)),
                            tail: matching_indices(
                                predicate.clone(),
                                needle.clone(),
                                Arc::clone(tail),
                                next_index,
                            ),
                        })));
                    }
                    index = next_index;
                    list = Arc::clone(tail);
                }
                _ => return Err(non_list("List.findIndices/elemIndices")),
            }
        }
    })
}

fn filter(predicate: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let mut list = Arc::clone(&input);
        loop {
            match evaluator.force(&list)?.as_ref() {
                Value::List(ListCell::Nil) => return Ok(Arc::new(Value::List(ListCell::Nil))),
                Value::List(ListCell::Cons { head, tail }) => {
                    if evaluator.force_bool(&predicate_callback(evaluator, &predicate, head))? {
                        return Ok(Arc::new(Value::List(ListCell::Cons {
                            head: Arc::clone(head),
                            tail: filter(Arc::clone(&predicate), Arc::clone(tail)),
                        })));
                    }
                    list = Arc::clone(tail);
                }
                _ => return Err(non_list("List.filter")),
            }
        }
    })
}

fn prefix(evaluator: &mut Evaluator, needle: &ThunkRef, input: &ThunkRef) -> RuntimeResult<Value> {
    let mut left = Arc::clone(needle);
    let mut right = Arc::clone(input);
    loop {
        let left_value = evaluator.force(&left)?;
        let Value::List(left_cell) = left_value.as_ref() else {
            return Err(non_list("List.isPrefixOf"));
        };
        let ListCell::Cons {
            head: left_head,
            tail: left_tail,
        } = left_cell
        else {
            return Ok(Value::Bool(true));
        };
        match evaluator.force(&right)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(Value::Bool(false)),
            Value::List(ListCell::Cons {
                head: right_head,
                tail: right_tail,
            }) => {
                if !evaluator.equal_values(left_head, right_head)? {
                    return Ok(Value::Bool(false));
                }
                left = Arc::clone(left_tail);
                right = Arc::clone(right_tail);
            }
            _ => return Err(non_list("List.isPrefixOf")),
        }
    }
}

fn subsequence(
    evaluator: &mut Evaluator,
    needle: &ThunkRef,
    input: &ThunkRef,
) -> RuntimeResult<Value> {
    let mut left = Arc::clone(needle);
    let mut right = Arc::clone(input);
    loop {
        let left_value = evaluator.force(&left)?;
        let Value::List(left_cell) = left_value.as_ref() else {
            return Err(non_list("List.isSubsequenceOf"));
        };
        let ListCell::Cons {
            head: left_head,
            tail: left_tail,
        } = left_cell
        else {
            return Ok(Value::Bool(true));
        };
        match evaluator.force(&right)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(Value::Bool(false)),
            Value::List(ListCell::Cons {
                head: right_head,
                tail: right_tail,
            }) => {
                if evaluator.equal_values(left_head, right_head)? {
                    left = Arc::clone(left_tail);
                }
                right = Arc::clone(right_tail);
            }
            _ => return Err(non_list("List.isSubsequenceOf")),
        }
    }
}

fn infix(evaluator: &mut Evaluator, needle: &ThunkRef, input: &ThunkRef) -> RuntimeResult<Value> {
    if matches!(
        evaluator.force(needle)?.as_ref(),
        Value::List(ListCell::Nil)
    ) {
        return Ok(Value::Bool(true));
    }
    let mut suffix = Arc::clone(input);
    loop {
        if let Value::Bool(true) = prefix(evaluator, needle, &suffix)? {
            return Ok(Value::Bool(true));
        }
        match evaluator.force(&suffix)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(Value::Bool(false)),
            Value::List(ListCell::Cons { tail, .. }) => suffix = Arc::clone(tail),
            _ => return Err(non_list("List.isInfixOf")),
        }
    }
}

fn suffix(evaluator: &mut Evaluator, needle: &ThunkRef, input: &ThunkRef) -> RuntimeResult<Value> {
    let needle = evaluator.force_list_elements(needle)?;
    let input = evaluator.force_list_elements(input)?;
    if needle.len() > input.len() {
        return Ok(Value::Bool(false));
    }
    for (left, right) in needle
        .iter()
        .zip(input[input.len() - needle.len()..].iter())
    {
        if !evaluator.equal_values(left, right)? {
            return Ok(Value::Bool(false));
        }
    }
    Ok(Value::Bool(true))
}

#[derive(Clone, Default)]
struct SeenTree(Option<Arc<SeenNode>>);

const SEEN_TREE_DELTA: usize = 3;
const SEEN_TREE_RATIO: usize = 2;

struct SeenNode {
    item: ThunkRef,
    left: SeenTree,
    right: SeenTree,
    size: usize,
}

impl SeenTree {
    fn insert(&self, evaluator: &mut Evaluator, item: &ThunkRef) -> RuntimeResult<(Self, bool)> {
        let Some(node) = &self.0 else {
            return Ok((
                Self::node(Arc::clone(item), Self::default(), Self::default()),
                true,
            ));
        };
        // Match containers' `Set` comparison: equality is checked first, then
        // less-than, and every remaining (including incomparable NaN) value is
        // routed right as greater.
        if evaluator.equal_values(item, &node.item)? {
            return Ok((self.clone(), false));
        }
        if evaluator.less_values(item, &node.item)? {
            let (left, inserted) = node.left.insert(evaluator, item)?;
            if !inserted {
                return Ok((self.clone(), false));
            }
            return Ok((
                Self::node(Arc::clone(&node.item), left, node.right.clone()).balanced(),
                true,
            ));
        }
        let (right, inserted) = node.right.insert(evaluator, item)?;
        if !inserted {
            return Ok((self.clone(), false));
        }
        Ok((
            Self::node(Arc::clone(&node.item), node.left.clone(), right).balanced(),
            true,
        ))
    }

    fn node(item: ThunkRef, left: Self, right: Self) -> Self {
        let size = left.size().saturating_add(right.size()).saturating_add(1);
        Self(Some(Arc::new(SeenNode {
            item,
            left,
            right,
            size,
        })))
    }

    fn size(&self) -> usize {
        self.0.as_ref().map_or(0, |node| node.size)
    }

    fn balanced(self) -> Self {
        let Some(node) = &self.0 else {
            return self;
        };
        let left_size = node.left.size();
        let right_size = node.right.size();
        if left_size.saturating_add(right_size) <= 1 {
            return self;
        }
        if left_size > SEEN_TREE_DELTA.saturating_mul(right_size) {
            let left = node
                .left
                .0
                .as_ref()
                .expect("left-heavy size-balanced tree has a left node");
            if left.right.size() >= SEEN_TREE_RATIO.saturating_mul(left.left.size()) {
                return Self::node(
                    Arc::clone(&node.item),
                    node.left.clone().rotate_left(),
                    node.right.clone(),
                )
                .rotate_right();
            }
            return self.rotate_right();
        }
        if right_size > SEEN_TREE_DELTA.saturating_mul(left_size) {
            let right = node
                .right
                .0
                .as_ref()
                .expect("right-heavy size-balanced tree has a right node");
            if right.left.size() >= SEEN_TREE_RATIO.saturating_mul(right.right.size()) {
                return Self::node(
                    Arc::clone(&node.item),
                    node.left.clone(),
                    node.right.clone().rotate_right(),
                )
                .rotate_left();
            }
            return self.rotate_left();
        }
        self
    }

    fn rotate_left(self) -> Self {
        let node = self.0.as_ref().expect("left rotation has a root");
        let right = node
            .right
            .0
            .as_ref()
            .expect("left rotation has a right node");
        let left = Self::node(
            Arc::clone(&node.item),
            node.left.clone(),
            right.left.clone(),
        );
        Self::node(Arc::clone(&right.item), left, right.right.clone())
    }

    fn rotate_right(self) -> Self {
        let node = self.0.as_ref().expect("right rotation has a root");
        let left = node
            .left
            .0
            .as_ref()
            .expect("right rotation has a left node");
        let right = Self::node(
            Arc::clone(&node.item),
            left.right.clone(),
            node.right.clone(),
        );
        Self::node(Arc::clone(&left.item), left.left.clone(), right)
    }
}

fn nub_ord(input: ThunkRef, seen: SeenTree) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let mut current = Arc::clone(&input);
        let mut seen = seen.clone();
        loop {
            evaluator.ensure_not_cancelled()?;
            match evaluator.force(&current)?.as_ref() {
                Value::List(ListCell::Nil) => return Ok(Arc::new(Value::List(ListCell::Nil))),
                Value::List(ListCell::Cons { head, tail }) => {
                    let (next_seen, inserted) = seen.insert(evaluator, head)?;
                    if inserted {
                        return Ok(Arc::new(Value::List(ListCell::Cons {
                            head: Arc::clone(head),
                            tail: nub_ord(Arc::clone(tail), next_seen),
                        })));
                    }
                    seen = next_seen;
                    current = Arc::clone(tail);
                }
                _ => return Err(non_list("List.nubOrd")),
            }
        }
    })
}

fn partition(predicate: &ThunkRef, input: &ThunkRef) -> ForceOutcome {
    let classified = classify(
        Classifier::Predicate(Arc::clone(predicate)),
        Arc::clone(input),
        "List.partition",
    );
    value(Value::Tuple(Arc::from([
        select_class(Arc::clone(&classified), true, "List.partition"),
        select_class(classified, false, "List.partition"),
    ])))
}

fn permutations(input: ThunkRef) -> ThunkRef {
    let original = Arc::clone(&input);
    Thunk::deferred(move |_| {
        Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(&original),
            tail: permutation_stages(
                Arc::clone(&input),
                Thunk::evaluated(Value::List(ListCell::Nil)),
            ),
        })))
    })
}

fn permutation_stages(input: ThunkRef, reversed_prefix: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            let stage = permutation_stage(
                permutations(Arc::clone(&reversed_prefix)),
                Arc::clone(head),
                Arc::clone(tail),
            );
            let next_prefix = Thunk::evaluated(Value::List(ListCell::Cons {
                head: Arc::clone(head),
                tail: Arc::clone(&reversed_prefix),
            }));
            evaluator.force(&append_lazy(
                stage,
                permutation_stages(Arc::clone(tail), next_prefix),
            ))
        }
        _ => Err(non_list("List.permutations")),
    })
}

fn permutation_stage(prefixes: ThunkRef, item: ThunkRef, suffix: ThunkRef) -> ThunkRef {
    Thunk::deferred(
        move |evaluator| match evaluator.force(&prefixes)?.as_ref() {
            Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
            Value::List(ListCell::Cons { head, tail }) => evaluator.force(&append_lazy(
                interleave_nonfinal(
                    Arc::clone(&item),
                    Arc::clone(head),
                    Arc::clone(&suffix),
                    Vec::new(),
                ),
                permutation_stage(Arc::clone(tail), Arc::clone(&item), Arc::clone(&suffix)),
            )),
            _ => Err(non_list("List.permutations prefix stream")),
        },
    )
}

fn interleave_nonfinal(
    item: ThunkRef,
    remaining: ThunkRef,
    suffix: ThunkRef,
    prefix: Vec<ThunkRef>,
) -> ThunkRef {
    Thunk::deferred(
        move |evaluator| match evaluator.force(&remaining)?.as_ref() {
            Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
            Value::List(ListCell::Cons { head, tail }) => {
                let inserted = append_lazy(Arc::clone(&remaining), Arc::clone(&suffix));
                let inserted = Thunk::evaluated(Value::List(ListCell::Cons {
                    head: Arc::clone(&item),
                    tail: inserted,
                }));
                let permutation = prefix.iter().rev().fold(inserted, |tail, head| {
                    Thunk::evaluated(Value::List(ListCell::Cons {
                        head: Arc::clone(head),
                        tail,
                    }))
                });
                let mut next_prefix = prefix.clone();
                next_prefix.push(Arc::clone(head));
                Ok(Arc::new(Value::List(ListCell::Cons {
                    head: permutation,
                    tail: interleave_nonfinal(
                        Arc::clone(&item),
                        Arc::clone(tail),
                        Arc::clone(&suffix),
                        next_prefix,
                    ),
                })))
            }
            _ => Err(non_list("List.permutations prefix")),
        },
    )
}

fn append_lazy(left: ThunkRef, right: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&left)?.as_ref() {
        Value::List(ListCell::Nil) => evaluator.force(&right),
        Value::List(ListCell::Cons { head, tail }) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(head),
            tail: append_lazy(Arc::clone(tail), Arc::clone(&right)),
        }))),
        _ => Err(non_list("List append")),
    })
}

fn scanl(function: ThunkRef, accumulator: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |_| {
        Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(&accumulator),
            tail: scanl_tail(
                Arc::clone(&function),
                Arc::clone(&accumulator),
                Arc::clone(&input),
            ),
        })))
    })
}

fn scanl_tail(function: ThunkRef, accumulator: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            let next = scan_callback(evaluator, &function, &accumulator, head);
            let forced = evaluator.force(&next)?;
            let next = Thunk::evaluated(forced.as_ref().clone());
            Ok(Arc::new(Value::List(ListCell::Cons {
                head: Arc::clone(&next),
                tail: scanl_tail(Arc::clone(&function), next, Arc::clone(tail)),
            })))
        }
        _ => Err(non_list("List.scanl'")),
    })
}

fn scanr(function: ThunkRef, seed: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(&seed),
            tail: Thunk::evaluated(Value::List(ListCell::Nil)),
        }))),
        Value::List(ListCell::Cons { head, tail }) => {
            let rest = scanr(Arc::clone(&function), Arc::clone(&seed), Arc::clone(tail));
            let function_for_head = Arc::clone(&function);
            let item = Arc::clone(head);
            let rest_for_head = Arc::clone(&rest);
            let accumulated = Thunk::deferred(move |evaluator| {
                let rest = evaluator.force(&rest_for_head)?;
                let Value::List(ListCell::Cons { head, .. }) = rest.as_ref() else {
                    return Err(RuntimeError::internal(
                        "List.scanr recursive result was empty or malformed",
                    ));
                };
                evaluator.force(&scan_callback(evaluator, &function_for_head, &item, head))
            });
            Ok(Arc::new(Value::List(ListCell::Cons {
                head: accumulated,
                tail: rest,
            })))
        }
        _ => Err(non_list("List.scanr")),
    })
}

#[cfg(feature = "compat-tracing")]
fn scan_callback(
    evaluator: &Evaluator,
    function: &ThunkRef,
    left: &ThunkRef,
    right: &ThunkRef,
) -> ThunkRef {
    evaluator
        .callback_application(
            Arc::clone(function),
            &[Arc::clone(left), Arc::clone(right)],
            0,
            "scan",
        )
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn scan_callback(
    _evaluator: &Evaluator,
    function: &ThunkRef,
    left: &ThunkRef,
    right: &ThunkRef,
) -> ThunkRef {
    apply2(function, left, right)
}

fn sort(evaluator: &mut Evaluator, input: &ThunkRef) -> RuntimeResult<Value> {
    let items = evaluator.force_list_elements(input)?;
    let mut runs = natural_sort_runs(evaluator, items)?;
    while runs.len() > 1 {
        evaluator.ensure_not_cancelled()?;
        let mut merged = Vec::with_capacity(runs.len().div_ceil(2));
        let mut current_runs = runs.into_iter();
        while let Some(left) = current_runs.next() {
            if let Some(right) = current_runs.next() {
                merged.push(merge_sorted(evaluator, left, right)?);
            } else {
                merged.push(left);
            }
        }
        runs = merged;
    }
    Ok(Value::List(list_cell_from(runs.pop().unwrap_or_default())))
}

fn natural_sort_runs(
    evaluator: &mut Evaluator,
    items: Vec<ThunkRef>,
) -> RuntimeResult<Vec<Vec<ThunkRef>>> {
    let mut remaining = items.into_iter().peekable();
    let mut runs = Vec::new();
    while let Some(first) = remaining.next() {
        let Some(second) = remaining.next() else {
            runs.push(vec![first]);
            break;
        };
        let descending = greater_than(evaluator, &first, &second)?;
        let mut run = vec![first];
        let mut current = second;
        while let Some(next) = remaining.peek() {
            let next_descending = greater_than(evaluator, &current, next)?;
            if next_descending != descending {
                break;
            }
            run.push(current);
            current = remaining.next().expect("peeked sort item exists");
        }
        run.push(current);
        if descending {
            run.reverse();
        }
        runs.push(run);
    }
    Ok(runs)
}

fn greater_than(
    evaluator: &mut Evaluator,
    left: &ThunkRef,
    right: &ThunkRef,
) -> RuntimeResult<bool> {
    Ok(!evaluator.equal_values(left, right)? && !evaluator.less_values(left, right)?)
}

fn merge_sorted(
    evaluator: &mut Evaluator,
    left: Vec<ThunkRef>,
    right: Vec<ThunkRef>,
) -> RuntimeResult<Vec<ThunkRef>> {
    let mut output = Vec::with_capacity(left.len().saturating_add(right.len()));
    let mut left = left.into_iter().peekable();
    let mut right = right.into_iter().peekable();
    while let (Some(left_item), Some(right_item)) = (left.peek(), right.peek()) {
        evaluator.ensure_not_cancelled()?;
        if greater_than(evaluator, left_item, right_item)? {
            output.push(right.next().expect("peeked right item exists"));
        } else {
            output.push(left.next().expect("peeked left item exists"));
        }
    }
    output.extend(left);
    output.extend(right);
    Ok(output)
}

fn split_at(
    evaluator: &mut Evaluator,
    amount: &ThunkRef,
    input: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut remaining = evaluator.force_int(amount)?.max(0);
    let mut prefix = Vec::new();
    let mut suffix = Arc::clone(input);
    while remaining > 0 {
        match evaluator.force(&suffix)?.as_ref() {
            Value::List(ListCell::Nil) => break,
            Value::List(ListCell::Cons { head, tail }) => {
                prefix.push(Arc::clone(head));
                suffix = Arc::clone(tail);
                remaining -= 1;
            }
            _ => return Err(non_list("List.splitAt")),
        }
    }
    Ok(value(Value::Tuple(Arc::from([list_from(prefix), suffix]))))
}

fn subsequences(input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |_| {
        Ok(Arc::new(Value::List(ListCell::Cons {
            head: Thunk::evaluated(Value::List(ListCell::Nil)),
            tail: non_empty_subsequences(Arc::clone(&input)),
        })))
    })
}

fn non_empty_subsequences(input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            let single = Thunk::evaluated(Value::List(ListCell::Cons {
                head: Arc::clone(head),
                tail: Thunk::evaluated(Value::List(ListCell::Nil)),
            }));
            Ok(Arc::new(Value::List(ListCell::Cons {
                head: single,
                tail: subsequence_pairs(
                    Arc::clone(head),
                    non_empty_subsequences(Arc::clone(tail)),
                    true,
                ),
            })))
        }
        _ => Err(non_list("List.subsequences")),
    })
}

fn subsequence_pairs(item: ThunkRef, subsets: ThunkRef, emit_plain: bool) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&subsets)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail: _ }) if emit_plain => {
            Ok(Arc::new(Value::List(ListCell::Cons {
                head: Arc::clone(head),
                tail: subsequence_pairs(Arc::clone(&item), Arc::clone(&subsets), false),
            })))
        }
        Value::List(ListCell::Cons { head, tail }) => {
            let item = Arc::clone(&item);
            let prefixed_item = Arc::clone(&item);
            let subset = Arc::clone(head);
            let prefixed =
                Thunk::deferred(move |evaluator| match evaluator.force(&subset)?.as_ref() {
                    Value::List(_) => Ok(Arc::new(Value::List(ListCell::Cons {
                        head: Arc::clone(&prefixed_item),
                        tail: Arc::clone(&subset),
                    }))),
                    _ => Err(non_list("List.subsequences result")),
                });
            Ok(Arc::new(Value::List(ListCell::Cons {
                head: prefixed,
                tail: subsequence_pairs(Arc::clone(&item), Arc::clone(tail), true),
            })))
        }
        _ => Err(non_list("List.subsequences")),
    })
}

fn tails(input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(&input),
            tail: Thunk::evaluated(Value::List(ListCell::Nil)),
        }))),
        Value::List(ListCell::Cons { tail, .. }) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(&input),
            tail: tails(Arc::clone(tail)),
        }))),
        _ => Err(non_list("List.tails")),
    })
}

fn transpose(input: ThunkRef) -> ThunkRef {
    let projected = project_rows(input);
    Thunk::deferred(
        move |evaluator| match evaluator.force(&projected)?.as_ref() {
            Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
            Value::List(ListCell::Cons { .. }) => Ok(Arc::new(Value::List(ListCell::Cons {
                head: project_field(Arc::clone(&projected), 0),
                tail: transpose(project_field(Arc::clone(&projected), 1)),
            }))),
            _ => Err(non_list("List.transpose")),
        },
    )
}

fn project_rows(input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let mut rows = Arc::clone(&input);
        loop {
            evaluator.ensure_not_cancelled()?;
            match evaluator.force(&rows)?.as_ref() {
                Value::List(ListCell::Nil) => return Ok(Arc::new(Value::List(ListCell::Nil))),
                Value::List(ListCell::Cons {
                    head: row,
                    tail: remaining_rows,
                }) => match evaluator.force(row)?.as_ref() {
                    Value::List(ListCell::Nil) => rows = Arc::clone(remaining_rows),
                    Value::List(ListCell::Cons { head, tail }) => {
                        return Ok(Arc::new(Value::List(ListCell::Cons {
                            head: Thunk::evaluated(Value::Tuple(
                                [Arc::clone(head), Arc::clone(tail)].into(),
                            )),
                            tail: project_rows(Arc::clone(remaining_rows)),
                        })));
                    }
                    _ => return Err(non_list("List.transpose row")),
                },
                _ => return Err(non_list("List.transpose")),
            }
        }
    })
}

fn project_field(projected: ThunkRef, index: usize) -> ThunkRef {
    Thunk::deferred(
        move |evaluator| match evaluator.force(&projected)?.as_ref() {
            Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
            Value::List(ListCell::Cons { head, tail }) => match evaluator.force(head)?.as_ref() {
                Value::Tuple(fields) if fields.len() == 2 => {
                    Ok(Arc::new(Value::List(ListCell::Cons {
                        head: Arc::clone(&fields[index]),
                        tail: project_field(Arc::clone(tail), index),
                    })))
                }
                _ => Err(RuntimeError::internal(
                    "List.transpose produced malformed row projection",
                )),
            },
            _ => Err(non_list("List.transpose")),
        },
    )
}

fn unfoldr(function: ThunkRef, seed: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let step = evaluator.force(&unfoldr_callback(evaluator, &function, &seed))?;
        match step.as_ref() {
            Value::Maybe(None) => Ok(Arc::new(Value::List(ListCell::Nil))),
            Value::Maybe(Some(pair)) => match evaluator.force(pair)?.as_ref() {
                Value::Tuple(elements) => {
                    let [item, next] = elements.as_ref() else {
                        return Err(RuntimeError::internal(
                            "List.unfoldr callback returned a tuple with the wrong arity",
                        ));
                    };
                    Ok(Arc::new(Value::List(ListCell::Cons {
                        head: Arc::clone(item),
                        tail: unfoldr(Arc::clone(&function), Arc::clone(next)),
                    })))
                }
                _ => Err(RuntimeError::internal(
                    "List.unfoldr callback returned a non-pair payload",
                )),
            },
            _ => Err(RuntimeError::internal(
                "List.unfoldr callback returned a non-Maybe value",
            )),
        }
    })
}

#[cfg(feature = "compat-tracing")]
fn unfoldr_callback(evaluator: &Evaluator, function: &ThunkRef, seed: &ThunkRef) -> ThunkRef {
    evaluator
        .callback_application(Arc::clone(function), std::slice::from_ref(seed), 0, "seed")
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn unfoldr_callback(_evaluator: &Evaluator, function: &ThunkRef, seed: &ThunkRef) -> ThunkRef {
    apply1(function, seed)
}

fn null(evaluator: &mut Evaluator, input: &ThunkRef) -> RuntimeResult<Value> {
    match evaluator.force(input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Value::Bool(true)),
        Value::List(ListCell::Cons { .. }) => Ok(Value::Bool(false)),
        _ => Err(non_list("List.null")),
    }
}

fn repeat(item: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |_| {
        Ok(Arc::new(Value::List(ListCell::Cons {
            head: Arc::clone(&item),
            tail: repeat(Arc::clone(&item)),
        })))
    })
}

fn take_while(predicate: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            if evaluator.force_bool(&predicate_callback(evaluator, &predicate, head))? {
                Ok(Arc::new(Value::List(ListCell::Cons {
                    head: Arc::clone(head),
                    tail: take_while(Arc::clone(&predicate), Arc::clone(tail)),
                })))
            } else {
                Ok(Arc::new(Value::List(ListCell::Nil)))
            }
        }
        _ => Err(non_list("List.takeWhile")),
    })
}

fn uncons(evaluator: &mut Evaluator, input: &ThunkRef) -> RuntimeResult<Value> {
    match evaluator.force(input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Value::Maybe(None)),
        Value::List(ListCell::Cons { head, tail }) => Ok(Value::Maybe(Some(Thunk::evaluated(
            Value::Tuple(Arc::from([Arc::clone(head), Arc::clone(tail)])),
        )))),
        _ => Err(non_list("List.uncons")),
    }
}

fn zip_with(function: ThunkRef, left: ThunkRef, right: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let left_value = evaluator.force(&left)?;
        let Value::List(left_cell) = left_value.as_ref() else {
            return Err(non_list("List.zipWith"));
        };
        let ListCell::Cons {
            head: left_head,
            tail: left_tail,
        } = left_cell
        else {
            return Ok(Arc::new(Value::List(ListCell::Nil)));
        };
        match evaluator.force(&right)?.as_ref() {
            Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
            Value::List(ListCell::Cons {
                head: right_head,
                tail: right_tail,
            }) => Ok(Arc::new(Value::List(ListCell::Cons {
                head: zip_with_callback(evaluator, &function, left_head, right_head),
                tail: zip_with(
                    Arc::clone(&function),
                    Arc::clone(left_tail),
                    Arc::clone(right_tail),
                ),
            }))),
            _ => Err(non_list("List.zipWith")),
        }
    })
}

#[cfg(feature = "compat-tracing")]
fn zip_with_callback(
    evaluator: &Evaluator,
    function: &ThunkRef,
    left: &ThunkRef,
    right: &ThunkRef,
) -> ThunkRef {
    evaluator
        .callback_application(
            Arc::clone(function),
            &[Arc::clone(left), Arc::clone(right)],
            0,
            "element",
        )
        .unwrap_or_else(Thunk::failed_without_admission)
}

#[cfg(not(feature = "compat-tracing"))]
fn zip_with_callback(
    _evaluator: &Evaluator,
    function: &ThunkRef,
    left: &ThunkRef,
    right: &ThunkRef,
) -> ThunkRef {
    apply2(function, left, right)
}

fn list_from(mut values: Vec<ThunkRef>) -> ThunkRef {
    let mut result = Thunk::evaluated(Value::List(ListCell::Nil));
    while let Some(head) = values.pop() {
        result = Thunk::evaluated(Value::List(ListCell::Cons { head, tail: result }));
    }
    result
}

fn list_cell_from(values: Vec<ThunkRef>) -> ListCell {
    let mut values = values.into_iter();
    values.next().map_or(ListCell::Nil, |head| ListCell::Cons {
        head,
        tail: list_from(values.collect()),
    })
}

#[cfg(not(feature = "compat-tracing"))]
fn apply1(function: &ThunkRef, argument: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(argument),
    })
}

#[cfg(not(feature = "compat-tracing"))]
fn apply2(function: &ThunkRef, first: &ThunkRef, second: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: apply1(function, first),
        argument: Arc::clone(second),
    })
}

fn non_list(operation: &'static str) -> Arc<RuntimeError> {
    RuntimeError::internal(format!("{operation} received a non-list"))
}
