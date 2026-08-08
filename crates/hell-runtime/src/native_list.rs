//! Lazy and finite-list native adapters.

use std::sync::Arc;

use crate::{
    Evaluator, ForceOutcome, ListCell, RuntimeError, RuntimeResult, Suspension, Thunk, ThunkRef,
    Value,
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
        .map(value),
        "list_break" | "list_span" => span(
            evaluator,
            &arguments[0],
            &arguments[1],
            implementation == "list_break",
        ),
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
        "list_drop_while_end" => drop_while_end(evaluator, &arguments[0], &arguments[1]).map(value),
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
        "list_nub_ord" => nub_ord(evaluator, &arguments[0]).map(value),
        "list_null" => null(evaluator, &arguments[0]).map(value),
        "list_partition" => partition(evaluator, &arguments[0], &arguments[1]),
        "list_permutations" => permutations(evaluator, &arguments[0]).map(value),
        "list_repeat" => Ok(ForceOutcome::Alias(repeat(Arc::clone(&arguments[0])))),
        "list_scanl_strict" => Ok(ForceOutcome::Alias(scanl(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
            Arc::clone(&arguments[2]),
        ))),
        "list_scanr" => scanr(evaluator, &arguments[0], &arguments[1], &arguments[2]),
        "list_sort" => sort(evaluator, &arguments[0]).map(value),
        "list_split_at" => split_at(evaluator, &arguments[0], &arguments[1]),
        "list_subsequences" => subsequences(evaluator, &arguments[0]).map(value),
        "list_tails" => Ok(ForceOutcome::Alias(tails(Arc::clone(&arguments[0])))),
        "list_take_while" => Ok(ForceOutcome::Alias(take_while(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        ))),
        "list_transpose" => transpose(evaluator, &arguments[0]).map(value),
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
                let matches = evaluator.force_bool(&apply1(predicate, head))?;
                if matches != all {
                    return Ok(Value::Bool(!all));
                }
                list = Arc::clone(tail);
            }
            _ => return Err(non_list("List.all/any")),
        }
    }
}

fn span(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    input: &ThunkRef,
    invert: bool,
) -> RuntimeResult<ForceOutcome> {
    let mut prefix = Vec::new();
    let mut suffix = Arc::clone(input);
    loop {
        match evaluator.force(&suffix)?.as_ref() {
            Value::List(ListCell::Nil) => break,
            Value::List(ListCell::Cons { head, tail }) => {
                let matches = evaluator.force_bool(&apply1(predicate, head))?;
                if matches == invert {
                    break;
                }
                prefix.push(Arc::clone(head));
                suffix = Arc::clone(tail);
            }
            _ => return Err(non_list("List.span/break")),
        }
    }
    Ok(value(Value::Tuple(Arc::from([list_from(prefix), suffix]))))
}

fn map_to_lists(function: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => Ok(Arc::new(Value::List(ListCell::Cons {
            head: apply1(&function, head),
            tail: map_to_lists(Arc::clone(&function), Arc::clone(tail)),
        }))),
        _ => Err(non_list("List.concatMap")),
    })
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
            if evaluator.force_bool(&apply2(&function, &needle, head))? {
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

fn drop_while_end(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    input: &ThunkRef,
) -> RuntimeResult<Value> {
    let mut items = evaluator.force_list_elements(input)?;
    while let Some(last) = items.last() {
        if !evaluator.force_bool(&apply1(predicate, last))? {
            break;
        }
        items.pop();
    }
    Ok(Value::List(list_cell_from(items)))
}

fn foldr(function: ThunkRef, seed: ThunkRef, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => evaluator.force(&seed),
        Value::List(ListCell::Cons { head, tail }) => evaluator.force(&apply2(
            &function,
            head,
            &foldr(Arc::clone(&function), Arc::clone(&seed), Arc::clone(tail)),
        )),
        _ => Err(non_list("List.foldr")),
    })
}

fn group_by(function: Option<ThunkRef>, input: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            let first = Arc::clone(head);
            let mut group = vec![Arc::clone(head)];
            let mut suffix = Arc::clone(tail);
            loop {
                match evaluator.force(&suffix)?.as_ref() {
                    Value::List(ListCell::Nil) => break,
                    Value::List(ListCell::Cons { head, tail }) => {
                        let matches = if let Some(function) = &function {
                            evaluator.force_bool(&apply2(function, &first, head))?
                        } else {
                            evaluator.equal_values(&first, head)?
                        };
                        if !matches {
                            break;
                        }
                        group.push(Arc::clone(head));
                        suffix = Arc::clone(tail);
                    }
                    _ => return Err(non_list("List.group/groupBy")),
                }
            }
            Ok(Arc::new(Value::List(ListCell::Cons {
                head: list_from(group),
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
                if !evaluator.force_bool(&apply1(predicate, head))? {
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
                if evaluator.force_bool(&apply1(predicate, head))? {
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
                    evaluator.force_bool(&apply1(predicate, head))?
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
                        evaluator.force_bool(&apply1(predicate, head))?
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
                    if evaluator.force_bool(&apply1(&predicate, head))? {
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

fn nub_ord(evaluator: &mut Evaluator, input: &ThunkRef) -> RuntimeResult<Value> {
    let items = evaluator.force_list_elements(input)?;
    let mut unique: Vec<ThunkRef> = Vec::new();
    'items: for item in items {
        for existing in &unique {
            if evaluator.equal_values(&item, existing)? {
                continue 'items;
            }
        }
        unique.push(item);
    }
    Ok(Value::List(list_cell_from(unique)))
}

fn partition(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    input: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let items = evaluator.force_list_elements(input)?;
    let mut matches = Vec::new();
    let mut rejects = Vec::new();
    for item in items {
        if evaluator.force_bool(&apply1(predicate, &item))? {
            matches.push(item);
        } else {
            rejects.push(item);
        }
    }
    Ok(value(Value::Tuple(Arc::from([
        list_from(matches),
        list_from(rejects),
    ]))))
}

fn permutations(evaluator: &mut Evaluator, input: &ThunkRef) -> RuntimeResult<Value> {
    let items = evaluator.force_list_elements(input)?;
    Ok(Value::List(list_cell_from(
        permutations_ordered(&items)
            .into_iter()
            .map(list_from)
            .collect(),
    )))
}

fn permutations_ordered(items: &[ThunkRef]) -> Vec<Vec<ThunkRef>> {
    if items.is_empty() {
        return vec![Vec::new()];
    }
    let mut output = vec![items.to_vec()];
    output.extend(permutations_tail(items, &[]));
    output
}

fn permutations_tail(items: &[ThunkRef], inserted: &[ThunkRef]) -> Vec<Vec<ThunkRef>> {
    let Some((item, tail)) = items.split_first() else {
        return Vec::new();
    };
    let mut next_inserted = Vec::with_capacity(inserted.len() + 1);
    next_inserted.push(Arc::clone(item));
    next_inserted.extend_from_slice(inserted);
    let mut output = permutations_tail(tail, &next_inserted);
    for permutation in permutations_ordered(inserted).into_iter().rev() {
        let mut suffix = permutation.clone();
        suffix.extend_from_slice(tail);
        let mut interleaved = Vec::with_capacity(permutation.len());
        for index in 0..permutation.len() {
            let mut value = suffix.clone();
            value.insert(index, Arc::clone(item));
            interleaved.push(value);
        }
        interleaved.extend(output);
        output = interleaved;
    }
    output
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
            let next = apply2(&function, &accumulator, head);
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

fn scanr(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    seed: &ThunkRef,
    input: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let items = evaluator.force_list_elements(input)?;
    let mut accumulator = Arc::clone(seed);
    let mut results = vec![Arc::clone(seed)];
    for item in items.iter().rev() {
        accumulator = apply2(function, item, &accumulator);
        results.push(Arc::clone(&accumulator));
    }
    results.reverse();
    Ok(ForceOutcome::Alias(list_from(results)))
}

fn sort(evaluator: &mut Evaluator, input: &ThunkRef) -> RuntimeResult<Value> {
    let items = evaluator.force_list_elements(input)?;
    let mut sorted: Vec<ThunkRef> = Vec::with_capacity(items.len());
    for item in items {
        let mut index = sorted.len();
        for (candidate_index, candidate) in sorted.iter().enumerate() {
            if evaluator.less_values(&item, candidate)? {
                index = candidate_index;
                break;
            }
        }
        sorted.insert(index, item);
    }
    Ok(Value::List(list_cell_from(sorted)))
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

fn subsequences(evaluator: &mut Evaluator, input: &ThunkRef) -> RuntimeResult<Value> {
    let items = evaluator.force_list_elements(input)?;
    let mut subsets: Vec<Vec<ThunkRef>> = vec![Vec::new()];
    for item in items {
        let additions = subsets
            .iter()
            .map(|subset| {
                let mut next = subset.clone();
                next.push(Arc::clone(&item));
                next
            })
            .collect::<Vec<_>>();
        subsets.extend(additions);
    }
    Ok(Value::List(list_cell_from(
        subsets.into_iter().map(list_from).collect(),
    )))
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

fn transpose(evaluator: &mut Evaluator, input: &ThunkRef) -> RuntimeResult<Value> {
    let mut rows = evaluator.force_list_elements(input)?;
    let mut columns = Vec::new();
    loop {
        let mut heads = Vec::new();
        let mut tails = Vec::new();
        for row in rows {
            match evaluator.force(&row)?.as_ref() {
                Value::List(ListCell::Nil) => {}
                Value::List(ListCell::Cons { head, tail }) => {
                    heads.push(Arc::clone(head));
                    tails.push(Arc::clone(tail));
                }
                _ => return Err(non_list("List.transpose row")),
            }
        }
        if heads.is_empty() {
            break;
        }
        columns.push(list_from(heads));
        rows = tails;
    }
    Ok(Value::List(list_cell_from(columns)))
}

fn unfoldr(function: ThunkRef, seed: ThunkRef) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let step = evaluator.force(&apply1(&function, &seed))?;
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
            if evaluator.force_bool(&apply1(&predicate, head))? {
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
                head: apply2(&function, left_head, right_head),
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

fn apply1(function: &ThunkRef, argument: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(argument),
    })
}

fn apply2(function: &ThunkRef, first: &ThunkRef, second: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: apply1(function, first),
        argument: Arc::clone(second),
    })
}

fn non_list(operation: &'static str) -> Arc<RuntimeError> {
    RuntimeError::internal(format!("{operation} received a non-list"))
}
