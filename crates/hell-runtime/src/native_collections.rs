//! Ordered `Map` and `Set` adapters over lazy runtime values.

use std::sync::Arc;

use crate::{
    Evaluator, ForceOutcome, RuntimeError, RuntimeResult, Suspension, Thunk, ThunkRef, Value,
    list_from_values,
};

type MapEntry = (ThunkRef, ThunkRef);

enum Position {
    Occupied(usize),
    Vacant(usize),
}

pub(super) fn apply_native(
    implementation: &str,
    arguments: &[ThunkRef],
    evaluator: &mut Evaluator,
) -> Option<RuntimeResult<ForceOutcome>> {
    Some(match implementation {
        "map_from_list" => map_from_list(evaluator, &arguments[0]),
        "map_to_list" => map_to_list(evaluator, &arguments[0]),
        "map_lookup" => map_lookup(evaluator, &arguments[0], &arguments[1]),
        "map_insert" => map_insert(evaluator, &arguments[0], &arguments[1], &arguments[2]),
        "map_delete" => map_delete(evaluator, &arguments[0], &arguments[1]),
        "map_singleton" => Ok(collection(Value::Map(
            [(Arc::clone(&arguments[0]), Arc::clone(&arguments[1]))].into(),
        ))),
        "map_size" => map_size(evaluator, &arguments[0]),
        "map_filter" => map_filter(evaluator, &arguments[0], &arguments[1], false),
        "map_filter_with_key" => map_filter(evaluator, &arguments[0], &arguments[1], true),
        "map_any" => map_quantifier(evaluator, &arguments[0], &arguments[1], false),
        "map_all" => map_quantifier(evaluator, &arguments[0], &arguments[1], true),
        "map_insert_with" => map_insert_with(evaluator, arguments),
        "map_adjust" => map_adjust(evaluator, arguments),
        "map_union_with" => map_union_with(evaluator, arguments),
        "map_map" => map_values(evaluator, &arguments[0], &arguments[1]),
        "map_keys" => map_keys(evaluator, &arguments[0]),
        "map_elems" => map_elems(evaluator, &arguments[0]),
        "set_from_list" => set_from_list(evaluator, &arguments[0]),
        "set_to_list" => set_to_list(evaluator, &arguments[0]),
        "set_insert" => set_insert(evaluator, &arguments[0], &arguments[1]),
        "set_member" => set_member(evaluator, &arguments[0], &arguments[1]),
        "set_delete" => set_delete(evaluator, &arguments[0], &arguments[1]),
        "set_union" => set_merge(evaluator, &arguments[0], &arguments[1], SetMerge::Union),
        "set_difference" => set_merge(
            evaluator,
            &arguments[0],
            &arguments[1],
            SetMerge::Difference,
        ),
        "set_intersection" => set_merge(
            evaluator,
            &arguments[0],
            &arguments[1],
            SetMerge::Intersection,
        ),
        "set_size" => set_size(evaluator, &arguments[0]),
        "set_singleton" => Ok(collection(Value::Set([Arc::clone(&arguments[0])].into()))),
        _ => return None,
    })
}

fn collection(value: Value) -> ForceOutcome {
    ForceOutcome::Value(Arc::new(value))
}

fn force_map(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<Arc<[MapEntry]>> {
    match evaluator.force(map)?.as_ref() {
        Value::Map(entries) => Ok(Arc::clone(entries)),
        _ => Err(RuntimeError::internal(
            "Map operation received a non-Map value",
        )),
    }
}

fn force_set(evaluator: &mut Evaluator, set: &ThunkRef) -> RuntimeResult<Arc<[ThunkRef]>> {
    match evaluator.force(set)?.as_ref() {
        Value::Set(elements) => Ok(Arc::clone(elements)),
        _ => Err(RuntimeError::internal(
            "Set operation received a non-Set value",
        )),
    }
}

fn position<T>(
    evaluator: &mut Evaluator,
    values: &[T],
    key: &ThunkRef,
    key_of: impl Fn(&T) -> &ThunkRef,
) -> RuntimeResult<Position> {
    for (index, value) in values.iter().enumerate() {
        let existing = key_of(value);
        if evaluator.equal_values(key, existing)? {
            return Ok(Position::Occupied(index));
        }
        if evaluator.less_values(key, existing)? {
            return Ok(Position::Vacant(index));
        }
    }
    Ok(Position::Vacant(values.len()))
}

fn map_from_list(evaluator: &mut Evaluator, list: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let pairs = evaluator.force_list_elements(list)?;
    let mut entries = Vec::<MapEntry>::with_capacity(pairs.len());
    for pair in pairs {
        let pair = evaluator.force(&pair)?;
        let Value::Tuple(elements) = pair.as_ref() else {
            return Err(RuntimeError::internal(
                "Map.fromList received a non-pair element",
            ));
        };
        let [key, item] = elements.as_ref() else {
            return Err(RuntimeError::internal(
                "Map.fromList received a tuple with the wrong arity",
            ));
        };
        match position(evaluator, &entries, key, |(key, _)| key)? {
            Position::Occupied(index) => {
                entries[index] = (Arc::clone(key), Arc::clone(item));
            }
            Position::Vacant(index) => {
                entries.insert(index, (Arc::clone(key), Arc::clone(item)));
            }
        }
    }
    Ok(collection(Value::Map(entries.into())))
}

fn map_to_list(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let pairs = entries
        .iter()
        .map(|(key, item)| {
            Thunk::evaluated(Value::Tuple([Arc::clone(key), Arc::clone(item)].into()))
        })
        .collect();
    Ok(ForceOutcome::Alias(list_from_values(pairs)))
}

fn map_lookup(
    evaluator: &mut Evaluator,
    key: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let found = match position(evaluator, &entries, key, |(key, _)| key)? {
        Position::Occupied(index) => Some(Arc::clone(&entries[index].1)),
        Position::Vacant(_) => None,
    };
    Ok(collection(Value::Maybe(found)))
}

fn map_insert(
    evaluator: &mut Evaluator,
    key: &ThunkRef,
    item: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut entries = force_map(evaluator, map)?.to_vec();
    match position(evaluator, &entries, key, |(key, _)| key)? {
        Position::Occupied(index) => {
            entries[index] = (Arc::clone(key), Arc::clone(item));
        }
        Position::Vacant(index) => {
            entries.insert(index, (Arc::clone(key), Arc::clone(item)));
        }
    }
    Ok(collection(Value::Map(entries.into())))
}

fn map_delete(
    evaluator: &mut Evaluator,
    key: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut entries = force_map(evaluator, map)?.to_vec();
    if let Position::Occupied(index) = position(evaluator, &entries, key, |(key, _)| key)? {
        entries.remove(index);
    }
    Ok(collection(Value::Map(entries.into())))
}

fn map_size(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let size = force_map(evaluator, map)?.len();
    Ok(collection(Value::Int(
        i64::try_from(size).unwrap_or(i64::MAX),
    )))
}

fn map_filter(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    map: &ThunkRef,
    with_key: bool,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let mut filtered = Vec::new();
    for (key, item) in entries.iter() {
        let application = if with_key {
            let with_key = apply(predicate, key);
            apply(&with_key, item)
        } else {
            apply(predicate, item)
        };
        if evaluator.force_bool(&application)? {
            filtered.push((Arc::clone(key), Arc::clone(item)));
        }
    }
    Ok(collection(Value::Map(filtered.into())))
}

fn map_quantifier(
    evaluator: &mut Evaluator,
    predicate: &ThunkRef,
    map: &ThunkRef,
    all: bool,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    for (_, item) in entries.iter() {
        if evaluator.force_bool(&apply(predicate, item))? != all {
            return Ok(collection(Value::Bool(!all)));
        }
    }
    Ok(collection(Value::Bool(all)))
}

fn map_insert_with(
    evaluator: &mut Evaluator,
    arguments: &[ThunkRef],
) -> RuntimeResult<ForceOutcome> {
    let function = &arguments[0];
    let key = &arguments[1];
    let item = &arguments[2];
    let mut entries = force_map(evaluator, &arguments[3])?.to_vec();
    match position(evaluator, &entries, key, |(key, _)| key)? {
        Position::Occupied(index) => {
            let combined = apply(&apply(function, item), &entries[index].1);
            entries[index] = (Arc::clone(key), combined);
        }
        Position::Vacant(index) => {
            entries.insert(index, (Arc::clone(key), Arc::clone(item)));
        }
    }
    Ok(collection(Value::Map(entries.into())))
}

fn map_adjust(evaluator: &mut Evaluator, arguments: &[ThunkRef]) -> RuntimeResult<ForceOutcome> {
    let function = &arguments[0];
    let key = &arguments[1];
    let mut entries = force_map(evaluator, &arguments[2])?.to_vec();
    if let Position::Occupied(index) = position(evaluator, &entries, key, |(key, _)| key)? {
        entries[index].1 = apply(function, &entries[index].1);
    }
    Ok(collection(Value::Map(entries.into())))
}

fn map_union_with(
    evaluator: &mut Evaluator,
    arguments: &[ThunkRef],
) -> RuntimeResult<ForceOutcome> {
    let function = &arguments[0];
    let mut entries = force_map(evaluator, &arguments[1])?.to_vec();
    let right = force_map(evaluator, &arguments[2])?;
    for (right_key, right_item) in right.iter() {
        match position(evaluator, &entries, right_key, |(key, _)| key)? {
            Position::Occupied(index) => {
                entries[index].1 = apply(&apply(function, &entries[index].1), right_item);
            }
            Position::Vacant(index) => {
                entries.insert(index, (Arc::clone(right_key), Arc::clone(right_item)));
            }
        }
    }
    Ok(collection(Value::Map(entries.into())))
}

fn map_values(
    evaluator: &mut Evaluator,
    function: &ThunkRef,
    map: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    let mapped = entries
        .iter()
        .map(|(key, item)| (Arc::clone(key), apply(function, item)))
        .collect::<Vec<_>>();
    Ok(collection(Value::Map(mapped.into())))
}

fn map_keys(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    Ok(ForceOutcome::Alias(list_from_values(
        entries.iter().map(|(key, _)| Arc::clone(key)).collect(),
    )))
}

fn map_elems(evaluator: &mut Evaluator, map: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let entries = force_map(evaluator, map)?;
    Ok(ForceOutcome::Alias(list_from_values(
        entries.iter().map(|(_, item)| Arc::clone(item)).collect(),
    )))
}

fn apply(function: &ThunkRef, argument: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(argument),
    })
}

fn set_from_list(evaluator: &mut Evaluator, list: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let input = evaluator.force_list_elements(list)?;
    let mut elements = Vec::with_capacity(input.len());
    for element in input {
        match position(evaluator, &elements, &element, |element| element)? {
            Position::Occupied(index) => elements[index] = element,
            Position::Vacant(index) => elements.insert(index, element),
        }
    }
    Ok(collection(Value::Set(elements.into())))
}

fn set_to_list(evaluator: &mut Evaluator, set: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    Ok(ForceOutcome::Alias(list_from_values(
        force_set(evaluator, set)?.to_vec(),
    )))
}

fn set_insert(
    evaluator: &mut Evaluator,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut elements = force_set(evaluator, set)?.to_vec();
    match position(evaluator, &elements, element, |element| element)? {
        Position::Occupied(index) => elements[index] = Arc::clone(element),
        Position::Vacant(index) => elements.insert(index, Arc::clone(element)),
    }
    Ok(collection(Value::Set(elements.into())))
}

fn set_member(
    evaluator: &mut Evaluator,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let elements = force_set(evaluator, set)?;
    Ok(collection(Value::Bool(matches!(
        position(evaluator, &elements, element, |element| element)?,
        Position::Occupied(_)
    ))))
}

fn set_delete(
    evaluator: &mut Evaluator,
    element: &ThunkRef,
    set: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let mut elements = force_set(evaluator, set)?.to_vec();
    if let Position::Occupied(index) = position(evaluator, &elements, element, |element| element)? {
        elements.remove(index);
    }
    Ok(collection(Value::Set(elements.into())))
}

#[derive(Clone, Copy)]
enum SetMerge {
    Union,
    Difference,
    Intersection,
}

fn set_merge(
    evaluator: &mut Evaluator,
    left: &ThunkRef,
    right: &ThunkRef,
    operation: SetMerge,
) -> RuntimeResult<ForceOutcome> {
    let left = force_set(evaluator, left)?;
    let right = force_set(evaluator, right)?;
    let mut output = match operation {
        SetMerge::Union | SetMerge::Difference => left.to_vec(),
        SetMerge::Intersection => Vec::new(),
    };
    match operation {
        SetMerge::Union => {
            for element in right.iter() {
                if let Position::Vacant(index) =
                    position(evaluator, &output, element, |element| element)?
                {
                    output.insert(index, Arc::clone(element));
                }
            }
        }
        SetMerge::Difference => {
            for element in right.iter() {
                if let Position::Occupied(index) =
                    position(evaluator, &output, element, |element| element)?
                {
                    output.remove(index);
                }
            }
        }
        SetMerge::Intersection => {
            for element in left.iter() {
                if matches!(
                    position(evaluator, &right, element, |element| element)?,
                    Position::Occupied(_)
                ) {
                    output.push(Arc::clone(element));
                }
            }
        }
    }
    Ok(collection(Value::Set(output.into())))
}

fn set_size(evaluator: &mut Evaluator, set: &ThunkRef) -> RuntimeResult<ForceOutcome> {
    let size = force_set(evaluator, set)?.len();
    Ok(collection(Value::Int(
        i64::try_from(size).unwrap_or(i64::MAX),
    )))
}
