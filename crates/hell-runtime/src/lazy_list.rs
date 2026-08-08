//! Shared co-recursive list building blocks for native adapters.

use std::sync::Arc;

use crate::{Evaluator, ListCell, RuntimeError, RuntimeResult, Suspension, Thunk, ThunkRef, Value};

#[derive(Clone)]
pub(crate) enum Classifier {
    Predicate(ThunkRef),
    Relation {
        first: ThunkRef,
        function: Option<ThunkRef>,
    },
}

impl Classifier {
    fn decision(&self, item: &ThunkRef) -> ThunkRef {
        match self {
            Self::Predicate(function) => apply1(function, item),
            Self::Relation {
                first,
                function: Some(function),
            } => apply2(function, first, item),
            Self::Relation {
                first,
                function: None,
            } => {
                let first = Arc::clone(first);
                let item = Arc::clone(item);
                Thunk::deferred(move |evaluator| {
                    Ok(Arc::new(Value::Bool(
                        evaluator.equal_values(&first, &item)?,
                    )))
                })
            }
        }
    }
}

pub(crate) fn apply1(function: &ThunkRef, argument: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: Arc::clone(function),
        argument: Arc::clone(argument),
    })
}

pub(crate) fn apply2(function: &ThunkRef, first: &ThunkRef, second: &ThunkRef) -> ThunkRef {
    Thunk::suspended(Suspension::Apply {
        function: apply1(function, first),
        argument: Arc::clone(second),
    })
}

/// Builds a memoized stream of `(decision, item, original-suffix)` triples.
/// Both consumers of a split operation therefore share every guest predicate
/// application and can return the untouched source at the first boundary.
pub(crate) fn classify(
    classifier: Classifier,
    input: ThunkRef,
    operation: &'static str,
) -> ThunkRef {
    Thunk::deferred(move |evaluator| match evaluator.force(&input)?.as_ref() {
        Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
        Value::List(ListCell::Cons { head, tail }) => {
            let decision = classifier.decision(head);
            let entry = Thunk::evaluated(Value::Tuple(
                [decision, Arc::clone(head), Arc::clone(&input)].into(),
            ));
            Ok(Arc::new(Value::List(ListCell::Cons {
                head: entry,
                tail: classify(classifier.clone(), Arc::clone(tail), operation),
            })))
        }
        _ => Err(non_list(operation)),
    })
}

pub(crate) fn take_class(classified: ThunkRef, wanted: bool, operation: &'static str) -> ThunkRef {
    Thunk::deferred(
        move |evaluator| match evaluator.force(&classified)?.as_ref() {
            Value::List(ListCell::Nil) => Ok(Arc::new(Value::List(ListCell::Nil))),
            Value::List(ListCell::Cons { head, tail }) => {
                let (decision, item, _) = force_classified(evaluator, head, operation)?;
                let accepted = force_bool(evaluator, &decision)?;
                if accepted == wanted {
                    Ok(Arc::new(Value::List(ListCell::Cons {
                        head: item,
                        tail: take_class(Arc::clone(tail), wanted, operation),
                    })))
                } else {
                    Ok(Arc::new(Value::List(ListCell::Nil)))
                }
            }
            _ => Err(non_list(operation)),
        },
    )
}

pub(crate) fn drop_class(classified: ThunkRef, wanted: bool, operation: &'static str) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let mut current = Arc::clone(&classified);
        loop {
            evaluator.ensure_not_cancelled()?;
            match evaluator.force(&current)?.as_ref() {
                Value::List(ListCell::Nil) => {
                    return Ok(Arc::new(Value::List(ListCell::Nil)));
                }
                Value::List(ListCell::Cons { head, tail }) => {
                    let (decision, _, original) = force_classified(evaluator, head, operation)?;
                    if force_bool(evaluator, &decision)? != wanted {
                        return evaluator.force(&original);
                    }
                    current = Arc::clone(tail);
                }
                _ => return Err(non_list(operation)),
            }
        }
    })
}

pub(crate) fn select_class(
    classified: ThunkRef,
    wanted: bool,
    operation: &'static str,
) -> ThunkRef {
    Thunk::deferred(move |evaluator| {
        let mut current = Arc::clone(&classified);
        loop {
            evaluator.ensure_not_cancelled()?;
            match evaluator.force(&current)?.as_ref() {
                Value::List(ListCell::Nil) => {
                    return Ok(Arc::new(Value::List(ListCell::Nil)));
                }
                Value::List(ListCell::Cons { head, tail }) => {
                    let (decision, item, _) = force_classified(evaluator, head, operation)?;
                    if force_bool(evaluator, &decision)? == wanted {
                        return Ok(Arc::new(Value::List(ListCell::Cons {
                            head: item,
                            tail: select_class(Arc::clone(tail), wanted, operation),
                        })));
                    }
                    current = Arc::clone(tail);
                }
                _ => return Err(non_list(operation)),
            }
        }
    })
}

fn force_classified(
    evaluator: &mut Evaluator,
    value: &ThunkRef,
    operation: &'static str,
) -> RuntimeResult<(ThunkRef, ThunkRef, ThunkRef)> {
    match evaluator.force(value)?.as_ref() {
        Value::Tuple(elements) if elements.len() == 3 => Ok((
            Arc::clone(&elements[0]),
            Arc::clone(&elements[1]),
            Arc::clone(&elements[2]),
        )),
        _ => Err(RuntimeError::internal(format!(
            "{operation} produced malformed classification state"
        ))),
    }
}

fn force_bool(evaluator: &mut Evaluator, value: &ThunkRef) -> RuntimeResult<bool> {
    match evaluator.force(value)?.as_ref() {
        Value::Bool(value) => Ok(*value),
        _ => Err(RuntimeError::internal(
            "lazy list classifier returned a non-Bool",
        )),
    }
}

fn non_list(operation: &'static str) -> Arc<RuntimeError> {
    RuntimeError::internal(format!("{operation} received a non-list"))
}
