//! Executable compatibility translation for the pinned row/tag primitives.

use std::sync::Arc;

use crate::{
    Evaluator, ForceOutcome, RuntimeError, RuntimeResult, Suspension, Thunk, ThunkRef, Value,
};

/// Runtime-only values used by the source implementation's row/tag lowering.
///
/// The Rust compiler normally emits direct record and variant core nodes, but
/// these shapes keep every pinned internal registry entry executable for core
/// compatibility and independently constructed verified programs.
#[derive(Clone, Debug)]
pub enum InternalValue {
    RecordNil,
    RecordCons { value: ThunkRef, tail: ThunkRef },
    VariantLeft(ThunkRef),
    VariantRight(ThunkRef),
    AccessorNil,
    AccessorCons { handler: ThunkRef, tail: ThunkRef },
    AccessorWild(ThunkRef),
    Tagged(ThunkRef),
    Nullary,
}

pub(super) fn apply_native(
    implementation: &str,
    arguments: &[ThunkRef],
    evaluator: &mut Evaluator,
) -> Option<RuntimeResult<ForceOutcome>> {
    let internal = |value| Ok(ForceOutcome::Value(Arc::new(Value::Internal(value))));
    Some(match implementation {
        "internal_record_nil" => internal(InternalValue::RecordNil),
        "internal_record_cons" => internal(InternalValue::RecordCons {
            value: Arc::clone(&arguments[0]),
            tail: Arc::clone(&arguments[1]),
        }),
        "internal_variant_left" => internal(InternalValue::VariantLeft(Arc::clone(&arguments[0]))),
        "internal_variant_right" => {
            internal(InternalValue::VariantRight(Arc::clone(&arguments[0])))
        }
        "internal_accessor_nil" => internal(InternalValue::AccessorNil),
        "internal_accessor_cons" => internal(InternalValue::AccessorCons {
            handler: Arc::clone(&arguments[0]),
            tail: Arc::clone(&arguments[1]),
        }),
        "internal_accessor_wild" => {
            internal(InternalValue::AccessorWild(Arc::clone(&arguments[0])))
        }
        "internal_tagged" => internal(InternalValue::Tagged(Arc::clone(&arguments[0]))),
        "internal_nullary" => internal(InternalValue::Nullary),
        "internal_run_accessor" => run_accessor(evaluator, &arguments[0], &arguments[1]),
        _ => return None,
    })
}

fn run_accessor(
    evaluator: &mut Evaluator,
    tagged: &ThunkRef,
    accessor: &ThunkRef,
) -> RuntimeResult<ForceOutcome> {
    let tagged = evaluator.force(tagged)?;
    let Value::Internal(InternalValue::Tagged(mut variant)) = tagged.as_ref().clone() else {
        return Err(RuntimeError::internal(
            "hell:Hell.runAccessor received an untagged variant",
        ));
    };
    let mut accessor = Arc::clone(accessor);
    loop {
        let accessor_value = evaluator.force(&accessor)?;
        match accessor_value.as_ref() {
            Value::Internal(InternalValue::AccessorWild(result)) => {
                return Ok(ForceOutcome::Alias(Arc::clone(result)));
            }
            Value::Internal(InternalValue::AccessorCons { handler, tail }) => {
                let variant_value = evaluator.force(&variant)?;
                match variant_value.as_ref() {
                    Value::Internal(InternalValue::VariantLeft(payload)) => {
                        return Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                            function: Arc::clone(handler),
                            argument: Arc::clone(payload),
                        })));
                    }
                    Value::Internal(InternalValue::VariantRight(next)) => {
                        variant = Arc::clone(next);
                        accessor = Arc::clone(tail);
                    }
                    _ => {
                        return Err(RuntimeError::internal(
                            "hell:Hell.runAccessor received a malformed variant spine",
                        ));
                    }
                }
            }
            Value::Internal(InternalValue::AccessorNil) => {
                return Err(RuntimeError::internal(
                    "hell:Hell.runAccessor reached a non-exhaustive accessor",
                ));
            }
            _ => {
                return Err(RuntimeError::internal(
                    "hell:Hell.runAccessor received a malformed accessor spine",
                ));
            }
        }
    }
}
