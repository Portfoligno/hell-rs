use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::{
    Evaluator, IoAction, ListCell, PrimitiveFamily, PrimitiveVariantValue, RuntimeContext,
    RuntimeError, RuntimeResult, Suspension, Thunk, ThunkRef, Value, list_from_values,
};
pub(super) use crate::scope::{CancelReason, CancellationToken};
use crate::scope::{ChildScopePolicy, ExecutionScope, ScopeGuard, TaskHandle};

pub(super) fn thread_delay(delay: ThunkRef) -> IoAction {
    IoAction::new(move |evaluator, _| {
        let microseconds = evaluator.force_int(&delay)?;
        if microseconds <= 0 {
            return Ok(Thunk::evaluated(Value::Unit));
        }
        let duration = Duration::from_micros(microseconds.cast_unsigned());
        let deadline = Instant::now()
            .checked_add(duration)
            .ok_or_else(|| RuntimeError::internal("thread delay duration overflowed"))?;
        loop {
            evaluator.ensure_not_cancelled()?;
            let now = Instant::now();
            if now >= deadline {
                return Ok(Thunk::evaluated(Value::Unit));
            }
            if evaluator.cancellation.wait_timeout(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(2)),
            ) {
                return Err(RuntimeError::cancelled());
            }
        }
    })
}

pub(super) fn timeout(delay: ThunkRef, action: ThunkRef) -> IoAction {
    IoAction::new(move |evaluator, context| {
        let microseconds = evaluator.force_int(&delay)?;
        if microseconds == 0 {
            return Ok(Thunk::evaluated(Value::Maybe(None)));
        }
        if microseconds < 0 {
            let action = evaluator.force_io(&action)?;
            let result = action.run(evaluator, context)?;
            return Ok(Thunk::evaluated(Value::Maybe(Some(result))));
        }

        let deadline_duration = Duration::from_micros(microseconds.cast_unsigned());
        let deadline = Instant::now()
            .checked_add(deadline_duration)
            .ok_or_else(|| RuntimeError::internal("timeout deadline overflowed"))?;
        let parent = current_scope(evaluator);
        let child_scope = parent
            .child(ChildScopePolicy {
                deadline: Some(deadline),
            })?
            .guard();
        let mut child = evaluator.fork_with_scope((*child_scope).clone());
        let worker_context = context.clone();
        let action = Arc::clone(&action);
        let worker =
            child_scope.spawn(move |_| run_thunk_caught(&action, &mut child, &worker_context))?;
        loop {
            if let Err(error) = evaluator.ensure_not_cancelled() {
                child_scope.cancel(&CancelReason::ParentCancelled);
                child_scope.close_with_primary(Some(error))?;
                unreachable!("closing with a primary error always returns that error")
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                child_scope.cancel(&CancelReason::Timeout);
                child_scope.close()?;
                return Ok(Thunk::evaluated(Value::Maybe(None)));
            }
            match worker.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(Ok(value)) => {
                    child_scope.close()?;
                    return Ok(Thunk::evaluated(Value::Maybe(Some(value))));
                }
                Ok(Err(error)) => {
                    child_scope.close_with_primary(Some(error))?;
                    unreachable!("closing with a primary error always returns that error")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    child_scope.cancel(&CancelReason::SiblingFailed);
                    child_scope.close_with_primary(Some(RuntimeError::internal(
                        "timeout worker disconnected",
                    )))?;
                    unreachable!("closing with a primary error always returns that error")
                }
            }
        }
    })
}

pub(super) fn concurrently(left: ThunkRef, right: ThunkRef) -> IoAction {
    parallel_pair(left, right, PairMode::Both)
}

pub(super) fn race(left: ThunkRef, right: ThunkRef) -> IoAction {
    parallel_pair(left, right, PairMode::Race)
}

#[derive(Clone, Copy)]
enum PairMode {
    Both,
    Race,
}

fn parallel_pair(left: ThunkRef, right: ThunkRef, mode: PairMode) -> IoAction {
    IoAction::new(move |evaluator, context| {
        evaluator.ensure_not_cancelled()?;
        let pair_scope = current_scope(evaluator)
            .child(ChildScopePolicy::default())?
            .guard();
        let left_scope = pair_scope.child(ChildScopePolicy::default())?.guard();
        let right_scope = pair_scope.child(ChildScopePolicy::default())?.guard();
        let mut left_evaluator = evaluator.fork_with_scope((*left_scope).clone());
        let mut right_evaluator = evaluator.fork_with_scope((*right_scope).clone());
        let left_context = context.clone();
        let right_context = context.clone();
        let left = Arc::clone(&left);
        let right = Arc::clone(&right);
        let (sender, receiver) = mpsc::channel();
        let left_sender = sender.clone();
        let left_worker = left_scope.spawn(move |_| {
            let result = run_thunk_caught(&left, &mut left_evaluator, &left_context);
            let _ignored = left_sender.send((0_usize, result));
            Ok(())
        });
        if let Err(error) = left_worker {
            close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
            unreachable!("closing scopes with a primary error returns the error")
        }
        let right_worker = right_scope.spawn(move |_| {
            let result = run_thunk_caught(&right, &mut right_evaluator, &right_context);
            let _ignored = sender.send((1_usize, result));
            Ok(())
        });
        if let Err(error) = right_worker {
            close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
            unreachable!("closing scopes with a primary error returns the error")
        }

        let first = match recv_parallel_result(&receiver, evaluator) {
            Ok(result) => result,
            Err(error) => {
                pair_scope.cancel(&CancelReason::ParentCancelled);
                close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
                unreachable!("closing scopes with a primary error returns the error")
            }
        };
        if matches!(mode, PairMode::Race) || first.1.is_err() {
            let loser = if first.0 == 0 {
                &right_scope
            } else {
                &left_scope
            };
            let reason = if matches!(mode, PairMode::Race) {
                CancelReason::RaceLost
            } else {
                CancelReason::SiblingFailed
            };
            loser.cancel(&reason);
        }

        match mode {
            PairMode::Race => {
                let (index, result) = first;
                close_pair_scopes(pair_scope, left_scope, right_scope, result.as_ref().err())?;
                result.map(|payload| {
                    Thunk::evaluated(Value::PrimitiveVariant(PrimitiveVariantValue {
                        family: PrimitiveFamily::Either,
                        constructor_index: u8::try_from(index).expect("race side is 0 or 1"),
                        payloads: Arc::from([payload]),
                    }))
                })
            }
            PairMode::Both => {
                if let Err(error) = first.1 {
                    close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
                    unreachable!("closing scopes with a primary error returns the error")
                }
                let second = match recv_parallel_result(&receiver, evaluator) {
                    Ok(result) => result,
                    Err(error) => {
                        pair_scope.cancel(&CancelReason::ParentCancelled);
                        close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
                        unreachable!("closing scopes with a primary error returns the error")
                    }
                };
                if let Err(error) = second.1 {
                    close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
                    unreachable!("closing scopes with a primary error returns the error")
                }
                let mut results: [Option<ThunkRef>; 2] = [None, None];
                let first_value = first.1.expect("parallel error handled above");
                let second_value = second.1.expect("parallel error handled above");
                results[first.0] = Some(first_value);
                results[second.0] = Some(second_value);
                close_pair_scopes(pair_scope, left_scope, right_scope, None)?;
                let left = results[0].take().expect("left parallel result installed");
                let right = results[1].take().expect("right parallel result installed");
                Ok(Thunk::evaluated(Value::Tuple([left, right].into())))
            }
        }
    })
}

fn recv_parallel_result(
    receiver: &mpsc::Receiver<(usize, RuntimeResult<ThunkRef>)>,
    evaluator: &Evaluator,
) -> RuntimeResult<(usize, RuntimeResult<ThunkRef>)> {
    loop {
        evaluator.ensure_not_cancelled()?;
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(result) => return Ok(result),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(RuntimeError::internal(
                    "parallel action workers disconnected",
                ));
            }
        }
    }
}

fn close_pair_scopes(
    pair: ScopeGuard,
    left: ScopeGuard,
    right: ScopeGuard,
    primary: Option<&Arc<RuntimeError>>,
) -> RuntimeResult<()> {
    let mut cleanup_errors = Vec::new();
    for scope in [right, left, pair] {
        if let Err(error) = scope.close() {
            cleanup_errors.push(error);
        }
    }
    if let Some(primary) = primary {
        let mut suppressed = primary.suppressed.to_vec();
        suppressed.extend(cleanup_errors);
        return Err(Arc::new(RuntimeError {
            code: primary.code,
            kind: primary.kind.clone(),
            message: Arc::clone(&primary.message),
            suppressed: suppressed.into(),
        }));
    }
    let mut cleanup_errors = cleanup_errors.into_iter();
    let Some(primary) = cleanup_errors.next() else {
        return Ok(());
    };
    let mut suppressed = primary.suppressed.to_vec();
    suppressed.extend(cleanup_errors);
    Err(Arc::new(RuntimeError {
        code: primary.code,
        kind: primary.kind.clone(),
        message: Arc::clone(&primary.message),
        suppressed: suppressed.into(),
    }))
}

#[allow(clippy::too_many_lines)]
pub(super) fn pooled(callback: ThunkRef, list: ThunkRef, discard_results: bool) -> IoAction {
    IoAction::new(move |evaluator, context| {
        evaluator.ensure_not_cancelled()?;
        let pool_scope = current_scope(evaluator)
            .child(ChildScopePolicy::default())?
            .guard();
        let cancellation = pool_scope.cancellation().clone();
        let worker_count = evaluator.concurrent_action_limit();
        let queue_capacity = worker_count.saturating_mul(2).max(1);
        let (job_sender, job_receiver) = mpsc::sync_channel(queue_capacity);
        let job_receiver = Arc::new(Mutex::new(job_receiver));
        let (result_sender, result_receiver) = mpsc::channel();

        let mut producer_evaluator = evaluator.fork_with_scope((*pool_scope).clone());
        let producer = {
            let list = Arc::clone(&list);
            pool_scope.spawn(move |task_scope| {
                produce_jobs(
                    &mut producer_evaluator,
                    list,
                    &job_sender,
                    task_scope.cancellation(),
                )
            })
        };
        let producer = match producer {
            Ok(producer) => producer,
            Err(error) => {
                pool_scope.close_with_primary(Some(error))?;
                unreachable!(
                    "closing a failed pool with its primary error always returns the error"
                )
            }
        };

        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let receiver = Arc::clone(&job_receiver);
            let sender = result_sender.clone();
            let callback = Arc::clone(&callback);
            let context = context.clone();
            let worker_cancellation = cancellation.clone();
            let mut worker_evaluator = evaluator.fork_with_scope((*pool_scope).clone());
            let worker = pool_scope.spawn(move |task_scope| {
                loop {
                    task_scope.safepoint()?;
                    if worker_cancellation.is_cancelled() {
                        break;
                    }
                    let job = receiver
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv_timeout(Duration::from_millis(10));
                    let (index, item) = match job {
                        Ok(job) => job,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let result = run_callback(&callback, item, &mut worker_evaluator, &context);
                    let failed = result.is_err();
                    if sender.send((index, result)).is_err() {
                        break;
                    }
                    if failed {
                        worker_cancellation.cancel(CancelReason::SiblingFailed);
                        break;
                    }
                }
                Ok(())
            });
            match worker {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    pool_scope.close_with_primary(Some(error))?;
                    unreachable!(
                        "closing a failed pool with its primary error always returns the error"
                    )
                }
            }
        }
        drop(job_receiver);
        drop(result_sender);

        let mut values = Vec::new();
        let mut first_error = None;
        loop {
            if let Err(error) = evaluator.ensure_not_cancelled() {
                pool_scope.cancel(&CancelReason::ParentCancelled);
                pool_scope.close_with_primary(Some(error))?;
                unreachable!(
                    "closing a failed pool with its primary error always returns the error"
                )
            }
            match result_receiver.recv_timeout(Duration::from_millis(10)) {
                Ok((index, result)) => match result {
                    Ok(value) => values.push((index, value)),
                    Err(error) => {
                        pool_scope.cancel(&CancelReason::SiblingFailed);
                        first_error.get_or_insert(error);
                    }
                },
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        if let Some(error) = first_error {
            pool_scope.close_with_primary(Some(error))?;
            unreachable!("closing a failed pool with its primary error always returns the error")
        }

        let cleanup_window = pool_scope.cleanup_window();
        let input_count =
            match recv_finished_task(&producer, "pooled input producer", cleanup_window) {
                Ok(count) => count,
                Err(error) => {
                    pool_scope.close_with_primary(Some(error))?;
                    unreachable!(
                        "closing a failed pool with its primary error always returns the error"
                    )
                }
            };
        for worker in &workers {
            if let Err(error) = recv_finished_task(worker, "pooled worker", cleanup_window) {
                pool_scope.close_with_primary(Some(error))?;
                unreachable!(
                    "closing a failed pool with its primary error always returns the error"
                )
            }
        }
        pool_scope.close()?;
        let count = input_count;
        values.sort_unstable_by_key(|(index, _)| *index);
        if values.len() != count {
            return Err(RuntimeError::internal(
                "pooled action completed without one result per input",
            ));
        }
        if discard_results {
            Ok(Thunk::evaluated(Value::Unit))
        } else {
            Ok(list_from_values(
                values.into_iter().map(|(_, value)| value).collect(),
            ))
        }
    })
}

fn recv_finished_task<T>(
    task: &TaskHandle<T>,
    label: &str,
    cleanup_window: Duration,
) -> RuntimeResult<T> {
    match task.recv_timeout(cleanup_window) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(RuntimeError::internal(format!(
            "CancellationStalled: {label} did not publish its completed result"
        ))),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(RuntimeError::internal(format!(
            "{label} disconnected without a result"
        ))),
    }
}

fn send_job(
    sender: &mpsc::SyncSender<(usize, ThunkRef)>,
    cancellation: &CancellationToken,
    mut job: (usize, ThunkRef),
) -> RuntimeResult<()> {
    loop {
        cancellation.check()?;
        match sender.try_send(job) {
            Ok(()) => return Ok(()),
            Err(mpsc::TrySendError::Full(returned)) => {
                job = returned;
                if cancellation.wait_timeout(Duration::from_millis(2)) {
                    return Err(RuntimeError::cancelled());
                }
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(RuntimeError::cancelled());
            }
        }
    }
}

fn produce_jobs(
    evaluator: &mut Evaluator,
    list: ThunkRef,
    sender: &mpsc::SyncSender<(usize, ThunkRef)>,
    cancellation: &CancellationToken,
) -> RuntimeResult<usize> {
    let mut current = list;
    let mut index = 0_usize;
    loop {
        if cancellation.is_cancelled() {
            return Err(RuntimeError::cancelled());
        }
        match evaluator.force(&current)?.as_ref() {
            Value::List(ListCell::Nil) => return Ok(index),
            Value::List(ListCell::Cons { head, tail }) => {
                send_job(sender, cancellation, (index, Arc::clone(head)))?;
                index = index
                    .checked_add(1)
                    .ok_or_else(|| RuntimeError::resource_limit("pooled input is too large"))?;
                current = Arc::clone(tail);
            }
            _ => return Err(RuntimeError::internal("pooled action received a non-list")),
        }
    }
}

fn run_callback(
    callback: &ThunkRef,
    item: ThunkRef,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
) -> RuntimeResult<ThunkRef> {
    evaluator.ensure_not_cancelled()?;
    let application = Thunk::suspended(Suspension::Apply {
        function: Arc::clone(callback),
        argument: item,
    });
    let action = evaluator.force_io(&application)?;
    run_caught(&action, evaluator, context)
}

fn run_caught(
    action: &IoAction,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
) -> RuntimeResult<ThunkRef> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluator.ensure_not_cancelled()?;
        action.run(evaluator, context)
    }))
    .unwrap_or_else(|_| {
        Err(RuntimeError::panic_contained(
            "panic crossed a concurrent IO action boundary",
        ))
    })
}

fn current_scope(evaluator: &Evaluator) -> ExecutionScope {
    evaluator.execution_scope().clone()
}

fn run_thunk_caught(
    action: &ThunkRef,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
) -> RuntimeResult<ThunkRef> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluator.ensure_not_cancelled()?;
        let action = evaluator.force_io(action)?;
        action.run(evaluator, context)
    }))
    .unwrap_or_else(|_| {
        Err(RuntimeError::panic_contained(
            "panic crossed a concurrent IO action boundary",
        ))
    })
}
