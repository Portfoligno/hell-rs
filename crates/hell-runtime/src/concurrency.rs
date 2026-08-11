use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

#[cfg(feature = "compat-tracing")]
use super::RuntimeErrorKind;
#[cfg(not(feature = "compat-tracing"))]
use super::Suspension;
use super::{
    BuiltinId, Evaluator, IoAction, ListCell, PrimitiveFamily, PrimitiveVariantValue,
    RuntimeContext, RuntimeError, RuntimeResult, Thunk, ThunkRef, Value, list_from_values,
};
#[cfg(feature = "compat-tracing")]
use crate::AdapterCausalIdentity;
pub(super) use crate::scope::{CancelReason, CancellationToken};
use crate::scope::{ChildScopePolicy, ExecutionScope, ScopeGuard, TaskHandle};

pub(super) fn thread_delay(builtin: BuiltinId, delay: ThunkRef) -> IoAction {
    IoAction::new(move |evaluator, _| {
        #[cfg(not(feature = "compat-tracing"))]
        let _ = builtin;
        #[cfg(feature = "compat-tracing")]
        let task = evaluator.record_task_started(builtin)?;
        let microseconds = match evaluator.force_int(&delay) {
            Ok(microseconds) => microseconds,
            Err(error) => {
                #[cfg(feature = "compat-tracing")]
                evaluator.record_task_terminal(builtin, task, "failed")?;
                return Err(error);
            }
        };
        if microseconds <= 0 {
            #[cfg(feature = "compat-tracing")]
            evaluator.record_task_terminal(builtin, task, "completed")?;
            return Ok(Thunk::evaluated(Value::Unit));
        }
        let duration = Duration::from_micros(microseconds.cast_unsigned());
        let Some(deadline) = Instant::now().checked_add(duration) else {
            #[cfg(feature = "compat-tracing")]
            evaluator.record_task_terminal(builtin, task, "failed")?;
            return Err(RuntimeError::internal("thread delay duration overflowed"));
        };
        loop {
            #[cfg(feature = "compat-tracing")]
            if let Err(error) = evaluator.ensure_not_cancelled() {
                evaluator.record_task_terminal(builtin, task, "cancelled")?;
                return Err(error);
            }
            #[cfg(not(feature = "compat-tracing"))]
            evaluator.ensure_not_cancelled()?;
            let now = Instant::now();
            if now >= deadline {
                #[cfg(feature = "compat-tracing")]
                evaluator.record_task_terminal(builtin, task, "completed")?;
                return Ok(Thunk::evaluated(Value::Unit));
            }
            if evaluator.cancellation.wait_timeout(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(2)),
            ) {
                #[cfg(feature = "compat-tracing")]
                evaluator.record_task_terminal(builtin, task, "cancelled")?;
                return Err(RuntimeError::cancelled());
            }
        }
    })
}

pub(super) fn timeout(builtin: BuiltinId, delay: ThunkRef, action: ThunkRef) -> IoAction {
    IoAction::new(move |evaluator, context| {
        #[cfg(not(feature = "compat-tracing"))]
        let _ = builtin;
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
        #[cfg(feature = "compat-tracing")]
        let task = evaluator.record_task_started(builtin)?;
        #[cfg(feature = "compat-tracing")]
        {
            child.current_evidence_task = (task != 0).then_some(task);
        }
        let worker_context = context.clone();
        let action = Arc::clone(&action);
        let worker =
            child_scope.spawn(move |_| run_thunk_caught(&action, &mut child, &worker_context))?;
        loop {
            if let Err(error) = evaluator.ensure_not_cancelled() {
                child_scope.cancel(&CancelReason::ParentCancelled);
                #[cfg(feature = "compat-tracing")]
                evaluator.record_task_terminal(builtin, task, "cancelled")?;
                child_scope.close_with_primary(Some(error))?;
                unreachable!("closing with a primary error always returns that error")
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                child_scope.cancel(&CancelReason::Timeout);
                #[cfg(feature = "compat-tracing")]
                evaluator.record_task_terminal(builtin, task, "cancelled")?;
                child_scope.close()?;
                return Ok(Thunk::evaluated(Value::Maybe(None)));
            }
            match worker.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(Ok(value)) => {
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_task_terminal(builtin, task, "completed")?;
                    child_scope.close()?;
                    return Ok(Thunk::evaluated(Value::Maybe(Some(value))));
                }
                Ok(Err(error)) => {
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_task_terminal(builtin, task, "failed")?;
                    child_scope.close_with_primary(Some(error))?;
                    unreachable!("closing with a primary error always returns that error")
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    child_scope.cancel(&CancelReason::SiblingFailed);
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_task_terminal(builtin, task, "cancelled")?;
                    child_scope.close_with_primary(Some(RuntimeError::internal(
                        "timeout worker disconnected",
                    )))?;
                    unreachable!("closing with a primary error always returns that error")
                }
            }
        }
    })
}

pub(super) fn concurrently(builtin: BuiltinId, left: ThunkRef, right: ThunkRef) -> IoAction {
    parallel_pair(builtin, left, right, PairMode::Both)
}

pub(super) fn race(builtin: BuiltinId, left: ThunkRef, right: ThunkRef) -> IoAction {
    parallel_pair(builtin, left, right, PairMode::Race)
}

#[derive(Clone, Copy)]
enum PairMode {
    Both,
    Race,
}

#[derive(Default)]
struct PairPreparationGate {
    state: Mutex<PairPreparationState>,
    ready: Condvar,
}

#[derive(Default)]
struct PairPreparationState {
    arrived: u8,
    aborted: bool,
}

impl PairPreparationGate {
    fn arrive_and_wait(&self) -> RuntimeResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::internal("pair preparation gate was poisoned"))?;
        state.arrived = state.arrived.saturating_add(1);
        self.ready.notify_all();
        while state.arrived != 2 && !state.aborted {
            state = self
                .ready
                .wait(state)
                .map_err(|_| RuntimeError::internal("pair preparation gate was poisoned"))?;
        }
        if state.aborted {
            Err(RuntimeError::internal("parallel pair preparation aborted"))
        } else {
            Ok(())
        }
    }

    fn abort(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.aborted = true;
            self.ready.notify_all();
        }
    }
}

type PreparedPair = (ScopeGuard, ScopeGuard, Evaluator, Evaluator, u64, u64);

fn prepare_pair(
    evaluator: &mut Evaluator,
    pair_scope: &ScopeGuard,
    builtin: BuiltinId,
) -> RuntimeResult<PreparedPair> {
    let left_scope = pair_scope.child(ChildScopePolicy::default())?.guard();
    let right_scope = pair_scope.child(ChildScopePolicy::default())?.guard();
    let mut left_evaluator = evaluator.fork_with_scope((*left_scope).clone());
    let mut right_evaluator = evaluator.fork_with_scope((*right_scope).clone());
    #[cfg(feature = "compat-tracing")]
    let left_task = evaluator.record_task_started(builtin)?;
    #[cfg(not(feature = "compat-tracing"))]
    let left_task = 0;
    #[cfg(feature = "compat-tracing")]
    let right_task = evaluator.record_task_started(builtin)?;
    #[cfg(not(feature = "compat-tracing"))]
    let right_task = 0;
    #[cfg(feature = "compat-tracing")]
    {
        left_evaluator.current_evidence_task = (left_task != 0).then_some(left_task);
        right_evaluator.current_evidence_task = (right_task != 0).then_some(right_task);
    }
    #[cfg(not(feature = "compat-tracing"))]
    {
        let _ = (
            &mut left_evaluator,
            &mut right_evaluator,
            builtin,
            left_task,
            right_task,
        );
    }
    Ok((
        left_scope,
        right_scope,
        left_evaluator,
        right_evaluator,
        left_task,
        right_task,
    ))
}

fn parallel_pair(builtin: BuiltinId, left: ThunkRef, right: ThunkRef, mode: PairMode) -> IoAction {
    parallel_pair_with_cancellation_observer(builtin, left, right, mode, || {})
}

fn parallel_pair_with_cancellation_observer(
    builtin: BuiltinId,
    left: ThunkRef,
    right: ThunkRef,
    mode: PairMode,
    observe_cancellation: impl Fn() + Send + Sync + 'static,
) -> IoAction {
    IoAction::new(move |evaluator, context| {
        #[cfg(not(feature = "compat-tracing"))]
        let _ = builtin;
        evaluator.ensure_not_cancelled()?;
        let pair_scope = current_scope(evaluator)
            .child(ChildScopePolicy::default())?
            .guard();
        let (
            left_scope,
            right_scope,
            mut left_evaluator,
            mut right_evaluator,
            left_task,
            right_task,
        ) = prepare_pair(evaluator, &pair_scope, builtin)?;
        let left_context = context.clone();
        let right_context = context.clone();
        let left = Arc::clone(&left);
        let right = Arc::clone(&right);
        let preparation_gate = Arc::new(PairPreparationGate::default());
        let (sender, receiver) = mpsc::channel();
        let left_sender = sender.clone();
        let left_gate = Arc::clone(&preparation_gate);
        let left_worker = left_scope.spawn(move |_| {
            let result =
                run_pair_thunk_caught(&left, &mut left_evaluator, &left_context, &left_gate);
            let _ignored = left_sender.send((0_usize, result));
            Ok(())
        });
        if let Err(error) = left_worker {
            close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
            unreachable!("closing scopes with a primary error returns the error")
        }
        let right_gate = Arc::clone(&preparation_gate);
        let right_worker = right_scope.spawn(move |_| {
            let result =
                run_pair_thunk_caught(&right, &mut right_evaluator, &right_context, &right_gate);
            let _ignored = sender.send((1_usize, result));
            Ok(())
        });
        if let Err(error) = right_worker {
            preparation_gate.abort();
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
        #[cfg(feature = "compat-tracing")]
        evaluator.record_task_terminal(
            builtin,
            if first.0 == 0 { left_task } else { right_task },
            if first.1.is_ok() {
                "completed"
            } else {
                "failed"
            },
        )?;
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
            observe_cancellation();
            loser.cancel(&reason);
            #[cfg(feature = "compat-tracing")]
            evaluator.record_task_terminal(
                builtin,
                if first.0 == 0 { right_task } else { left_task },
                "cancelled",
            )?;
        }

        finish_parallel_pair(
            mode,
            (pair_scope, left_scope, right_scope),
            evaluator,
            &receiver,
            first,
            (builtin, left_task, right_task),
        )
    })
}

type ParallelResult = (usize, RuntimeResult<ThunkRef>);

fn finish_parallel_pair(
    mode: PairMode,
    scopes: (ScopeGuard, ScopeGuard, ScopeGuard),
    evaluator: &mut Evaluator,
    receiver: &mpsc::Receiver<ParallelResult>,
    first: ParallelResult,
    trace: (BuiltinId, u64, u64),
) -> RuntimeResult<ThunkRef> {
    let (pair_scope, left_scope, right_scope) = scopes;
    let (builtin, left_task, right_task) = trace;
    if matches!(mode, PairMode::Race) {
        let (index, result) = first;
        close_pair_scopes(pair_scope, left_scope, right_scope, result.as_ref().err())?;
        return result.map(|payload| {
            Thunk::evaluated(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::Either,
                constructor_index: u8::try_from(index).expect("race side is 0 or 1"),
                payloads: Arc::from([payload]),
            }))
        });
    }
    if let Err(error) = first.1 {
        close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
        unreachable!("closing scopes with a primary error returns the error")
    }
    let second = match recv_parallel_result(receiver, evaluator) {
        Ok(result) => result,
        Err(error) => {
            pair_scope.cancel(&CancelReason::ParentCancelled);
            close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
            unreachable!("closing scopes with a primary error returns the error")
        }
    };
    #[cfg(feature = "compat-tracing")]
    evaluator.record_task_terminal(
        builtin,
        if second.0 == 0 { left_task } else { right_task },
        if second.1.is_ok() {
            "completed"
        } else {
            "failed"
        },
    )?;
    #[cfg(not(feature = "compat-tracing"))]
    let _ = (builtin, left_task, right_task);
    if let Err(error) = second.1 {
        close_pair_scopes(pair_scope, left_scope, right_scope, Some(&error))?;
        unreachable!("closing scopes with a primary error returns the error")
    }
    let mut results: [Option<ThunkRef>; 2] = [None, None];
    results[first.0] = Some(first.1.expect("parallel error handled above"));
    results[second.0] = Some(second.1.expect("parallel error handled above"));
    close_pair_scopes(pair_scope, left_scope, right_scope, None)?;
    let left = results[0].take().expect("left parallel result installed");
    let right = results[1].take().expect("right parallel result installed");
    Ok(Thunk::evaluated(Value::Tuple([left, right].into())))
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
pub(super) fn pooled(
    builtin: BuiltinId,
    callback: ThunkRef,
    list: ThunkRef,
    discard_results: bool,
    callback_argument: u16,
    #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
) -> IoAction {
    IoAction::new(move |evaluator, context| {
        #[cfg(not(feature = "compat-tracing"))]
        let _ = builtin;
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
                    let (index, evidence_task, item) = match job {
                        Ok(job) => job,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    #[cfg(not(feature = "compat-tracing"))]
                    let _ = evidence_task;
                    #[cfg(feature = "compat-tracing")]
                    {
                        let logical_invocation = u64::try_from(index)
                            .map_err(|_| RuntimeError::internal("pooled input index exceeds u64"))?
                            .checked_add(1)
                            .ok_or_else(|| {
                                RuntimeError::internal("pooled input ordinal overflowed")
                            })?;
                        worker_evaluator.register_pooled_task_ordinal(
                            builtin,
                            evidence_task,
                            logical_invocation,
                        )?;
                        worker_evaluator.record_task_started_with_id(builtin, evidence_task)?;
                        worker_evaluator.current_evidence_task =
                            (evidence_task != 0).then_some(evidence_task);
                    }
                    if worker_cancellation.is_cancelled() {
                        #[cfg(feature = "compat-tracing")]
                        {
                            worker_evaluator.record_task_terminal(
                                builtin,
                                evidence_task,
                                "cancelled",
                            )?;
                        }
                        break;
                    }
                    let result = run_callback(
                        PooledCallbackRequest {
                            callback: &callback,
                            item,
                            callback_argument,
                            #[cfg(feature = "compat-tracing")]
                            parent: callback_parent,
                            #[cfg(feature = "compat-tracing")]
                            logical_invocation: u64::try_from(index)
                                .unwrap_or(u64::MAX)
                                .saturating_add(1),
                            #[cfg(feature = "compat-tracing")]
                            logical_task: evidence_task,
                        },
                        &mut worker_evaluator,
                        &context,
                    );
                    #[cfg(feature = "compat-tracing")]
                    {
                        let lifecycle = match &result {
                            Ok(_) => "completed",
                            Err(error) if error.kind == RuntimeErrorKind::Cancelled => "cancelled",
                            Err(_) => "failed",
                        };
                        worker_evaluator.record_task_terminal(builtin, evidence_task, lifecycle)?;
                        worker_evaluator.current_evidence_task = None;
                    }
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
    sender: &mpsc::SyncSender<(usize, u64, ThunkRef)>,
    cancellation: &CancellationToken,
    mut job: (usize, u64, ThunkRef),
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
    sender: &mpsc::SyncSender<(usize, u64, ThunkRef)>,
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
                #[cfg(feature = "compat-tracing")]
                let evidence_task = evaluator.allocate_evidence_task()?;
                #[cfg(not(feature = "compat-tracing"))]
                let evidence_task = 0;
                send_job(
                    sender,
                    cancellation,
                    (index, evidence_task, Arc::clone(head)),
                )?;
                index = index
                    .checked_add(1)
                    .ok_or_else(|| RuntimeError::resource_limit("pooled input is too large"))?;
                current = Arc::clone(tail);
            }
            _ => return Err(RuntimeError::internal("pooled action received a non-list")),
        }
    }
}

struct PooledCallbackRequest<'a> {
    callback: &'a ThunkRef,
    item: ThunkRef,
    callback_argument: u16,
    #[cfg(feature = "compat-tracing")]
    parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")]
    logical_invocation: u64,
    #[cfg(feature = "compat-tracing")]
    logical_task: u64,
}

fn run_callback(
    request: PooledCallbackRequest<'_>,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
) -> RuntimeResult<ThunkRef> {
    evaluator.ensure_not_cancelled()?;
    #[cfg(feature = "compat-tracing")]
    let application = Evaluator::pooled_callback_application(
        request.parent,
        Arc::clone(request.callback),
        request.item,
        request.callback_argument,
        request.logical_invocation,
        request.logical_task,
    );
    #[cfg(not(feature = "compat-tracing"))]
    let _ = request.callback_argument;
    #[cfg(not(feature = "compat-tracing"))]
    let application = Thunk::suspended(Suspension::Apply {
        function: Arc::clone(request.callback),
        argument: request.item,
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

fn run_pair_thunk_caught(
    action: &ThunkRef,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
    preparation_gate: &PairPreparationGate,
) -> RuntimeResult<ThunkRef> {
    let prepared = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        evaluator.ensure_not_cancelled()?;
        evaluator.force_io(action)
    }));
    preparation_gate.arrive_and_wait()?;
    match prepared {
        Ok(Ok(action)) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.ensure_not_cancelled()?;
            action.run(evaluator, context)
        }))
        .unwrap_or_else(|_| {
            Err(RuntimeError::panic_contained(
                "panic crossed a concurrent IO action boundary",
            ))
        }),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(RuntimeError::panic_contained(
            "panic crossed a concurrent IO action preparation boundary",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, OnceLock, mpsc};
    use std::time::{Duration, Instant};

    use hell_compiler::{CompilerSession, compile_source};

    use super::{CancelReason, PairMode, parallel_pair_with_cancellation_observer, thread_delay};
    use crate::{
        Evaluator, IoAction, RuntimeContext, RuntimeError, RuntimeErrorKind, Thunk, Value,
    };

    #[test]
    fn failure_cancels_a_peer_delay_without_waiting_for_its_deadline() {
        let program = compile_source(
            &mut CompilerSession::default(),
            "concurrent-cancellation.hell",
            "main = IO.pure ()\n",
        )
        .expect("cancellation harness compiles");
        let mut evaluator = Evaluator::new(Arc::new(program.executable().clone()));
        let context = RuntimeContext::new(Vec::new(), Vec::new());
        let (failure_ready_sender, failure_ready_receiver) = mpsc::sync_channel(0);
        let failure_ready_receiver = Arc::new(Mutex::new(failure_ready_receiver));
        let (delay_ready_sender, delay_ready_receiver) = mpsc::sync_channel(0);
        let delay_ready_receiver = Arc::new(Mutex::new(delay_ready_receiver));
        let cancellation_started = Arc::new(OnceLock::new());
        let waiting_cancellation = Arc::new(OnceLock::new());

        let branch_delay_ready_receiver = Arc::clone(&delay_ready_receiver);
        let branch_waiting_cancellation = Arc::clone(&waiting_cancellation);
        let failure = Thunk::evaluated(Value::Io(IoAction::new(move |_, _| {
            failure_ready_sender.send(()).map_err(|_| {
                RuntimeError::internal("cancellation test waiting branch disconnected")
            })?;
            let cancellation = branch_delay_ready_receiver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv()
                .map_err(|_| {
                    RuntimeError::internal("cancellation test waiting branch disconnected")
                })?;
            branch_waiting_cancellation
                .set(cancellation)
                .expect("waiting branch records its cancellation handle once");
            Err(Arc::new(RuntimeError {
                code: "H0901",
                kind: RuntimeErrorKind::UserError,
                message: "boom".into(),
                suppressed: Arc::from([]),
            }))
        })));

        let branch_failure_ready_receiver = Arc::clone(&failure_ready_receiver);
        let waiting = Thunk::evaluated(Value::Io(IoAction::new(move |evaluator, context| {
            branch_failure_ready_receiver
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv()
                .map_err(|_| {
                    RuntimeError::internal("cancellation test failing branch disconnected")
                })?;
            delay_ready_sender
                .send(evaluator.cancellation_handle())
                .map_err(|_| {
                    RuntimeError::internal("cancellation test failing branch disconnected")
                })?;
            thread_delay(
                hell_builtins::lookup("Concurrent.threadDelay")
                    .expect("thread delay builtin")
                    .id,
                Thunk::evaluated(Value::Int(5_000_000)),
            )
            .run(evaluator, context)
        })));
        let observed_cancellation_started = Arc::clone(&cancellation_started);
        let error = parallel_pair_with_cancellation_observer(
            hell_builtins::BuiltinId(0),
            failure,
            waiting,
            PairMode::Both,
            move || {
                observed_cancellation_started
                    .set(Instant::now())
                    .expect("peer cancellation is observed once");
            },
        )
        .run(&mut evaluator, &context)
        .expect_err("failing branch remains the primary error");
        let started = cancellation_started
            .get()
            .expect("peer cancellation was observed");
        let waiting_cancellation = waiting_cancellation
            .get()
            .expect("waiting branch reached the five-second delay");
        assert_eq!(error.message.as_ref(), "boom");
        assert_eq!(
            waiting_cancellation.reason(),
            Some(CancelReason::SiblingFailed)
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "peer cancellation took {:?}; cancellation reason: {:?}",
            started.elapsed(),
            waiting_cancellation.reason()
        );
    }
}
