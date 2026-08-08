use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::{
    Evaluator, IoAction, ListCell, PrimitiveFamily, PrimitiveVariantValue, RuntimeContext,
    RuntimeError, RuntimeResult, Suspension, Thunk, ThunkRef, Value, list_from_values,
};

#[derive(Clone, Debug)]
pub(super) struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    parent: Option<Arc<Self>>,
}

impl CancellationToken {
    pub(super) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            parent: None,
        }
    }

    pub(super) fn child(&self) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            parent: Some(Arc::new(self.clone())),
        }
    }

    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.is_cancelled())
    }
}

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
            std::thread::sleep(
                deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(2)),
            );
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

        let cancellation = evaluator.child_cancellation();
        let mut child = evaluator.fork_with_cancellation(cancellation.clone());
        let context = context.clone();
        let action = Arc::clone(&action);
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = run_thunk_caught(&action, &mut child, &context);
            let _ignored = sender.send(result);
        });
        let waited = receiver.recv_timeout(Duration::from_micros(microseconds.cast_unsigned()));
        match waited {
            Ok(result) => {
                join_worker(worker)?;
                result.map(|value| Thunk::evaluated(Value::Maybe(Some(value))))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                cancellation.cancel();
                join_worker(worker)?;
                Ok(Thunk::evaluated(Value::Maybe(None)))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                cancellation.cancel();
                join_worker(worker)?;
                Err(RuntimeError::internal("timeout worker disconnected"))
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
        let cancellation = evaluator.child_cancellation();
        let mut left_evaluator = evaluator.fork_with_cancellation(cancellation.clone());
        let mut right_evaluator = evaluator.fork_with_cancellation(cancellation.clone());
        let left_context = context.clone();
        let right_context = context.clone();
        let left = Arc::clone(&left);
        let right = Arc::clone(&right);
        let (sender, receiver) = mpsc::channel();
        let left_sender = sender.clone();
        let left_worker = std::thread::spawn(move || {
            let result = run_thunk_caught(&left, &mut left_evaluator, &left_context);
            let _ignored = left_sender.send((0_usize, result));
        });
        let right_worker = std::thread::spawn(move || {
            let result = run_thunk_caught(&right, &mut right_evaluator, &right_context);
            let _ignored = sender.send((1_usize, result));
        });

        let first = receiver
            .recv()
            .map_err(|_| RuntimeError::internal("parallel action workers disconnected"))?;
        if matches!(mode, PairMode::Race) || first.1.is_err() {
            cancellation.cancel();
        }
        let second = receiver
            .recv()
            .map_err(|_| RuntimeError::internal("parallel action workers disconnected"))?;
        join_worker(left_worker)?;
        join_worker(right_worker)?;

        match mode {
            PairMode::Race => {
                let (index, result) = first;
                result.map(|payload| {
                    Thunk::evaluated(Value::PrimitiveVariant(PrimitiveVariantValue {
                        family: PrimitiveFamily::Either,
                        constructor_index: u8::try_from(index).expect("race side is 0 or 1"),
                        payloads: Arc::from([payload]),
                    }))
                })
            }
            PairMode::Both => {
                let mut results: [Option<ThunkRef>; 2] = [None, None];
                let first_value = first.1?;
                let second_value = second.1?;
                results[first.0] = Some(first_value);
                results[second.0] = Some(second_value);
                let left = results[0].take().expect("left parallel result installed");
                let right = results[1].take().expect("right parallel result installed");
                Ok(Thunk::evaluated(Value::Tuple([left, right].into())))
            }
        }
    })
}

pub(super) fn pooled(callback: ThunkRef, list: ThunkRef, discard_results: bool) -> IoAction {
    IoAction::new(move |evaluator, context| {
        evaluator.ensure_not_cancelled()?;
        let cancellation = evaluator.child_cancellation();
        let worker_count = evaluator.concurrent_action_limit();
        let queue_capacity = worker_count.saturating_mul(2).max(1);
        let (job_sender, job_receiver) = mpsc::sync_channel(queue_capacity);
        let job_receiver = Arc::new(Mutex::new(job_receiver));
        let (result_sender, result_receiver) = mpsc::channel();

        let mut producer_evaluator = evaluator.fork_with_cancellation(cancellation.clone());
        let producer_cancellation = cancellation.clone();
        let producer = {
            let list = Arc::clone(&list);
            std::thread::spawn(move || {
                produce_jobs(
                    &mut producer_evaluator,
                    list,
                    &job_sender,
                    &producer_cancellation,
                )
            })
        };

        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let receiver = Arc::clone(&job_receiver);
            let sender = result_sender.clone();
            let callback = Arc::clone(&callback);
            let context = context.clone();
            let worker_cancellation = cancellation.clone();
            let mut worker_evaluator =
                evaluator.fork_with_cancellation(worker_cancellation.clone());
            workers.push(std::thread::spawn(move || {
                loop {
                    if worker_cancellation.is_cancelled() {
                        break;
                    }
                    let job = receiver
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv();
                    let Ok((index, item)) = job else {
                        break;
                    };
                    let result = run_callback(&callback, item, &mut worker_evaluator, &context);
                    let failed = result.is_err();
                    if sender.send((index, result)).is_err() {
                        break;
                    }
                    if failed {
                        worker_cancellation.cancel();
                        break;
                    }
                }
            }));
        }
        drop(job_receiver);
        drop(result_sender);

        let mut values = Vec::new();
        let mut first_error = None;
        for (index, result) in result_receiver {
            match result {
                Ok(value) => values.push((index, value)),
                Err(error) => {
                    cancellation.cancel();
                    first_error.get_or_insert(error);
                }
            }
        }
        let input_count = join_producer(producer)?;
        for worker in workers {
            join_worker(worker)?;
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        let count = input_count?;
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
                sender
                    .send((index, Arc::clone(head)))
                    .map_err(|_| RuntimeError::cancelled())?;
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

fn join_worker(worker: std::thread::JoinHandle<()>) -> RuntimeResult<()> {
    worker
        .join()
        .map_err(|_| RuntimeError::panic_contained("concurrent IO worker panicked"))
}

fn join_producer(
    producer: std::thread::JoinHandle<RuntimeResult<usize>>,
) -> RuntimeResult<RuntimeResult<usize>> {
    producer
        .join()
        .map_err(|_| RuntimeError::panic_contained("pooled input producer panicked"))
}
