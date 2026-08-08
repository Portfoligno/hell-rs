use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, OnceLock};
use std::time::Duration;

use hell_compiler::{CompilerSession, compile_source};
use hell_core::ExecutableProgram;
use hell_runtime::scope::CancelReason;
use hell_runtime::{Evaluator, RuntimeError, RuntimeErrorKind, Thunk, ThunkRef, Value};

fn executable(source: &str) -> Arc<ExecutableProgram> {
    let program = compile_source(&mut CompilerSession::default(), "machine.hell", source).unwrap();
    Arc::new(program.executable().clone())
}

#[test]
fn concurrent_waiters_share_one_successful_evaluation() {
    let program = executable("main = IO.pure ()\n");
    let evaluations = Arc::new(AtomicUsize::new(0));
    let operation_evaluations = Arc::clone(&evaluations);
    let thunk = Thunk::deferred(move |_| {
        operation_evaluations.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(20));
        Ok(Arc::new(Value::Int(42)))
    });
    let start = Arc::new(Barrier::new(3));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let program = Arc::clone(&program);
            let thunk = Arc::clone(&thunk);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let mut evaluator = Evaluator::new(program);
                start.wait();
                evaluator.force(&thunk).unwrap()
            })
        })
        .collect();
    start.wait();
    let mut values = threads.into_iter().map(|thread| thread.join().unwrap());
    let first = values.next().unwrap();
    let second = values.next().unwrap();
    assert!(matches!(first.as_ref(), Value::Int(42)));
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(evaluations.load(Ordering::SeqCst), 1);
}

#[test]
fn concurrent_waiters_share_one_failed_evaluation() {
    let program = executable("main = IO.pure ()\n");
    let evaluations = Arc::new(AtomicUsize::new(0));
    let operation_evaluations = Arc::clone(&evaluations);
    let failure = Arc::new(RuntimeError {
        code: "H0901",
        kind: RuntimeErrorKind::UserError,
        message: "shared failure".into(),
        suppressed: Arc::from([]),
    });
    let operation_failure = Arc::clone(&failure);
    let thunk = Thunk::deferred(move |_| {
        operation_evaluations.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(20));
        Err(Arc::clone(&operation_failure))
    });
    let start = Arc::new(Barrier::new(3));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let program = Arc::clone(&program);
            let thunk = Arc::clone(&thunk);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let mut evaluator = Evaluator::new(program);
                start.wait();
                evaluator.force(&thunk).unwrap_err()
            })
        })
        .collect();
    start.wait();
    let mut errors = threads.into_iter().map(|thread| thread.join().unwrap());
    let first = errors.next().unwrap();
    let second = errors.next().unwrap();
    assert!(Arc::ptr_eq(&first, &failure));
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(evaluations.load(Ordering::SeqCst), 1);
}

#[test]
fn same_evaluator_reentry_is_a_memoized_black_hole() {
    let program = executable("main = IO.pure ()\n");
    let slot = Arc::new(OnceLock::<ThunkRef>::new());
    let target = Arc::clone(&slot);
    let thunk = Thunk::deferred(move |evaluator| {
        evaluator.force(target.get().expect("recursive thunk installed"))
    });
    slot.set(Arc::clone(&thunk)).unwrap();
    let mut evaluator = Evaluator::new(program);
    let first = evaluator.force(&thunk).unwrap_err();
    let second = evaluator.force(&thunk).unwrap_err();
    assert_eq!(first.code, "H0902");
    assert_eq!(first.kind, RuntimeErrorKind::BlackHole);
    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn cross_evaluator_wait_cycles_fail_instead_of_deadlocking() {
    let program = executable("main = IO.pure ()\n");
    let left_slot = Arc::new(OnceLock::<ThunkRef>::new());
    let right_slot = Arc::new(OnceLock::<ThunkRef>::new());
    let entered = Arc::new(Barrier::new(2));

    let right_target = Arc::clone(&right_slot);
    let left_entered = Arc::clone(&entered);
    let left = Thunk::deferred(move |evaluator| {
        left_entered.wait();
        evaluator.force(right_target.get().expect("right thunk installed"))
    });
    let left_target = Arc::clone(&left_slot);
    let right_entered = Arc::clone(&entered);
    let right = Thunk::deferred(move |evaluator| {
        right_entered.wait();
        evaluator.force(left_target.get().expect("left thunk installed"))
    });
    left_slot.set(Arc::clone(&left)).unwrap();
    right_slot.set(Arc::clone(&right)).unwrap();

    let left_thread = {
        let program = Arc::clone(&program);
        std::thread::spawn(move || Evaluator::new(program).force(&left).unwrap_err())
    };
    let right_thread =
        std::thread::spawn(move || Evaluator::new(program).force(&right).unwrap_err());
    let left_error = left_thread.join().unwrap();
    let right_error = right_thread.join().unwrap();
    assert_eq!(left_error.kind, RuntimeErrorKind::BlackHole);
    assert_eq!(right_error.kind, RuntimeErrorKind::BlackHole);
}

#[test]
fn unwind_guard_fails_and_wakes_the_claimed_thunk() {
    let program = executable("main = IO.pure ()\n");
    let evaluations = Arc::new(AtomicUsize::new(0));
    let operation_evaluations = Arc::clone(&evaluations);
    let thunk = Thunk::deferred(move |_| {
        operation_evaluations.fetch_add(1, Ordering::SeqCst);
        panic!("test native panic");
    });
    let mut first_evaluator = Evaluator::new(Arc::clone(&program));
    let first = first_evaluator.force(&thunk).unwrap_err();
    let second = Evaluator::new(program).force(&thunk).unwrap_err();
    assert_eq!(first.kind, RuntimeErrorKind::InternalInvariant);
    assert_eq!(second.kind, RuntimeErrorKind::InternalInvariant);
    assert_eq!(evaluations.load(Ordering::SeqCst), 1);
}

#[test]
fn configured_machine_frame_limit_is_a_structured_error() {
    let mut source = String::from("main = ");
    for _ in 0..20 {
        source.push_str("Function.id $ ");
    }
    source.push_str("IO.pure ()\n");
    let program = executable(&source);
    let evaluator = Evaluator::with_max_machine_frames(program, 4);
    let root = evaluator.root_thunk();
    let mut evaluator = evaluator;
    let first = evaluator.force(&root).unwrap_err();
    let second = evaluator.force(&root).unwrap_err();
    assert_eq!(first.code, "H0803");
    assert_eq!(first.kind, RuntimeErrorKind::ResourceLimit);
    assert!(Arc::ptr_eq(&first, &second));
}

#[test]
fn cancelling_a_blocked_waiter_preserves_the_shared_thunk_result() {
    let program = executable("main = IO.pure ()\n");
    let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
    let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
    let release_receiver = Arc::new(std::sync::Mutex::new(release_receiver));
    let thunk = Thunk::deferred(move |_| {
        entered_sender.send(()).unwrap();
        release_receiver.lock().unwrap().recv().unwrap();
        Ok(Arc::new(Value::Int(42)))
    });

    let owner = {
        let program = Arc::clone(&program);
        let thunk = Arc::clone(&thunk);
        std::thread::spawn(move || Evaluator::new(program).force(&thunk).unwrap())
    };
    entered_receiver.recv().unwrap();

    let waiter = Evaluator::new(Arc::clone(&program));
    let cancellation = waiter.cancellation_handle();
    let waiting_thunk = Arc::clone(&thunk);
    let waiter = std::thread::spawn(move || {
        let mut waiter = waiter;
        waiter.force(&waiting_thunk).unwrap_err()
    });
    std::thread::sleep(Duration::from_millis(20));
    cancellation.cancel(CancelReason::UserInterrupt);
    assert_eq!(waiter.join().unwrap().kind, RuntimeErrorKind::Cancelled);

    release_sender.send(()).unwrap();
    let owner_result = owner.join().unwrap();
    let retained = Evaluator::new(program).force(&thunk).unwrap();
    assert!(Arc::ptr_eq(&owner_result, &retained));
}

#[test]
fn embedding_cancellation_interrupts_a_running_pure_evaluator_loop() {
    let program = executable("main = IO.pure ()\n");
    let thunk = Thunk::deferred(|evaluator| {
        loop {
            evaluator.cancellation_handle().check()?;
            std::hint::spin_loop();
        }
    });
    let evaluator = Evaluator::new(program);
    let cancellation = evaluator.cancellation_handle();
    let worker = std::thread::spawn(move || {
        let mut evaluator = evaluator;
        evaluator.force(&thunk).unwrap_err()
    });
    std::thread::sleep(Duration::from_millis(20));
    cancellation.cancel(CancelReason::UserInterrupt);
    assert_eq!(worker.join().unwrap().kind, RuntimeErrorKind::Cancelled);
}
