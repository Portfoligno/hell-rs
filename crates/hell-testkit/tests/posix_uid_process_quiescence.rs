#![cfg(unix)]

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use hell_testkit::{
    PosixUidProcess, PosixUidProcessState, PosixUidQuiescenceGoal,
    parse_posix_uid_process_snapshot, wait_for_posix_uid_process_quiescence,
};

fn process(
    pid: u32,
    parent_pid: u32,
    state: PosixUidProcessState,
    raw_state: &str,
) -> PosixUidProcess {
    PosixUidProcess {
        pid,
        parent_pid,
        state,
        raw_state: raw_state.to_owned(),
    }
}

fn deadline() -> Instant {
    Instant::now()
        .checked_add(Duration::from_secs(1))
        .expect("test deadline must be representable")
}

#[test]
fn typed_process_snapshot_accepts_only_canonical_pid_parent_and_state_rows() {
    let parsed = parse_posix_uid_process_snapshot(Some(0), b" 12 1 R+\n 13 12 Zs\n\n", b"")
        .expect("canonical process rows must parse");
    assert_eq!(
        parsed,
        vec![
            process(12, 1, PosixUidProcessState::Live, "R+"),
            process(13, 12, PosixUidProcessState::Zombie, "Zs"),
        ]
    );
    assert!(
        parse_posix_uid_process_snapshot(Some(0), b" \n", b"")
            .expect("canonical empty output must parse")
            .is_empty()
    );
    assert!(
        parse_posix_uid_process_snapshot(Some(1), b"", b"")
            .expect("exact absence status must parse")
            .is_empty()
    );

    for (status, stdout, stderr) in [
        (None, b"".as_slice(), b"".as_slice()),
        (Some(2), b"".as_slice(), b"".as_slice()),
        (Some(1), b" \n".as_slice(), b"".as_slice()),
        (Some(0), b"".as_slice(), b"ps warning\n".as_slice()),
        (Some(0), b"12 R\n".as_slice(), b"".as_slice()),
        (Some(0), b"12 1\n".as_slice(), b"".as_slice()),
        (Some(0), b"12 1 R extra\n".as_slice(), b"".as_slice()),
        (Some(0), b"0 1 R\n".as_slice(), b"".as_slice()),
        (Some(0), b"012 1 R\n".as_slice(), b"".as_slice()),
        (Some(0), b"12 0 R\n".as_slice(), b"".as_slice()),
        (Some(0), b"12 1 Z?\n".as_slice(), b"".as_slice()),
        (Some(0), b"12 1 R\n12 1 Z\n".as_slice(), b"".as_slice()),
    ] {
        assert!(
            parse_posix_uid_process_snapshot(status, stdout, stderr).is_err(),
            "malformed process inventory must fail closed"
        );
    }
    let mut oversized = Vec::new();
    for pid in 1..=4_097_u32 {
        oversized.extend_from_slice(pid.to_string().as_bytes());
        oversized.extend_from_slice(b" 1 R\n");
    }
    assert!(parse_posix_uid_process_snapshot(Some(0), &oversized, b"").is_err());
}

#[test]
fn repeated_live_observation_authorizes_then_signals_exactly_once() {
    let live = process(31, 1, PosixUidProcessState::Live, "R+");
    let snapshots = RefCell::new(VecDeque::from([vec![live.clone()], vec![live], Vec::new()]));
    let events = RefCell::new(Vec::new());
    wait_for_posix_uid_process_quiescence(
        deadline(),
        PosixUidQuiescenceGoal::Empty,
        || {
            snapshots
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| io::Error::other("test process snapshots were exhausted"))
        },
        || {
            events.borrow_mut().push("identity");
            Ok(())
        },
        || {
            assert_eq!(events.borrow().last(), Some(&"identity"));
            events.borrow_mut().push("signal");
            Ok(())
        },
    )
    .expect("repeated live PID must be signaled only once before absence");
    assert_eq!(&*events.borrow(), &["identity", "signal"]);
}

#[test]
fn already_expired_deadline_returns_typed_diagnostic_without_signaling() {
    let signals = Cell::new(0_u32);
    let error = wait_for_posix_uid_process_quiescence(
        Instant::now(),
        PosixUidQuiescenceGoal::Empty,
        || Ok(vec![process(31, 1, PosixUidProcessState::Live, "R+")]),
        || Err(io::Error::other("expired wait must not authorize a signal")),
        || {
            signals.set(signals.get() + 1);
            Ok(())
        },
    )
    .expect_err("a retained live process must fail at an expired monotonic deadline");
    assert_eq!(signals.get(), 0);
    assert!(error.to_string().contains("quiescence deadline expired"));
    assert!(error.to_string().contains("pid=31,ppid=1,state=R+"));
}

#[test]
fn candidate_identity_rebound_rejects_signal_authorization() {
    let signals = Cell::new(0_u32);
    let error = wait_for_posix_uid_process_quiescence(
        deadline(),
        PosixUidQuiescenceGoal::Empty,
        || Ok(vec![process(32, 1, PosixUidProcessState::Live, "S")]),
        || Err(io::Error::other("candidate principal UID rebound")),
        || {
            signals.set(signals.get() + 1);
            Ok(())
        },
    )
    .expect_err("identity rebound must fail before signaling");
    assert_eq!(signals.get(), 0);
    assert!(error.to_string().contains("UID rebound"));
}

#[test]
fn empty_goal_observes_live_then_zombie_then_absent_without_resignaling() {
    let snapshots = RefCell::new(VecDeque::from([
        vec![process(41, 1, PosixUidProcessState::Live, "S")],
        vec![process(41, 1, PosixUidProcessState::Zombie, "Z+")],
        Vec::new(),
    ]));
    let signals = Cell::new(0_u32);
    let result = wait_for_posix_uid_process_quiescence(
        deadline(),
        PosixUidQuiescenceGoal::Empty,
        || {
            snapshots
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| io::Error::other("test process snapshots were exhausted"))
        },
        || Ok(()),
        || {
            signals.set(signals.get() + 1);
            Ok(())
        },
    )
    .expect("live-to-zombie-to-absent transition must quiesce");
    assert!(result.is_empty());
    assert_eq!(signals.get(), 1);
    assert!(snapshots.borrow().is_empty());
}

#[test]
fn zombie_only_is_accepted_for_no_live_but_empty_waits_for_absence() {
    let zombie = process(51, 1, PosixUidProcessState::Zombie, "Zs");
    let no_live_observations = Cell::new(0_u32);
    let accepted = wait_for_posix_uid_process_quiescence(
        deadline(),
        PosixUidQuiescenceGoal::NoLiveProcesses,
        || {
            no_live_observations.set(no_live_observations.get() + 1);
            Ok(vec![zombie.clone()])
        },
        || Err(io::Error::other("a zombie must not authorize a signal")),
        || Err(io::Error::other("a zombie must not be signaled")),
    )
    .expect("zombie-only inventory has no live candidate process");
    assert_eq!(accepted, vec![zombie.clone()]);
    assert_eq!(no_live_observations.get(), 1);

    let snapshots = RefCell::new(VecDeque::from([vec![zombie], Vec::new()]));
    let empty = wait_for_posix_uid_process_quiescence(
        deadline(),
        PosixUidQuiescenceGoal::Empty,
        || {
            snapshots
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| io::Error::other("test process snapshots were exhausted"))
        },
        || Err(io::Error::other("a zombie must not authorize a signal")),
        || Err(io::Error::other("a zombie must not be signaled")),
    )
    .expect("empty goal must wait until the zombie is reaped");
    assert!(empty.is_empty());
    assert!(snapshots.borrow().is_empty());
}

#[test]
fn uid_deletion_is_released_only_after_an_empty_snapshot() {
    let snapshots = RefCell::new(VecDeque::from([
        vec![process(61, 1, PosixUidProcessState::Zombie, "Z")],
        Vec::new(),
    ]));
    let deletion_started = Cell::new(false);
    wait_for_posix_uid_process_quiescence(
        deadline(),
        PosixUidQuiescenceGoal::Empty,
        || {
            assert!(!deletion_started.get());
            snapshots
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| io::Error::other("test process snapshots were exhausted"))
        },
        || Err(io::Error::other("a zombie must not authorize a signal")),
        || Err(io::Error::other("a zombie must not be signaled")),
    )
    .expect("UID deletion gate must observe exact absence");
    deletion_started.set(true);
    assert!(deletion_started.get());
    assert!(snapshots.borrow().is_empty());
}
