use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct SealedAdmission {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    limit: usize,
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Debug)]
struct State {
    active: usize,
    closed: bool,
    poisoned: Option<String>,
}

impl SealedAdmission {
    /// Creates an admission owner with a fixed root-attempt capacity.
    ///
    /// # Panics
    ///
    /// Panics when `limit` is zero.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        assert!(limit != 0, "sealed admission limit must be positive");
        Self {
            inner: Arc::new(Inner {
                limit,
                state: Mutex::new(State {
                    active: 0,
                    closed: false,
                    poisoned: None,
                }),
                changed: Condvar::new(),
            }),
        }
    }

    #[must_use]
    pub fn windows_default() -> Self {
        Self::new(4)
    }

    /// Acquires one root-attempt permit before an absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if admission is closed or poisoned, or the deadline expires.
    pub fn acquire_until(&self, deadline: Instant) -> Result<AdmissionLease, AdmissionError> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(reason) = &state.poisoned {
                return Err(AdmissionError::Poisoned(reason.clone()));
            }
            if state.closed {
                return Err(AdmissionError::Closed);
            }
            if state.active < self.inner.limit {
                state.active += 1;
                return Ok(AdmissionLease {
                    inner: Arc::clone(&self.inner),
                    terminal: false,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(AdmissionError::DeadlineExpired);
            }
            let (next, timeout) = self
                .inner
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out() && state.active >= self.inner.limit {
                return Err(AdmissionError::DeadlineExpired);
            }
        }
    }

    pub fn close(&self) {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed = true;
        self.inner.changed.notify_all();
    }

    pub fn poison(&self, reason: impl Into<String>) {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poisoned = Some(reason.into());
        self.inner.changed.notify_all();
    }

    #[must_use]
    pub fn active(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }
}

#[derive(Debug)]
pub struct AdmissionLease {
    inner: Arc<Inner>,
    terminal: bool,
}

impl AdmissionLease {
    /// Releases capacity only after provider retirement was validated.
    pub fn retire(mut self) {
        self.terminal = true;
        release(&self.inner);
    }

    /// Marks unresolved retirement and permanently poisons this admission owner.
    pub fn fail_dirty(mut self, reason: impl Into<String>) {
        self.terminal = true;
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = state.active.saturating_sub(1);
        state.poisoned = Some(reason.into());
        drop(state);
        self.inner.changed.notify_all();
    }
}

impl Drop for AdmissionLease {
    fn drop(&mut self) {
        if self.terminal {
            return;
        }
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = state.active.saturating_sub(1);
        state.poisoned = Some("admission lease dropped without validated retirement".to_owned());
        drop(state);
        self.inner.changed.notify_all();
    }
}

fn release(inner: &Inner) {
    let mut state = inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.active = state.active.saturating_sub(1);
    drop(state);
    inner.changed.notify_all();
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Closed,
    Poisoned(String),
    DeadlineExpired,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => formatter.write_str("sealed admission is closed"),
            Self::Poisoned(reason) => write!(formatter, "sealed admission is poisoned: {reason}"),
            Self::DeadlineExpired => formatter.write_str("sealed admission deadline expired"),
        }
    }
}

impl std::error::Error for AdmissionError {}
