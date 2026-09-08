use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct AbsoluteDeadlines {
    pub execute: Instant,
    pub complete: Instant,
}

impl AbsoluteDeadlines {
    /// Creates ordered execution and completion deadlines.
    ///
    /// # Errors
    ///
    /// Returns an error when completion precedes execution.
    pub fn new(execute: Instant, complete: Instant) -> Result<Self, DeadlineError> {
        if complete < execute {
            return Err(DeadlineError::CompletionPrecedesExecution);
        }
        Ok(Self { execute, complete })
    }

    /// Computes a positive provider attempt budget after reserving cleanup time.
    ///
    /// # Errors
    ///
    /// Returns an error when no whole positive millisecond remains.
    pub fn inner_budget(
        self,
        now: Instant,
        cleanup_reserve: Duration,
    ) -> Result<InnerBudget, DeadlineError> {
        let remaining = self.execute.saturating_duration_since(now);
        let duration = remaining
            .checked_sub(cleanup_reserve)
            .ok_or(DeadlineError::NoInnerBudget)?;
        if duration < Duration::from_millis(1) {
            return Err(DeadlineError::NoInnerBudget);
        }
        Ok(InnerBudget(duration))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InnerBudget(Duration);

impl InnerBudget {
    #[must_use]
    pub const fn duration(self) -> Duration {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineError {
    CompletionPrecedesExecution,
    NoInnerBudget,
}

impl std::fmt::Display for DeadlineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::CompletionPrecedesExecution => "completion deadline precedes execution deadline",
            Self::NoInnerBudget => "execution deadline leaves no positive sealed-attempt budget",
        })
    }
}

impl std::error::Error for DeadlineError {}
