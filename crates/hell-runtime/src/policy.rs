//! Explicit compatibility and sandbox policy for guest-visible limits.

use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit<T> {
    Unlimited,
    At(T),
}

impl<T> Limit<T> {
    #[must_use]
    pub fn value(self) -> Option<T> {
        match self {
            Self::Unlimited => None,
            Self::At(value) => Some(value),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeProfile {
    Upstream,
    Sandboxed,
    DeterministicTest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Capabilities {
    pub filesystem: bool,
    pub process: bool,
    pub network_loopback: bool,
    pub network_external: bool,
    pub environment_read: bool,
    pub clock: bool,
    pub exit_process: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeLimits {
    pub evaluator_steps: Limit<u64>,
    pub machine_frames: Limit<usize>,
    pub allocations: Limit<u64>,
    pub live_thunks: Limit<u64>,
    pub list_materialized_elements: Limit<u64>,
    pub stdin_bytes: Limit<u64>,
    pub handle_read_bytes: Limit<u64>,
    pub process_capture_bytes: Limit<u64>,
    pub json_depth: Limit<u32>,
    pub json_nodes: Limit<u64>,
    pub numeric_precision: Limit<u32>,
    pub concurrent_tasks: Limit<usize>,
    pub open_handles: Limit<usize>,
    pub child_processes: Limit<usize>,
    pub http_connections: Limit<usize>,
    pub http_header_bytes: Limit<u64>,
    pub http_header_count: Limit<u32>,
    pub http_body_bytes: Limit<u64>,
    pub http_reason_bytes: Limit<u64>,
    pub temp_resources: Limit<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancellationPolicy {
    pub graceful_shutdown: Duration,
    pub forced_shutdown: Duration,
    pub stalled_cleanup_is_error: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupPolicy {
    pub temp_create_retries: Limit<usize>,
    pub temp_delete_retries: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimePolicy {
    pub id: Arc<str>,
    pub profile: RuntimeProfile,
    pub capabilities: Capabilities,
    pub limits: RuntimeLimits,
    pub cancellation: CancellationPolicy,
    pub cleanup: CleanupPolicy,
}

impl RuntimePolicy {
    #[must_use]
    pub fn upstream() -> Self {
        Self {
            id: Arc::from("upstream"),
            profile: RuntimeProfile::Upstream,
            capabilities: Capabilities {
                filesystem: true,
                process: true,
                network_loopback: true,
                network_external: true,
                environment_read: true,
                clock: true,
                exit_process: true,
            },
            limits: RuntimeLimits::unlimited(),
            cancellation: CancellationPolicy::upstream(),
            cleanup: CleanupPolicy::upstream(),
        }
    }

    #[must_use]
    pub fn sandboxed() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            id: Arc::from("sandboxed"),
            profile: RuntimeProfile::Sandboxed,
            capabilities: Capabilities {
                filesystem: false,
                process: false,
                network_loopback: true,
                network_external: false,
                environment_read: false,
                clock: true,
                exit_process: false,
            },
            limits: RuntimeLimits {
                evaluator_steps: Limit::At(10_000_000),
                machine_frames: Limit::At(1_000_000),
                allocations: Limit::At(10_000_000),
                live_thunks: Limit::At(1_000_000),
                list_materialized_elements: Limit::At(1_000_000),
                stdin_bytes: Limit::At(64 * MIB),
                handle_read_bytes: Limit::At(64 * MIB),
                process_capture_bytes: Limit::At(64 * MIB),
                json_depth: Limit::At(512),
                json_nodes: Limit::At(1_000_000),
                numeric_precision: Limit::At(1_000),
                concurrent_tasks: Limit::At(64),
                open_handles: Limit::At(256),
                child_processes: Limit::At(64),
                http_connections: Limit::At(256),
                http_header_bytes: Limit::At(64 * 1024),
                http_header_count: Limit::At(256),
                http_body_bytes: Limit::At(16 * MIB),
                http_reason_bytes: Limit::At(1_024),
                temp_resources: Limit::At(256),
            },
            cancellation: CancellationPolicy::default(),
            cleanup: CleanupPolicy::sandboxed(),
        }
    }

    #[must_use]
    pub fn deterministic_test() -> Self {
        let mut policy = Self::sandboxed();
        policy.id = Arc::from("deterministic-test");
        policy.profile = RuntimeProfile::DeterministicTest;
        policy.limits.concurrent_tasks = Limit::At(2);
        policy
    }
}

impl RuntimeLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            evaluator_steps: Limit::Unlimited,
            machine_frames: Limit::Unlimited,
            allocations: Limit::Unlimited,
            live_thunks: Limit::Unlimited,
            list_materialized_elements: Limit::Unlimited,
            stdin_bytes: Limit::Unlimited,
            handle_read_bytes: Limit::Unlimited,
            process_capture_bytes: Limit::Unlimited,
            json_depth: Limit::Unlimited,
            json_nodes: Limit::Unlimited,
            numeric_precision: Limit::Unlimited,
            concurrent_tasks: Limit::Unlimited,
            open_handles: Limit::Unlimited,
            child_processes: Limit::Unlimited,
            http_connections: Limit::Unlimited,
            http_header_bytes: Limit::Unlimited,
            http_header_count: Limit::Unlimited,
            http_body_bytes: Limit::Unlimited,
            http_reason_bytes: Limit::Unlimited,
            temp_resources: Limit::Unlimited,
        }
    }
}

impl Default for CancellationPolicy {
    fn default() -> Self {
        Self {
            graceful_shutdown: Duration::from_millis(100),
            forced_shutdown: Duration::from_millis(150),
            stalled_cleanup_is_error: true,
        }
    }
}

impl CancellationPolicy {
    #[must_use]
    pub const fn upstream() -> Self {
        Self {
            graceful_shutdown: Duration::from_secs(5),
            forced_shutdown: Duration::from_millis(150),
            stalled_cleanup_is_error: true,
        }
    }
}

impl Default for CleanupPolicy {
    fn default() -> Self {
        Self::sandboxed()
    }
}

impl CleanupPolicy {
    #[must_use]
    pub const fn upstream() -> Self {
        Self {
            temp_create_retries: Limit::Unlimited,
            temp_delete_retries: 1,
        }
    }

    #[must_use]
    pub const fn sandboxed() -> Self {
        Self {
            temp_create_retries: Limit::At(1_024),
            temp_delete_retries: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_profiles_make_capabilities_limits_and_temp_retries_explicit() {
        let upstream = RuntimePolicy::upstream();
        assert_eq!(upstream.cleanup.temp_create_retries, Limit::Unlimited);
        assert!(upstream.capabilities.network_external);

        let sandboxed = RuntimePolicy::sandboxed();
        assert_eq!(sandboxed.cleanup.temp_create_retries, Limit::At(1_024));
        assert!(!sandboxed.capabilities.network_external);
    }
}
