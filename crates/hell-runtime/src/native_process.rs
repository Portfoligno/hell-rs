//! Immutable child-process descriptions used by the process adapters.

use std::sync::Arc;

use crate::native_handle::HostHandle;

type ProcessEnvironment = Arc<[(Arc<str>, Arc<str>)]>;

/// A reusable child-process description. Executing the value always starts a
/// fresh operating-system process.
#[derive(Clone, Debug)]
pub struct ProcessSpec {
    pub(crate) command: Arc<str>,
    pub(crate) arguments: Arc<[Arc<str>]>,
    pub(crate) working_directory: Option<Arc<str>>,
    pub(crate) environment: Option<ProcessEnvironment>,
    pub(crate) stdin: HostHandle,
    pub(crate) stdin_bytes: Option<Arc<[u8]>>,
    pub(crate) stdout: HostHandle,
    pub(crate) stderr: HostHandle,
}

impl ProcessSpec {
    pub(crate) fn new(command: Arc<str>, arguments: Arc<[Arc<str>]>) -> Self {
        Self {
            command,
            arguments,
            working_directory: None,
            environment: None,
            stdin: HostHandle::Stdin,
            stdin_bytes: None,
            stdout: HostHandle::Stdout,
            stderr: HostHandle::Stderr,
        }
    }
}
