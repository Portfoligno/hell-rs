//! Call-by-need graph evaluator and reusable IO action values.

pub mod budget;
mod concurrency;
pub mod internal;
mod lazy_list;
mod native_collections;
pub mod native_handle;
pub mod native_http;
pub mod native_integer;
mod native_json;
mod native_list;
pub mod native_process;
mod native_temp;
pub mod native_time;
pub mod policy;
pub mod scope;
mod typeclasses;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::SystemTime;

use hell_builtins::BuiltinId;
use hell_core::{
    CaseBranch, ClassEvidence, Constant, CoreId, CoreKind, ExecutableProgram, Projection,
    RecordLayout, VariantLayout, VerifiedProgram,
};
use hell_host::{HostServices, SupervisedChild};
use native_handle::{BufferMode, FileMode, HostHandle};
use native_integer::BigInteger;
use native_process::ProcessSpec;
use policy::{Limit, RuntimePolicy};
use typeclasses::{
    CaseInsensitiveValue, InfoModifiers, OptionModifiers, OptionParser, ParserInfo, TreeValue,
};

pub use native_collections::{OrderedMap, OrderedSet};
pub use native_json::{JsonDocument, JsonNumber};

pub type ThunkRef = Arc<Thunk>;
pub type ValueRef = Arc<Value>;
pub type RuntimeResult<T> = Result<T, Arc<RuntimeError>>;
pub type EvaluationId = NonZeroU64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeErrorKind {
    UserError,
    BlackHole,
    Cancelled,
    Exit(i32),
    Io,
    ResourceLimit,
    CancellationStalled,
    InternalInvariant,
}

#[derive(Clone, Debug)]
pub struct RuntimeError {
    pub code: &'static str,
    pub kind: RuntimeErrorKind,
    pub message: Arc<str>,
    pub suppressed: Arc<[Arc<RuntimeError>]>,
}

impl RuntimeError {
    fn user(message: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            code: "H0901",
            kind: RuntimeErrorKind::UserError,
            message: message.into(),
            suppressed: Arc::from([]),
        })
    }

    fn internal(message: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            code: "H9001",
            kind: RuntimeErrorKind::InternalInvariant,
            message: message.into(),
            suppressed: Arc::from([]),
        })
    }

    fn resource_limit(message: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            code: "H0803",
            kind: RuntimeErrorKind::ResourceLimit,
            message: message.into(),
            suppressed: Arc::from([]),
        })
    }

    fn cancelled() -> Arc<Self> {
        Arc::new(Self {
            code: "H0906",
            kind: RuntimeErrorKind::Cancelled,
            message: "IO action was cancelled".into(),
            suppressed: Arc::from([]),
        })
    }

    fn cancellation_stalled(message: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            code: "H0909",
            kind: RuntimeErrorKind::CancellationStalled,
            message: message.into(),
            suppressed: Arc::from([]),
        })
    }

    fn exit(status: i32) -> Arc<Self> {
        Arc::new(Self {
            code: "H0907",
            kind: RuntimeErrorKind::Exit(status),
            message: "guest requested process exit".into(),
            suppressed: Arc::from([]),
        })
    }

    fn panic_contained(message: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            code: "H9004",
            kind: RuntimeErrorKind::InternalInvariant,
            message: message.into(),
            suppressed: Arc::from([]),
        })
    }

    fn http(message: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            code: "H0908",
            kind: RuntimeErrorKind::Io,
            message: message.into(),
            suppressed: Arc::from([]),
        })
    }

    fn resource_closed(message: impl Into<Arc<str>>) -> Arc<Self> {
        Arc::new(Self {
            code: "H0909",
            kind: RuntimeErrorKind::Io,
            message: message.into(),
            suppressed: Arc::from([]),
        })
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone)]
pub struct RuntimeContext {
    pub args: Arc<[OsString]>,
    environment: Arc<[(Arc<str>, Arc<str>)]>,
    stdin: Arc<Mutex<Box<dyn BufRead + Send>>>,
    stdout: Arc<Mutex<Box<dyn Write + Send>>>,
    stderr: Arc<Mutex<Box<dyn Write + Send>>>,
    stdin_buffering: Arc<Mutex<BufferMode>>,
    stdout_buffering: Arc<Mutex<BufferMode>>,
    stderr_buffering: Arc<Mutex<BufferMode>>,
    cwd: Arc<Mutex<PathBuf>>,
    allow_filesystem: bool,
    allow_process: bool,
    max_concurrent_actions: Option<usize>,
    current_time: Option<SystemTime>,
    allow_network: bool,
    http_request_limit: Option<usize>,
    policy: Arc<RuntimePolicy>,
    budget: Arc<budget::Budget>,
    host_services: Arc<HostServices>,
}

impl fmt::Debug for RuntimeContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeContext")
            .field("args", &self.args)
            .field("environment_entries", &self.environment.len())
            .field("allow_filesystem", &self.allow_filesystem)
            .field("allow_process", &self.allow_process)
            .field("max_concurrent_actions", &self.max_concurrent_actions)
            .field("current_time_override", &self.current_time.is_some())
            .field("allow_network", &self.allow_network)
            .field("http_request_limit", &self.http_request_limit)
            .field("policy", &self.policy.id)
            .finish_non_exhaustive()
    }
}

impl RuntimeContext {
    #[must_use]
    pub fn new(args: Vec<Arc<str>>, stdout: impl Write + Send + 'static) -> Self {
        Self::with_environment(args, Vec::new(), stdout)
    }

    #[must_use]
    pub fn with_environment(
        args: Vec<Arc<str>>,
        environment: Vec<(Arc<str>, Arc<str>)>,
        stdout: impl Write + Send + 'static,
    ) -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self::with_host(args, environment, stdout, cwd, true)
    }

    /// Creates a runtime context with an explicit logical working directory
    /// and filesystem capability.
    #[must_use]
    pub fn with_host(
        args: Vec<Arc<str>>,
        environment: Vec<(Arc<str>, Arc<str>)>,
        stdout: impl Write + Send + 'static,
        cwd: PathBuf,
        allow_filesystem: bool,
    ) -> Self {
        Self::with_host_capabilities(args, environment, stdout, cwd, allow_filesystem, true)
    }

    /// Creates a runtime context with explicit filesystem and child-process
    /// capabilities.
    #[must_use]
    pub fn with_host_capabilities(
        args: Vec<Arc<str>>,
        environment: Vec<(Arc<str>, Arc<str>)>,
        stdout: impl Write + Send + 'static,
        cwd: PathBuf,
        allow_filesystem: bool,
        allow_process: bool,
    ) -> Self {
        let host_environment = environment
            .iter()
            .map(|(name, value)| {
                (
                    OsString::from(name.as_ref()),
                    OsString::from(value.as_ref()),
                )
            })
            .collect();
        let policy = Arc::new(RuntimePolicy::upstream());
        let budget = Arc::new(budget::Budget::new(Arc::clone(&policy)));
        Self {
            args: args
                .into_iter()
                .map(|argument| OsString::from(argument.as_ref()))
                .collect(),
            environment: environment.into(),
            stdin: Arc::new(Mutex::new(Box::new(BufReader::new(std::io::stdin())))),
            stdout: Arc::new(Mutex::new(Box::new(stdout))),
            stderr: Arc::new(Mutex::new(Box::new(std::io::stderr()))),
            stdin_buffering: Arc::new(Mutex::new(BufferMode::Line)),
            stdout_buffering: Arc::new(Mutex::new(BufferMode::Line)),
            stderr_buffering: Arc::new(Mutex::new(BufferMode::None)),
            cwd: Arc::new(Mutex::new(cwd)),
            allow_filesystem,
            allow_process,
            max_concurrent_actions: None,
            current_time: None,
            allow_network: true,
            http_request_limit: None,
            policy,
            budget,
            host_services: Arc::new(HostServices::from_environment(host_environment)),
        }
    }

    #[must_use]
    pub fn with_policy(mut self, policy: RuntimePolicy) -> Self {
        let policy = Arc::new(policy);
        self.budget = Arc::new(budget::Budget::new(Arc::clone(&policy)));
        self.allow_filesystem = policy.capabilities.filesystem;
        self.allow_process = policy.capabilities.process;
        self.allow_network =
            policy.capabilities.network_loopback || policy.capabilities.network_external;
        self.policy = policy;
        self
    }

    #[must_use]
    pub fn policy(&self) -> &RuntimePolicy {
        &self.policy
    }

    #[must_use]
    pub fn budget(&self) -> &Arc<budget::Budget> {
        &self.budget
    }

    /// Overrides the number of workers used by pooled concurrency actions.
    #[must_use]
    pub fn with_max_concurrent_actions(mut self, max_concurrent_actions: usize) -> Self {
        self.max_concurrent_actions = Some(max_concurrent_actions.max(1));
        self
    }

    /// Overrides standard input for deterministic embedding and tests.
    #[must_use]
    pub fn with_stdin(mut self, stdin: impl Read + Send + 'static) -> Self {
        self.stdin = Arc::new(Mutex::new(Box::new(BufReader::new(stdin))));
        self
    }

    /// Overrides the UTC clock used by `UTCTime.getCurrentTime`.
    #[must_use]
    pub fn with_current_time(mut self, current_time: SystemTime) -> Self {
        self.current_time = Some(current_time);
        self
    }

    /// Enables or disables HTTP listener creation for this runtime.
    #[must_use]
    pub fn with_network_capability(mut self, allow_network: bool) -> Self {
        self.allow_network = allow_network;
        self
    }

    /// Bounds the requests served by `Http.run` before its action returns.
    #[must_use]
    pub fn with_http_request_limit(mut self, request_limit: usize) -> Self {
        self.http_request_limit = Some(request_limit.max(1));
        self
    }

    pub(crate) fn current_time(&self) -> RuntimeResult<SystemTime> {
        self.require_clock("UTCTime.getCurrentTime")?;
        Ok(self.current_time.unwrap_or_else(SystemTime::now))
    }

    fn require_network(&self, operation: &'static str) -> RuntimeResult<()> {
        if self.allow_network {
            Ok(())
        } else {
            Err(RuntimeError::http(format!(
                "{operation}: network capability is disabled"
            )))
        }
    }

    fn require_environment_read(&self, operation: &'static str) -> RuntimeResult<()> {
        self.policy
            .capabilities
            .environment_read
            .then_some(())
            .ok_or_else(|| Self::io_error(operation, "environment read capability is disabled"))
    }

    fn require_clock(&self, operation: &'static str) -> RuntimeResult<()> {
        self.policy
            .capabilities
            .clock
            .then_some(())
            .ok_or_else(|| Self::io_error(operation, "clock capability is disabled"))
    }

    fn require_exit_process(&self, operation: &'static str) -> RuntimeResult<()> {
        self.policy
            .capabilities
            .exit_process
            .then_some(())
            .ok_or_else(|| Self::io_error(operation, "process-exit capability is disabled"))
    }

    /// Creates a runtime view of the current process environment.
    ///
    /// # Errors
    ///
    /// Returns an invalid-data error rather than silently dropping an
    /// environment name or value that cannot be represented as Hell `Text`.
    pub fn process(args: Vec<OsString>) -> std::io::Result<Self> {
        let environment = std::env::vars_os()
            .map(|(name, value)| {
                let name = name.into_string().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Environment.getEnvironment: variable name is not valid UTF-8",
                    )
                })?;
                let value = value.into_string().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Environment.getEnvironment: variable value is not valid UTF-8",
                    )
                })?;
                Ok((Arc::<str>::from(name), Arc::<str>::from(value)))
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        let mut context = Self::with_environment(Vec::new(), environment, std::io::stdout());
        context.args = args.into();
        Ok(context)
    }

    fn write(&self, bytes: &[u8]) -> RuntimeResult<()> {
        let mut stdout = self
            .stdout
            .lock()
            .map_err(|_| RuntimeError::internal("stdout mutex was poisoned"))?;
        stdout
            .write_all(bytes)
            .map_err(|error| Self::io_error("IO.stdout", error))?;
        let mode = *self
            .stdout_buffering
            .lock()
            .map_err(|_| RuntimeError::internal("stdout-buffering mutex was poisoned"))?;
        if mode == BufferMode::None || (mode == BufferMode::Line && bytes.contains(&b'\n')) {
            stdout
                .flush()
                .map_err(|error| Self::io_error("IO.stdout", error))?;
        }
        Ok(())
    }

    fn write_stderr(&self, bytes: &[u8]) -> RuntimeResult<()> {
        let mut stderr = self
            .stderr
            .lock()
            .map_err(|_| RuntimeError::internal("stderr mutex was poisoned"))?;
        stderr
            .write_all(bytes)
            .map_err(|error| Self::io_error("IO.stderr", error))?;
        let mode = *self
            .stderr_buffering
            .lock()
            .map_err(|_| RuntimeError::internal("stderr-buffering mutex was poisoned"))?;
        if mode == BufferMode::None || (mode == BufferMode::Line && bytes.contains(&b'\n')) {
            stderr
                .flush()
                .map_err(|error| Self::io_error("IO.stderr", error))?;
        }
        Ok(())
    }

    fn text_args(&self, operation: &'static str) -> RuntimeResult<Vec<Arc<str>>> {
        self.args
            .iter()
            .map(|argument| {
                argument.to_str().map(Arc::from).ok_or_else(|| {
                    Self::io_error(operation, "argument is not valid Unicode on this platform")
                })
            })
            .collect()
    }

    fn read_stdin_line(&self, operation: &'static str) -> RuntimeResult<Arc<str>> {
        let mut input = self
            .stdin
            .lock()
            .map_err(|_| RuntimeError::internal("stdin mutex was poisoned"))?;
        let mut line = String::new();
        let read = input
            .read_line(&mut line)
            .map_err(|error| Self::io_error(operation, error))?;
        if read == 0 {
            return Err(Self::io_error(operation, "end of input"));
        }
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(line.into())
    }

    fn read_stdin_up_to(&self, operation: &'static str, amount: usize) -> RuntimeResult<Vec<u8>> {
        let mut input = self
            .stdin
            .lock()
            .map_err(|_| RuntimeError::internal("stdin mutex was poisoned"))?;
        let mut bytes = Vec::with_capacity(amount);
        input
            .by_ref()
            .take(u64::try_from(amount).expect("usize fits u64"))
            .read_to_end(&mut bytes)
            .map_err(|error| Self::io_error(operation, error))?;
        Ok(bytes)
    }

    fn read_stdin_all(&self, operation: &'static str) -> RuntimeResult<Vec<u8>> {
        match self.policy.limits.stdin_bytes {
            Limit::Unlimited => {
                let mut input = self
                    .stdin
                    .lock()
                    .map_err(|_| RuntimeError::internal("stdin mutex was poisoned"))?;
                let mut bytes = Vec::new();
                input
                    .read_to_end(&mut bytes)
                    .map_err(|error| Self::io_error(operation, error))?;
                Ok(bytes)
            }
            Limit::At(limit) => {
                let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                let bytes = self.read_stdin_up_to(operation, limit.saturating_add(1))?;
                if bytes.len() > limit {
                    return Err(RuntimeError::resource_limit(format!(
                        "{operation} exceeds the configured input limit of {limit} bytes"
                    )));
                }
                Ok(bytes)
            }
        }
    }

    fn io_error(operation: &'static str, error: impl fmt::Display) -> Arc<RuntimeError> {
        Arc::new(RuntimeError {
            code: "H0903",
            kind: RuntimeErrorKind::Io,
            message: format!("{operation}: {error}").into(),
            suppressed: Arc::from([]),
        })
    }

    fn require_filesystem(&self, operation: &'static str) -> RuntimeResult<()> {
        if self.allow_filesystem {
            Ok(())
        } else {
            Err(Self::io_error(
                operation,
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "filesystem capability is disabled",
                ),
            ))
        }
    }

    fn require_process(&self, operation: &'static str) -> RuntimeResult<()> {
        if self.allow_process {
            Ok(())
        } else {
            Err(Self::io_error(
                operation,
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "child-process capability is disabled",
                ),
            ))
        }
    }

    fn set_buffering(&self, handle: &HostHandle, mode: BufferMode) -> RuntimeResult<()> {
        if let HostHandle::File { handle, .. } = handle {
            return handle
                .set_buffering(mode)
                .map_err(|error| Self::io_error("IO.hSetBuffering", error));
        }
        let target = match handle {
            HostHandle::Stdin => &self.stdin_buffering,
            HostHandle::Stdout => &self.stdout_buffering,
            HostHandle::Stderr => &self.stderr_buffering,
            HostHandle::Null => {
                return Err(RuntimeError::internal(
                    "cannot configure buffering on the null stream",
                ));
            }
            HostHandle::File { .. } => unreachable!("file handles returned above"),
        };
        *target
            .lock()
            .map_err(|_| RuntimeError::internal("handle-buffering mutex was poisoned"))? = mode;
        Ok(())
    }

    fn resolve_path(&self, operation: &'static str, path: &str) -> RuntimeResult<PathBuf> {
        self.require_filesystem(operation)?;
        let path = Path::new(path);
        if path.is_absolute() {
            return Ok(path.to_owned());
        }
        let cwd = self
            .cwd
            .lock()
            .map_err(|_| RuntimeError::internal("working-directory mutex was poisoned"))?;
        Ok(cwd.join(path))
    }
}

type IoOperation = dyn Fn(&mut Evaluator, &RuntimeContext) -> RuntimeResult<ThunkRef> + Send + Sync;
type NativeThunkOperation = dyn Fn(&mut Evaluator) -> RuntimeResult<ValueRef> + Send + Sync;

#[derive(Clone)]
pub struct IoAction {
    operation: Arc<IoOperation>,
}

impl fmt::Debug for IoAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IoAction").finish_non_exhaustive()
    }
}

impl IoAction {
    fn new(
        operation: impl Fn(&mut Evaluator, &RuntimeContext) -> RuntimeResult<ThunkRef>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            operation: Arc::new(operation),
        }
    }

    fn run(&self, evaluator: &mut Evaluator, context: &RuntimeContext) -> RuntimeResult<ThunkRef> {
        let budget = Arc::clone(&evaluator.budget);
        let _budget = ActiveBudgetGuard::enter(&budget);
        (self.operation)(evaluator, context)
    }
}

#[derive(Clone, Debug)]
pub enum Value {
    Unit,
    Bool(bool),
    Int(i64),
    Integer(Arc<BigInteger>),
    Double(f64),
    JsonNumber(JsonNumber),
    JsonDocument(Arc<JsonDocument>, usize),
    Day(native_time::Day),
    DayOfWeek(native_time::DayOfWeek),
    UtcTime(native_time::UtcTime),
    TimeOfDay(native_time::TimeOfDay),
    HttpStatus(native_http::Status),
    HttpFilePart(native_http::FilePart),
    HttpRequest(Arc<native_http::Request>),
    HttpResponse(Arc<native_http::Response>),
    HttpResponseReceived(u64),
    Character(char),
    Builder(Arc<[u8]>),
    Internal(internal::InternalValue),
    CaseInsensitive(CaseInsensitiveValue),
    Tree(TreeValue),
    OptionsMod(OptionModifiers),
    OptionsInfoMod(InfoModifiers),
    OptionsParser(Arc<OptionParser>),
    OptionsParserInfo(ParserInfo),
    Text(Arc<str>),
    ByteString(Arc<[u8]>),
    Process(Arc<ProcessSpec>),
    Handle(HostHandle),
    BufferMode(BufferMode),
    FileMode(FileMode),
    Function(FunctionValue),
    Tuple(Arc<[ThunkRef]>),
    Record {
        layout: Arc<RecordLayout>,
        fields: Arc<[ThunkRef]>,
    },
    Variant {
        layout: Arc<VariantLayout>,
        constructor_index: u16,
        payload: Option<ThunkRef>,
    },
    Maybe(Option<ThunkRef>),
    PrimitiveVariant(PrimitiveVariantValue),
    List(ListCell),
    Vector(Arc<[ThunkRef]>),
    Map(Arc<OrderedMap>),
    Set(Arc<OrderedSet>),
    Io(IoAction),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimitiveFamily {
    Either,
    Exit,
    These,
    Json,
}

#[derive(Clone, Debug)]
pub struct PrimitiveVariantValue {
    pub family: PrimitiveFamily,
    pub constructor_index: u8,
    pub payloads: Arc<[ThunkRef]>,
}

impl PrimitiveVariantValue {
    fn constructor_name(&self) -> Option<&'static str> {
        let constructors: &[&str] = match self.family {
            PrimitiveFamily::Either => &["Left", "Right"],
            PrimitiveFamily::Exit => &["ExitSuccess", "ExitFailure"],
            PrimitiveFamily::These => &["This", "That", "These"],
            PrimitiveFamily::Json => &["Null", "Bool", "String", "Number", "Array", "Object"],
        };
        constructors
            .get(usize::from(self.constructor_index))
            .copied()
    }
}

#[derive(Clone, Debug)]
pub enum ListCell {
    Nil,
    Cons { head: ThunkRef, tail: ThunkRef },
}

#[derive(Clone, Debug)]
pub enum FunctionValue {
    Guest {
        body: CoreId,
        environment: Environment,
    },
    Native {
        builtin: BuiltinId,
        arguments: Arc<[ThunkRef]>,
        evidence: Option<ClassEvidence>,
    },
    Host(HostFunction),
}

type HostFunctionOperation = dyn Fn(ThunkRef) -> RuntimeResult<ForceOutcome> + Send + Sync;

#[derive(Clone)]
pub struct HostFunction {
    operation: Arc<HostFunctionOperation>,
}

impl HostFunction {
    fn new(
        operation: impl Fn(ThunkRef) -> RuntimeResult<ForceOutcome> + Send + Sync + 'static,
    ) -> Self {
        Self {
            operation: Arc::new(operation),
        }
    }

    fn apply(&self, argument: ThunkRef) -> RuntimeResult<ForceOutcome> {
        (self.operation)(argument)
    }
}

impl fmt::Debug for HostFunction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostFunction")
            .finish_non_exhaustive()
    }
}

type Environment = Arc<[ThunkRef]>;

pub struct Thunk {
    state: Mutex<ThunkState>,
    ready: Condvar,
    _live_thunk_permit: Option<budget::BudgetPermit>,
}

impl fmt::Debug for Thunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Thunk").finish_non_exhaustive()
    }
}

enum ThunkState {
    Suspended(Suspension),
    Evaluating { owner: EvaluationId },
    Evaluated(ValueRef),
    Indirection(ThunkRef),
    Failed(Arc<RuntimeError>),
}

/// Ensures a claimed thunk can never be left in `Evaluating`, including when
/// native code unwinds or an update lock is poisoned.
struct ThunkUpdateGuard {
    thunk: ThunkRef,
    completed: bool,
}

impl ThunkUpdateGuard {
    fn new(thunk: ThunkRef) -> Self {
        Self {
            thunk,
            completed: false,
        }
    }

    fn store(&mut self, result: &RuntimeResult<ForceOutcome>) -> RuntimeResult<()> {
        let mut state = self
            .thunk
            .state
            .lock()
            .map_err(|_| RuntimeError::internal("thunk mutex was poisoned"))?;
        match result {
            Ok(ForceOutcome::Value(value)) => *state = ThunkState::Evaluated(Arc::clone(value)),
            Ok(ForceOutcome::Alias(target)) => {
                *state = ThunkState::Indirection(Arc::clone(target));
            }
            Err(error) => *state = ThunkState::Failed(Arc::clone(error)),
        }
        self.thunk.ready.notify_all();
        self.completed = true;
        Ok(())
    }
}

impl Drop for ThunkUpdateGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let error = RuntimeError::internal("evaluation unwound while updating a thunk");
        let mut state = self
            .thunk
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, ThunkState::Evaluating { .. }) {
            *state = ThunkState::Failed(error);
        }
        self.thunk.ready.notify_all();
    }
}

#[derive(Clone)]
enum Suspension {
    Expression {
        node: CoreId,
        environment: Environment,
    },
    ListLiteral {
        nodes: Arc<[CoreId]>,
        index: usize,
        environment: Environment,
    },
    ListTake {
        remaining: i64,
        list: ThunkRef,
    },
    ListIterate {
        function: ThunkRef,
        current: ThunkRef,
        force_current: bool,
    },
    ListMap {
        function: ThunkRef,
        list: ThunkRef,
    },
    ListZip {
        left: ThunkRef,
        right: ThunkRef,
    },
    SemigroupAppend {
        left: ThunkRef,
        right: ThunkRef,
    },
    Apply {
        function: ThunkRef,
        argument: ThunkRef,
    },
    Fix {
        function: ThunkRef,
        recursive: Weak<Thunk>,
    },
    Native(Arc<NativeThunkOperation>),
}

impl Thunk {
    fn allocate(state: ThunkState) -> ThunkRef {
        let admission = ACTIVE_BUDGET.with(|active| {
            active
                .borrow()
                .as_ref()
                .and_then(Weak::upgrade)
                .map(|budget| {
                    budget
                        .charge_allocation(1)
                        .and_then(|()| budget.acquire_live_thunk())
                })
        });
        let (state, permit) = match admission {
            Some(Ok(permit)) => (state, Some(permit)),
            Some(Err(error)) => (ThunkState::Failed(error), None),
            None => (state, None),
        };
        Arc::new(Self {
            state: Mutex::new(state),
            ready: Condvar::new(),
            _live_thunk_permit: permit,
        })
    }

    fn suspended(suspension: Suspension) -> ThunkRef {
        Self::allocate(ThunkState::Suspended(suspension))
    }

    fn failed_without_admission(error: Arc<RuntimeError>) -> ThunkRef {
        Arc::new(Self {
            state: Mutex::new(ThunkState::Failed(error)),
            ready: Condvar::new(),
            _live_thunk_permit: None,
        })
    }

    fn fixed(function: ThunkRef) -> ThunkRef {
        let admission = ACTIVE_BUDGET.with(|active| {
            active
                .borrow()
                .as_ref()
                .and_then(Weak::upgrade)
                .map(|budget| {
                    budget
                        .charge_allocation(1)
                        .and_then(|()| budget.acquire_live_thunk())
                })
        });
        let permit = match admission {
            Some(Err(error)) => return Self::failed_without_admission(error),
            Some(Ok(permit)) => Some(permit),
            None => None,
        };
        Arc::new_cyclic(|recursive| Self {
            state: Mutex::new(ThunkState::Suspended(Suspension::Fix {
                function,
                recursive: recursive.clone(),
            })),
            ready: Condvar::new(),
            _live_thunk_permit: permit,
        })
    }

    #[must_use]
    pub fn evaluated(value: Value) -> ThunkRef {
        Self::allocate(ThunkState::Evaluated(Arc::new(value)))
    }

    /// Creates a memoized deferred host computation for embedding and runtime
    /// state-machine tests. Guest built-ins should prefer explicit suspension
    /// variants so their demand remains auditable.
    #[must_use]
    pub fn deferred(
        operation: impl Fn(&mut Evaluator) -> RuntimeResult<ValueRef> + Send + Sync + 'static,
    ) -> ThunkRef {
        Self::suspended(Suspension::Native(Arc::new(operation)))
    }
}

thread_local! {
    static ACTIVE_BUDGET: RefCell<Option<Weak<budget::Budget>>> = const { RefCell::new(None) };
}

struct ActiveBudgetGuard {
    previous: Option<Weak<budget::Budget>>,
}

impl ActiveBudgetGuard {
    fn enter(budget: &Arc<budget::Budget>) -> Self {
        let previous =
            ACTIVE_BUDGET.with(|active| active.borrow_mut().replace(Arc::downgrade(budget)));
        Self { previous }
    }
}

impl Drop for ActiveBudgetGuard {
    fn drop(&mut self) {
        ACTIVE_BUDGET.with(|active| {
            *active.borrow_mut() = self.previous.take();
        });
    }
}

static NEXT_EVALUATION_ID: AtomicU64 = AtomicU64::new(1);
static WAIT_GRAPH: OnceLock<Mutex<HashMap<EvaluationId, EvaluationId>>> = OnceLock::new();

struct WaitRegistration {
    waiter: EvaluationId,
}

impl Drop for WaitRegistration {
    fn drop(&mut self) {
        let graph = WAIT_GRAPH.get_or_init(|| Mutex::new(HashMap::new()));
        graph
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.waiter);
    }
}

fn register_wait(waiter: EvaluationId, owner: EvaluationId) -> RuntimeResult<WaitRegistration> {
    let mut graph = WAIT_GRAPH
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| RuntimeError::internal("evaluation wait graph was poisoned"))?;
    let mut current = owner;
    let mut visited = HashSet::new();
    while visited.insert(current) {
        if current == waiter {
            return Err(Arc::new(RuntimeError {
                code: "H0902",
                kind: RuntimeErrorKind::BlackHole,
                message: "cross-evaluator black hole detected in thunk wait graph".into(),
                suppressed: Arc::from([]),
            }));
        }
        let Some(next) = graph.get(&current) else {
            break;
        };
        current = *next;
    }
    graph.insert(waiter, owner);
    Ok(WaitRegistration { waiter })
}

fn next_evaluation_id() -> EvaluationId {
    loop {
        let id = NEXT_EVALUATION_ID.fetch_add(1, Ordering::Relaxed);
        if let Some(id) = NonZeroU64::new(id) {
            return id;
        }
    }
}

pub struct Evaluator {
    program: Arc<ExecutableProgram>,
    evaluation_id: EvaluationId,
    max_machine_frames: Limit<usize>,
    policy: Arc<RuntimePolicy>,
    budget: Arc<budget::Budget>,
    scope: scope::ExecutionScope,
    cancellation: concurrency::CancellationToken,
    max_concurrent_actions: usize,
}

enum Control {
    Evaluate {
        node: CoreId,
        environment: Environment,
    },
    Enter(ThunkRef),
    Return(ForceOutcome),
    Raise(Arc<RuntimeError>),
}

enum Frame {
    Update(ThunkUpdateGuard),
    Apply {
        argument: ThunkRef,
    },
    InvokeNative {
        builtin: BuiltinId,
        arguments: Arc<[ThunkRef]>,
        next_demand: usize,
        evidence: Option<ClassEvidence>,
    },
    ProjectTuple {
        arity: u8,
        index: u8,
    },
    RecordGet {
        layout: Arc<RecordLayout>,
        field_index: u16,
    },
    RecordSet {
        layout: Arc<RecordLayout>,
        field_index: u16,
        value: ThunkRef,
    },
    RecordModify {
        layout: Arc<RecordLayout>,
        field_index: u16,
        function: ThunkRef,
    },
    Case {
        layout: Arc<VariantLayout>,
        branches: Arc<[CaseBranch]>,
        default: Option<CoreId>,
        environment: Environment,
    },
    ListTake {
        remaining: i64,
    },
    ListIterateCurrent {
        function: ThunkRef,
        current: ThunkRef,
    },
    ListMap {
        function: ThunkRef,
    },
    ListZipLeft {
        right: ThunkRef,
    },
    ListZipRight {
        left_head: ThunkRef,
        left_tail: ThunkRef,
    },
    SemigroupText {
        left: Arc<str>,
    },
    SemigroupVector {
        left: Arc<[ThunkRef]>,
    },
    SemigroupLeft {
        left: ThunkRef,
        right: ThunkRef,
    },
    SemigroupMaybe {
        left: ThunkRef,
        left_payload: ThunkRef,
    },
}

impl Evaluator {
    #[must_use]
    pub fn new(program: Arc<ExecutableProgram>) -> Self {
        let policy = Arc::new(RuntimePolicy::upstream());
        let budget = Arc::new(budget::Budget::new(Arc::clone(&policy)));
        let cancellation = concurrency::CancellationToken::new();
        let scope = scope::ExecutionScope::with_cancellation(
            Arc::clone(&policy),
            Arc::clone(&budget),
            cancellation.clone(),
        );
        Self {
            program,
            evaluation_id: next_evaluation_id(),
            max_machine_frames: policy.limits.machine_frames,
            budget,
            policy,
            scope,
            cancellation,
            max_concurrent_actions: std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get),
        }
    }

    /// Creates an evaluator with an explicit heap-backed machine-frame limit.
    #[must_use]
    pub fn with_max_machine_frames(
        program: Arc<ExecutableProgram>,
        max_machine_frames: usize,
    ) -> Self {
        let policy = Arc::new(RuntimePolicy::sandboxed());
        let budget = Arc::new(budget::Budget::new(Arc::clone(&policy)));
        let cancellation = concurrency::CancellationToken::new();
        let scope = scope::ExecutionScope::with_cancellation(
            Arc::clone(&policy),
            Arc::clone(&budget),
            cancellation.clone(),
        );
        Self {
            program,
            evaluation_id: next_evaluation_id(),
            max_machine_frames: Limit::At(max_machine_frames),
            budget,
            policy,
            scope,
            cancellation,
            max_concurrent_actions: std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get),
        }
    }

    #[must_use]
    pub fn with_policy(mut self, policy: Arc<RuntimePolicy>, budget: Arc<budget::Budget>) -> Self {
        self.max_machine_frames = policy.limits.machine_frames;
        self.max_concurrent_actions = policy
            .limits
            .concurrent_tasks
            .value()
            .unwrap_or_else(|| {
                std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
            })
            .max(1);
        self.scope = scope::ExecutionScope::with_cancellation(
            Arc::clone(&policy),
            Arc::clone(&budget),
            self.cancellation.clone(),
        );
        self.budget = budget;
        self.policy = policy;
        self
    }

    /// Overrides the bounded worker count used by pooled concurrency actions.
    #[must_use]
    pub fn with_max_concurrent_actions(mut self, max_concurrent_actions: usize) -> Self {
        self.max_concurrent_actions = max_concurrent_actions.max(1);
        self
    }

    /// Allocates a suspended thunk for the verified program root.
    #[must_use]
    pub fn root_thunk(&self) -> ThunkRef {
        self.expression_thunk(self.program.root(), Arc::from([]))
    }

    /// Returns a wakeable cancellation handle for embedding-controlled shutdown.
    #[must_use]
    pub fn cancellation_handle(&self) -> scope::CancellationToken {
        self.cancellation.clone()
    }

    fn fork_with_scope(&self, scope: scope::ExecutionScope) -> Self {
        let cancellation = scope.cancellation().clone();
        Self {
            program: Arc::clone(&self.program),
            evaluation_id: next_evaluation_id(),
            max_machine_frames: self.max_machine_frames,
            policy: Arc::clone(&self.policy),
            budget: Arc::clone(&self.budget),
            scope,
            cancellation,
            max_concurrent_actions: self.max_concurrent_actions,
        }
    }

    fn child_cancellation(&self) -> concurrency::CancellationToken {
        self.cancellation.child()
    }

    fn execution_scope(&self) -> &scope::ExecutionScope {
        &self.scope
    }

    fn concurrent_action_limit(&self) -> usize {
        self.max_concurrent_actions
    }

    fn ensure_not_cancelled(&self) -> RuntimeResult<()> {
        if self.cancellation.is_cancelled() {
            Err(RuntimeError::cancelled())
        } else {
            Ok(())
        }
    }

    #[allow(clippy::unused_self)]
    fn expression_thunk(&self, node: CoreId, environment: Environment) -> ThunkRef {
        let _budget = ActiveBudgetGuard::enter(&self.budget);
        Thunk::suspended(Suspension::Expression { node, environment })
    }

    /// Forces a thunk to weak-head normal form, memoizing success and failure.
    ///
    /// # Errors
    ///
    /// Returns a runtime error for user failures, black holes, invalid verified
    /// invariants, or when the controlled evaluator stack limit is exceeded.
    pub fn force(&mut self, original: &ThunkRef) -> RuntimeResult<ValueRef> {
        let budget = Arc::clone(&self.budget);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _budget = ActiveBudgetGuard::enter(&budget);
            self.run_machine(Control::Enter(Arc::clone(original)))
        }))
        .unwrap_or_else(|_| {
            Err(RuntimeError::internal(
                "panic crossed the native/core evaluation boundary",
            ))
        })
    }

    fn push_frame(&self, stack: &mut Vec<Frame>, frame: Frame) -> RuntimeResult<()> {
        if let Limit::At(maximum) = self.max_machine_frames
            && stack.len() >= maximum
        {
            return Err(RuntimeError::resource_limit(format!(
                "evaluation exceeded the configured limit of {maximum} machine frames"
            )));
        }
        stack.push(frame);
        Ok(())
    }

    fn run_machine(&mut self, mut control: Control) -> RuntimeResult<ValueRef> {
        let mut stack = Vec::new();
        loop {
            self.budget.charge_steps(1)?;
            self.ensure_not_cancelled()?;
            match control {
                Control::Raise(error) => return Self::unwind_machine(&mut stack, error),
                Control::Return(ForceOutcome::Alias(target)) => {
                    if matches!(stack.last(), Some(Frame::Update(_))) {
                        let Some(Frame::Update(mut update)) = stack.pop() else {
                            unreachable!("update frame was just inspected")
                        };
                        let result = Ok(ForceOutcome::Alias(Arc::clone(&target)));
                        if let Err(error) = update.store(&result) {
                            control = Control::Raise(error);
                            continue;
                        }
                    }
                    control = Control::Enter(target);
                }
                Control::Return(ForceOutcome::Value(value)) => {
                    let Some(frame) = stack.pop() else {
                        return Ok(value);
                    };
                    control = match self.resume_frame(frame, value, &mut stack) {
                        Ok(control) => control,
                        Err(error) => Control::Raise(error),
                    };
                }
                Control::Enter(thunk) => {
                    control = match self.enter_thunk(thunk, &mut stack) {
                        Ok(control) => control,
                        Err(error) => Control::Raise(error),
                    };
                }
                Control::Evaluate { node, environment } => {
                    control = match self.evaluate_control(node, environment, &mut stack) {
                        Ok(control) => control,
                        Err(error) => Control::Raise(error),
                    };
                }
            }
        }
    }

    fn unwind_machine(
        stack: &mut Vec<Frame>,
        mut error: Arc<RuntimeError>,
    ) -> RuntimeResult<ValueRef> {
        while let Some(frame) = stack.pop() {
            if let Frame::Update(mut update) = frame {
                let result = Err(Arc::clone(&error));
                if let Err(update_error) = update.store(&result) {
                    error = update_error;
                }
            }
        }
        Err(error)
    }

    fn enter_thunk(&mut self, thunk: ThunkRef, stack: &mut Vec<Frame>) -> RuntimeResult<Control> {
        let mut current = thunk;
        loop {
            let mut state = current
                .state
                .lock()
                .map_err(|_| RuntimeError::internal("thunk mutex was poisoned"))?;
            match &*state {
                ThunkState::Evaluated(value) => {
                    return Ok(Control::Return(ForceOutcome::Value(Arc::clone(value))));
                }
                ThunkState::Failed(error) => return Ok(Control::Raise(Arc::clone(error))),
                ThunkState::Indirection(target) => {
                    let target = Arc::clone(target);
                    drop(state);
                    current = target;
                }
                ThunkState::Evaluating { owner } if *owner == self.evaluation_id => {
                    return Ok(Control::Raise(Arc::new(RuntimeError {
                        code: "H0902",
                        kind: RuntimeErrorKind::BlackHole,
                        message: "black hole while forcing a recursive thunk".into(),
                        suppressed: Arc::from([]),
                    })));
                }
                ThunkState::Evaluating { owner } => {
                    let wait = register_wait(self.evaluation_id, *owner)?;
                    let (next_state, _) = current
                        .ready
                        .wait_timeout(state, std::time::Duration::from_millis(10))
                        .map_err(|_| RuntimeError::internal("thunk mutex was poisoned"))?;
                    state = next_state;
                    drop(wait);
                    drop(state);
                    self.ensure_not_cancelled()?;
                }
                ThunkState::Suspended(_) => {
                    if let Limit::At(maximum) = self.max_machine_frames
                        && stack.len() >= maximum
                    {
                        return Err(RuntimeError::resource_limit(format!(
                            "evaluation exceeded the configured limit of {maximum} machine frames"
                        )));
                    }
                    let old = std::mem::replace(
                        &mut *state,
                        ThunkState::Evaluating {
                            owner: self.evaluation_id,
                        },
                    );
                    let ThunkState::Suspended(suspension) = old else {
                        return Err(RuntimeError::internal("invalid thunk transition"));
                    };
                    drop(state);
                    stack.push(Frame::Update(ThunkUpdateGuard::new(Arc::clone(&current))));
                    return self.enter_suspension(suspension, stack);
                }
            }
        }
    }

    fn enter_suspension(
        &mut self,
        suspension: Suspension,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        match suspension {
            Suspension::Expression { node, environment } => {
                Ok(Control::Evaluate { node, environment })
            }
            Suspension::Apply { function, argument } => {
                self.push_frame(stack, Frame::Apply { argument })?;
                Ok(Control::Enter(function))
            }
            Suspension::Fix {
                function,
                recursive,
            } => {
                let recursive = recursive.upgrade().ok_or_else(|| {
                    RuntimeError::internal("Function.fix recursive thunk was released")
                })?;
                self.push_frame(
                    stack,
                    Frame::Apply {
                        argument: recursive,
                    },
                )?;
                Ok(Control::Enter(function))
            }
            Suspension::ListLiteral {
                nodes,
                index,
                environment,
            } => {
                if index >= nodes.len() {
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::List(
                        ListCell::Nil,
                    )))))
                } else {
                    let head = self.expression_thunk(nodes[index], Arc::clone(&environment));
                    let tail = Thunk::suspended(Suspension::ListLiteral {
                        nodes,
                        index: index + 1,
                        environment,
                    });
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::List(
                        ListCell::Cons { head, tail },
                    )))))
                }
            }
            Suspension::ListTake { remaining, list } => {
                if remaining <= 0 {
                    return Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::List(
                        ListCell::Nil,
                    )))));
                }
                self.push_frame(stack, Frame::ListTake { remaining })?;
                Ok(Control::Enter(list))
            }
            Suspension::ListIterate {
                function,
                current,
                force_current,
            } => {
                if force_current {
                    self.push_frame(
                        stack,
                        Frame::ListIterateCurrent {
                            function,
                            current: Arc::clone(&current),
                        },
                    )?;
                    Ok(Control::Enter(current))
                } else {
                    Ok(Control::Return(ForceOutcome::Value(Self::iterate_cell(
                        function, current,
                    ))))
                }
            }
            Suspension::ListMap { function, list } => {
                self.push_frame(stack, Frame::ListMap { function })?;
                Ok(Control::Enter(list))
            }
            Suspension::ListZip { left, right } => {
                self.push_frame(stack, Frame::ListZipLeft { right })?;
                Ok(Control::Enter(left))
            }
            Suspension::SemigroupAppend { left, right } => {
                self.push_frame(
                    stack,
                    Frame::SemigroupLeft {
                        left: Arc::clone(&left),
                        right,
                    },
                )?;
                Ok(Control::Enter(left))
            }
            Suspension::Native(operation) => operation(self)
                .map(ForceOutcome::Value)
                .map(Control::Return),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate_control(
        &mut self,
        id: CoreId,
        environment: Environment,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        let node = self
            .program
            .node(id)
            .cloned()
            .ok_or_else(|| RuntimeError::internal("core id is out of bounds"))?;
        match node.kind {
            CoreKind::BoundVar {
                de_bruijn,
                projection,
            } => {
                let index = environment
                    .len()
                    .checked_sub(de_bruijn as usize + 1)
                    .ok_or_else(|| RuntimeError::internal("de Bruijn index is out of scope"))?;
                let local = Arc::clone(&environment[index]);
                match projection {
                    Projection::Identity => Ok(Control::Return(ForceOutcome::Alias(local))),
                    Projection::TupleElement { arity, index } => {
                        self.push_frame(stack, Frame::ProjectTuple { arity, index })?;
                        Ok(Control::Enter(local))
                    }
                }
            }
            CoreKind::Lambda { body, .. } => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                Value::Function(FunctionValue::Guest { body, environment }),
            )))),
            CoreKind::Apply { function, argument } => {
                let function = self.expression_thunk(function, Arc::clone(&environment));
                let argument = self.expression_thunk(argument, environment);
                self.push_frame(stack, Frame::Apply { argument })?;
                Ok(Control::Enter(function))
            }
            CoreKind::Constant(constant) => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                match constant {
                    Constant::Unit => Value::Unit,
                    Constant::Bool(value) => Value::Bool(value),
                    Constant::Int(value) => Value::Int(value),
                    Constant::Double(value) => Value::Double(value),
                    Constant::Character(value) => Value::Character(value),
                    Constant::Text(value) => Value::Text(value),
                },
            )))),
            CoreKind::Builtin { builtin, evidence } => {
                let spec = hell_builtins::registry()
                    .get(builtin.0 as usize)
                    .ok_or_else(|| RuntimeError::internal("unknown built-in id"))?;
                if spec.arity == 0 {
                    self.schedule_native(builtin, &Arc::from([]), 0, evidence, stack)
                } else {
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(
                        Value::Function(FunctionValue::Native {
                            builtin,
                            arguments: Arc::from([]),
                            evidence,
                        }),
                    ))))
                }
            }
            CoreKind::Tuple { elements } => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                Value::Tuple(
                    elements
                        .iter()
                        .map(|child| self.expression_thunk(*child, Arc::clone(&environment)))
                        .collect::<Vec<_>>()
                        .into(),
                ),
            )))),
            CoreKind::List { elements } => self.enter_suspension(
                Suspension::ListLiteral {
                    nodes: elements,
                    index: 0,
                    environment,
                },
                stack,
            ),
            CoreKind::Record { layout, fields } => Ok(Control::Return(ForceOutcome::Value(
                Arc::new(Value::Record {
                    layout,
                    fields: fields
                        .iter()
                        .map(|child| self.expression_thunk(*child, Arc::clone(&environment)))
                        .collect::<Vec<_>>()
                        .into(),
                }),
            ))),
            CoreKind::RecordGet {
                layout,
                field_index,
                record,
            } => {
                let record = self.expression_thunk(record, environment);
                self.push_frame(
                    stack,
                    Frame::RecordGet {
                        layout,
                        field_index,
                    },
                )?;
                Ok(Control::Enter(record))
            }
            CoreKind::RecordSet {
                layout,
                field_index,
                value,
                record,
            } => {
                let record = self.expression_thunk(record, Arc::clone(&environment));
                let value = self.expression_thunk(value, environment);
                self.push_frame(
                    stack,
                    Frame::RecordSet {
                        layout,
                        field_index,
                        value,
                    },
                )?;
                Ok(Control::Enter(record))
            }
            CoreKind::RecordModify {
                layout,
                field_index,
                function,
                record,
            } => {
                let record = self.expression_thunk(record, Arc::clone(&environment));
                let function = self.expression_thunk(function, environment);
                self.push_frame(
                    stack,
                    Frame::RecordModify {
                        layout,
                        field_index,
                        function,
                    },
                )?;
                Ok(Control::Enter(record))
            }
            CoreKind::Variant {
                layout,
                constructor_index,
                payload,
            } => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                Value::Variant {
                    layout,
                    constructor_index,
                    payload: payload.map(|child| self.expression_thunk(child, environment)),
                },
            )))),
            CoreKind::Case {
                scrutinee,
                layout,
                branches,
                default,
            } => {
                let scrutinee = self.expression_thunk(scrutinee, Arc::clone(&environment));
                self.push_frame(
                    stack,
                    Frame::Case {
                        layout,
                        branches,
                        default,
                        environment,
                    },
                )?;
                Ok(Control::Enter(scrutinee))
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn resume_frame(
        &mut self,
        frame: Frame,
        value: ValueRef,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        match frame {
            Frame::Update(mut update) => {
                let result = Ok(ForceOutcome::Value(Arc::clone(&value)));
                update.store(&result)?;
                Ok(Control::Return(ForceOutcome::Value(value)))
            }
            Frame::Apply { argument } => self.apply_value(&value, argument, stack),
            Frame::InvokeNative {
                builtin,
                arguments,
                next_demand,
                evidence,
            } => self.schedule_native(builtin, &arguments, next_demand, evidence, stack),
            Frame::ProjectTuple { arity, index } => {
                let Value::Tuple(elements) = value.as_ref() else {
                    return Err(RuntimeError::internal(
                        "tuple projection received a non-tuple",
                    ));
                };
                if elements.len() != usize::from(arity) {
                    return Err(RuntimeError::internal("tuple projection arity mismatch"));
                }
                let selected = elements.get(usize::from(index)).ok_or_else(|| {
                    RuntimeError::internal("tuple projection index is out of bounds")
                })?;
                Ok(Control::Return(ForceOutcome::Alias(Arc::clone(selected))))
            }
            Frame::RecordGet {
                layout,
                field_index,
            } => {
                let Value::Record {
                    layout: actual_layout,
                    fields,
                } = value.as_ref()
                else {
                    return Err(RuntimeError::internal("Record.get received a non-record"));
                };
                if actual_layout.as_ref() != layout.as_ref() {
                    return Err(RuntimeError::internal("Record.get layout mismatch"));
                }
                let field = fields.get(usize::from(field_index)).ok_or_else(|| {
                    RuntimeError::internal("Record.get field index is out of bounds")
                })?;
                Ok(Control::Return(ForceOutcome::Alias(Arc::clone(field))))
            }
            Frame::RecordSet {
                layout,
                field_index,
                value: replacement,
            } => {
                let Value::Record {
                    layout: actual_layout,
                    fields,
                } = value.as_ref()
                else {
                    return Err(RuntimeError::internal("Record.set received a non-record"));
                };
                if actual_layout.as_ref() != layout.as_ref() {
                    return Err(RuntimeError::internal("Record.set layout mismatch"));
                }
                let mut updated = fields.to_vec();
                let Some(field) = updated.get_mut(usize::from(field_index)) else {
                    return Err(RuntimeError::internal(
                        "Record.set field index is out of bounds",
                    ));
                };
                *field = replacement;
                Ok(Control::Return(ForceOutcome::Value(Arc::new(
                    Value::Record {
                        layout: Arc::clone(actual_layout),
                        fields: updated.into(),
                    },
                ))))
            }
            Frame::RecordModify {
                layout,
                field_index,
                function,
            } => {
                let Value::Record {
                    layout: actual_layout,
                    fields,
                } = value.as_ref()
                else {
                    return Err(RuntimeError::internal(
                        "Record.modify received a non-record",
                    ));
                };
                if actual_layout.as_ref() != layout.as_ref() {
                    return Err(RuntimeError::internal("Record.modify layout mismatch"));
                }
                let mut updated = fields.to_vec();
                let Some(field) = updated.get_mut(usize::from(field_index)) else {
                    return Err(RuntimeError::internal(
                        "Record.modify field index is out of bounds",
                    ));
                };
                *field = Thunk::suspended(Suspension::Apply {
                    function,
                    argument: Arc::clone(field),
                });
                Ok(Control::Return(ForceOutcome::Value(Arc::new(
                    Value::Record {
                        layout: Arc::clone(actual_layout),
                        fields: updated.into(),
                    },
                ))))
            }
            Frame::Case {
                layout,
                branches,
                default,
                environment,
            } => {
                let Value::Variant {
                    layout: actual_layout,
                    constructor_index,
                    payload,
                } = value.as_ref()
                else {
                    return Err(RuntimeError::internal("case scrutinee was not a variant"));
                };
                if actual_layout.as_ref() != layout.as_ref() {
                    return Err(RuntimeError::internal("case variant layout mismatch"));
                }
                if let Some(branch) = branches
                    .iter()
                    .find(|branch| branch.constructor_index == *constructor_index)
                {
                    let mut selected_environment = environment.to_vec();
                    match (&branch.payload_type, payload) {
                        (Some(_), Some(payload)) => selected_environment.push(Arc::clone(payload)),
                        (None, None) => {}
                        _ => {
                            return Err(RuntimeError::internal(
                                "case branch payload shape mismatch",
                            ));
                        }
                    }
                    Ok(Control::Evaluate {
                        node: branch.body,
                        environment: selected_environment.into(),
                    })
                } else if let Some(default) = default {
                    Ok(Control::Evaluate {
                        node: default,
                        environment,
                    })
                } else {
                    Err(RuntimeError::internal(
                        "verified non-exhaustive case reached runtime",
                    ))
                }
            }
            Frame::ListTake { remaining } => match value.as_ref() {
                Value::List(ListCell::Nil) => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                    Value::List(ListCell::Nil),
                )))),
                Value::List(ListCell::Cons { head, tail }) => {
                    let output_tail = Thunk::suspended(Suspension::ListTake {
                        remaining: remaining - 1,
                        list: Arc::clone(tail),
                    });
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::List(
                        ListCell::Cons {
                            head: Arc::clone(head),
                            tail: output_tail,
                        },
                    )))))
                }
                _ => Err(RuntimeError::internal("List.take received a non-list")),
            },
            Frame::ListIterateCurrent { function, current } => Ok(Control::Return(
                ForceOutcome::Value(Self::iterate_cell(function, current)),
            )),
            Frame::ListMap { function } => match value.as_ref() {
                Value::List(ListCell::Nil) => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                    Value::List(ListCell::Nil),
                )))),
                Value::List(ListCell::Cons { head, tail }) => {
                    let mapped = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&function),
                        argument: Arc::clone(head),
                    });
                    let mapped_tail = Thunk::suspended(Suspension::ListMap {
                        function,
                        list: Arc::clone(tail),
                    });
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::List(
                        ListCell::Cons {
                            head: mapped,
                            tail: mapped_tail,
                        },
                    )))))
                }
                _ => Err(RuntimeError::internal("List.map received a non-list")),
            },
            Frame::ListZipLeft { right } => match value.as_ref() {
                Value::List(ListCell::Nil) => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                    Value::List(ListCell::Nil),
                )))),
                Value::List(ListCell::Cons { head, tail }) => {
                    self.push_frame(
                        stack,
                        Frame::ListZipRight {
                            left_head: Arc::clone(head),
                            left_tail: Arc::clone(tail),
                        },
                    )?;
                    Ok(Control::Enter(right))
                }
                _ => Err(RuntimeError::internal("List.zip received a non-list")),
            },
            Frame::ListZipRight {
                left_head,
                left_tail,
            } => match value.as_ref() {
                Value::List(ListCell::Nil) => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                    Value::List(ListCell::Nil),
                )))),
                Value::List(ListCell::Cons {
                    head: right_head,
                    tail: right_tail,
                }) => {
                    let head =
                        Thunk::evaluated(Value::Tuple([left_head, Arc::clone(right_head)].into()));
                    let tail = Thunk::suspended(Suspension::ListZip {
                        left: left_tail,
                        right: Arc::clone(right_tail),
                    });
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::List(
                        ListCell::Cons { head, tail },
                    )))))
                }
                _ => Err(RuntimeError::internal("List.zip received a non-list")),
            },
            Frame::SemigroupText { left } => {
                let Value::Text(right) = value.as_ref() else {
                    return Err(RuntimeError::internal(
                        "Semigroup Text received an incompatible value",
                    ));
                };
                let mut output = String::with_capacity(left.len() + right.len());
                output.push_str(&left);
                output.push_str(right);
                Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::Text(
                    output.into(),
                )))))
            }
            Frame::SemigroupVector { left } => {
                let Value::Vector(right) = value.as_ref() else {
                    return Err(RuntimeError::internal(
                        "Semigroup Vector received an incompatible value",
                    ));
                };
                let mut output = Vec::with_capacity(left.len() + right.len());
                output.extend(left.iter().cloned());
                output.extend(right.iter().cloned());
                Ok(Control::Return(ForceOutcome::Value(Arc::new(
                    Value::Vector(output.into()),
                ))))
            }
            Frame::SemigroupLeft { left, right } => match value.as_ref() {
                Value::Text(left_text) => {
                    self.push_frame(
                        stack,
                        Frame::SemigroupText {
                            left: Arc::clone(left_text),
                        },
                    )?;
                    Ok(Control::Enter(right))
                }
                Value::Vector(left_values) => {
                    self.push_frame(
                        stack,
                        Frame::SemigroupVector {
                            left: Arc::clone(left_values),
                        },
                    )?;
                    Ok(Control::Enter(right))
                }
                Value::Builder(left_bytes) => {
                    let right_value = self.force(&right)?;
                    let Value::Builder(right_bytes) = right_value.as_ref() else {
                        return Err(RuntimeError::internal(
                            "Semigroup Builder received an incompatible value",
                        ));
                    };
                    let mut output = Vec::with_capacity(left_bytes.len() + right_bytes.len());
                    output.extend_from_slice(left_bytes);
                    output.extend_from_slice(right_bytes);
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(
                        Value::Builder(output.into()),
                    ))))
                }
                Value::OptionsMod(left_modifiers) => {
                    let right_value = self.force(&right)?;
                    let Value::OptionsMod(right_modifiers) = right_value.as_ref() else {
                        return Err(RuntimeError::internal(
                            "Semigroup Options.Mod received an incompatible value",
                        ));
                    };
                    let mut output = left_modifiers.0.to_vec();
                    output.extend(right_modifiers.0.iter().cloned());
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(
                        Value::OptionsMod(OptionModifiers(output.into())),
                    ))))
                }
                Value::OptionsInfoMod(left_modifiers) => {
                    let right_value = self.force(&right)?;
                    let Value::OptionsInfoMod(right_modifiers) = right_value.as_ref() else {
                        return Err(RuntimeError::internal(
                            "Semigroup Options.InfoMod received an incompatible value",
                        ));
                    };
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(
                        Value::OptionsInfoMod(InfoModifiers {
                            full_description: left_modifiers.full_description
                                || right_modifiers.full_description,
                            program_description: right_modifiers
                                .program_description
                                .clone()
                                .or_else(|| left_modifiers.program_description.clone()),
                            header: right_modifiers
                                .header
                                .clone()
                                .or_else(|| left_modifiers.header.clone()),
                        }),
                    ))))
                }
                Value::List(ListCell::Nil) | Value::Maybe(None) => {
                    Ok(Control::Return(ForceOutcome::Alias(right)))
                }
                Value::List(ListCell::Cons { head, tail }) => {
                    let appended_tail = Thunk::suspended(Suspension::SemigroupAppend {
                        left: Arc::clone(tail),
                        right,
                    });
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::List(
                        ListCell::Cons {
                            head: Arc::clone(head),
                            tail: appended_tail,
                        },
                    )))))
                }
                Value::Maybe(Some(left_payload)) => {
                    self.push_frame(
                        stack,
                        Frame::SemigroupMaybe {
                            left,
                            left_payload: Arc::clone(left_payload),
                        },
                    )?;
                    Ok(Control::Enter(right))
                }
                Value::PrimitiveVariant(left_variant)
                    if left_variant.family == PrimitiveFamily::Either =>
                {
                    match left_variant.constructor_index {
                        0 => Ok(Control::Return(ForceOutcome::Alias(right))),
                        1 => Ok(Control::Return(ForceOutcome::Alias(left))),
                        _ => Err(RuntimeError::internal(
                            "Semigroup Either constructor is out of bounds",
                        )),
                    }
                }
                _ => Err(RuntimeError::internal(
                    "Semigroup evidence did not match runtime values",
                )),
            },
            Frame::SemigroupMaybe { left, left_payload } => match value.as_ref() {
                Value::Maybe(None) => Ok(Control::Return(ForceOutcome::Alias(left))),
                Value::Maybe(Some(right_payload)) => {
                    let payload = Thunk::suspended(Suspension::SemigroupAppend {
                        left: left_payload,
                        right: Arc::clone(right_payload),
                    });
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(
                        Value::Maybe(Some(payload)),
                    ))))
                }
                _ => Err(RuntimeError::internal(
                    "Semigroup Maybe received incompatible values",
                )),
            },
        }
    }

    fn apply_value(
        &mut self,
        function: &ValueRef,
        argument: ThunkRef,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        match function.as_ref() {
            Value::Function(FunctionValue::Guest { body, environment }) => {
                let mut extended = environment.to_vec();
                extended.push(argument);
                Ok(Control::Evaluate {
                    node: *body,
                    environment: extended.into(),
                })
            }
            Value::Function(FunctionValue::Native {
                builtin,
                arguments,
                evidence,
            }) => {
                let mut captured = arguments.to_vec();
                captured.push(argument);
                let arity = hell_builtins::registry()[builtin.0 as usize].arity as usize;
                if captured.len() < arity {
                    Ok(Control::Return(ForceOutcome::Value(Arc::new(
                        Value::Function(FunctionValue::Native {
                            builtin: *builtin,
                            arguments: captured.into(),
                            evidence: *evidence,
                        }),
                    ))))
                } else {
                    for extra in captured[arity..].iter().rev() {
                        self.push_frame(
                            stack,
                            Frame::Apply {
                                argument: Arc::clone(extra),
                            },
                        )?;
                    }
                    let arguments = Arc::from(captured[..arity].to_vec());
                    self.schedule_native(*builtin, &arguments, 0, *evidence, stack)
                }
            }
            Value::Function(FunctionValue::Host(function)) => {
                function.apply(argument).map(Control::Return)
            }
            _ => Err(RuntimeError::internal("attempted to apply a non-function")),
        }
    }

    fn schedule_native(
        &mut self,
        builtin: BuiltinId,
        arguments: &Arc<[ThunkRef]>,
        next_demand: usize,
        evidence: Option<ClassEvidence>,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        let spec = hell_builtins::registry()
            .get(builtin.0 as usize)
            .ok_or_else(|| RuntimeError::internal("unknown built-in id"))?;
        // Drive declared WHNF demand through this machine before entering the
        // adapter. Its typed force helpers then hit memoized values instead of
        // nesting evaluator calls on the Rust stack. Subtraction is a pinned
        // flipped primitive, so its observable failure order is right-to-left.
        let reverse_binary = matches!(
            spec.implementation,
            Some("int_subtract" | "integer_subtract" | "double_subtract")
        );
        for position in next_demand..arguments.len() {
            let index = if reverse_binary {
                arguments.len() - position - 1
            } else {
                position
            };
            if matches!(
                spec.demand.get(index),
                Some(
                    hell_builtins::Demand::Whnf
                        | hell_builtins::Demand::Deep
                        | hell_builtins::Demand::Conditional
                )
            ) {
                self.push_frame(
                    stack,
                    Frame::InvokeNative {
                        builtin,
                        arguments: Arc::clone(arguments),
                        next_demand: position + 1,
                        evidence,
                    },
                )?;
                return Ok(Control::Enter(Arc::clone(&arguments[index])));
            }
        }
        self.apply_native(builtin, arguments, evidence)
            .map(Control::Return)
    }

    fn iterate_cell(function: ThunkRef, current: ThunkRef) -> ValueRef {
        let next = Thunk::suspended(Suspension::Apply {
            function: Arc::clone(&function),
            argument: Arc::clone(&current),
        });
        let tail = Thunk::suspended(Suspension::ListIterate {
            function,
            current: next,
            force_current: true,
        });
        Arc::new(Value::List(ListCell::Cons {
            head: current,
            tail,
        }))
    }

    #[allow(clippy::float_cmp, clippy::too_many_lines)]
    fn apply_native(
        &mut self,
        builtin: BuiltinId,
        arguments: &[ThunkRef],
        evidence: Option<ClassEvidence>,
    ) -> RuntimeResult<ForceOutcome> {
        let spec = &hell_builtins::registry()[builtin.0 as usize];
        let implementation = spec
            .implementation
            .ok_or_else(|| RuntimeError::internal("unavailable native reached runtime"))?;
        if let Some(result) = typeclasses::apply_native(implementation, arguments, evidence, self) {
            return result;
        }
        if let Some(result) = internal::apply_native(implementation, arguments, self) {
            return result;
        }
        if let Some(result) = native_time::apply_native(implementation, arguments, self) {
            return result;
        }
        if let Some(result) = native_http::apply_native(implementation, arguments, self) {
            return result;
        }
        if let Some(result) = native_list::apply_native(implementation, arguments, self) {
            return result;
        }
        if let Some(result) = native_collections::apply_native(implementation, arguments, self) {
            return result;
        }
        let value = |value| Ok(ForceOutcome::Value(Arc::new(value)));
        match implementation {
            "bool_false" => value(Value::Bool(false)),
            "bool_true" => value(Value::Bool(true)),
            "bool_not" => value(Value::Bool(!self.force_bool(&arguments[0])?)),
            "bool_choose" => {
                let selected = usize::from(self.force_bool(&arguments[2])?);
                Ok(ForceOutcome::Alias(Arc::clone(&arguments[selected])))
            }
            "identity" => Ok(ForceOutcome::Alias(Arc::clone(&arguments[0]))),
            "apply" => Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                function: Arc::clone(&arguments[0]),
                argument: Arc::clone(&arguments[1]),
            }))),
            "fix" => Ok(ForceOutcome::Alias(Thunk::fixed(Arc::clone(&arguments[0])))),
            "error" => Err(RuntimeError::user(self.force_text(&arguments[0])?)),
            "int_eq" => value(Value::Bool(
                self.force_int(&arguments[0])? == self.force_int(&arguments[1])?,
            )),
            "eq" => value(Value::Bool(
                self.equal_values(&arguments[0], &arguments[1])?,
            )),
            "ord_lt" => value(Value::Bool(self.less_values(&arguments[0], &arguments[1])?)),
            "ord_gt" => value(Value::Bool(self.less_values(&arguments[1], &arguments[0])?)),
            "int_plus" => value(Value::Int(
                self.force_int(&arguments[0])?
                    .wrapping_add(self.force_int(&arguments[1])?),
            )),
            "int_subtract" => value(Value::Int(
                self.force_int(&arguments[1])?
                    .wrapping_sub(self.force_int(&arguments[0])?),
            )),
            "int_mult" => value(Value::Int(
                self.force_int(&arguments[0])?
                    .wrapping_mul(self.force_int(&arguments[1])?),
            )),
            "int_show" => value(Value::Text(
                self.force_int(&arguments[0])?.to_string().into(),
            )),
            "int_read_maybe" => {
                let parsed = self
                    .force_text(&arguments[0])?
                    .trim()
                    .parse::<i64>()
                    .ok()
                    .map(|number| Thunk::evaluated(Value::Int(number)));
                value(Value::Maybe(parsed))
            }
            "int_to_integer" => value(Value::Integer(Arc::new(BigInteger::from_i64(
                self.force_int(&arguments[0])?,
            )))),
            "int_from_integer" => value(Value::Int(
                self.force_integer(&arguments[0])?.wrapping_i64(),
            )),
            "integer_plus" => {
                let left = self.force_integer(&arguments[0])?;
                let right = self.force_integer(&arguments[1])?;
                value(Value::Integer(Arc::new(left.add(right.as_ref()))))
            }
            "integer_subtract" => {
                let subtrahend = self.force_integer(&arguments[0])?;
                let minuend = self.force_integer(&arguments[1])?;
                value(Value::Integer(Arc::new(
                    minuend.subtract(subtrahend.as_ref()),
                )))
            }
            "integer_mult" => {
                let left = self.force_integer(&arguments[0])?;
                let right = self.force_integer(&arguments[1])?;
                value(Value::Integer(Arc::new(left.multiply(right.as_ref()))))
            }
            "integer_read_maybe" => {
                let parsed = BigInteger::parse(&self.force_text(&arguments[0])?)
                    .map(|number| Thunk::evaluated(Value::Integer(Arc::new(number))));
                value(Value::Maybe(parsed))
            }
            "double_eq" => value(Value::Bool(
                self.force_double(&arguments[0])? == self.force_double(&arguments[1])?,
            )),
            "double_from_int" => {
                value(Value::Double(int_to_double(self.force_int(&arguments[0])?)))
            }
            "double_plus" => value(Value::Double(
                self.force_double(&arguments[0])? + self.force_double(&arguments[1])?,
            )),
            "double_subtract" => value(Value::Double(
                self.force_double(&arguments[1])? - self.force_double(&arguments[0])?,
            )),
            "double_mult" => value(Value::Double(
                self.force_double(&arguments[0])? * self.force_double(&arguments[1])?,
            )),
            "double_read_maybe" => {
                let parsed = self
                    .force_text(&arguments[0])?
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .map(|number| Thunk::evaluated(Value::Double(number)));
                value(Value::Maybe(parsed))
            }
            "double_show" => value(Value::Text(
                show_double(self.force_double(&arguments[0])?).into(),
            )),
            "double_show_e_float" | "double_show_f_float" => {
                let precision = self.force_optional_int(&arguments[0])?;
                let number = self.force_double(&arguments[1])?;
                let suffix = self.force_text(&arguments[2])?;
                let rendered = if implementation == "double_show_e_float" {
                    show_double_exponential(
                        number,
                        precision,
                        self.policy.limits.numeric_precision,
                    )?
                } else {
                    show_double_fixed(number, precision, self.policy.limits.numeric_precision)?
                };
                value(Value::Text(format!("{rendered}{suffix}").into()))
            }
            "show" => value(Value::Text(self.show_value(&arguments[0])?.into())),
            "text_eq" => value(Value::Bool(
                self.force_text(&arguments[0])? == self.force_text(&arguments[1])?,
            )),
            "text_all" => {
                let predicate = Arc::clone(&arguments[0]);
                let text = self.force_text(&arguments[1])?;
                for character in text.chars() {
                    let application = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&predicate),
                        argument: Thunk::evaluated(Value::Character(character)),
                    });
                    if !self.force_bool(&application)? {
                        return value(Value::Bool(false));
                    }
                }
                value(Value::Bool(true))
            }
            "text_any" => {
                let predicate = Arc::clone(&arguments[0]);
                let text = self.force_text(&arguments[1])?;
                for character in text.chars() {
                    let application = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&predicate),
                        argument: Thunk::evaluated(Value::Character(character)),
                    });
                    if self.force_bool(&application)? {
                        return value(Value::Bool(true));
                    }
                }
                value(Value::Bool(false))
            }
            "text_break_on" => {
                let needle = self.force_text(&arguments[0])?;
                let source = self.force_text(&arguments[1])?;
                let boundary = source.find(needle.as_ref()).unwrap_or(source.len());
                value(Value::Tuple(
                    [
                        Thunk::evaluated(Value::Text(Arc::from(&source[..boundary]))),
                        Thunk::evaluated(Value::Text(Arc::from(&source[boundary..]))),
                    ]
                    .into(),
                ))
            }
            "text_length" => value(Value::Int(
                i64::try_from(self.force_text(&arguments[0])?.chars().count()).unwrap_or(i64::MAX),
            )),
            "text_concat" => {
                let mut output = String::new();
                let mut list = Arc::clone(&arguments[0]);
                loop {
                    match self.force(&list)?.as_ref() {
                        Value::List(ListCell::Nil) => break,
                        Value::List(ListCell::Cons { head, tail }) => {
                            output.push_str(&self.force_text(head)?);
                            list = Arc::clone(tail);
                        }
                        _ => {
                            return Err(RuntimeError::internal("Text.concat received a non-list"));
                        }
                    }
                }
                value(Value::Text(output.into()))
            }
            "text_get_line" => value(Value::Io(IoAction::new(|_, context| {
                Ok(Thunk::evaluated(Value::Text(
                    context.read_stdin_line("Text.getLine")?,
                )))
            }))),
            "text_get_contents" => value(Value::Io(IoAction::new(|_, context| {
                let bytes = context.read_stdin_all("Text.getContents")?;
                let text = String::from_utf8(bytes).map_err(|error| {
                    RuntimeContext::io_error(
                        "Text.getContents",
                        format!(
                            "input is not valid UTF-8 at byte {}",
                            error.utf8_error().valid_up_to()
                        ),
                    )
                })?;
                Ok(Thunk::evaluated(Value::Text(text.into())))
            }))),
            "text_interact" => {
                let function = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let bytes = context.read_stdin_all("Text.interact")?;
                    let input = String::from_utf8(bytes).map_err(|error| {
                        RuntimeContext::io_error(
                            "Text.interact",
                            format!(
                                "input is not valid UTF-8 at byte {}",
                                error.utf8_error().valid_up_to()
                            ),
                        )
                    })?;
                    let output = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&function),
                        argument: Thunk::evaluated(Value::Text(input.into())),
                    });
                    let output = evaluator.force_text(&output)?;
                    context.write(output.as_bytes())?;
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "text_take" | "text_drop" => {
                let amount = self.force_int(&arguments[0])?;
                let text = self.force_text(&arguments[1])?;
                let boundary = if amount <= 0 {
                    0
                } else {
                    text.char_indices()
                        .nth(usize::try_from(amount).unwrap_or(usize::MAX))
                        .map_or(text.len(), |(index, _)| index)
                };
                if implementation == "text_take" {
                    value(Value::Text(Arc::from(&text[..boundary])))
                } else {
                    value(Value::Text(Arc::from(&text[boundary..])))
                }
            }
            "text_take_end" | "text_drop_end" => {
                let amount = self.force_int(&arguments[0])?.max(0);
                let text = self.force_text(&arguments[1])?;
                let character_count = text.chars().count();
                let amount = usize::try_from(amount).unwrap_or(usize::MAX);
                let boundary_character = character_count.saturating_sub(amount);
                let boundary = text
                    .char_indices()
                    .nth(boundary_character)
                    .map_or(text.len(), |(index, _)| index);
                if implementation == "text_take_end" {
                    value(Value::Text(Arc::from(&text[boundary..])))
                } else {
                    value(Value::Text(Arc::from(&text[..boundary])))
                }
            }
            "text_filter" => {
                let predicate = Arc::clone(&arguments[0]);
                let text = self.force_text(&arguments[1])?;
                let mut output = String::new();
                for character in text.chars() {
                    let application = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&predicate),
                        argument: Thunk::evaluated(Value::Character(character)),
                    });
                    if self.force_bool(&application)? {
                        output.push(character);
                    }
                }
                value(Value::Text(output.into()))
            }
            "text_strip" => value(Value::Text(
                self.force_text(&arguments[0])?.trim().to_owned().into(),
            )),
            "text_strip_prefix" | "text_strip_suffix" => {
                let affix = self.force_text(&arguments[0])?;
                let source = self.force_text(&arguments[1])?;
                let stripped = if implementation == "text_strip_prefix" {
                    source.strip_prefix(affix.as_ref())
                } else {
                    source.strip_suffix(affix.as_ref())
                };
                value(Value::Maybe(stripped.map(|stripped| {
                    Thunk::evaluated(Value::Text(Arc::from(stripped)))
                })))
            }
            "text_is_infix_of" | "text_is_prefix_of" | "text_is_suffix_of" => {
                let affix = self.force_text(&arguments[0])?;
                let source = self.force_text(&arguments[1])?;
                let matches = match implementation {
                    "text_is_infix_of" => source.contains(affix.as_ref()),
                    "text_is_prefix_of" => source.starts_with(affix.as_ref()),
                    "text_is_suffix_of" => source.ends_with(affix.as_ref()),
                    _ => unreachable!("text containment implementation matched"),
                };
                value(Value::Bool(matches))
            }
            "text_intercalate" => {
                let separator = self.force_text(&arguments[0])?;
                let mut parts = Vec::new();
                let mut list = Arc::clone(&arguments[1]);
                loop {
                    match self.force(&list)?.as_ref() {
                        Value::List(ListCell::Nil) => break,
                        Value::List(ListCell::Cons { head, tail }) => {
                            parts.push(self.force_text(head)?);
                            list = Arc::clone(tail);
                        }
                        _ => {
                            return Err(RuntimeError::internal(
                                "Text.intercalate received a non-list",
                            ));
                        }
                    }
                }
                let mut output = String::new();
                for (index, part) in parts.iter().enumerate() {
                    if index > 0 {
                        output.push_str(&separator);
                    }
                    output.push_str(part);
                }
                value(Value::Text(output.into()))
            }
            "text_reverse" => value(Value::Text(
                self.force_text(&arguments[0])?
                    .chars()
                    .rev()
                    .collect::<String>()
                    .into(),
            )),
            "text_lines" | "text_words" => {
                let text = self.force_text(&arguments[0])?;
                let parts: Vec<_> = if implementation == "text_lines" {
                    text.split_terminator('\n').collect()
                } else {
                    text.split_whitespace().collect()
                };
                let parts = parts
                    .into_iter()
                    .map(|part| Thunk::evaluated(Value::Text(Arc::from(part))))
                    .collect();
                Ok(ForceOutcome::Alias(list_from_values(parts)))
            }
            "text_pack" => {
                let characters = self.force_list_elements(&arguments[0])?;
                let mut text = String::with_capacity(characters.len());
                for character in characters {
                    text.push(self.force_character(&character)?);
                }
                value(Value::Text(text.into()))
            }
            "text_replace" => {
                let needle = self.force_text(&arguments[0])?;
                let replacement = self.force_text(&arguments[1])?;
                let source = self.force_text(&arguments[2])?;
                value(Value::Text(
                    source.replace(needle.as_ref(), replacement.as_ref()).into(),
                ))
            }
            "text_split_on" => {
                let separator = self.force_text(&arguments[0])?;
                if separator.is_empty() {
                    return Err(RuntimeError::user("Data.Text.splitOn: empty input"));
                }
                let source = self.force_text(&arguments[1])?;
                let parts = source
                    .split(separator.as_ref())
                    .map(|part| Thunk::evaluated(Value::Text(Arc::from(part))))
                    .collect();
                Ok(ForceOutcome::Alias(list_from_values(parts)))
            }
            "text_to_lower" => value(Value::Text(
                self.force_text(&arguments[0])?.to_lowercase().into(),
            )),
            "text_to_upper" => value(Value::Text(
                self.force_text(&arguments[0])?.to_uppercase().into(),
            )),
            "text_unlines" | "text_unwords" => {
                let elements = self.force_list_elements(&arguments[0])?;
                let mut parts = Vec::with_capacity(elements.len());
                for element in elements {
                    parts.push(self.force_text(&element)?);
                }
                let text = if implementation == "text_unlines" {
                    let mut text = String::new();
                    for part in parts {
                        text.push_str(&part);
                        text.push('\n');
                    }
                    text
                } else {
                    parts
                        .iter()
                        .map(AsRef::as_ref)
                        .collect::<Vec<&str>>()
                        .join(" ")
                };
                value(Value::Text(text.into()))
            }
            "text_unpack" => {
                let text = self.force_text(&arguments[0])?;
                let characters = text
                    .chars()
                    .map(|character| Thunk::evaluated(Value::Character(character)))
                    .collect();
                Ok(ForceOutcome::Alias(list_from_values(characters)))
            }
            "text_encode_utf8" => value(Value::ByteString(Arc::from(
                self.force_text(&arguments[0])?.as_bytes(),
            ))),
            "text_decode_utf8" => {
                let bytes = self.force_bytes(&arguments[0])?;
                let text = std::str::from_utf8(&bytes).map_err(|error| {
                    RuntimeContext::io_error(
                        "Text.decodeUtf8",
                        format!("invalid UTF-8 at byte {}", error.valid_up_to()),
                    )
                })?;
                value(Value::Text(Arc::from(text)))
            }
            "io_pure" => {
                let result = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |_, _| {
                    Ok(Arc::clone(&result))
                })))
            }
            "io_then" => {
                let first = Arc::clone(&arguments[0]);
                let second = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let first_action = evaluator.force_io(&first)?;
                    let _discarded = first_action.run(evaluator, context)?;
                    let second_action = evaluator.force_io(&second)?;
                    second_action.run(evaluator, context)
                })))
            }
            "io_bind" => {
                let action = Arc::clone(&arguments[0]);
                let continuation = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let action = evaluator.force_io(&action)?;
                    let result = action.run(evaluator, context)?;
                    let applied = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&continuation),
                        argument: result,
                    });
                    let next = evaluator.force_io(&applied)?;
                    next.run(evaluator, context)
                })))
            }
            "thread_delay" => value(Value::Io(concurrency::thread_delay(Arc::clone(
                &arguments[0],
            )))),
            "timeout" => value(Value::Io(concurrency::timeout(
                Arc::clone(&arguments[0]),
                Arc::clone(&arguments[1]),
            ))),
            "async_concurrently" => value(Value::Io(concurrency::concurrently(
                Arc::clone(&arguments[0]),
                Arc::clone(&arguments[1]),
            ))),
            "async_race" => value(Value::Io(concurrency::race(
                Arc::clone(&arguments[0]),
                Arc::clone(&arguments[1]),
            ))),
            "async_pooled_map" | "async_pooled_for" | "async_pooled_map_" | "async_pooled_for_" => {
                let (callback, list) =
                    if matches!(implementation, "async_pooled_for" | "async_pooled_for_") {
                        (Arc::clone(&arguments[1]), Arc::clone(&arguments[0]))
                    } else {
                        (Arc::clone(&arguments[0]), Arc::clone(&arguments[1]))
                    };
                value(Value::Io(concurrency::pooled(
                    callback,
                    list,
                    implementation.ends_with('_'),
                )))
            }
            "text_put_str" | "text_put_str_ln" => {
                let argument = Arc::clone(&arguments[0]);
                let newline = implementation == "text_put_str_ln";
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let text = evaluator.force_text(&argument)?;
                    context.write(text.as_bytes())?;
                    if newline {
                        context.write(b"\n")?;
                    }
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "text_read_file" => {
                let path = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path("Text.readFile", &path)?;
                    let bytes = std::fs::read(path)
                        .map_err(|error| RuntimeContext::io_error("Text.readFile", error))?;
                    let text = String::from_utf8(bytes).map_err(|error| {
                        Arc::new(RuntimeError {
                            code: "H0903",
                            kind: RuntimeErrorKind::Io,
                            message: format!(
                                "Text.readFile: invalid UTF-8 at byte {}",
                                error.utf8_error().valid_up_to()
                            )
                            .into(),
                            suppressed: Arc::from([]),
                        })
                    })?;
                    Ok(Thunk::evaluated(Value::Text(text.into())))
                })))
            }
            "text_write_file" | "text_append_file" => {
                let path = Arc::clone(&arguments[0]);
                let contents = Arc::clone(&arguments[1]);
                let append = implementation == "text_append_file";
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let operation = if append {
                        "Text.appendFile"
                    } else {
                        "Text.writeFile"
                    };
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path(operation, &path)?;
                    let contents = evaluator.force_text(&contents)?;
                    if append {
                        let mut file = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(path)
                            .map_err(|error| RuntimeContext::io_error(operation, error))?;
                        file.write_all(contents.as_bytes())
                            .map_err(|error| RuntimeContext::io_error(operation, error))?;
                    } else {
                        std::fs::write(path, contents.as_bytes())
                            .map_err(|error| RuntimeContext::io_error(operation, error))?;
                    }
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "bytes_read_file" => {
                let path = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path("ByteString.readFile", &path)?;
                    let bytes = std::fs::read(path)
                        .map_err(|error| RuntimeContext::io_error("ByteString.readFile", error))?;
                    Ok(Thunk::evaluated(Value::ByteString(bytes.into())))
                })))
            }
            "bytes_write_file" => {
                let path = Arc::clone(&arguments[0]);
                let contents = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path("ByteString.writeFile", &path)?;
                    let contents = evaluator.force_bytes(&contents)?;
                    std::fs::write(path, contents.as_ref())
                        .map_err(|error| RuntimeContext::io_error("ByteString.writeFile", error))?;
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "io_stdin" => value(Value::Handle(HostHandle::Stdin)),
            "io_stdout" => value(Value::Handle(HostHandle::Stdout)),
            "io_stderr" => value(Value::Handle(HostHandle::Stderr)),
            "io_no_buffering" => value(Value::BufferMode(BufferMode::None)),
            "io_line_buffering" => value(Value::BufferMode(BufferMode::Line)),
            "io_block_buffering" => value(Value::BufferMode(BufferMode::Block)),
            "io_read_mode" => value(Value::FileMode(FileMode::Read)),
            "io_write_mode" => value(Value::FileMode(FileMode::Write)),
            "io_append_mode" => value(Value::FileMode(FileMode::Append)),
            "io_read_write_mode" => value(Value::FileMode(FileMode::ReadWrite)),
            "io_open_file" => {
                let path = Arc::clone(&arguments[0]);
                let mode = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let mode = evaluator.force_file_mode(&mode)?;
                    let path = context.resolve_path("IO.openFile", &path)?;
                    let permit = context.budget.acquire_handle()?;
                    let handle = native_handle::FileHandle::open(&path, mode, permit)
                        .map_err(|error| RuntimeContext::io_error("IO.openFile", error))?;
                    evaluator
                        .execution_scope()
                        .register(ScopedFileResource(Arc::clone(&handle)))?;
                    Ok(Thunk::evaluated(Value::Handle(HostHandle::File {
                        handle,
                        close_after_process: false,
                    })))
                })))
            }
            "io_h_close" => {
                let handle = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, _context| {
                    match evaluator.force_handle(&handle)? {
                        HostHandle::File { handle, .. } => handle
                            .close()
                            .map_err(|error| RuntimeContext::io_error("IO.hClose", error))?,
                        HostHandle::Null => {}
                        HostHandle::Stdin | HostHandle::Stdout | HostHandle::Stderr => {
                            return Err(RuntimeContext::io_error(
                                "IO.hClose",
                                "closing a standard handle is not supported",
                            ));
                        }
                    }
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "io_h_set_buffering" => {
                let handle = Arc::clone(&arguments[0]);
                let mode = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let handle = evaluator.force_handle(&handle)?;
                    let mode = evaluator.force_buffer_mode(&mode)?;
                    context.set_buffering(&handle, mode)?;
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "temp_with_directory" => {
                let template = Arc::clone(&arguments[0]);
                let callback = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    context.require_filesystem("Temp.withSystemTempDirectory")?;
                    let _permit = context.budget.acquire_temp_resource()?;
                    let template = evaluator.force_text(&template)?;
                    let resource = native_temp::TempResource::create_directory(
                        &template,
                        context.policy.cleanup.temp_create_retries,
                        context.policy.cleanup.temp_delete_retries,
                    )
                    .map_err(|error| {
                        RuntimeContext::io_error("Temp.withSystemTempDirectory", error)
                    })?;
                    let resource = ScopedTempResource::new(resource);
                    evaluator.execution_scope().register(resource.clone())?;
                    let path = path_to_text("Temp.withSystemTempDirectory", resource.path()?)?;
                    let applied = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&callback),
                        argument: Thunk::evaluated(Value::Text(path)),
                    });
                    let result = evaluator
                        .force_io(&applied)
                        .and_then(|action| action.run(evaluator, context));
                    let cleanup = resource.cleanup().map_err(|error| {
                        RuntimeContext::io_error("Temp.withSystemTempDirectory cleanup", error)
                    });
                    finish_with_cleanup(result, [cleanup])
                })))
            }
            "temp_with_file" => {
                let template = Arc::clone(&arguments[0]);
                let callback = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    context.require_filesystem("Temp.withSystemTempFile")?;
                    let _permit = context.budget.acquire_temp_resource()?;
                    let handle_permit = context.budget.acquire_handle()?;
                    let template = evaluator.force_text(&template)?;
                    let (resource, handle) = native_temp::TempResource::create_file(
                        &template,
                        context.policy.cleanup.temp_create_retries,
                        context.policy.cleanup.temp_delete_retries,
                    )
                    .map_err(|error| RuntimeContext::io_error("Temp.withSystemTempFile", error))?;
                    handle.attach_permit(handle_permit).map_err(|error| {
                        RuntimeContext::io_error("Temp.withSystemTempFile", error)
                    })?;
                    evaluator
                        .execution_scope()
                        .register(ScopedFileResource(Arc::clone(&handle)))?;
                    let resource = ScopedTempResource::new(resource);
                    evaluator.execution_scope().register(resource.clone())?;
                    let path = path_to_text("Temp.withSystemTempFile", resource.path()?)?;
                    let path_application = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&callback),
                        argument: Thunk::evaluated(Value::Text(path)),
                    });
                    let application = Thunk::suspended(Suspension::Apply {
                        function: path_application,
                        argument: Thunk::evaluated(Value::Handle(HostHandle::File {
                            handle: Arc::clone(&handle),
                            close_after_process: false,
                        })),
                    });
                    let result = evaluator
                        .force_io(&application)
                        .and_then(|action| action.run(evaluator, context));
                    let close = handle.close().map_err(|error| {
                        RuntimeContext::io_error("Temp.withSystemTempFile close", error)
                    });
                    let cleanup = resource.cleanup().map_err(|error| {
                        RuntimeContext::io_error("Temp.withSystemTempFile cleanup", error)
                    });
                    finish_with_cleanup(result, [close, cleanup])
                })))
            }
            "process_null_stream" => value(Value::Handle(HostHandle::Null)),
            "text_h_put_str" | "bytes_h_put_str" => {
                let handle = Arc::clone(&arguments[0]);
                let contents = Arc::clone(&arguments[1]);
                let text = implementation == "text_h_put_str";
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let handle = evaluator.force_handle(&handle)?;
                    let bytes = if text {
                        evaluator.force_text(&contents)?.as_bytes().to_vec()
                    } else {
                        evaluator.force_bytes(&contents)?.to_vec()
                    };
                    match handle {
                        HostHandle::Stdout => context.write(&bytes)?,
                        HostHandle::Stderr => context.write_stderr(&bytes)?,
                        HostHandle::Null => {}
                        HostHandle::File { handle, .. } => handle
                            .write_all(&bytes)
                            .map_err(|error| RuntimeContext::io_error("IO.hPutStr", error))?,
                        HostHandle::Stdin => {
                            return Err(RuntimeError::internal(
                                "cannot write to the standard-input handle",
                            ));
                        }
                    }
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "bytes_h_get" => {
                let handle = Arc::clone(&arguments[0]);
                let amount = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let handle = evaluator.force_handle(&handle)?;
                    let amount = evaluator.force_int(&amount)?;
                    let amount = usize::try_from(amount).map_err(|_| {
                        RuntimeContext::io_error(
                            "ByteString.hGet",
                            "byte count must be non-negative",
                        )
                    })?;
                    if context
                        .policy
                        .limits
                        .handle_read_bytes
                        .value()
                        .is_some_and(|limit| u64::try_from(amount).unwrap_or(u64::MAX) > limit)
                    {
                        return Err(RuntimeError::resource_limit(format!(
                            "ByteString.hGet exceeds the configured per-read limit of {:?} bytes",
                            context.policy.limits.handle_read_bytes.value()
                        )));
                    }
                    let mut bytes = Vec::with_capacity(amount);
                    match handle {
                        HostHandle::Stdin => {
                            bytes = context.read_stdin_up_to("ByteString.hGet", amount)?;
                        }
                        HostHandle::Null => {}
                        HostHandle::File { handle, .. } => {
                            bytes = handle.read_up_to(amount).map_err(|error| {
                                RuntimeContext::io_error("ByteString.hGet", error)
                            })?;
                        }
                        HostHandle::Stdout | HostHandle::Stderr => {
                            return Err(RuntimeError::internal(
                                "cannot read from an output handle",
                            ));
                        }
                    }
                    Ok(Thunk::evaluated(Value::ByteString(bytes.into())))
                })))
            }
            "bytes_get_contents" => value(Value::Io(IoAction::new(|_, context| {
                let bytes = context.read_stdin_all("ByteString.getContents")?;
                Ok(Thunk::evaluated(Value::ByteString(bytes.into())))
            }))),
            "bytes_interact" => {
                let function = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let input = context.read_stdin_all("ByteString.interact")?;
                    let output = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&function),
                        argument: Thunk::evaluated(Value::ByteString(input.into())),
                    });
                    let output = evaluator.force_bytes(&output)?;
                    context.write(&output)?;
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "process_proc" => {
                let command = self.force_text(&arguments[0])?;
                let arguments = self.force_list_elements(&arguments[1])?;
                let mut values = Vec::with_capacity(arguments.len());
                for argument in arguments {
                    values.push(self.force_text(&argument)?);
                }
                value(Value::Process(Arc::new(ProcessSpec::new(
                    command,
                    values.into(),
                ))))
            }
            "text_set_stdin" => {
                let input = self.force_text(&arguments[0])?;
                let process = self.force_process(&arguments[1])?;
                let mut process = process.as_ref().clone();
                process.stdin_bytes = Some(Arc::from(input.as_bytes()));
                value(Value::Process(Arc::new(process)))
            }
            "process_set_env" => {
                let environment = self.force_list_elements(&arguments[0])?;
                let mut values = Vec::with_capacity(environment.len());
                for entry in environment {
                    let entry = self.force(&entry)?;
                    let Value::Tuple(elements) = entry.as_ref() else {
                        return Err(RuntimeError::internal(
                            "Process.setEnv received a non-pair element",
                        ));
                    };
                    let [name, value] = elements.as_ref() else {
                        return Err(RuntimeError::internal(
                            "Process.setEnv received a tuple with the wrong arity",
                        ));
                    };
                    values.push((self.force_text(name)?, self.force_text(value)?));
                }
                let process = self.force_process(&arguments[1])?;
                let mut process = process.as_ref().clone();
                process.environment = Some(values.into());
                value(Value::Process(Arc::new(process)))
            }
            "process_set_stdin" | "process_set_stdout" | "process_set_stderr" => {
                let handle = self.force_handle(&arguments[0])?;
                let process = self.force_process(&arguments[1])?;
                let mut process = process.as_ref().clone();
                match implementation {
                    "process_set_stdin" => {
                        process.stdin = handle;
                        process.stdin_bytes = None;
                    }
                    "process_set_stdout" => process.stdout = handle,
                    "process_set_stderr" => process.stderr = handle,
                    _ => unreachable!("process stream setter implementation matched"),
                }
                value(Value::Process(Arc::new(process)))
            }
            "process_set_working_dir" => {
                let directory = self.force_text(&arguments[0])?;
                let process = self.force_process(&arguments[1])?;
                let mut process = process.as_ref().clone();
                process.working_directory = Some(directory);
                value(Value::Process(Arc::new(process)))
            }
            "process_use_handle_close" | "process_use_handle_open" => {
                let handle = self.force_handle(&arguments[0])?;
                value(Value::Handle(handle.with_process_close(
                    implementation == "process_use_handle_close",
                )))
            }
            "process_run" | "process_run_checked" => {
                let process = Arc::clone(&arguments[0]);
                let checked = implementation == "process_run_checked";
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let process = evaluator.force_process(&process)?;
                    let output = run_child_process(
                        process.as_ref(),
                        context,
                        "Process.runProcess",
                        false,
                        &evaluator.cancellation,
                        evaluator.execution_scope(),
                    )?;
                    if checked {
                        ensure_process_success(process.as_ref(), &output)?;
                        Ok(Thunk::evaluated(Value::Unit))
                    } else {
                        Ok(Thunk::evaluated(exit_code_value(&output)))
                    }
                })))
            }
            "text_read_process"
            | "text_read_process_checked"
            | "text_read_process_stdout_checked"
            | "bytes_read_process"
            | "bytes_read_process_checked"
            | "bytes_read_process_stdout_checked" => {
                let process = Arc::clone(&arguments[0]);
                let implementation = implementation.to_owned();
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let process = evaluator.force_process(&process)?;
                    let output = run_child_process(
                        process.as_ref(),
                        context,
                        "readProcess",
                        true,
                        &evaluator.cancellation,
                        evaluator.execution_scope(),
                    )?;
                    if implementation.contains("checked") {
                        ensure_process_success(process.as_ref(), &output)?;
                    }
                    let text = implementation.starts_with("text_");
                    let exit = Thunk::evaluated(exit_code_value(&output));
                    let stdout = process_output_value("readProcess stdout", output.stdout, text)?;
                    if implementation.ends_with("stdout_checked") {
                        return Ok(Thunk::evaluated(stdout));
                    }
                    let stderr = process_output_value("readProcess stderr", output.stderr, text)?;
                    let elements = if implementation.ends_with("_read_process") {
                        vec![exit, Thunk::evaluated(stdout), Thunk::evaluated(stderr)]
                    } else {
                        vec![Thunk::evaluated(stdout), Thunk::evaluated(stderr)]
                    };
                    Ok(Thunk::evaluated(Value::Tuple(elements.into())))
                })))
            }
            "io_print" => {
                let argument = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let rendered = evaluator.show_value(&argument)?;
                    context.write(rendered.as_bytes())?;
                    context.write(b"\n")?;
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "list_nil" => value(Value::List(ListCell::Nil)),
            "list_cons" => value(Value::List(ListCell::Cons {
                head: Arc::clone(&arguments[0]),
                tail: Arc::clone(&arguments[1]),
            })),
            "list_take" => Ok(ForceOutcome::Alias(Thunk::suspended(
                Suspension::ListTake {
                    remaining: self.force_int(&arguments[0])?,
                    list: Arc::clone(&arguments[1]),
                },
            ))),
            "list_iterate" => Ok(ForceOutcome::Alias(Thunk::suspended(
                Suspension::ListIterate {
                    function: Arc::clone(&arguments[0]),
                    current: Arc::clone(&arguments[1]),
                    force_current: false,
                },
            ))),
            "list_map" => Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::ListMap {
                function: Arc::clone(&arguments[0]),
                list: Arc::clone(&arguments[1]),
            }))),
            "list_zip" => Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::ListZip {
                left: Arc::clone(&arguments[0]),
                right: Arc::clone(&arguments[1]),
            }))),
            "list_foldl_strict" => {
                let function = Arc::clone(&arguments[0]);
                let mut accumulator = Arc::clone(&arguments[1]);
                let mut list = Arc::clone(&arguments[2]);
                loop {
                    match self.force(&list)?.as_ref() {
                        Value::List(ListCell::Nil) => {
                            return Ok(ForceOutcome::Alias(accumulator));
                        }
                        Value::List(ListCell::Cons { head, tail }) => {
                            let first = Thunk::suspended(Suspension::Apply {
                                function: Arc::clone(&function),
                                argument: accumulator,
                            });
                            let second = Thunk::suspended(Suspension::Apply {
                                function: first,
                                argument: Arc::clone(head),
                            });
                            let forced = self.force(&second)?;
                            accumulator = Thunk::evaluated(forced.as_ref().clone());
                            list = Arc::clone(tail);
                        }
                        _ => {
                            return Err(RuntimeError::internal("List.foldl' received a non-list"));
                        }
                    }
                }
            }
            "list_reverse" => {
                let mut input = Arc::clone(&arguments[0]);
                let mut output = Thunk::evaluated(Value::List(ListCell::Nil));
                loop {
                    match self.force(&input)?.as_ref() {
                        Value::List(ListCell::Nil) => return Ok(ForceOutcome::Alias(output)),
                        Value::List(ListCell::Cons { head, tail }) => {
                            output = Thunk::evaluated(Value::List(ListCell::Cons {
                                head: Arc::clone(head),
                                tail: output,
                            }));
                            input = Arc::clone(tail);
                        }
                        _ => {
                            return Err(RuntimeError::internal("List.reverse received a non-list"));
                        }
                    }
                }
            }
            "list_length" => {
                let mut count = 0_i64;
                let mut list = Arc::clone(&arguments[0]);
                loop {
                    match self.force(&list)?.as_ref() {
                        Value::List(ListCell::Nil) => break,
                        Value::List(ListCell::Cons { tail, .. }) => {
                            count = count.wrapping_add(1);
                            list = Arc::clone(tail);
                        }
                        _ => return Err(RuntimeError::internal("List.length received a non-list")),
                    }
                }
                value(Value::Int(count))
            }
            "list_lookup" => {
                let key = Arc::clone(&arguments[0]);
                let mut list = Arc::clone(&arguments[1]);
                loop {
                    match self.force(&list)?.as_ref() {
                        Value::List(ListCell::Nil) => return value(Value::Maybe(None)),
                        Value::List(ListCell::Cons { head, tail }) => {
                            let pair = self.force(head)?;
                            let Value::Tuple(elements) = pair.as_ref() else {
                                return Err(RuntimeError::internal(
                                    "List.lookup received a non-pair element",
                                ));
                            };
                            let [candidate, found] = elements.as_ref() else {
                                return Err(RuntimeError::internal(
                                    "List.lookup received a tuple with the wrong arity",
                                ));
                            };
                            if self.equal_values(&key, candidate)? {
                                return value(Value::Maybe(Some(Arc::clone(found))));
                            }
                            list = Arc::clone(tail);
                        }
                        _ => {
                            return Err(RuntimeError::internal("List.lookup received a non-list"));
                        }
                    }
                }
            }
            "list_and" => {
                let mut list = Arc::clone(&arguments[0]);
                loop {
                    match self.force(&list)?.as_ref() {
                        Value::List(ListCell::Nil) => return value(Value::Bool(true)),
                        Value::List(ListCell::Cons { head, tail }) => {
                            if !self.force_bool(head)? {
                                return value(Value::Bool(false));
                            }
                            list = Arc::clone(tail);
                        }
                        _ => return Err(RuntimeError::internal("List.and received a non-list")),
                    }
                }
            }
            "list_or" => {
                let mut list = Arc::clone(&arguments[0]);
                loop {
                    match self.force(&list)?.as_ref() {
                        Value::List(ListCell::Nil) => return value(Value::Bool(false)),
                        Value::List(ListCell::Cons { head, tail }) => {
                            if self.force_bool(head)? {
                                return value(Value::Bool(true));
                            }
                            list = Arc::clone(tail);
                        }
                        _ => return Err(RuntimeError::internal("List.or received a non-list")),
                    }
                }
            }
            "vector_from_list" => {
                let elements = self.force_list_elements(&arguments[0])?;
                value(Value::Vector(elements.into()))
            }
            "vector_to_list" => {
                let vector = self.force(&arguments[0])?;
                let Value::Vector(elements) = vector.as_ref() else {
                    return Err(RuntimeError::internal(
                        "Vector.toList received a non-vector",
                    ));
                };
                Ok(ForceOutcome::Alias(list_from_values(elements.to_vec())))
            }
            "maybe_nothing" => value(Value::Maybe(None)),
            "maybe_just" => value(Value::Maybe(Some(Arc::clone(&arguments[0])))),
            "maybe_eliminate" => match self.force(&arguments[2])?.as_ref() {
                Value::Maybe(None) => Ok(ForceOutcome::Alias(Arc::clone(&arguments[0]))),
                Value::Maybe(Some(payload)) => {
                    Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&arguments[1]),
                        argument: Arc::clone(payload),
                    })))
                }
                _ => Err(RuntimeError::internal("Maybe.maybe received a non-Maybe")),
            },
            "either_left" => value(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::Either,
                constructor_index: 0,
                payloads: Arc::from([Arc::clone(&arguments[0])]),
            })),
            "either_right" => value(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::Either,
                constructor_index: 1,
                payloads: Arc::from([Arc::clone(&arguments[0])]),
            })),
            "either_eliminate" => {
                self.eliminate_primitive(&arguments[2], PrimitiveFamily::Either, &arguments[..2])
            }
            "exit_success" => value(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::Exit,
                constructor_index: 0,
                payloads: Arc::from([]),
            })),
            "exit_failure" => value(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::Exit,
                constructor_index: 1,
                payloads: Arc::from([Arc::clone(&arguments[0])]),
            })),
            "exit_eliminate" => {
                self.eliminate_primitive(&arguments[2], PrimitiveFamily::Exit, &arguments[..2])
            }
            "exit_die" => {
                let message = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    context.require_exit_process("Exit.die")?;
                    let message = evaluator.force_text(&message)?;
                    context.write_stderr(message.as_bytes())?;
                    context.write_stderr(b"\n")?;
                    Err(RuntimeError::exit(1))
                })))
            }
            "exit_with" => {
                let exit = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    context.require_exit_process("Exit.exitWith")?;
                    let exit = evaluator.force(&exit)?;
                    let Value::PrimitiveVariant(exit) = exit.as_ref() else {
                        return Err(RuntimeError::internal(
                            "Exit.exitWith received a non-ExitCode value",
                        ));
                    };
                    let status = match exit.constructor_index {
                        0 => 0,
                        1 => evaluator.force_int(exit.payloads.first().ok_or_else(|| {
                            RuntimeError::internal("ExitFailure payload is missing")
                        })?)?,
                        _ => {
                            return Err(RuntimeError::internal(
                                "Exit.exitWith constructor is out of bounds",
                            ));
                        }
                    };
                    Err(RuntimeError::exit(
                        i32::try_from(status).unwrap_or(if status < 0 { -1 } else { i32::MAX }),
                    ))
                })))
            }
            "these_this" => value(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::These,
                constructor_index: 0,
                payloads: Arc::from([Arc::clone(&arguments[0])]),
            })),
            "these_that" => value(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::These,
                constructor_index: 1,
                payloads: Arc::from([Arc::clone(&arguments[0])]),
            })),
            "these_both" => value(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::These,
                constructor_index: 2,
                payloads: Arc::from([Arc::clone(&arguments[0]), Arc::clone(&arguments[1])]),
            })),
            "these_eliminate" => {
                self.eliminate_primitive(&arguments[3], PrimitiveFamily::These, &arguments[..3])
            }
            "json_null" => value(Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::Json,
                constructor_index: 0,
                payloads: Arc::from([]),
            })),
            "json_bool" | "json_string" | "json_number" | "json_array" | "json_object" => {
                let constructor_index = match implementation {
                    "json_bool" => 1,
                    "json_string" => 2,
                    "json_number" => 3,
                    "json_array" => 4,
                    "json_object" => 5,
                    _ => unreachable!("JSON constructor implementation matched"),
                };
                value(Value::PrimitiveVariant(PrimitiveVariantValue {
                    family: PrimitiveFamily::Json,
                    constructor_index,
                    payloads: Arc::from([Arc::clone(&arguments[0])]),
                }))
            }
            "json_eliminate" => {
                self.eliminate_primitive(&arguments[6], PrimitiveFamily::Json, &arguments[..6])
            }
            "json_encode" => {
                let mut output = String::new();
                self.encode_json(&arguments[0], &mut output)?;
                value(Value::ByteString(Arc::from(output.into_bytes())))
            }
            "json_decode" => {
                let bytes = self.force_bytes(&arguments[0])?;
                let max_depth = self
                    .policy
                    .limits
                    .json_depth
                    .value()
                    .map(|value| usize::try_from(value).unwrap_or(usize::MAX));
                let max_nodes = self.policy.limits.json_nodes.value();
                let decoded = native_json::parse_with_limits(&bytes, max_depth, max_nodes)
                    .map(JsonDocument::from_node)
                    .map(|document| {
                        let root = document.root();
                        Value::JsonDocument(Arc::new(document), root)
                    })
                    .map(Thunk::evaluated);
                value(Value::Maybe(decoded))
            }
            "io_map_m_" | "io_for_m_" => {
                let (callback, list) = if implementation == "io_map_m_" {
                    (Arc::clone(&arguments[0]), Arc::clone(&arguments[1]))
                } else {
                    (Arc::clone(&arguments[1]), Arc::clone(&arguments[0]))
                };
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let mut current = Arc::clone(&list);
                    loop {
                        match evaluator.force(&current)?.as_ref() {
                            Value::List(ListCell::Nil) => {
                                return Ok(Thunk::evaluated(Value::Unit));
                            }
                            Value::List(ListCell::Cons { head, tail }) => {
                                let application = Thunk::suspended(Suspension::Apply {
                                    function: Arc::clone(&callback),
                                    argument: Arc::clone(head),
                                });
                                let action = evaluator.force_io(&application)?;
                                let _discarded = action.run(evaluator, context)?;
                                current = Arc::clone(tail);
                            }
                            _ => {
                                return Err(RuntimeError::internal(
                                    "monadic list traversal received a non-list",
                                ));
                            }
                        }
                    }
                })))
            }
            "environment_get_args" => value(Value::Io(IoAction::new(|_, context| {
                let elements = context
                    .text_args("Environment.getArgs")?
                    .into_iter()
                    .map(|argument| Thunk::evaluated(Value::Text(argument)))
                    .collect();
                Ok(list_from_values(elements))
            }))),
            "environment_get_env" => {
                let name = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    context.require_environment_read("Environment.getEnv")?;
                    let name = evaluator.force_text(&name)?;
                    let value = context
                        .environment
                        .iter()
                        .find(|(candidate, _)| candidate.as_ref() == name.as_ref())
                        .map(|(_, value)| Arc::clone(value))
                        .ok_or_else(|| {
                            Arc::new(RuntimeError {
                                code: "H0903",
                                kind: RuntimeErrorKind::Io,
                                message: format!("environment variable `{name}` is not set").into(),
                                suppressed: Arc::from([]),
                            })
                        })?;
                    Ok(Thunk::evaluated(Value::Text(value)))
                })))
            }
            "environment_get_environment" => value(Value::Io(IoAction::new(|_, context| {
                context.require_environment_read("Environment.getEnvironment")?;
                let entries = context
                    .environment
                    .iter()
                    .map(|(name, value)| {
                        Thunk::evaluated(Value::Tuple(
                            [
                                Thunk::evaluated(Value::Text(Arc::clone(name))),
                                Thunk::evaluated(Value::Text(Arc::clone(value))),
                            ]
                            .into(),
                        ))
                    })
                    .collect();
                Ok(list_from_values(entries))
            }))),
            "directory_get_current" => value(Value::Io(IoAction::new(|_, context| {
                context.require_filesystem("Directory.getCurrentDirectory")?;
                let cwd = context
                    .cwd
                    .lock()
                    .map_err(|_| RuntimeError::internal("working-directory mutex was poisoned"))?
                    .clone();
                Ok(Thunk::evaluated(Value::Text(path_to_text(
                    "Directory.getCurrentDirectory",
                    cwd,
                )?)))
            }))),
            "directory_get_home" => value(Value::Io(IoAction::new(|_, context| {
                context.require_filesystem("Directory.getHomeDirectory")?;
                let home = context.host_services.home_directory().ok_or_else(|| {
                    RuntimeContext::io_error(
                        "Directory.getHomeDirectory",
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "platform home directory is unavailable",
                        ),
                    )
                })?;
                Ok(Thunk::evaluated(Value::Text(path_to_text(
                    "Directory.getHomeDirectory",
                    home,
                )?)))
            }))),
            "directory_copy_file" | "directory_rename_file" => {
                let source = Arc::clone(&arguments[0]);
                let target = Arc::clone(&arguments[1]);
                let rename = implementation == "directory_rename_file";
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let operation = if rename {
                        "Directory.renameFile"
                    } else {
                        "Directory.copyFile"
                    };
                    let source = evaluator.force_text(&source)?;
                    let target = evaluator.force_text(&target)?;
                    let source = context.resolve_path(operation, &source)?;
                    let target = context.resolve_path(operation, &target)?;
                    if rename {
                        std::fs::rename(source, target)
                            .map_err(|error| RuntimeContext::io_error(operation, error))?;
                    } else {
                        let _bytes = std::fs::copy(source, target)
                            .map_err(|error| RuntimeContext::io_error(operation, error))?;
                    }
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "directory_create" | "directory_remove" | "directory_remove_file" => {
                let path = Arc::clone(&arguments[0]);
                let operation = match implementation {
                    "directory_create" => "Directory.createDirectory",
                    "directory_remove" => "Directory.removeDirectory",
                    "directory_remove_file" => "Directory.removeFile",
                    _ => unreachable!("directory operation implementation matched"),
                };
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path(operation, &path)?;
                    let result = match operation {
                        "Directory.createDirectory" => std::fs::create_dir(path),
                        "Directory.removeDirectory" => std::fs::remove_dir(path),
                        "Directory.removeFile" => std::fs::remove_file(path),
                        _ => unreachable!("directory operation selected"),
                    };
                    result.map_err(|error| RuntimeContext::io_error(operation, error))?;
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "directory_create_if_missing" => {
                let parents = Arc::clone(&arguments[0]);
                let path = Arc::clone(&arguments[1]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let parents = evaluator.force_bool(&parents)?;
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path("Directory.createDirectoryIfMissing", &path)?;
                    let result = if parents {
                        std::fs::create_dir_all(path)
                    } else {
                        std::fs::create_dir(path)
                    };
                    result.map_err(|error| {
                        RuntimeContext::io_error("Directory.createDirectoryIfMissing", error)
                    })?;
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "directory_is_directory" | "directory_is_file" | "directory_is_symlink" => {
                let path = Arc::clone(&arguments[0]);
                let implementation = implementation.to_owned();
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let operation = match implementation.as_str() {
                        "directory_is_directory" => "Directory.doesDirectoryExist",
                        "directory_is_file" => "Directory.doesFileExist",
                        "directory_is_symlink" => "Directory.pathIsSymbolicLink",
                        _ => unreachable!("directory predicate implementation matched"),
                    };
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path(operation, &path)?;
                    let metadata = if implementation == "directory_is_symlink" {
                        std::fs::symlink_metadata(path)
                    } else {
                        std::fs::metadata(path)
                    };
                    let matches = match metadata {
                        Ok(metadata) if implementation == "directory_is_directory" => {
                            metadata.is_dir()
                        }
                        Ok(metadata) if implementation == "directory_is_file" => metadata.is_file(),
                        Ok(metadata) => metadata.file_type().is_symlink(),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                        Err(error) => return Err(RuntimeContext::io_error(operation, error)),
                    };
                    Ok(Thunk::evaluated(Value::Bool(matches)))
                })))
            }
            "directory_file_size" => {
                let path = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path("Directory.getFileSize", &path)?;
                    let size = std::fs::metadata(path)
                        .map_err(|error| RuntimeContext::io_error("Directory.getFileSize", error))?
                        .len();
                    Ok(Thunk::evaluated(Value::Integer(Arc::new(
                        BigInteger::from_u64(size),
                    ))))
                })))
            }
            "directory_symlink_target" => {
                let path = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path("Directory.getSymbolicLinkTarget", &path)?;
                    let target = std::fs::read_link(path).map_err(|error| {
                        RuntimeContext::io_error("Directory.getSymbolicLinkTarget", error)
                    })?;
                    Ok(Thunk::evaluated(Value::Text(path_to_text(
                        "Directory.getSymbolicLinkTarget",
                        target,
                    )?)))
                })))
            }
            "directory_list" => {
                let path = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path("Directory.listDirectory", &path)?;
                    let entries = std::fs::read_dir(path)
                        .map_err(|error| {
                            RuntimeContext::io_error("Directory.listDirectory", error)
                        })?
                        .map(|entry| {
                            let entry = entry.map_err(|error| {
                                RuntimeContext::io_error("Directory.listDirectory", error)
                            })?;
                            let name = entry.file_name().into_string().map_err(|_| {
                                RuntimeContext::io_error(
                                    "Directory.listDirectory",
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        "directory entry is not valid UTF-8",
                                    ),
                                )
                            })?;
                            Ok(Thunk::evaluated(Value::Text(name.into())))
                        })
                        .collect::<RuntimeResult<Vec<_>>>()?;
                    Ok(list_from_values(entries))
                })))
            }
            "directory_set_current" => {
                let path = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let path = evaluator.force_text(&path)?;
                    let path = context.resolve_path("Directory.setCurrentDirectory", &path)?;
                    let path = std::fs::canonicalize(path).map_err(|error| {
                        RuntimeContext::io_error("Directory.setCurrentDirectory", error)
                    })?;
                    if !path.is_dir() {
                        return Err(RuntimeContext::io_error(
                            "Directory.setCurrentDirectory",
                            std::io::Error::new(
                                std::io::ErrorKind::NotADirectory,
                                "path is not a directory",
                            ),
                        ));
                    }
                    *context.cwd.lock().map_err(|_| {
                        RuntimeError::internal("working-directory mutex was poisoned")
                    })? = path;
                    Ok(Thunk::evaluated(Value::Unit))
                })))
            }
            "tuple2" | "tuple3" | "tuple4" => value(Value::Tuple(arguments.to_vec().into())),
            "compose" => {
                let outer = Arc::clone(&arguments[0]);
                let inner = Arc::clone(&arguments[1]);
                let input = Arc::clone(&arguments[2]);
                let intermediate = Thunk::suspended(Suspension::Apply {
                    function: inner,
                    argument: input,
                });
                Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                    function: outer,
                    argument: intermediate,
                })))
            }
            "semigroup_append" => Ok(ForceOutcome::Alias(Thunk::suspended(
                Suspension::SemigroupAppend {
                    left: Arc::clone(&arguments[0]),
                    right: Arc::clone(&arguments[1]),
                },
            ))),
            _ => Err(RuntimeError::internal(format!(
                "native implementation `{implementation}` is not dispatched"
            ))),
        }
    }

    fn eliminate_primitive(
        &mut self,
        scrutinee: &ThunkRef,
        family: PrimitiveFamily,
        handlers: &[ThunkRef],
    ) -> RuntimeResult<ForceOutcome> {
        let value = self.force(scrutinee)?;
        if family == PrimitiveFamily::Json
            && let Value::JsonDocument(document, index) = value.as_ref()
        {
            let materialized = Thunk::evaluated(json_document_value(document, *index)?);
            return self.eliminate_primitive(&materialized, family, handlers);
        }
        let Value::PrimitiveVariant(variant) = value.as_ref() else {
            return Err(RuntimeError::internal(
                "primitive eliminator received a non-primitive variant",
            ));
        };
        if variant.family != family {
            return Err(RuntimeError::internal(
                "primitive eliminator received the wrong variant family",
            ));
        }
        let handler = handlers
            .get(usize::from(variant.constructor_index))
            .ok_or_else(|| RuntimeError::internal("primitive constructor is out of bounds"))?;
        let mut selected = Arc::clone(handler);
        for payload in variant.payloads.iter() {
            let payload = if family == PrimitiveFamily::Json && variant.constructor_index == 3 {
                match self.force(payload)?.as_ref() {
                    Value::JsonNumber(number) => Thunk::evaluated(Value::Double(number.to_f64())),
                    Value::Double(_) => Arc::clone(payload),
                    _ => {
                        return Err(RuntimeError::internal(
                            "Json.Number payload is neither exact decimal nor Double",
                        ));
                    }
                }
            } else {
                Arc::clone(payload)
            };
            selected = Thunk::suspended(Suspension::Apply {
                function: selected,
                argument: payload,
            });
        }
        Ok(ForceOutcome::Alias(selected))
    }

    #[allow(clippy::too_many_lines)]
    fn encode_json(&mut self, thunk: &ThunkRef, output: &mut String) -> RuntimeResult<()> {
        enum Task {
            Value(ThunkRef, usize),
            ObjectKey(ThunkRef),
            Raw(&'static str),
        }

        let mut tasks = vec![Task::Value(Arc::clone(thunk), 0)];
        while let Some(task) = tasks.pop() {
            self.ensure_not_cancelled()?;
            match task {
                Task::Raw(text) => output.push_str(text),
                Task::ObjectKey(key) => {
                    native_json::push_string(output, &self.force_text(&key)?);
                }
                Task::Value(thunk, depth) => {
                    if self
                        .policy
                        .limits
                        .json_depth
                        .value()
                        .is_some_and(|maximum| {
                            usize::try_from(maximum).is_ok_and(|maximum| depth > maximum)
                        })
                    {
                        return Err(RuntimeError::resource_limit(format!(
                            "JSON encoding exceeds the configured nesting limit {:?}",
                            self.policy.limits.json_depth.value()
                        )));
                    }
                    let value = self.force(&thunk)?;
                    if let Value::JsonDocument(document, index) = value.as_ref() {
                        tasks.push(Task::Value(
                            Thunk::evaluated(json_document_value(document, *index)?),
                            depth,
                        ));
                        continue;
                    }
                    let Value::PrimitiveVariant(value) = value.as_ref() else {
                        return Err(RuntimeError::internal("Json.encode received a non-Value"));
                    };
                    if value.family != PrimitiveFamily::Json {
                        return Err(RuntimeError::internal(
                            "Json.encode received the wrong primitive family",
                        ));
                    }
                    match (value.constructor_index, value.payloads.as_ref()) {
                        (0, []) => output.push_str("null"),
                        (1, [payload]) => output.push_str(if self.force_bool(payload)? {
                            "true"
                        } else {
                            "false"
                        }),
                        (2, [payload]) => {
                            native_json::push_string(output, &self.force_text(payload)?);
                        }
                        (3, [payload]) => {
                            let payload = self.force(payload)?;
                            match payload.as_ref() {
                                Value::JsonNumber(number) => number.push_json(output),
                                Value::Double(number) if number.is_nan() => output.push_str("null"),
                                Value::Double(number) if number.is_infinite() => {
                                    output.push_str(if number.is_sign_negative() {
                                        "\"-inf\""
                                    } else {
                                        "\"+inf\""
                                    });
                                }
                                Value::Double(number)
                                    if number.classify() == std::num::FpCategory::Zero =>
                                {
                                    output.push('0');
                                }
                                Value::Double(number) => output.push_str(&number.to_string()),
                                _ => {
                                    return Err(RuntimeError::internal(
                                        "Json.Number payload is neither exact decimal nor Double",
                                    ));
                                }
                            }
                        }
                        (4, [payload]) => {
                            let payload = self.force(payload)?;
                            let Value::Vector(values) = payload.as_ref() else {
                                return Err(RuntimeError::internal(
                                    "Json.Array payload is not a Vector",
                                ));
                            };
                            output.push('[');
                            tasks.push(Task::Raw("]"));
                            for (index, value) in values.iter().enumerate().rev() {
                                tasks.push(Task::Value(Arc::clone(value), depth + 1));
                                if index != 0 {
                                    tasks.push(Task::Raw(","));
                                }
                            }
                        }
                        (5, [payload]) => {
                            let payload = self.force(payload)?;
                            let Value::Map(entries) = payload.as_ref() else {
                                return Err(RuntimeError::internal(
                                    "Json.Object payload is not a Map",
                                ));
                            };
                            output.push('{');
                            tasks.push(Task::Raw("}"));
                            for (index, (key, value)) in entries.iter().enumerate().rev() {
                                tasks.push(Task::Value(Arc::clone(value), depth + 1));
                                tasks.push(Task::Raw(":"));
                                tasks.push(Task::ObjectKey(Arc::clone(key)));
                                if index != 0 {
                                    tasks.push(Task::Raw(","));
                                }
                            }
                        }
                        _ => {
                            return Err(RuntimeError::internal(
                                "Json.encode received a malformed constructor payload",
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn force_bool(&mut self, thunk: &ThunkRef) -> RuntimeResult<bool> {
        match self.force(thunk)?.as_ref() {
            Value::Bool(value) => Ok(*value),
            _ => Err(RuntimeError::internal("expected Bool")),
        }
    }

    fn force_int(&mut self, thunk: &ThunkRef) -> RuntimeResult<i64> {
        match self.force(thunk)?.as_ref() {
            Value::Int(value) => Ok(*value),
            _ => Err(RuntimeError::internal("expected Int")),
        }
    }

    fn force_integer(&mut self, thunk: &ThunkRef) -> RuntimeResult<Arc<BigInteger>> {
        match self.force(thunk)?.as_ref() {
            Value::Integer(value) => Ok(Arc::clone(value)),
            _ => Err(RuntimeError::internal("expected Integer")),
        }
    }

    fn force_double(&mut self, thunk: &ThunkRef) -> RuntimeResult<f64> {
        match self.force(thunk)?.as_ref() {
            Value::Double(value) => Ok(*value),
            _ => Err(RuntimeError::internal("expected Double")),
        }
    }

    fn force_day(&mut self, thunk: &ThunkRef) -> RuntimeResult<native_time::Day> {
        match self.force(thunk)?.as_ref() {
            Value::Day(value) => Ok(value.clone()),
            _ => Err(RuntimeError::internal("expected Day")),
        }
    }

    fn force_utc_time(&mut self, thunk: &ThunkRef) -> RuntimeResult<native_time::UtcTime> {
        match self.force(thunk)?.as_ref() {
            Value::UtcTime(value) => Ok(value.clone()),
            _ => Err(RuntimeError::internal("expected UTCTime")),
        }
    }

    fn force_time_of_day(&mut self, thunk: &ThunkRef) -> RuntimeResult<native_time::TimeOfDay> {
        match self.force(thunk)?.as_ref() {
            Value::TimeOfDay(value) => Ok(*value),
            _ => Err(RuntimeError::internal("expected TimeOfDay")),
        }
    }

    fn force_character(&mut self, thunk: &ThunkRef) -> RuntimeResult<char> {
        match self.force(thunk)?.as_ref() {
            Value::Character(value) => Ok(*value),
            _ => Err(RuntimeError::internal("expected Char")),
        }
    }

    fn force_optional_int(&mut self, thunk: &ThunkRef) -> RuntimeResult<Option<i64>> {
        let forced = self.force(thunk)?;
        match forced.as_ref() {
            Value::Maybe(None) => Ok(None),
            Value::Maybe(Some(value)) => {
                let value = Arc::clone(value);
                self.force_int(&value).map(Some)
            }
            _ => Err(RuntimeError::internal("expected Maybe Int")),
        }
    }

    fn force_list_elements(&mut self, thunk: &ThunkRef) -> RuntimeResult<Vec<ThunkRef>> {
        let mut elements = Vec::new();
        let mut list = Arc::clone(thunk);
        loop {
            match self.force(&list)?.as_ref() {
                Value::List(ListCell::Nil) => return Ok(elements),
                Value::List(ListCell::Cons { head, tail }) => {
                    self.budget.charge_materialization(1)?;
                    self.ensure_not_cancelled()?;
                    elements.push(Arc::clone(head));
                    list = Arc::clone(tail);
                }
                _ => return Err(RuntimeError::internal("expected list")),
            }
        }
    }

    fn force_text(&mut self, thunk: &ThunkRef) -> RuntimeResult<Arc<str>> {
        match self.force(thunk)?.as_ref() {
            Value::Text(value) => Ok(Arc::clone(value)),
            _ => Err(RuntimeError::internal("expected Text")),
        }
    }

    fn force_bytes(&mut self, thunk: &ThunkRef) -> RuntimeResult<Arc<[u8]>> {
        match self.force(thunk)?.as_ref() {
            Value::ByteString(value) => Ok(Arc::clone(value)),
            _ => Err(RuntimeError::internal("expected ByteString")),
        }
    }

    fn force_process(&mut self, thunk: &ThunkRef) -> RuntimeResult<Arc<ProcessSpec>> {
        match self.force(thunk)?.as_ref() {
            Value::Process(value) => Ok(Arc::clone(value)),
            _ => Err(RuntimeError::internal("expected Process")),
        }
    }

    fn force_handle(&mut self, thunk: &ThunkRef) -> RuntimeResult<HostHandle> {
        match self.force(thunk)?.as_ref() {
            Value::Handle(value) => Ok(value.clone()),
            _ => Err(RuntimeError::internal("expected Handle")),
        }
    }

    fn force_buffer_mode(&mut self, thunk: &ThunkRef) -> RuntimeResult<BufferMode> {
        match self.force(thunk)?.as_ref() {
            Value::BufferMode(value) => Ok(*value),
            _ => Err(RuntimeError::internal("expected BufferMode")),
        }
    }

    fn force_file_mode(&mut self, thunk: &ThunkRef) -> RuntimeResult<FileMode> {
        match self.force(thunk)?.as_ref() {
            Value::FileMode(value) => Ok(*value),
            _ => Err(RuntimeError::internal("expected FileMode")),
        }
    }

    fn force_io(&mut self, thunk: &ThunkRef) -> RuntimeResult<IoAction> {
        match self.force(thunk)?.as_ref() {
            Value::Io(action) => Ok(action.clone()),
            _ => Err(RuntimeError::internal("expected IO action")),
        }
    }

    fn show_value(&mut self, thunk: &ThunkRef) -> RuntimeResult<String> {
        self.show_value_at(thunk, 0)
    }

    #[allow(clippy::too_many_lines)]
    fn show_value_at(&mut self, thunk: &ThunkRef, precedence: u8) -> RuntimeResult<String> {
        match self.force(thunk)?.as_ref() {
            Value::Unit => Ok("()".into()),
            Value::Bool(value) => Ok(if *value { "True" } else { "False" }.into()),
            Value::Int(value) => Ok(value.to_string()),
            Value::Integer(value) => Ok(value.to_string()),
            Value::Double(value) => Ok(show_double(*value)),
            Value::JsonNumber(value) => Ok(value.as_json().to_owned()),
            Value::JsonDocument(document, index) => self.show_value_at(
                &Thunk::evaluated(json_document_value(document, *index)?),
                precedence,
            ),
            Value::Character(value) => Ok(format!("{value:?}")),
            Value::Builder(value) | Value::ByteString(value) => Ok(format!("{value:?}")),
            Value::CaseInsensitive(value) => self.show_value_at(&value.original, precedence),
            Value::Tree(value) => Ok(format!(
                "Node {{rootLabel = {}, subForest = {}}}",
                self.show_value_at(&value.root, 0)?,
                self.show_value_at(&value.children, 0)?
            )),
            Value::Day(value) => Ok(value.to_string()),
            Value::DayOfWeek(value) => Ok(value.to_string()),
            Value::UtcTime(value) => Ok(value.to_string()),
            Value::TimeOfDay(value) => Ok(value.to_string()),
            Value::Text(value) => Ok(format!("{value:?}")),
            Value::Tuple(elements) => {
                let elements = elements.clone();
                let mut rendered = Vec::with_capacity(elements.len());
                for element in elements.iter() {
                    rendered.push(self.show_value_at(element, 0)?);
                }
                Ok(format!("({})", rendered.join(",")))
            }
            Value::Record { layout, fields } => {
                let mut rendered = Vec::with_capacity(fields.len());
                for (field, value) in layout.fields.iter().zip(fields.iter()) {
                    rendered.push(format!(
                        "{} = {}",
                        field.name,
                        self.show_value_at(value, 0)?
                    ));
                }
                Ok(parenthesize_application(
                    format!("{} {{ {} }}", layout.constructor, rendered.join(", ")),
                    precedence,
                ))
            }
            Value::Variant {
                layout,
                constructor_index,
                payload,
            } => {
                let constructor = layout
                    .constructors
                    .get(usize::from(*constructor_index))
                    .ok_or_else(|| {
                        RuntimeError::internal("variant constructor is out of bounds")
                    })?;
                if let Some(payload) = payload {
                    Ok(parenthesize_application(
                        format!("{} {}", constructor.name, self.show_value_at(payload, 11)?),
                        precedence,
                    ))
                } else {
                    Ok(constructor.name.to_string())
                }
            }
            Value::Maybe(None) => Ok("Nothing".into()),
            Value::Maybe(Some(payload)) => Ok(parenthesize_application(
                format!("Just {}", self.show_value_at(payload, 11)?),
                precedence,
            )),
            Value::PrimitiveVariant(variant) => {
                let name = variant.constructor_name().ok_or_else(|| {
                    RuntimeError::internal("primitive constructor is out of bounds")
                })?;
                let mut rendered = Vec::with_capacity(variant.payloads.len());
                for payload in variant.payloads.iter() {
                    rendered.push(self.show_value_at(payload, 11)?);
                }
                if rendered.is_empty() {
                    Ok(name.into())
                } else {
                    Ok(parenthesize_application(
                        format!("{name} {}", rendered.join(" ")),
                        precedence,
                    ))
                }
            }
            Value::Vector(elements) => {
                let elements = elements.clone();
                let mut rendered = Vec::with_capacity(elements.len());
                for element in elements.iter() {
                    rendered.push(self.show_value_at(element, 0)?);
                }
                Ok(format!("[{}]", rendered.join(",")))
            }
            Value::Map(entries) => {
                let entries = entries.clone();
                let mut rendered = Vec::with_capacity(entries.len());
                for (key, item) in entries.iter() {
                    rendered.push(format!(
                        "({},{})",
                        self.show_value_at(key, 0)?,
                        self.show_value_at(item, 0)?
                    ));
                }
                Ok(parenthesize_application(
                    format!("fromList [{}]", rendered.join(",")),
                    precedence,
                ))
            }
            Value::Set(elements) => {
                let elements = Arc::clone(elements);
                let mut rendered = Vec::with_capacity(elements.len());
                for element in elements.iter() {
                    rendered.push(self.show_value_at(element, 0)?);
                }
                Ok(parenthesize_application(
                    format!("fromList [{}]", rendered.join(",")),
                    precedence,
                ))
            }
            Value::List(_) => {
                let mut rendered = Vec::new();
                let mut current = Arc::clone(thunk);
                loop {
                    match self.force(&current)?.as_ref() {
                        Value::List(ListCell::Nil) => break,
                        Value::List(ListCell::Cons { head, tail }) => {
                            rendered.push(self.show_value_at(head, 0)?);
                            current = Arc::clone(tail);
                        }
                        _ => return Err(RuntimeError::internal("malformed list spine")),
                    }
                }
                Ok(format!("[{}]", rendered.join(",")))
            }
            Value::Function(_)
            | Value::Internal(_)
            | Value::Process(_)
            | Value::Handle(_)
            | Value::BufferMode(_)
            | Value::FileMode(_)
            | Value::HttpStatus(_)
            | Value::HttpFilePart(_)
            | Value::HttpRequest(_)
            | Value::HttpResponse(_)
            | Value::HttpResponseReceived(_)
            | Value::OptionsMod(_)
            | Value::OptionsInfoMod(_)
            | Value::OptionsParser(_)
            | Value::OptionsParserInfo(_)
            | Value::Io(_) => Err(RuntimeError::internal(
                "no Show evidence exists for this runtime value",
            )),
        }
    }

    // Hell's `Eq Double` is exact IEEE equality; approximate comparison would
    // change the language semantics (notably for NaN and signed zero).
    #[allow(clippy::float_cmp)]
    #[allow(clippy::too_many_lines)]
    fn equal_values(&mut self, left: &ThunkRef, right: &ThunkRef) -> RuntimeResult<bool> {
        let left = self.force(left)?;
        let right = self.force(right)?;
        match (left.as_ref(), right.as_ref()) {
            (Value::Unit, Value::Unit) | (Value::Maybe(None), Value::Maybe(None)) => Ok(true),
            (Value::Bool(left), Value::Bool(right)) => Ok(left == right),
            (Value::Int(left), Value::Int(right)) => Ok(left == right),
            (Value::Integer(left), Value::Integer(right)) => Ok(left == right),
            (Value::Double(left), Value::Double(right)) => Ok(left == right),
            (Value::JsonNumber(left), Value::JsonNumber(right)) => Ok(left == right),
            (Value::JsonDocument(document, index), _) => self.equal_values(
                &Thunk::evaluated(json_document_value(document, *index)?),
                &Thunk::evaluated(right.as_ref().clone()),
            ),
            (_, Value::JsonDocument(document, index)) => self.equal_values(
                &Thunk::evaluated(left.as_ref().clone()),
                &Thunk::evaluated(json_document_value(document, *index)?),
            ),
            (Value::Character(left), Value::Character(right)) => Ok(left == right),
            (Value::Builder(left), Value::Builder(right))
            | (Value::ByteString(left), Value::ByteString(right)) => Ok(left == right),
            (Value::CaseInsensitive(left), Value::CaseInsensitive(right)) => {
                self.equal_values(&left.folded, &right.folded)
            }
            (Value::Tree(left), Value::Tree(right)) => Ok(self
                .equal_values(&left.root, &right.root)?
                && self.equal_values(&left.children, &right.children)?),
            (Value::Day(left), Value::Day(right)) => Ok(left == right),
            (Value::DayOfWeek(left), Value::DayOfWeek(right)) => Ok(left == right),
            (Value::UtcTime(left), Value::UtcTime(right)) => Ok(left == right),
            (Value::TimeOfDay(left), Value::TimeOfDay(right)) => Ok(left == right),
            (Value::Text(left), Value::Text(right)) => Ok(left == right),
            (Value::Tuple(left), Value::Tuple(right)) if left.len() == right.len() => {
                for (left, right) in left.iter().zip(right.iter()) {
                    if !self.equal_values(left, right)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (
                Value::Record {
                    layout: left_layout,
                    fields: left,
                },
                Value::Record {
                    layout: right_layout,
                    fields: right,
                },
            ) if left_layout == right_layout && left.len() == right.len() => {
                for (left, right) in left.iter().zip(right.iter()) {
                    if !self.equal_values(left, right)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (
                Value::Variant {
                    layout: left_layout,
                    constructor_index: left_index,
                    payload: left_payload,
                },
                Value::Variant {
                    layout: right_layout,
                    constructor_index: right_index,
                    payload: right_payload,
                },
            ) if left_layout == right_layout && left_index == right_index => {
                match (left_payload, right_payload) {
                    (None, None) => Ok(true),
                    (Some(left), Some(right)) => self.equal_values(left, right),
                    _ => Ok(false),
                }
            }
            (Value::Maybe(Some(left)), Value::Maybe(Some(right))) => self.equal_values(left, right),
            (Value::Maybe(_), Value::Maybe(_)) => Ok(false),
            (Value::PrimitiveVariant(left), Value::PrimitiveVariant(right)) => {
                self.equal_primitive_variants(left, right)
            }
            (Value::Vector(left), Value::Vector(right)) => {
                if left.len() != right.len() {
                    return Ok(false);
                }
                for (left, right) in left.iter().zip(right.iter()) {
                    if !self.equal_values(left, right)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (Value::Set(left), Value::Set(right)) => {
                if left.len() != right.len() {
                    return Ok(false);
                }
                for (left, right) in left.iter().zip(right.iter()) {
                    if !self.equal_values(left, right)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (Value::Map(left), Value::Map(right)) => {
                if left.len() != right.len() {
                    return Ok(false);
                }
                for ((left_key, left_item), (right_key, right_item)) in
                    left.iter().zip(right.iter())
                {
                    if !self.equal_values(left_key, right_key)?
                        || !self.equal_values(left_item, right_item)?
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            (Value::List(_), Value::List(_)) => {
                let mut left = Thunk::evaluated(left.as_ref().clone());
                let mut right = Thunk::evaluated(right.as_ref().clone());
                loop {
                    let left_value = self.force(&left)?;
                    let right_value = self.force(&right)?;
                    match (left_value.as_ref(), right_value.as_ref()) {
                        (Value::List(ListCell::Nil), Value::List(ListCell::Nil)) => {
                            return Ok(true);
                        }
                        (
                            Value::List(ListCell::Cons {
                                head: left_head,
                                tail: left_tail,
                            }),
                            Value::List(ListCell::Cons {
                                head: right_head,
                                tail: right_tail,
                            }),
                        ) => {
                            if !self.equal_values(left_head, right_head)? {
                                return Ok(false);
                            }
                            left = Arc::clone(left_tail);
                            right = Arc::clone(right_tail);
                        }
                        (Value::List(ListCell::Nil), Value::List(ListCell::Cons { .. }))
                        | (Value::List(ListCell::Cons { .. }), Value::List(ListCell::Nil)) => {
                            return Ok(false);
                        }
                        _ => return Err(RuntimeError::internal("malformed list equality")),
                    }
                }
            }
            _ => Err(RuntimeError::internal(
                "Eq evidence did not match runtime values",
            )),
        }
    }

    fn equal_primitive_variants(
        &mut self,
        left: &PrimitiveVariantValue,
        right: &PrimitiveVariantValue,
    ) -> RuntimeResult<bool> {
        if left.family != right.family
            || left.constructor_index != right.constructor_index
            || left.payloads.len() != right.payloads.len()
        {
            return Ok(false);
        }
        for (left, right) in left.payloads.iter().zip(right.payloads.iter()) {
            if !self.equal_values(left, right)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn less_values(&mut self, left: &ThunkRef, right: &ThunkRef) -> RuntimeResult<bool> {
        let left = self.force(left)?;
        let right = self.force(right)?;
        match (left.as_ref(), right.as_ref()) {
            (Value::Bool(left), Value::Bool(right)) => Ok(left < right),
            (Value::Int(left), Value::Int(right)) => Ok(left < right),
            (Value::Integer(left), Value::Integer(right)) => Ok(left < right),
            (Value::Double(left), Value::Double(right)) => Ok(left < right),
            (Value::Character(left), Value::Character(right)) => Ok(left < right),
            (Value::Builder(left), Value::Builder(right))
            | (Value::ByteString(left), Value::ByteString(right)) => Ok(left < right),
            (Value::CaseInsensitive(left), Value::CaseInsensitive(right)) => {
                self.less_values(&left.folded, &right.folded)
            }
            (Value::Tree(left), Value::Tree(right)) => {
                if self.less_values(&left.root, &right.root)? {
                    Ok(true)
                } else if self.equal_values(&left.root, &right.root)? {
                    self.less_values(&left.children, &right.children)
                } else {
                    Ok(false)
                }
            }
            (Value::Day(left), Value::Day(right)) => Ok(left < right),
            (Value::DayOfWeek(left), Value::DayOfWeek(right)) => Ok(left < right),
            (Value::UtcTime(left), Value::UtcTime(right)) => Ok(left < right),
            (Value::TimeOfDay(left), Value::TimeOfDay(right)) => Ok(left < right),
            (Value::Text(left), Value::Text(right)) => Ok(left < right),
            (Value::Tuple(left), Value::Tuple(right)) if left.len() == right.len() => {
                let left = Arc::clone(left);
                let right = Arc::clone(right);
                for (left, right) in left.iter().zip(right.iter()) {
                    if self.less_values(left, right)? {
                        return Ok(true);
                    }
                    if !self.equal_values(left, right)? {
                        return Ok(false);
                    }
                }
                Ok(false)
            }
            (Value::Maybe(None), Value::Maybe(Some(_))) => Ok(true),
            (Value::Maybe(Some(_) | None), Value::Maybe(None)) => Ok(false),
            (Value::Maybe(Some(left)), Value::Maybe(Some(right))) => self.less_values(left, right),
            (Value::PrimitiveVariant(left), Value::PrimitiveVariant(right))
                if left.family == PrimitiveFamily::Either
                    && right.family == PrimitiveFamily::Either =>
            {
                if left.constructor_index != right.constructor_index {
                    return Ok(left.constructor_index < right.constructor_index);
                }
                for (left, right) in left.payloads.iter().zip(right.payloads.iter()) {
                    if self.less_values(left, right)? {
                        return Ok(true);
                    }
                    if !self.equal_values(left, right)? {
                        return Ok(false);
                    }
                }
                Ok(false)
            }
            (Value::Set(left), Value::Set(right)) => self.less_ordered_sets(left, right),
            (Value::List(_), Value::List(_)) => {
                let mut left = Thunk::evaluated(left.as_ref().clone());
                let mut right = Thunk::evaluated(right.as_ref().clone());
                loop {
                    let left_value = self.force(&left)?;
                    let right_value = self.force(&right)?;
                    match (left_value.as_ref(), right_value.as_ref()) {
                        (Value::List(_), Value::List(ListCell::Nil)) => return Ok(false),
                        (Value::List(ListCell::Nil), Value::List(ListCell::Cons { .. })) => {
                            return Ok(true);
                        }
                        (
                            Value::List(ListCell::Cons {
                                head: left_head,
                                tail: left_tail,
                            }),
                            Value::List(ListCell::Cons {
                                head: right_head,
                                tail: right_tail,
                            }),
                        ) => {
                            if self.less_values(left_head, right_head)? {
                                return Ok(true);
                            }
                            if !self.equal_values(left_head, right_head)? {
                                return Ok(false);
                            }
                            left = Arc::clone(left_tail);
                            right = Arc::clone(right_tail);
                        }
                        _ => return Err(RuntimeError::internal("malformed list ordering")),
                    }
                }
            }
            _ => Err(RuntimeError::internal(
                "Ord evidence did not match runtime values",
            )),
        }
    }

    fn less_ordered_slices(
        &mut self,
        left: &[ThunkRef],
        right: &[ThunkRef],
    ) -> RuntimeResult<bool> {
        for (left, right) in left.iter().zip(right.iter()) {
            if self.less_values(left, right)? {
                return Ok(true);
            }
            if !self.equal_values(left, right)? {
                return Ok(false);
            }
        }
        Ok(left.len() < right.len())
    }

    fn less_ordered_sets(&mut self, left: &OrderedSet, right: &OrderedSet) -> RuntimeResult<bool> {
        let left = left.iter().cloned().collect::<Vec<_>>();
        let right = right.iter().cloned().collect::<Vec<_>>();
        self.less_ordered_slices(&left, &right)
    }
}

fn parenthesize_application(rendered: String, precedence: u8) -> String {
    if precedence > 10 {
        format!("({rendered})")
    } else {
        rendered
    }
}

enum ForceOutcome {
    Value(ValueRef),
    Alias(ThunkRef),
}

fn list_from_values(mut values: Vec<ThunkRef>) -> ThunkRef {
    let mut result = Thunk::evaluated(Value::List(ListCell::Nil));
    while let Some(head) = values.pop() {
        result = Thunk::evaluated(Value::List(ListCell::Cons { head, tail: result }));
    }
    result
}

fn finish_with_cleanup<T>(
    body: RuntimeResult<T>,
    cleanup: impl IntoIterator<Item = RuntimeResult<()>>,
) -> RuntimeResult<T> {
    let cleanup_errors = cleanup
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    match body {
        Ok(value) => {
            let Some((primary, suppressed)) = cleanup_errors.split_first() else {
                return Ok(value);
            };
            Err(error_with_suppressed(primary, suppressed.iter().cloned()))
        }
        Err(primary) if cleanup_errors.is_empty() => Err(primary),
        Err(primary) => Err(error_with_suppressed(&primary, cleanup_errors)),
    }
}

#[cfg(test)]
mod capability_policy_tests {
    use super::*;

    #[test]
    fn sandbox_denies_environment_clock_and_process_exit_capabilities() {
        let mut policy = RuntimePolicy::sandboxed();
        policy.capabilities.clock = false;
        let context = RuntimeContext::new(Vec::new(), Vec::new()).with_policy(policy);
        assert!(
            context
                .require_environment_read("Environment.getEnvironment")
                .is_err()
        );
        assert!(context.current_time().is_err());
        assert!(context.require_exit_process("Exit.exitWith").is_err());
        assert!(context.require_network("Http.run").is_ok());
        assert!(!context.policy.capabilities.network_external);
    }
}

fn error_with_suppressed(
    primary: &Arc<RuntimeError>,
    additional: impl IntoIterator<Item = Arc<RuntimeError>>,
) -> Arc<RuntimeError> {
    let mut suppressed = primary.suppressed.to_vec();
    suppressed.extend(additional);
    Arc::new(RuntimeError {
        code: primary.code,
        kind: primary.kind.clone(),
        message: Arc::clone(&primary.message),
        suppressed: suppressed.into(),
    })
}

fn json_document_value(document: &Arc<JsonDocument>, index: usize) -> RuntimeResult<Value> {
    let node = document
        .node(index)
        .ok_or_else(|| RuntimeError::internal("decoded JSON node index is out of bounds"))?;
    Ok(match node {
        native_json::JsonDocumentNode::Null => json_primitive_value(0, Arc::from([])),
        native_json::JsonDocumentNode::Bool(value) => {
            json_primitive_value(1, Arc::from([Thunk::evaluated(Value::Bool(*value))]))
        }
        native_json::JsonDocumentNode::String(value) => json_primitive_value(
            2,
            Arc::from([Thunk::evaluated(Value::Text(value.clone().into()))]),
        ),
        native_json::JsonDocumentNode::Number(value) => json_primitive_value(
            3,
            Arc::from([Thunk::evaluated(Value::JsonNumber(value.clone()))]),
        ),
        native_json::JsonDocumentNode::Array(children) => {
            let children = children
                .iter()
                .map(|index| Thunk::evaluated(Value::JsonDocument(Arc::clone(document), *index)))
                .collect::<Vec<_>>();
            json_primitive_value(
                4,
                Arc::from([Thunk::evaluated(Value::Vector(children.into()))]),
            )
        }
        native_json::JsonDocumentNode::Object(entries) => {
            let entries = entries
                .iter()
                .map(|(key, index)| {
                    (
                        Thunk::evaluated(Value::Text(key.clone().into())),
                        Thunk::evaluated(Value::JsonDocument(Arc::clone(document), *index)),
                    )
                })
                .collect::<Vec<_>>();
            json_primitive_value(
                5,
                Arc::from([Thunk::evaluated(Value::Map(Arc::new(
                    OrderedMap::from_sorted(&entries),
                )))]),
            )
        }
    })
}

fn json_primitive_value(constructor_index: u8, payloads: Arc<[ThunkRef]>) -> Value {
    Value::PrimitiveVariant(PrimitiveVariantValue {
        family: PrimitiveFamily::Json,
        constructor_index,
        payloads,
    })
}

fn path_to_text(operation: &'static str, path: PathBuf) -> RuntimeResult<Arc<str>> {
    path.into_os_string()
        .into_string()
        .map(Arc::<str>::from)
        .map_err(|_| {
            RuntimeContext::io_error(
                operation,
                std::io::Error::new(std::io::ErrorKind::InvalidData, "path is not valid UTF-8"),
            )
        })
}

struct ScopedFileResource(Arc<native_handle::FileHandle>);

impl scope::ScopedResource for ScopedFileResource {
    fn kind(&self) -> scope::ResourceKind {
        scope::ResourceKind::Handle
    }

    fn request_cancel(&self, _reason: &scope::CancelReason) {
        let _ignored = self.0.close();
    }

    fn close(&self) -> RuntimeResult<()> {
        self.0
            .close()
            .map_err(|error| RuntimeContext::io_error("scoped handle cleanup", error))
    }

    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

struct ScopedProcessResource(Mutex<Option<SupervisedChild>>);

impl ScopedProcessResource {
    fn new(child: SupervisedChild) -> Self {
        Self(Mutex::new(Some(child)))
    }

    fn take_stdin(&self) -> Option<std::process::ChildStdin> {
        self.0.lock().ok()?.as_mut()?.take_stdin()
    }

    fn take_stdout(&self) -> Option<std::process::ChildStdout> {
        self.0.lock().ok()?.as_mut()?.take_stdout()
    }

    fn take_stderr(&self) -> Option<std::process::ChildStderr> {
        self.0.lock().ok()?.as_mut()?.take_stderr()
    }

    fn try_wait(&self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("process-resource mutex was poisoned"))?
            .as_mut()
            .ok_or_else(|| std::io::Error::other("process tree is closed"))?
            .try_wait()
    }

    fn terminate(&self) -> std::io::Result<std::process::ExitStatus> {
        let mut child = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("process-resource mutex was poisoned"))?
            .take()
            .ok_or_else(|| std::io::Error::other("process tree is closed"))?;
        child.terminate().map(|(status, _)| status)
    }
}

#[derive(Clone)]
struct ScopedTempResource(Arc<Mutex<Option<native_temp::TempResource>>>);

impl ScopedTempResource {
    fn new(resource: native_temp::TempResource) -> Self {
        Self(Arc::new(Mutex::new(Some(resource))))
    }

    fn path(&self) -> RuntimeResult<PathBuf> {
        self.0
            .lock()
            .map_err(|_| RuntimeError::internal("temporary-resource mutex was poisoned"))?
            .as_ref()
            .map(|resource| resource.path().to_owned())
            .ok_or_else(|| RuntimeError::resource_closed("temporary resource is closed"))
    }

    fn cleanup(&self) -> std::io::Result<()> {
        let resource = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("temporary-resource mutex was poisoned"))?
            .take();
        resource.map_or(Ok(()), native_temp::TempResource::cleanup)
    }
}

impl scope::ScopedResource for ScopedTempResource {
    fn kind(&self) -> scope::ResourceKind {
        scope::ResourceKind::Temporary
    }

    fn request_cancel(&self, _reason: &scope::CancelReason) {
        let _ignored = self.cleanup();
    }

    fn close(&self) -> RuntimeResult<()> {
        self.cleanup()
            .map_err(|error| RuntimeContext::io_error("scoped temporary cleanup", error))
    }

    fn is_closed(&self) -> bool {
        self.0.lock().map_or(true, |resource| resource.is_none())
    }
}

impl scope::ScopedResource for ScopedProcessResource {
    fn kind(&self) -> scope::ResourceKind {
        scope::ResourceKind::Process
    }

    fn request_cancel(&self, _reason: &scope::CancelReason) {
        let _ignored = self.terminate();
    }

    fn close(&self) -> RuntimeResult<()> {
        if self.is_closed() {
            return Ok(());
        }
        self.terminate()
            .map(|_| ())
            .map_err(|error| RuntimeContext::io_error("scoped process cleanup", error))
    }

    fn is_closed(&self) -> bool {
        self.0.lock().map_or(true, |child| child.is_none())
    }
}

#[allow(clippy::too_many_lines)]
fn run_child_process(
    process: &ProcessSpec,
    context: &RuntimeContext,
    operation: &'static str,
    capture: bool,
    cancellation: &concurrency::CancellationToken,
    execution_scope: &scope::ExecutionScope,
) -> RuntimeResult<Output> {
    context.require_process(operation)?;
    let _permit = context.budget.acquire_process()?;
    validate_process_streams(process)?;

    let mut command = Command::new(process.command.as_ref());
    command.args(process.arguments.iter().map(AsRef::as_ref));
    let working_directory = if let Some(directory) = &process.working_directory {
        context.resolve_path(operation, directory)?
    } else {
        context
            .cwd
            .lock()
            .map_err(|_| RuntimeError::internal("working-directory mutex was poisoned"))?
            .clone()
    };
    command.current_dir(working_directory);
    if let Some(environment) = &process.environment {
        command.env_clear();
        command.envs(
            environment
                .iter()
                .map(|(name, value)| (name.as_ref(), value.as_ref())),
        );
    }
    if process.stdin_bytes.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(match &process.stdin {
            HostHandle::Stdin => Stdio::inherit(),
            HostHandle::Null => Stdio::null(),
            HostHandle::File { handle, .. } => Stdio::from(
                handle
                    .try_clone_file()
                    .map_err(|error| RuntimeContext::io_error(operation, error))?,
            ),
            HostHandle::Stdout | HostHandle::Stderr => {
                return Err(RuntimeError::internal(
                    "process stdin handle redirection is not available for this handle",
                ));
            }
        });
    }
    if capture {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    } else {
        command
            .stdout(process_output_stdio(&process.stdout, true, operation)?)
            .stderr(process_output_stdio(&process.stderr, false, operation)?);
    }
    let body = (|| {
        let child = SupervisedChild::spawn(&mut command)
            .map_err(|error| RuntimeContext::io_error(operation, error))?;
        let child = execution_scope.register(ScopedProcessResource::new(child))?;

        let stdout = child.resource().take_stdout().map(|stdout| {
            let context = context.clone();
            let target = process.stdout.clone();
            let limit = context.policy.limits.process_capture_bytes;
            std::thread::spawn(move || {
                if capture {
                    read_process_capture(stdout, limit)
                } else {
                    forward_process_reader(stdout, &target, &context).map(|()| Vec::new())
                }
            })
        });
        let stderr = child.resource().take_stderr().map(|stderr| {
            let context = context.clone();
            let target = process.stderr.clone();
            let limit = context.policy.limits.process_capture_bytes;
            std::thread::spawn(move || {
                if capture {
                    read_process_capture(stderr, limit)
                } else {
                    forward_process_reader(stderr, &target, &context).map(|()| Vec::new())
                }
            })
        });
        let stdin_writer = if let Some(input) = &process.stdin_bytes {
            let mut stdin = child.resource().take_stdin().ok_or_else(|| {
                RuntimeError::internal("piped child stdin was unavailable after spawn")
            })?;
            let input = Arc::clone(input);
            Some(std::thread::spawn(move || {
                stdin
                    .write_all(&input)
                    .map_err(|error| RuntimeContext::io_error(operation, error))
            }))
        } else {
            None
        };
        let mut was_cancelled = false;
        let status = loop {
            if cancellation.wait_timeout(std::time::Duration::from_millis(2)) {
                was_cancelled = true;
                let status = child
                    .resource()
                    .terminate()
                    .map_err(|error| RuntimeContext::io_error(operation, error))?;
                break status;
            }
            if let Some(status) = child
                .resource()
                .try_wait()
                .map_err(|error| RuntimeContext::io_error(operation, error))?
            {
                // A descendant can inherit a capture pipe and outlive the process
                // leader. Close the scoped process tree before joining pipe
                // readers so a detached descendant cannot hang the evaluator.
                child
                    .resource()
                    .terminate()
                    .map_err(|error| RuntimeContext::io_error(operation, error))?;
                break status;
            }
        };
        let stdout = join_process_reader(stdout, operation)?;
        let stderr = join_process_reader(stderr, operation)?;
        if let Some(writer) = stdin_writer {
            writer
                .join()
                .map_err(|_| RuntimeError::panic_contained("process stdin writer panicked"))??;
        }
        if was_cancelled {
            return Err(RuntimeError::cancelled());
        }
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    })();
    finish_with_cleanup(body, [close_process_handles(process, operation)])
}

fn validate_process_streams(process: &ProcessSpec) -> RuntimeResult<()> {
    if matches!(process.stdout, HostHandle::Stdin) || matches!(process.stderr, HostHandle::Stdin) {
        return Err(RuntimeError::internal(
            "process output was configured with the standard-input handle",
        ));
    }
    Ok(())
}

fn close_process_handles(process: &ProcessSpec, operation: &'static str) -> RuntimeResult<()> {
    let mut cleanup = Vec::new();
    if let HostHandle::File {
        handle,
        close_after_process: true,
    } = &process.stdout
    {
        cleanup.push(
            handle
                .close()
                .map_err(|error| RuntimeContext::io_error(operation, error)),
        );
    }
    if let HostHandle::File {
        handle,
        close_after_process: true,
    } = &process.stderr
    {
        let already_closed = matches!(
            &process.stdout,
            HostHandle::File {
                handle: stdout,
                close_after_process: true,
            } if Arc::ptr_eq(stdout, handle)
        );
        if !already_closed {
            cleanup.push(
                handle
                    .close()
                    .map_err(|error| RuntimeContext::io_error(operation, error)),
            );
        }
    }
    finish_with_cleanup(Ok(()), cleanup)
}

fn process_output_stdio(
    stream: &HostHandle,
    is_stdout: bool,
    operation: &'static str,
) -> RuntimeResult<Stdio> {
    match stream {
        HostHandle::Stdout if is_stdout => Ok(Stdio::inherit()),
        HostHandle::Stderr if !is_stdout => Ok(Stdio::inherit()),
        HostHandle::Stdout | HostHandle::Stderr => Ok(Stdio::piped()),
        HostHandle::Null => Ok(Stdio::null()),
        HostHandle::File { handle, .. } => handle
            .try_clone_file()
            .map(Stdio::from)
            .map_err(|error| RuntimeContext::io_error(operation, error)),
        HostHandle::Stdin => Err(RuntimeError::internal(
            "process output was configured with the standard-input handle",
        )),
    }
}

fn forward_process_reader(
    mut reader: impl Read,
    stream: &HostHandle,
    context: &RuntimeContext,
) -> RuntimeResult<()> {
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| RuntimeContext::io_error("Process output", error))?;
        if read == 0 {
            return Ok(());
        }
        match stream {
            HostHandle::Stdout => context.write(&buffer[..read])?,
            HostHandle::Stderr => context.write_stderr(&buffer[..read])?,
            HostHandle::Null | HostHandle::File { .. } => {}
            HostHandle::Stdin => unreachable!("process streams validated"),
        }
    }
}

fn read_process_capture(mut reader: impl Read, limit: Limit<u64>) -> RuntimeResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut exceeded = false;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| RuntimeContext::io_error("readProcess", error))?;
        if read == 0 {
            break;
        }
        let next = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if limit.value().is_some_and(|maximum| next > maximum) {
            exceeded = true;
        } else if !exceeded {
            bytes.extend_from_slice(&buffer[..read]);
        }
    }
    if exceeded {
        Err(RuntimeError::resource_limit(
            "readProcess output exceeded the configured capture budget",
        ))
    } else {
        Ok(bytes)
    }
}

fn join_process_reader(
    reader: Option<std::thread::JoinHandle<RuntimeResult<Vec<u8>>>>,
    operation: &'static str,
) -> RuntimeResult<Vec<u8>> {
    reader.map_or_else(
        || Ok(Vec::new()),
        |reader| {
            reader
                .join()
                .map_err(|_| RuntimeError::panic_contained(operation))?
        },
    )
}

fn ensure_process_success(process: &ProcessSpec, output: &Output) -> RuntimeResult<()> {
    if output.status.success() {
        return Ok(());
    }
    Err(RuntimeContext::io_error(
        "runProcess",
        format!(
            "received {} when running `{}`",
            exit_code_text(output),
            process.command
        ),
    ))
}

fn exit_code_text(output: &Output) -> String {
    output.status.code().map_or_else(
        || "an unknown signal exit".to_owned(),
        |code| format!("ExitFailure {code}"),
    )
}

fn exit_code_value(output: &Output) -> Value {
    output.status.code().map_or_else(
        || {
            Value::PrimitiveVariant(PrimitiveVariantValue {
                family: PrimitiveFamily::Exit,
                constructor_index: 1,
                payloads: Arc::from([Thunk::evaluated(Value::Int(-1))]),
            })
        },
        |code| {
            if code == 0 {
                Value::PrimitiveVariant(PrimitiveVariantValue {
                    family: PrimitiveFamily::Exit,
                    constructor_index: 0,
                    payloads: Arc::from([]),
                })
            } else {
                Value::PrimitiveVariant(PrimitiveVariantValue {
                    family: PrimitiveFamily::Exit,
                    constructor_index: 1,
                    payloads: Arc::from([Thunk::evaluated(Value::Int(i64::from(code)))]),
                })
            }
        },
    )
}

fn process_output_value(
    operation: &'static str,
    bytes: Vec<u8>,
    text: bool,
) -> RuntimeResult<Value> {
    if text {
        let text = String::from_utf8(bytes).map_err(|error| {
            RuntimeContext::io_error(
                operation,
                format!("invalid UTF-8 at byte {}", error.utf8_error().valid_up_to()),
            )
        })?;
        Ok(Value::Text(text.into()))
    } else {
        Ok(Value::ByteString(bytes.into()))
    }
}

fn show_double(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value == f64::INFINITY {
        return "Infinity".into();
    }
    if value == f64::NEG_INFINITY {
        return "-Infinity".into();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0".into()
        } else {
            "0.0".into()
        };
    }
    let magnitude = value.abs();
    if !(0.1..10_000_000.0).contains(&magnitude) {
        return format_double_exponential(value);
    }
    let mut rendered = value.to_string();
    if !rendered.contains(['.', 'e', 'E']) {
        rendered.push_str(".0");
    }
    rendered
}

fn checked_precision(precision: i64, limit: Limit<u32>) -> RuntimeResult<usize> {
    let precision = precision.max(0);
    if limit
        .value()
        .is_some_and(|maximum| u64::try_from(precision).unwrap_or(u64::MAX) > u64::from(maximum))
    {
        return Err(RuntimeError::resource_limit(format!(
            "floating-point output precision exceeds the configured limit {:?}",
            limit.value()
        )));
    }
    usize::try_from(precision)
        .map_err(|_| RuntimeError::resource_limit("floating-point precision is out of range"))
}

fn show_double_exponential(
    value: f64,
    precision: Option<i64>,
    limit: Limit<u32>,
) -> RuntimeResult<String> {
    if !value.is_finite() {
        return Ok(show_double(value));
    }
    Ok(match precision {
        Some(precision) => {
            let precision = checked_precision(precision, limit)?;
            format!("{value:.precision$e}")
        }
        None => format_double_exponential(value),
    })
}

fn format_double_exponential(value: f64) -> String {
    let rendered = format!("{value:e}");
    let Some(exponent) = rendered.find('e') else {
        return rendered;
    };
    if rendered[..exponent].contains('.') {
        rendered
    } else {
        format!("{}.0{}", &rendered[..exponent], &rendered[exponent..])
    }
}

fn show_double_fixed(
    value: f64,
    precision: Option<i64>,
    limit: Limit<u32>,
) -> RuntimeResult<String> {
    if !value.is_finite() {
        return Ok(show_double(value));
    }
    Ok(match precision {
        Some(precision) => {
            let precision = checked_precision(precision, limit)?;
            format!("{value:.precision$}")
        }
        None => format_double_fixed(value),
    })
}

fn format_double_fixed(value: f64) -> String {
    let mut rendered = value.to_string();
    if !rendered.contains('.') {
        rendered.push_str(".0");
    }
    rendered
}

#[allow(clippy::cast_precision_loss)]
fn int_to_double(value: i64) -> f64 {
    value as f64
}

/// Executes the sealed `main :: IO ()` action once.
///
/// Taking ownership of the sealed program and runtime context makes the
/// execution boundary explicit while individual [`IoAction`] descriptions
/// remain reusable.
///
/// # Errors
///
/// Returns any user, I/O, black-hole, resource-limit, or verified-invariant
/// failure encountered while evaluating and executing the action.
#[allow(clippy::needless_pass_by_value)]
pub fn run_main(program: VerifiedProgram, context: RuntimeContext) -> RuntimeResult<()> {
    let executable = Arc::new(program.executable().clone());
    let mut evaluator = Evaluator::new(executable)
        .with_policy(Arc::clone(&context.policy), Arc::clone(&context.budget));
    if let Some(max_concurrent_actions) = context.max_concurrent_actions {
        evaluator = evaluator.with_max_concurrent_actions(max_concurrent_actions);
    }
    let root_scope = evaluator.execution_scope().clone().guard();
    let body = (|| {
        let main = evaluator.root_thunk();
        let action = evaluator.force_io(&main)?;
        let result = action.run(&mut evaluator, &context)?;
        match evaluator.force(&result)?.as_ref() {
            Value::Unit => Ok(()),
            _ => Err(RuntimeError::internal(
                "verified IO () action returned a non-unit value",
            )),
        }
    })();
    match body {
        Ok(()) => {
            let report = root_scope.close()?;
            let after = &report.after;
            let budget = &after.budget;
            if after.child_scopes != 0
                || after.live_tasks != 0
                || after.resources != 0
                || after.finalizers != 0
                || budget.live_tasks != 0
                || budget.live_handles != 0
                || budget.live_processes != 0
                || budget.live_http_connections != 0
                || budget.live_temp_resources != 0
            {
                return Err(RuntimeError::cancellation_stalled(format!(
                    "execution scope did not return to its resource baseline: {after:?}"
                )));
            }
            Ok(())
        }
        Err(error) => root_scope.close_with_primary(Some(error)).map(|_| ()),
    }
}
