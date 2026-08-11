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

#[cfg(feature = "mutation-testing")]
pub(crate) fn semantic_mutant_active(id: &str) -> bool {
    std::env::var("HELL_ASSURANCE_MUTANT_ID").as_deref() == Ok(id)
}

#[cfg(not(feature = "mutation-testing"))]
pub(crate) const fn semantic_mutant_active(_id: &str) -> bool {
    false
}

pub use hell_builtins::RuntimeDiagnosticCode;
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

    /// Overrides standard error for deterministic embedding and tests.
    #[must_use]
    pub fn with_stderr(mut self, stderr: impl Write + Send + 'static) -> Self {
        self.stderr = Arc::new(Mutex::new(Box::new(stderr)));
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
    evidence_builtin: Option<BuiltinId>,
    #[cfg(feature = "compat-tracing")]
    evidence_arguments: Arc<[(usize, ThunkRef)]>,
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
            evidence_builtin: None,
            #[cfg(feature = "compat-tracing")]
            evidence_arguments: Arc::from([]),
        }
    }

    fn with_evidence_builtin(mut self, builtin: BuiltinId) -> Self {
        self.evidence_builtin = Some(builtin);
        self
    }

    #[cfg(feature = "compat-tracing")]
    fn with_evidence_arguments(mut self, arguments: Vec<(usize, ThunkRef)>) -> Self {
        self.evidence_arguments = arguments.into();
        self
    }

    fn run(&self, evaluator: &mut Evaluator, context: &RuntimeContext) -> RuntimeResult<ThunkRef> {
        let budget = Arc::clone(&evaluator.budget);
        let _budget = ActiveBudgetGuard::enter(&budget);
        #[cfg(feature = "compat-tracing")]
        let effect = self
            .evidence_builtin
            .map(|builtin| evaluator.record_effect_started(builtin))
            .transpose()?
            .flatten();
        let result = (self.operation)(evaluator, context);
        #[cfg(feature = "compat-tracing")]
        if let Some(builtin) = self.evidence_builtin {
            for (argument, thunk) in self.evidence_arguments.iter() {
                evaluator.record_argument_snapshot(
                    builtin,
                    *argument,
                    "io-execution-complete",
                    thunk,
                )?;
            }
        }
        #[cfg(feature = "compat-tracing")]
        if let Some(effect) = effect {
            evaluator.record_effect_terminal(
                effect,
                if result.is_ok() {
                    "completed"
                } else {
                    "failed"
                },
            )?;
        }
        result
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
        #[cfg(feature = "compat-tracing")]
        callback_parent: Option<AdapterCausalIdentity>,
    },
    ListMap {
        function: ThunkRef,
        list: ThunkRef,
        #[cfg(feature = "compat-tracing")]
        callback_parent: Option<AdapterCausalIdentity>,
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
    #[cfg(feature = "compat-tracing")]
    CallbackApply {
        function: ThunkRef,
        argument: ThunkRef,
        parent: AdapterCausalIdentity,
        callback_argument: u16,
        branch: &'static str,
        evidence_arguments: Arc<[ThunkRef]>,
        logical_invocation: Option<u64>,
        logical_task: Option<u64>,
    },
    #[cfg(feature = "compat-tracing")]
    CallbackForce {
        target: ThunkRef,
        parent: AdapterCausalIdentity,
        callback_argument: u16,
        branch: &'static str,
    },
    Fix {
        function: ThunkRef,
        recursive: Weak<Thunk>,
    },
    Native(Arc<NativeThunkOperation>),
}

#[cfg(feature = "compat-tracing")]
struct CallbackApplication {
    function: ThunkRef,
    argument: ThunkRef,
    parent: AdapterCausalIdentity,
    callback_argument: u16,
    branch: &'static str,
    evidence_arguments: Arc<[ThunkRef]>,
    logical_invocation: Option<u64>,
    logical_task: Option<u64>,
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
    #[cfg(feature = "compat-tracing")]
    evidence_trace: Option<Arc<Mutex<EvidenceTrace>>>,
    #[cfg(feature = "compat-tracing")]
    current_evidence_task: Option<u64>,
    #[cfg(feature = "compat-tracing")]
    adapter_obligation_stack: Vec<ActiveAdapterObligation>,
    #[cfg(feature = "compat-tracing")]
    pending_adapter_parent: Option<AdapterCausalIdentity>,
    #[cfg(feature = "compat-tracing")]
    effect_stack: Vec<EffectCausalIdentity>,
}

#[cfg(feature = "compat-tracing")]
#[derive(Default)]
struct EvidenceTrace {
    next_task_id: u64,
    next_resource_id: u64,
    parsed_builtins: Vec<BuiltinId>,
    resolved_builtins: Vec<BuiltinId>,
    specialized_builtins: Vec<BuiltinId>,
    entered_adapters: Vec<BuiltinId>,
    forced_arguments: Vec<ForcedArgumentEvidence>,
    typed_result_target: Option<BuiltinId>,
    typed_result_target_invocations: u64,
    typed_results: Vec<(BuiltinId, usize, &'static str, ThunkRef)>,
    effect_events: Vec<EffectEvidence>,
    task_events: Vec<(BuiltinId, u64, &'static str)>,
    presentation_fields: Vec<(BuiltinId, &'static str)>,
    resource_events: Vec<(BuiltinId, u64, Option<u64>, &'static str)>,
    obligation_events: Vec<AdapterObligationEvidence>,
    callback_events: Vec<CallbackInvocationEvidence>,
    callback_sequences: HashMap<(Option<u64>, u64), u64>,
    comparator_events: Vec<ComparatorInvocationEvidence>,
    comparator_sequences: HashMap<(Option<u64>, u64), u64>,
    pooled_task_ordinals: HashMap<u64, (BuiltinId, u64)>,
    adapter_sequences: HashMap<Option<u64>, u64>,
    effect_sequences: HashMap<Option<u64>, u64>,
    deferred_adapter_parents: HashMap<usize, AdapterCausalIdentity>,
    resource_ids: HashMap<usize, u64>,
    live_resources: HashSet<u64>,
}

#[cfg(feature = "compat-tracing")]
struct AdapterObligationEvidence {
    builtin: BuiltinId,
    instance_target: Option<Arc<str>>,
    instance_premises: Vec<(Arc<str>, u8)>,
    outcome: &'static str,
    owner_task: Option<u64>,
    sequence: u64,
    parent_sequence: Option<u64>,
    materialized_before: u64,
    materialized_after: u64,
}

#[cfg(feature = "compat-tracing")]
struct ActiveAdapterObligation {
    builtin: BuiltinId,
    instance_target: Option<Arc<str>>,
    instance_premises: Vec<(Arc<str>, u8)>,
    owner_task: Option<u64>,
    sequence: u64,
    parent_sequence: Option<u64>,
    materialized_elements: u64,
}

#[cfg(feature = "compat-tracing")]
#[derive(Clone, Copy, Debug)]
pub struct AdapterCausalIdentity {
    builtin: BuiltinId,
    owner_task: Option<u64>,
    sequence: u64,
}

#[cfg(feature = "compat-tracing")]
#[derive(Clone)]
struct CallbackInvocationIdentity {
    parent: AdapterCausalIdentity,
    invocation: u64,
    callback_argument: u16,
    branch: &'static str,
    arguments: Arc<[ThunkRef]>,
}

#[cfg(feature = "compat-tracing")]
struct CallbackInvocationEvidence {
    identity: CallbackInvocationIdentity,
    outcome: &'static str,
    result: ThunkRef,
}

#[cfg(feature = "compat-tracing")]
struct ComparatorInvocationEvidence {
    parent: AdapterCausalIdentity,
    invocation: u64,
    comparator: BuiltinId,
    child_sequence: u64,
    left: ThunkRef,
    right: ThunkRef,
    outcome: &'static str,
    result: ThunkRef,
}

#[cfg(feature = "compat-tracing")]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct EffectCausalIdentity {
    builtin: BuiltinId,
    owner_task: Option<u64>,
    sequence: u64,
    parent_sequence: Option<u64>,
}

#[cfg(feature = "compat-tracing")]
struct EffectEvidence {
    identity: EffectCausalIdentity,
    lifecycle: &'static str,
}

#[cfg(feature = "compat-tracing")]
struct ForcedArgumentEvidence {
    builtin: BuiltinId,
    argument: usize,
    boundary_class: &'static str,
    thunk: ThunkRef,
    snapshot_outcome: Option<&'static str>,
}

#[cfg(feature = "compat-tracing")]
impl EvidenceTrace {
    fn from_program(program: &ExecutableProgram) -> Self {
        Self {
            parsed_builtins: program.compiler_evidence().parsed.clone(),
            resolved_builtins: program.compiler_evidence().resolved.clone(),
            specialized_builtins: program.compiler_evidence().specialized.clone(),
            typed_result_target: evidence_typed_result_target(),
            ..Self::default()
        }
    }

    fn from_program_and_typed_target(
        program: &ExecutableProgram,
        typed_result_target: Option<BuiltinId>,
    ) -> Self {
        Self {
            typed_result_target: typed_result_target.or_else(evidence_typed_result_target),
            ..Self::from_program(program)
        }
    }
}

#[cfg(feature = "compat-tracing")]
fn evidence_typed_result_target() -> Option<BuiltinId> {
    let raw = std::env::var("HELL_EVIDENCE_TYPED_RESULT_BUILTIN_ID").ok()?;
    let raw = raw.parse::<u16>().ok()?;
    (usize::from(raw) < hell_builtins::registry().len()).then_some(BuiltinId(raw))
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
    #[cfg(feature = "compat-tracing")]
    RestoreAdapterParent {
        parent: Option<AdapterCausalIdentity>,
    },
    #[cfg(feature = "compat-tracing")]
    FinishCallback {
        identity: CallbackInvocationIdentity,
    },
    ProjectTuple {
        arity: u8,
        index: u8,
    },
    RecordGet {
        builtin: BuiltinId,
        layout: Arc<RecordLayout>,
        field_index: u16,
    },
    RecordSet {
        builtin: BuiltinId,
        layout: Arc<RecordLayout>,
        field_index: u16,
        value: ThunkRef,
    },
    RecordModify {
        builtin: BuiltinId,
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
        #[cfg(feature = "compat-tracing")]
        callback_parent: Option<AdapterCausalIdentity>,
    },
    ListMap {
        function: ThunkRef,
        #[cfg(feature = "compat-tracing")]
        callback_parent: Option<AdapterCausalIdentity>,
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
        #[cfg(feature = "compat-tracing")]
        let evidence_trace = std::env::var_os("HELL_EVIDENCE_SEMANTIC_TRACE")
            .map(|_| Arc::new(Mutex::new(EvidenceTrace::from_program(&program))));
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
            #[cfg(feature = "compat-tracing")]
            evidence_trace,
            #[cfg(feature = "compat-tracing")]
            current_evidence_task: None,
            #[cfg(feature = "compat-tracing")]
            adapter_obligation_stack: Vec::new(),
            #[cfg(feature = "compat-tracing")]
            pending_adapter_parent: None,
            #[cfg(feature = "compat-tracing")]
            effect_stack: Vec::new(),
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
        #[cfg(feature = "compat-tracing")]
        let evidence_trace = std::env::var_os("HELL_EVIDENCE_SEMANTIC_TRACE")
            .map(|_| Arc::new(Mutex::new(EvidenceTrace::from_program(&program))));
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
            #[cfg(feature = "compat-tracing")]
            evidence_trace,
            #[cfg(feature = "compat-tracing")]
            current_evidence_task: None,
            #[cfg(feature = "compat-tracing")]
            adapter_obligation_stack: Vec::new(),
            #[cfg(feature = "compat-tracing")]
            pending_adapter_parent: None,
            #[cfg(feature = "compat-tracing")]
            effect_stack: Vec::new(),
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
            #[cfg(feature = "compat-tracing")]
            evidence_trace: self.evidence_trace.clone(),
            #[cfg(feature = "compat-tracing")]
            current_evidence_task: self.current_evidence_task,
            #[cfg(feature = "compat-tracing")]
            adapter_obligation_stack: Vec::new(),
            #[cfg(feature = "compat-tracing")]
            pending_adapter_parent: None,
            #[cfg(feature = "compat-tracing")]
            effect_stack: Vec::new(),
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
                Control::Raise(error) => return self.unwind_machine(&mut stack, error),
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
                    #[cfg(feature = "compat-tracing")]
                    if let Some(parent) = self.pending_adapter_parent {
                        self.register_deferred_adapter_parent(&target, parent)?;
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
        &mut self,
        stack: &mut Vec<Frame>,
        mut error: Arc<RuntimeError>,
    ) -> RuntimeResult<ValueRef> {
        #[cfg(not(feature = "compat-tracing"))]
        std::hint::black_box(self.evaluation_id);
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Update(mut update) => {
                    let result = Err(Arc::clone(&error));
                    if let Err(update_error) = update.store(&result) {
                        error = update_error;
                    }
                }
                #[cfg(feature = "compat-tracing")]
                Frame::RestoreAdapterParent { parent } => {
                    self.pending_adapter_parent = parent;
                }
                #[cfg(feature = "compat-tracing")]
                Frame::FinishCallback { identity } => {
                    self.retain_callback_result(
                        identity,
                        "error",
                        Thunk::failed_without_admission(Arc::clone(&error)),
                    )?;
                }
                _ => {}
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
                    #[cfg(feature = "compat-tracing")]
                    let prior_parent = {
                        let inherited = self
                            .evidence_trace
                            .as_ref()
                            .and_then(|trace| trace.lock().ok())
                            .and_then(|trace| {
                                trace
                                    .deferred_adapter_parents
                                    .get(&(Arc::as_ptr(&current) as usize))
                                    .copied()
                            });
                        let prior = self.pending_adapter_parent;
                        if inherited.is_some() {
                            self.pending_adapter_parent = inherited;
                        }
                        prior
                    };
                    #[cfg(feature = "compat-tracing")]
                    stack.push(Frame::RestoreAdapterParent {
                        parent: prior_parent,
                    });
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
            #[cfg(feature = "compat-tracing")]
            suspension @ Suspension::CallbackApply { .. } => {
                self.enter_callback_suspension(suspension, stack)
            }
            #[cfg(feature = "compat-tracing")]
            Suspension::CallbackForce {
                target,
                parent,
                callback_argument,
                branch,
            } => self.enter_callback_force(target, parent, callback_argument, branch, stack),
            Suspension::Fix {
                function,
                recursive,
            } => {
                let recursive = recursive.upgrade().ok_or_else(|| {
                    RuntimeError::internal("Function.fix recursive thunk was released")
                })?;
                #[cfg(feature = "compat-tracing")]
                {
                    let callback =
                        self.callback_application(function, &[recursive], 0, "recursive")?;
                    Ok(Control::Enter(callback))
                }
                #[cfg(not(feature = "compat-tracing"))]
                {
                    self.push_frame(
                        stack,
                        Frame::Apply {
                            argument: recursive,
                        },
                    )?;
                    Ok(Control::Enter(function))
                }
            }
            Suspension::ListLiteral {
                nodes,
                index,
                environment,
            } => Ok(self.enter_list_literal(nodes, index, environment)),
            Suspension::ListTake { remaining, list } => {
                self.enter_list_take(remaining, list, stack)
            }
            Suspension::ListIterate {
                function,
                current,
                force_current,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            } => self.enter_list_iterate(
                function,
                current,
                force_current,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
                stack,
            ),
            Suspension::ListMap {
                function,
                list,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            } => {
                self.push_frame(
                    stack,
                    Frame::ListMap {
                        function,
                        #[cfg(feature = "compat-tracing")]
                        callback_parent,
                    },
                )?;
                Ok(Control::Enter(list))
            }
            Suspension::ListZip { left, right } => {
                self.push_frame(stack, Frame::ListZipLeft { right })?;
                Ok(Control::Enter(left))
            }
            Suspension::SemigroupAppend { left, right } => {
                self.enter_semigroup_append(left, right, stack)
            }
            Suspension::Native(operation) => operation(self)
                .map(ForceOutcome::Value)
                .map(Control::Return),
        }
    }

    fn enter_list_literal(
        &self,
        nodes: Arc<[CoreId]>,
        index: usize,
        environment: Environment,
    ) -> Control {
        if index >= nodes.len() {
            return Control::Return(ForceOutcome::Value(Arc::new(Value::List(ListCell::Nil))));
        }
        let head = self.expression_thunk(nodes[index], Arc::clone(&environment));
        let tail = Thunk::suspended(Suspension::ListLiteral {
            nodes,
            index: index + 1,
            environment,
        });
        Control::Return(ForceOutcome::Value(Arc::new(Value::List(ListCell::Cons {
            head,
            tail,
        }))))
    }

    fn enter_list_take(
        &mut self,
        remaining: i64,
        list: ThunkRef,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        if remaining <= 0 {
            return Ok(Control::Return(ForceOutcome::Value(Arc::new(Value::List(
                ListCell::Nil,
            )))));
        }
        self.push_frame(stack, Frame::ListTake { remaining })?;
        Ok(Control::Enter(list))
    }

    fn enter_list_iterate(
        &mut self,
        function: ThunkRef,
        current: ThunkRef,
        force_current: bool,
        #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        if !force_current {
            return Ok(Control::Return(ForceOutcome::Value(Self::iterate_cell(
                function,
                current,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            ))));
        }
        self.push_frame(
            stack,
            Frame::ListIterateCurrent {
                function,
                current: Arc::clone(&current),
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            },
        )?;
        Ok(Control::Enter(current))
    }

    fn enter_semigroup_append(
        &mut self,
        left: ThunkRef,
        right: ThunkRef,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        self.push_frame(
            stack,
            Frame::SemigroupLeft {
                left: Arc::clone(&left),
                right,
            },
        )?;
        Ok(Control::Enter(left))
    }

    #[cfg(feature = "compat-tracing")]
    fn enter_callback_suspension(
        &mut self,
        suspension: Suspension,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        let Suspension::CallbackApply {
            function,
            argument,
            parent,
            callback_argument,
            branch,
            evidence_arguments,
            logical_invocation,
            logical_task,
        } = suspension
        else {
            unreachable!("callback suspension helper received a different variant")
        };
        self.enter_callback_apply(
            CallbackApplication {
                function,
                argument,
                parent,
                callback_argument,
                branch,
                evidence_arguments,
                logical_invocation,
                logical_task,
            },
            stack,
        )
    }

    #[cfg(feature = "compat-tracing")]
    fn enter_callback_apply(
        &mut self,
        callback: CallbackApplication,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        let identity = self.begin_callback(
            callback.parent,
            callback.callback_argument,
            callback.branch,
            callback.evidence_arguments,
            callback.logical_invocation,
            callback.logical_task,
        )?;
        self.push_frame(stack, Frame::FinishCallback { identity })?;
        self.push_frame(
            stack,
            Frame::Apply {
                argument: callback.argument,
            },
        )?;
        Ok(Control::Enter(callback.function))
    }

    #[cfg(feature = "compat-tracing")]
    fn enter_callback_force(
        &mut self,
        target: ThunkRef,
        parent: AdapterCausalIdentity,
        callback_argument: u16,
        branch: &'static str,
        stack: &mut Vec<Frame>,
    ) -> RuntimeResult<Control> {
        let identity =
            self.begin_callback(parent, callback_argument, branch, Arc::from([]), None, None)?;
        self.push_frame(stack, Frame::FinishCallback { identity })?;
        Ok(Control::Enter(target))
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
            CoreKind::Tuple { elements } => {
                let values = elements
                    .iter()
                    .map(|child| self.expression_thunk(*child, Arc::clone(&environment)))
                    .collect::<Vec<_>>();
                let builtin_name = match values.len() {
                    2 => Some("Tuple.(,)"),
                    3 => Some("Tuple.(,,)"),
                    4 => Some("Tuple.(,,,)"),
                    _ => None,
                };
                let outcome = ForceOutcome::Value(Arc::new(Value::Tuple(values.clone().into())));
                let Some(builtin_name) = builtin_name else {
                    return Ok(Control::Return(outcome));
                };
                let builtin = hell_builtins::lookup(builtin_name)
                    .expect("tuple constructor is registry-backed")
                    .id;
                #[cfg(feature = "compat-tracing")]
                self.begin_adapter_obligation(builtin, None)?;
                #[cfg(feature = "compat-tracing")]
                for (argument, value) in values.iter().enumerate() {
                    self.retain_specialized_forced_argument(builtin, argument, value)?;
                }
                #[cfg(feature = "compat-tracing")]
                self.record_lazy_argument_exit_states(builtin, &values)?;
                self.finish_native_outcome(builtin, Ok(outcome))
                    .map(Control::Return)
            }
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
                let builtin = hell_builtins::lookup("Record.get")
                    .expect("Record.get is registry-backed")
                    .id;
                #[cfg(feature = "compat-tracing")]
                self.begin_adapter_obligation(builtin, None)?;
                let record = self.expression_thunk(record, environment);
                #[cfg(feature = "compat-tracing")]
                self.retain_specialized_forced_argument(builtin, 0, &record)?;
                self.push_frame(
                    stack,
                    Frame::RecordGet {
                        builtin,
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
                let builtin = hell_builtins::lookup("Record.set")
                    .expect("Record.set is registry-backed")
                    .id;
                #[cfg(feature = "compat-tracing")]
                self.begin_adapter_obligation(builtin, None)?;
                let record = self.expression_thunk(record, Arc::clone(&environment));
                #[cfg(feature = "compat-tracing")]
                self.retain_specialized_forced_argument(builtin, 1, &record)?;
                let value = self.expression_thunk(value, environment);
                #[cfg(feature = "compat-tracing")]
                self.retain_specialized_forced_argument(builtin, 0, &value)?;
                self.push_frame(
                    stack,
                    Frame::RecordSet {
                        builtin,
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
                let builtin = hell_builtins::lookup("Record.modify")
                    .expect("Record.modify is registry-backed")
                    .id;
                #[cfg(feature = "compat-tracing")]
                self.begin_adapter_obligation(builtin, None)?;
                let record = self.expression_thunk(record, Arc::clone(&environment));
                #[cfg(feature = "compat-tracing")]
                self.retain_specialized_forced_argument(builtin, 1, &record)?;
                let function = self.expression_thunk(function, environment);
                #[cfg(feature = "compat-tracing")]
                self.retain_specialized_forced_argument(builtin, 0, &function)?;
                self.push_frame(
                    stack,
                    Frame::RecordModify {
                        builtin,
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
                #[cfg(feature = "compat-tracing")]
                if let Some(parent) = self.pending_adapter_parent {
                    for child in evidence_value_children(&value) {
                        self.register_deferred_adapter_parent(child, parent)?;
                    }
                }
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
            #[cfg(feature = "compat-tracing")]
            Frame::RestoreAdapterParent { parent } => {
                self.pending_adapter_parent = parent;
                Ok(Control::Return(ForceOutcome::Value(value)))
            }
            #[cfg(feature = "compat-tracing")]
            Frame::FinishCallback { identity } => {
                self.retain_callback_result(identity, "value", Thunk::evaluated((*value).clone()))?;
                Ok(Control::Return(ForceOutcome::Value(value)))
            }
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
                builtin,
                layout,
                field_index,
            } => {
                let outcome = (|| {
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
                    Ok(ForceOutcome::Alias(Arc::clone(field)))
                })();
                self.finish_native_outcome(builtin, outcome)
                    .map(Control::Return)
            }
            Frame::RecordSet {
                builtin,
                layout,
                field_index,
                value: replacement,
            } => {
                let outcome = (|| {
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
                    Ok(ForceOutcome::Value(Arc::new(Value::Record {
                        layout: Arc::clone(actual_layout),
                        fields: updated.into(),
                    })))
                })();
                self.finish_native_outcome(builtin, outcome)
                    .map(Control::Return)
            }
            Frame::RecordModify {
                builtin,
                layout,
                field_index,
                function,
            } => {
                let outcome = (|| {
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
                    #[cfg(feature = "compat-tracing")]
                    let modified =
                        self.callback_application(function, &[Arc::clone(field)], 0, "field")?;
                    #[cfg(not(feature = "compat-tracing"))]
                    let modified = Thunk::suspended(Suspension::Apply {
                        function,
                        argument: Arc::clone(field),
                    });
                    *field = modified;
                    Ok(ForceOutcome::Value(Arc::new(Value::Record {
                        layout: Arc::clone(actual_layout),
                        fields: updated.into(),
                    })))
                })();
                self.finish_native_outcome(builtin, outcome)
                    .map(Control::Return)
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
            Frame::ListIterateCurrent {
                function,
                current,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            } => Ok(Control::Return(ForceOutcome::Value(Self::iterate_cell(
                function,
                current,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            )))),
            Frame::ListMap {
                function,
                #[cfg(feature = "compat-tracing")]
                callback_parent,
            } => match value.as_ref() {
                Value::List(ListCell::Nil) => Ok(Control::Return(ForceOutcome::Value(Arc::new(
                    Value::List(ListCell::Nil),
                )))),
                Value::List(ListCell::Cons { head, tail }) => {
                    #[cfg(feature = "compat-tracing")]
                    let mapped = Self::callback_application_for_optional_parent(
                        callback_parent,
                        Arc::clone(&function),
                        &[Arc::clone(head)],
                        0,
                        "element",
                    );
                    #[cfg(not(feature = "compat-tracing"))]
                    let mapped = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&function),
                        argument: Arc::clone(head),
                    });
                    let mapped_tail = Thunk::suspended(Suspension::ListMap {
                        function,
                        list: Arc::clone(tail),
                        #[cfg(feature = "compat-tracing")]
                        callback_parent,
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
        #[cfg(feature = "compat-tracing")]
        if next_demand > 0 {
            let position = next_demand - 1;
            let index = if reverse_binary {
                arguments.len() - position - 1
            } else {
                position
            };
            let boundary_class = match spec.demand[index] {
                hell_builtins::Demand::Whnf => Some("whnf-force-complete"),
                hell_builtins::Demand::Conditional => Some("conditional-force-complete"),
                hell_builtins::Demand::Deep
                | hell_builtins::Demand::Lazy
                | hell_builtins::Demand::OnIoExecution => None,
            };
            if let Some(boundary_class) = boundary_class {
                self.record_argument_snapshot(builtin, index, boundary_class, &arguments[index])?;
            }
        }
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

    fn iterate_cell(
        function: ThunkRef,
        current: ThunkRef,
        #[cfg(feature = "compat-tracing")] callback_parent: Option<AdapterCausalIdentity>,
    ) -> ValueRef {
        #[cfg(feature = "compat-tracing")]
        let next = Self::callback_application_for_optional_parent(
            callback_parent,
            Arc::clone(&function),
            &[Arc::clone(&current)],
            0,
            "element",
        );
        #[cfg(not(feature = "compat-tracing"))]
        let next = Thunk::suspended(Suspension::Apply {
            function: Arc::clone(&function),
            argument: Arc::clone(&current),
        });
        let tail = Thunk::suspended(Suspension::ListIterate {
            function,
            current: next,
            force_current: true,
            #[cfg(feature = "compat-tracing")]
            callback_parent,
        });
        Arc::new(Value::List(ListCell::Cons {
            head: current,
            tail,
        }))
    }

    fn apply_native(
        &mut self,
        builtin: BuiltinId,
        arguments: &[ThunkRef],
        evidence: Option<ClassEvidence>,
    ) -> RuntimeResult<ForceOutcome> {
        #[cfg(feature = "compat-tracing")]
        let instance_evidence = evidence
            .map(|evidence| typeclasses::retained_instance_evidence(self, evidence))
            .transpose()?;
        #[cfg(feature = "compat-tracing")]
        self.begin_adapter_obligation(builtin, instance_evidence)?;
        #[cfg(feature = "compat-tracing")]
        self.record_lazy_argument_entry_states(builtin, arguments)?;
        let outcome = self.apply_native_inner(builtin, arguments, evidence);
        #[cfg(feature = "compat-tracing")]
        let outcome = Self::attach_io_execution_argument_evidence(builtin, arguments, outcome);
        #[cfg(feature = "compat-tracing")]
        self.record_lazy_argument_exit_states(builtin, arguments)?;
        self.finish_native_outcome(builtin, outcome)
    }

    #[cfg(feature = "compat-tracing")]
    fn attach_io_execution_argument_evidence(
        builtin: BuiltinId,
        arguments: &[ThunkRef],
        outcome: RuntimeResult<ForceOutcome>,
    ) -> RuntimeResult<ForceOutcome> {
        let evidence_arguments = hell_builtins::registry()[usize::from(builtin.0)]
            .demand
            .iter()
            .zip(arguments)
            .enumerate()
            .filter(|(_, (demand, _))| **demand == hell_builtins::Demand::OnIoExecution)
            .map(|(index, (_, argument))| (index, Arc::clone(argument)))
            .collect::<Vec<_>>();
        if evidence_arguments.is_empty() {
            return outcome;
        }
        match outcome {
            Ok(ForceOutcome::Value(value)) => match value.as_ref() {
                Value::Io(action) => Ok(ForceOutcome::Value(Arc::new(Value::Io(
                    action.clone().with_evidence_arguments(evidence_arguments),
                )))),
                _ => Ok(ForceOutcome::Value(value)),
            },
            other => other,
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn begin_adapter_obligation(
        &mut self,
        builtin: BuiltinId,
        instance_evidence: Option<typeclasses::RetainedInstanceEvidence>,
    ) -> RuntimeResult<()> {
        if let Some(trace) = &self.evidence_trace {
            let owner_task = self.current_evidence_task;
            let mut trace = trace
                .lock()
                .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
            let sequence = trace.adapter_sequences.entry(owner_task).or_default();
            *sequence = sequence.saturating_add(1);
            let sequence = *sequence;
            drop(trace);
            let stack_parent = self
                .adapter_obligation_stack
                .last()
                .map(|parent| parent.sequence);
            let inherited_parent = self
                .pending_adapter_parent
                .take()
                .filter(|parent| parent.owner_task == owner_task)
                .map(|parent| parent.sequence);
            let parent_sequence = stack_parent.or(inherited_parent);
            self.adapter_obligation_stack.push(ActiveAdapterObligation {
                builtin,
                instance_target: instance_evidence
                    .as_ref()
                    .map(|evidence| Arc::clone(&evidence.target)),
                instance_premises: instance_evidence
                    .map_or_else(Vec::new, |evidence| evidence.premises),
                owner_task,
                sequence,
                parent_sequence,
                materialized_elements: 0,
            });
        }
        if let Some(trace) = &self.evidence_trace {
            let mut trace = trace
                .lock()
                .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
            trace.entered_adapters.push(builtin);
        }
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn retain_specialized_forced_argument(
        &self,
        builtin: BuiltinId,
        argument: usize,
        thunk: &ThunkRef,
    ) -> RuntimeResult<()> {
        if let Some(trace) = &self.evidence_trace {
            trace
                .lock()
                .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?
                .forced_arguments
                .push(ForcedArgumentEvidence {
                    builtin,
                    argument,
                    boundary_class: "lazy-adapter-entry",
                    thunk: Arc::clone(thunk),
                    snapshot_outcome: Some(evidence_thunk_outcome(thunk).0),
                });
        }
        Ok(())
    }

    #[allow(clippy::float_cmp, clippy::too_many_lines)]
    fn apply_native_inner(
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
        if let Some(result) =
            native_collections::apply_native(implementation, arguments, evidence, self)
        {
            return result;
        }
        let value = |value| Ok(ForceOutcome::Value(Arc::new(value)));
        match implementation {
            "bool_false" => value(Value::Bool(false)),
            "bool_true" => value(Value::Bool(true)),
            "bool_not" => value(Value::Bool(!self.force_bool(&arguments[0])?)),
            "bool_choose" => {
                let selected = usize::from(self.force_bool(&arguments[2])?);
                #[cfg(feature = "compat-tracing")]
                for (index, argument) in arguments[..2].iter().enumerate() {
                    self.record_forced_argument(builtin, index, "conditional-branch", argument)?;
                }
                if semantic_mutant_active("strictness-force-both-branches") {
                    self.force(&arguments[0])?;
                    self.force(&arguments[1])?;
                }
                #[cfg(feature = "compat-tracing")]
                self.record_typed_result(
                    builtin,
                    selected,
                    "conditional-selected",
                    &arguments[selected],
                )?;
                Ok(ForceOutcome::Alias(Arc::clone(&arguments[selected])))
            }
            "identity" => Ok(ForceOutcome::Alias(Arc::clone(&arguments[0]))),
            "apply" => {
                #[cfg(feature = "compat-tracing")]
                {
                    if self.evidence_trace.is_some() {
                        self.callback_application(
                            Arc::clone(&arguments[0]),
                            &[Arc::clone(&arguments[1])],
                            0,
                            "function",
                        )
                        .map(ForceOutcome::Alias)
                    } else {
                        Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                            function: Arc::clone(&arguments[0]),
                            argument: Arc::clone(&arguments[1]),
                        })))
                    }
                }
                #[cfg(not(feature = "compat-tracing"))]
                {
                    Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&arguments[0]),
                        argument: Arc::clone(&arguments[1]),
                    })))
                }
            }
            "fix" => Ok(ForceOutcome::Alias(Thunk::fixed(Arc::clone(&arguments[0])))),
            "error" => Err(RuntimeError::user(self.force_text(&arguments[0])?)),
            "int_eq" => {
                let left = self.force_int(&arguments[0])?;
                let right = self.force_int(&arguments[1])?;
                value(Value::Bool(
                    semantic_mutant_active("int-equality-constant-true") || left == right,
                ))
            }
            "eq" => {
                let equal = self.equal_values(&arguments[0], &arguments[1])?;
                value(Value::Bool(
                    semantic_mutant_active("generic-equality-constant-true") || equal,
                ))
            }
            "ord_lt" => {
                let less = self.less_values(&arguments[0], &arguments[1])?;
                value(Value::Bool(
                    semantic_mutant_active("ordering-comparator-constant-true") || less,
                ))
            }
            "ord_gt" => {
                let greater = self.less_values(&arguments[1], &arguments[0])?;
                value(Value::Bool(
                    semantic_mutant_active("ordering-comparator-constant-true") || greater,
                ))
            }
            "int_plus" => value(Value::Int(
                self.force_int(&arguments[0])?
                    .wrapping_add(self.force_int(&arguments[1])?),
            )),
            "int_subtract" => value(Value::Int(
                if semantic_mutant_active("numeric-operand-order-overflow") {
                    self.force_int(&arguments[0])?
                        .wrapping_sub(self.force_int(&arguments[1])?)
                } else {
                    self.force_int(&arguments[1])?
                        .wrapping_sub(self.force_int(&arguments[0])?)
                },
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
            "double_eq" => {
                let left = self.force_double(&arguments[0])?;
                let right = self.force_double(&arguments[1])?;
                value(Value::Bool(
                    semantic_mutant_active("double-equality-constant-true") || left == right,
                ))
            }
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
            "text_eq" => {
                let left = self.force_text(&arguments[0])?;
                let right = self.force_text(&arguments[1])?;
                value(Value::Bool(
                    semantic_mutant_active("text-equality-constant-true") || left == right,
                ))
            }
            "text_all" => {
                let predicate = Arc::clone(&arguments[0]);
                let text = self.force_text(&arguments[1])?;
                for character in text.chars() {
                    #[cfg(feature = "compat-tracing")]
                    let application = self.callback_application(
                        Arc::clone(&predicate),
                        &[Thunk::evaluated(Value::Character(character))],
                        0,
                        "predicate",
                    )?;
                    #[cfg(not(feature = "compat-tracing"))]
                    let application = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&predicate),
                        argument: Thunk::evaluated(Value::Character(character)),
                    });
                    if !self.force_bool(&application)? {
                        return value(Value::Bool(semantic_mutant_active("all-constant-true")));
                    }
                }
                value(Value::Bool(true))
            }
            "text_any" => {
                let predicate = Arc::clone(&arguments[0]);
                let text = self.force_text(&arguments[1])?;
                for character in text.chars() {
                    #[cfg(feature = "compat-tracing")]
                    let application = self.callback_application(
                        Arc::clone(&predicate),
                        &[Thunk::evaluated(Value::Character(character))],
                        0,
                        "predicate",
                    )?;
                    #[cfg(not(feature = "compat-tracing"))]
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
                    #[cfg(feature = "compat-tracing")]
                    let application = self.callback_application(
                        Arc::clone(&predicate),
                        &[Thunk::evaluated(Value::Character(character))],
                        0,
                        "predicate",
                    )?;
                    #[cfg(not(feature = "compat-tracing"))]
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
                if semantic_mutant_active("io-pure-force-argument") {
                    self.force(&arguments[0])?;
                }
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
            "thread_delay" => value(Value::Io(concurrency::thread_delay(
                builtin,
                Arc::clone(&arguments[0]),
            ))),
            "timeout" => value(Value::Io(concurrency::timeout(
                builtin,
                Arc::clone(&arguments[0]),
                Arc::clone(&arguments[1]),
            ))),
            "async_concurrently" => value(Value::Io(concurrency::concurrently(
                builtin,
                Arc::clone(&arguments[0]),
                Arc::clone(&arguments[1]),
            ))),
            "async_race" => value(Value::Io(concurrency::race(
                builtin,
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
                #[cfg(feature = "compat-tracing")]
                let callback_parent = self.active_adapter_identity_optional()?;
                value(Value::Io(concurrency::pooled(
                    builtin,
                    callback,
                    list,
                    implementation.ends_with('_'),
                    u16::from(matches!(
                        implementation,
                        "async_pooled_for" | "async_pooled_for_"
                    )),
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
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
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_resource_event(
                        builtin,
                        Arc::as_ptr(&handle) as usize,
                        "acquire",
                    )?;
                    Ok(Thunk::evaluated(Value::Handle(HostHandle::File {
                        handle,
                        close_after_process: false,
                        process_close_builtin: None,
                    })))
                })))
            }
            "io_h_close" => {
                let handle = Arc::clone(&arguments[0]);
                value(Value::Io(IoAction::new(move |evaluator, _context| {
                    match evaluator.force_handle(&handle)? {
                        HostHandle::File { handle, .. } => {
                            handle
                                .close()
                                .map_err(|error| RuntimeContext::io_error("IO.hClose", error))?;
                            #[cfg(feature = "compat-tracing")]
                            evaluator.record_resource_event(
                                builtin,
                                Arc::as_ptr(&handle) as usize,
                                "close",
                            )?;
                        }
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
                    #[cfg(feature = "compat-tracing")]
                    let resource_key = Arc::as_ptr(&resource.0) as usize;
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_resource_event(builtin, resource_key, "acquire")?;
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
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_resource_event(
                        builtin,
                        resource_key,
                        if cleanup.is_ok() {
                            "close"
                        } else {
                            "cleanup-failure"
                        },
                    )?;
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
                    #[cfg(feature = "compat-tracing")]
                    let handle_key = Arc::as_ptr(&handle) as usize;
                    #[cfg(feature = "compat-tracing")]
                    let resource_key = Arc::as_ptr(&resource.0) as usize;
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_resource_event(builtin, handle_key, "acquire")?;
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_resource_event(builtin, resource_key, "acquire")?;
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
                            process_close_builtin: None,
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
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_resource_event(
                        builtin,
                        handle_key,
                        if close.is_ok() {
                            "close"
                        } else {
                            "cleanup-failure"
                        },
                    )?;
                    #[cfg(feature = "compat-tracing")]
                    evaluator.record_resource_event(
                        builtin,
                        resource_key,
                        if cleanup.is_ok() {
                            "close"
                        } else {
                            "cleanup-failure"
                        },
                    )?;
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
                    let mut input = context.read_stdin_all("ByteString.interact")?;
                    if semantic_mutant_active("text-invalid-utf8-handling") {
                        input = String::from_utf8_lossy(&input).into_owned().into_bytes();
                    }
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
                    (implementation == "process_use_handle_close").then_some(builtin.0),
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
                    );
                    #[cfg(feature = "compat-tracing")]
                    record_closed_process_handle_events(evaluator, builtin, process.as_ref())?;
                    let output = output?;
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
                    );
                    #[cfg(feature = "compat-tracing")]
                    record_closed_process_handle_events(evaluator, builtin, process.as_ref())?;
                    let output = output?;
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
            "list_iterate" => {
                #[cfg(feature = "compat-tracing")]
                let callback_parent = self.active_adapter_identity_optional()?;
                Ok(ForceOutcome::Alias(Thunk::suspended(
                    Suspension::ListIterate {
                        function: Arc::clone(&arguments[0]),
                        current: Arc::clone(&arguments[1]),
                        force_current: false,
                        #[cfg(feature = "compat-tracing")]
                        callback_parent,
                    },
                )))
            }
            "list_map" => {
                #[cfg(feature = "compat-tracing")]
                let callback_parent = self.active_adapter_identity_optional()?;
                Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::ListMap {
                    function: Arc::clone(&arguments[0]),
                    list: Arc::clone(&arguments[1]),
                    #[cfg(feature = "compat-tracing")]
                    callback_parent,
                })))
            }
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
                            #[cfg(feature = "compat-tracing")]
                            let second = self.callback_application(
                                Arc::clone(&function),
                                &[Arc::clone(&accumulator), Arc::clone(head)],
                                0,
                                "fold",
                            )?;
                            #[cfg(not(feature = "compat-tracing"))]
                            let first = Thunk::suspended(Suspension::Apply {
                                function: Arc::clone(&function),
                                argument: accumulator,
                            });
                            #[cfg(not(feature = "compat-tracing"))]
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
                Value::Maybe(None) => {
                    #[cfg(feature = "compat-tracing")]
                    let selected =
                        self.callback_application(Arc::clone(&arguments[0]), &[], 0, "nothing")?;
                    #[cfg(not(feature = "compat-tracing"))]
                    let selected = Arc::clone(&arguments[0]);
                    Ok(ForceOutcome::Alias(selected))
                }
                Value::Maybe(Some(payload)) => {
                    #[cfg(feature = "compat-tracing")]
                    let application = self.callback_application(
                        Arc::clone(&arguments[1]),
                        std::slice::from_ref(payload),
                        1,
                        "just",
                    )?;
                    #[cfg(not(feature = "compat-tracing"))]
                    let application = Thunk::suspended(Suspension::Apply {
                        function: Arc::clone(&arguments[1]),
                        argument: Arc::clone(payload),
                    });
                    Ok(ForceOutcome::Alias(application))
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
                #[cfg(feature = "compat-tracing")]
                let callback_argument = u16::from(implementation != "io_map_m_");
                let (callback, list) = if implementation == "io_map_m_" {
                    (Arc::clone(&arguments[0]), Arc::clone(&arguments[1]))
                } else {
                    (Arc::clone(&arguments[1]), Arc::clone(&arguments[0]))
                };
                #[cfg(feature = "compat-tracing")]
                let callback_parent = self.active_adapter_identity_optional()?;
                value(Value::Io(IoAction::new(move |evaluator, context| {
                    let mut current = Arc::clone(&list);
                    loop {
                        match evaluator.force(&current)?.as_ref() {
                            Value::List(ListCell::Nil) => {
                                return Ok(Thunk::evaluated(Value::Unit));
                            }
                            Value::List(ListCell::Cons { head, tail }) => {
                                #[cfg(feature = "compat-tracing")]
                                let application = Self::callback_application_for_optional_parent(
                                    callback_parent,
                                    Arc::clone(&callback),
                                    &[Arc::clone(head)],
                                    callback_argument,
                                    "element",
                                );
                                #[cfg(not(feature = "compat-tracing"))]
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
                #[cfg(feature = "compat-tracing")]
                {
                    if self.evidence_trace.is_some() {
                        let parent = self.active_adapter_identity()?;
                        let intermediate = Self::callback_application_for_parent(
                            parent,
                            inner,
                            &[input],
                            1,
                            "inner",
                        );
                        Ok(ForceOutcome::Alias(Self::callback_application_for_parent(
                            parent,
                            outer,
                            &[intermediate],
                            0,
                            "outer",
                        )))
                    } else {
                        let intermediate = Thunk::suspended(Suspension::Apply {
                            function: inner,
                            argument: input,
                        });
                        Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                            function: outer,
                            argument: intermediate,
                        })))
                    }
                }
                #[cfg(not(feature = "compat-tracing"))]
                {
                    let intermediate = Thunk::suspended(Suspension::Apply {
                        function: inner,
                        argument: input,
                    });
                    Ok(ForceOutcome::Alias(Thunk::suspended(Suspension::Apply {
                        function: outer,
                        argument: intermediate,
                    })))
                }
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

    fn finish_native_outcome(
        &mut self,
        builtin: BuiltinId,
        outcome: RuntimeResult<ForceOutcome>,
    ) -> RuntimeResult<ForceOutcome> {
        #[cfg(not(feature = "compat-tracing"))]
        std::hint::black_box(self.evaluation_id);
        #[cfg(feature = "compat-tracing")]
        if let Some(trace) = &self.evidence_trace {
            let active = self.adapter_obligation_stack.pop().ok_or_else(|| {
                RuntimeError::internal("semantic adapter outcome has no active invocation")
            })?;
            if active.builtin != builtin {
                return Err(RuntimeError::internal(
                    "semantic adapter outcome does not match its active invocation",
                ));
            }
            if let Ok(ForceOutcome::Alias(target)) = &outcome {
                let mut trace = trace
                    .lock()
                    .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
                trace.deferred_adapter_parents.insert(
                    Arc::as_ptr(target) as usize,
                    AdapterCausalIdentity {
                        builtin,
                        owner_task: active.owner_task,
                        sequence: active.sequence,
                    },
                );
                drop(trace);
            }
            if let Ok(ForceOutcome::Value(value)) = &outcome {
                let identity = AdapterCausalIdentity {
                    builtin,
                    owner_task: active.owner_task,
                    sequence: active.sequence,
                };
                let mut trace = trace
                    .lock()
                    .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
                for child in evidence_value_children(value) {
                    trace
                        .deferred_adapter_parents
                        .insert(Arc::as_ptr(child) as usize, identity);
                }
                drop(trace);
            }
            let mut trace = trace
                .lock()
                .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
            let metadata = hell_builtins::registry()[usize::from(builtin.0)].assurance_metadata();
            if metadata
                .sensitivities
                .contains(&hell_builtins::AssuranceSensitivity::Presentation)
            {
                trace.presentation_fields.push((builtin, "rendered-output"));
            }
            if trace.typed_result_target == Some(builtin) {
                trace.typed_result_target_invocations =
                    trace.typed_result_target_invocations.saturating_add(1);
                if trace.typed_results.is_empty() {
                    let retained = match &outcome {
                        Ok(ForceOutcome::Value(value)) => {
                            Thunk::allocate(ThunkState::Evaluated(Arc::clone(value)))
                        }
                        Ok(ForceOutcome::Alias(target)) => Arc::clone(target),
                        Err(error) => Thunk::failed_without_admission(Arc::clone(error)),
                    };
                    trace
                        .typed_results
                        .push((builtin, 0, "adapter-result", retained));
                }
            }
            let outcome_name = match &outcome {
                Ok(ForceOutcome::Value(value)) if matches!(value.as_ref(), Value::Io(_)) => {
                    "io-action"
                }
                Ok(ForceOutcome::Value(_)) => "value",
                Ok(ForceOutcome::Alias(_)) => "alias",
                Err(_) => "error",
            };
            trace.obligation_events.push(AdapterObligationEvidence {
                builtin,
                instance_target: active.instance_target,
                instance_premises: active.instance_premises,
                outcome: outcome_name,
                owner_task: active.owner_task,
                sequence: active.sequence,
                parent_sequence: active.parent_sequence,
                materialized_before: 0,
                materialized_after: active.materialized_elements,
            });
        }
        outcome.map(|outcome| outcome.with_evidence_builtin(builtin))
    }

    #[cfg(feature = "compat-tracing")]
    fn register_deferred_adapter_parent(
        &self,
        thunk: &ThunkRef,
        parent: AdapterCausalIdentity,
    ) -> RuntimeResult<()> {
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?
            .deferred_adapter_parents
            .insert(Arc::as_ptr(thunk) as usize, parent);
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn register_current_adapter_child(&self, thunk: &ThunkRef) -> RuntimeResult<()> {
        if self.evidence_trace.is_none() {
            return Ok(());
        }
        let parent = self
            .adapter_obligation_stack
            .last()
            .map(|active| AdapterCausalIdentity {
                builtin: active.builtin,
                owner_task: active.owner_task,
                sequence: active.sequence,
            })
            .or(self.pending_adapter_parent)
            .ok_or_else(|| RuntimeError::internal("deferred child has no logical adapter"))?;
        self.register_deferred_adapter_parent(thunk, parent)
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn active_adapter_identity(&self) -> RuntimeResult<AdapterCausalIdentity> {
        self.active_adapter_identity_optional()?
            .ok_or_else(|| RuntimeError::internal("callback has no active target adapter"))
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn active_adapter_identity_optional(
        &self,
    ) -> RuntimeResult<Option<AdapterCausalIdentity>> {
        let identity = self
            .adapter_obligation_stack
            .last()
            .map(|active| AdapterCausalIdentity {
                builtin: active.builtin,
                owner_task: active.owner_task,
                sequence: active.sequence,
            });
        if identity.is_none() && self.evidence_trace.is_some() {
            return Err(RuntimeError::internal(
                "callback has no active target adapter",
            ));
        }
        Ok(identity)
    }

    #[cfg(feature = "compat-tracing")]
    fn callback_application(
        &self,
        function: ThunkRef,
        arguments: &[ThunkRef],
        callback_argument: u16,
        branch: &'static str,
    ) -> RuntimeResult<ThunkRef> {
        let parent = self
            .adapter_obligation_stack
            .last()
            .map(|active| AdapterCausalIdentity {
                builtin: active.builtin,
                owner_task: active.owner_task,
                sequence: active.sequence,
            })
            .or(self.pending_adapter_parent);
        if parent.is_none() && self.evidence_trace.is_some() {
            return Err(RuntimeError::internal(
                "callback has no logical target adapter",
            ));
        }
        Ok(Self::callback_application_for_optional_parent(
            parent,
            function,
            arguments,
            callback_argument,
            branch,
        ))
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn callback_application_for_parent(
        parent: AdapterCausalIdentity,
        function: ThunkRef,
        arguments: &[ThunkRef],
        callback_argument: u16,
        branch: &'static str,
    ) -> ThunkRef {
        let evidence_arguments = Arc::<[ThunkRef]>::from(arguments.to_vec());
        let Some((last, prefix)) = arguments.split_last() else {
            return Thunk::suspended(Suspension::CallbackForce {
                target: function,
                parent,
                callback_argument,
                branch,
            });
        };
        let function = prefix.iter().fold(function, |function, argument| {
            Thunk::suspended(Suspension::Apply {
                function,
                argument: Arc::clone(argument),
            })
        });
        Thunk::suspended(Suspension::CallbackApply {
            function,
            argument: Arc::clone(last),
            parent,
            callback_argument,
            branch,
            evidence_arguments,
            logical_invocation: None,
            logical_task: None,
        })
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn pooled_callback_application(
        parent: Option<AdapterCausalIdentity>,
        function: ThunkRef,
        argument: ThunkRef,
        callback_argument: u16,
        logical_invocation: u64,
        logical_task: u64,
    ) -> ThunkRef {
        match parent {
            None => Thunk::suspended(Suspension::Apply { function, argument }),
            Some(parent) => Thunk::suspended(Suspension::CallbackApply {
                function,
                argument: Arc::clone(&argument),
                parent,
                callback_argument,
                branch: "element",
                evidence_arguments: Arc::from([argument]),
                logical_invocation: Some(logical_invocation),
                logical_task: Some(logical_task),
            }),
        }
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn callback_application_for_optional_parent(
        parent: Option<AdapterCausalIdentity>,
        function: ThunkRef,
        arguments: &[ThunkRef],
        callback_argument: u16,
        branch: &'static str,
    ) -> ThunkRef {
        match parent {
            None => arguments.iter().fold(function, |function, argument| {
                Thunk::suspended(Suspension::Apply {
                    function,
                    argument: Arc::clone(argument),
                })
            }),
            Some(parent) => Self::callback_application_for_parent(
                parent,
                function,
                arguments,
                callback_argument,
                branch,
            ),
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn begin_callback(
        &self,
        parent: AdapterCausalIdentity,
        callback_argument: u16,
        branch: &'static str,
        arguments: Arc<[ThunkRef]>,
        logical_invocation: Option<u64>,
        logical_task: Option<u64>,
    ) -> RuntimeResult<CallbackInvocationIdentity> {
        let Some(trace) = &self.evidence_trace else {
            return Err(RuntimeError::internal(
                "callback evidence suspension has no semantic trace",
            ));
        };
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        let invocation = match (logical_invocation, logical_task) {
            (Some(invocation), Some(task)) => {
                if invocation == 0
                    || self.current_evidence_task != Some(task)
                    || trace.pooled_task_ordinals.get(&task) != Some(&(parent.builtin, invocation))
                {
                    return Err(RuntimeError::internal(
                        "pooled callback ordinal does not match its logical input task",
                    ));
                }
                invocation
            }
            (None, None) => {
                let sequence = trace
                    .callback_sequences
                    .entry((parent.owner_task, parent.sequence))
                    .or_default();
                *sequence = sequence.saturating_add(1);
                *sequence
            }
            _ => {
                return Err(RuntimeError::internal(
                    "callback logical ordinal and task are incomplete",
                ));
            }
        };
        Ok(CallbackInvocationIdentity {
            parent,
            invocation,
            callback_argument,
            branch,
            arguments,
        })
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn register_pooled_task_ordinal(
        &self,
        builtin: BuiltinId,
        task: u64,
        ordinal: u64,
    ) -> RuntimeResult<()> {
        if task == 0 || ordinal == 0 {
            return Ok(());
        }
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        if trace
            .pooled_task_ordinals
            .insert(task, (builtin, ordinal))
            .is_some()
            || trace
                .pooled_task_ordinals
                .iter()
                .any(|(other_task, identity)| {
                    *other_task != task && *identity == (builtin, ordinal)
                })
        {
            return Err(RuntimeError::internal(
                "pooled task ordinal is duplicated or substituted",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn retain_callback_result(
        &self,
        identity: CallbackInvocationIdentity,
        outcome: &'static str,
        result: ThunkRef,
    ) -> RuntimeResult<()> {
        let Some(trace) = &self.evidence_trace else {
            return Err(RuntimeError::internal(
                "callback result has no semantic trace",
            ));
        };
        trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?
            .callback_events
            .push(CallbackInvocationEvidence {
                identity,
                outcome,
                result,
            });
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    pub(crate) fn record_ord_comparator_invocation(
        &self,
        comparator: BuiltinId,
        evidence: ClassEvidence,
        left: &ThunkRef,
        right: &ThunkRef,
        result: bool,
    ) -> RuntimeResult<()> {
        if self.evidence_trace.is_none() {
            return Ok(());
        }
        let parent = self.active_adapter_identity()?;
        let parent_name = hell_builtins::registry()[usize::from(parent.builtin.0)].name;
        match parent_name {
            "Map.fromList" | "Map.lookup" | "Map.insert" | "Map.delete" | "Map.singleton"
            | "Set.fromList" | "Set.insert" | "Set.member" | "Set.delete" | "Set.singleton"
            | "Map.insertWith" | "Map.adjust" | "Map.unionWith" | "Set.union"
            | "Set.difference" | "Set.intersection" => {}
            _ => {
                return Err(RuntimeError::internal(
                    "Ord comparator observation has no collection parent",
                ));
            }
        }
        match hell_builtins::registry()[usize::from(comparator.0)].name {
            "Ord.lt" | "Ord.gt" => {}
            _ => {
                return Err(RuntimeError::internal(
                    "collection comparator observation is not Ord.lt/Ord.gt",
                ));
            }
        }
        let retained = typeclasses::retained_instance_evidence(self, evidence)?;
        let active = self
            .adapter_obligation_stack
            .last()
            .ok_or_else(|| RuntimeError::internal("Ord comparator parent disappeared"))?;
        if active.instance_target.as_deref() != Some(retained.target.as_ref())
            || active.instance_premises != retained.premises
        {
            return Err(RuntimeError::internal(
                "Ord comparator evidence disagrees with its collection parent",
            ));
        }
        let mut trace = self
            .evidence_trace
            .as_ref()
            .expect("semantic trace was checked above")
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        let child_sequence = trace
            .obligation_events
            .iter()
            .rev()
            .find(|child| {
                child.owner_task == parent.owner_task
                    && child.parent_sequence == Some(parent.sequence)
                    && child.builtin == comparator
            })
            .map(|child| child.sequence)
            .filter(|sequence| {
                !trace.comparator_events.iter().any(|comparison| {
                    comparison.parent.owner_task == parent.owner_task
                        && comparison.parent.sequence == parent.sequence
                        && comparison.child_sequence == *sequence
                })
            })
            .ok_or_else(|| {
                RuntimeError::internal("Ord comparator direct child identity disappeared")
            })?;
        let invocation = trace
            .comparator_sequences
            .entry((parent.owner_task, parent.sequence))
            .and_modify(|sequence| *sequence = sequence.saturating_add(1))
            .or_insert(1);
        let invocation = *invocation;
        trace.comparator_events.push(ComparatorInvocationEvidence {
            parent,
            invocation,
            comparator,
            child_sequence,
            left: Arc::clone(left),
            right: Arc::clone(right),
            outcome: "value",
            result: Thunk::evaluated(Value::Bool(result)),
        });
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_effect_started(
        &mut self,
        builtin: BuiltinId,
    ) -> RuntimeResult<Option<EffectCausalIdentity>> {
        let Some(trace) = &self.evidence_trace else {
            return Ok(None);
        };
        let metadata = hell_builtins::registry()[usize::from(builtin.0)].assurance_metadata();
        let owner_task = self.current_evidence_task;
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        let effect = if metadata.effect_kind == hell_builtins::EffectKind::Io {
            let sequence = trace.effect_sequences.entry(owner_task).or_default();
            *sequence = sequence.saturating_add(1);
            let sequence = *sequence;
            let identity = EffectCausalIdentity {
                builtin,
                owner_task,
                sequence,
                parent_sequence: self.effect_stack.last().map(|parent| parent.sequence),
            };
            self.effect_stack.push(identity);
            Some(identity)
        } else {
            None
        };
        if let Some(identity) = effect {
            trace.effect_events.push(EffectEvidence {
                identity,
                lifecycle: "started",
            });
        }
        Ok(effect)
    }

    #[cfg(feature = "compat-tracing")]
    fn record_effect_terminal(
        &mut self,
        identity: EffectCausalIdentity,
        lifecycle: &'static str,
    ) -> RuntimeResult<()> {
        let active = self.effect_stack.pop().ok_or_else(|| {
            RuntimeError::internal("semantic effect terminal has no active invocation")
        })?;
        if active != identity {
            return Err(RuntimeError::internal(
                "semantic effect terminal does not match its active invocation",
            ));
        }
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?
            .effect_events
            .push(EffectEvidence {
                identity,
                lifecycle,
            });
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_task_started(&mut self, builtin: BuiltinId) -> RuntimeResult<u64> {
        let task = self.allocate_evidence_task()?;
        self.record_task_started_with_id(builtin, task)?;
        Ok(task)
    }

    #[cfg(feature = "compat-tracing")]
    fn allocate_evidence_task(&self) -> RuntimeResult<u64> {
        let Some(trace) = &self.evidence_trace else {
            return Ok(0);
        };
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        trace.next_task_id = trace.next_task_id.saturating_add(1);
        Ok(trace.next_task_id)
    }

    #[cfg(feature = "compat-tracing")]
    fn record_task_started_with_id(&self, builtin: BuiltinId, task: u64) -> RuntimeResult<()> {
        if task == 0 {
            return Ok(());
        }
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        trace.task_events.push((builtin, task, "started"));
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_task_terminal(
        &self,
        builtin: BuiltinId,
        task: u64,
        lifecycle: &'static str,
    ) -> RuntimeResult<()> {
        if task == 0 {
            return Ok(());
        }
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        trace.task_events.push((builtin, task, lifecycle));
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_resource_event(
        &self,
        builtin: BuiltinId,
        resource_key: usize,
        lifecycle: &'static str,
    ) -> RuntimeResult<()> {
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        let resource = if lifecycle == "acquire" {
            if trace.resource_ids.contains_key(&resource_key) {
                return Err(RuntimeError::internal(
                    "semantic resource was acquired more than once",
                ));
            }
            trace.next_resource_id = trace.next_resource_id.saturating_add(1);
            let resource = trace.next_resource_id;
            trace.resource_ids.insert(resource_key, resource);
            trace.live_resources.insert(resource);
            resource
        } else {
            *trace.resource_ids.get(&resource_key).ok_or_else(|| {
                RuntimeError::internal("semantic resource terminal event has no acquisition")
            })?
        };
        if matches!(lifecycle, "close" | "cancel") && !trace.live_resources.remove(&resource) {
            return Err(RuntimeError::internal(
                "semantic resource terminal event is duplicated",
            ));
        }
        trace
            .resource_events
            .push((builtin, resource, self.current_evidence_task, lifecycle));
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_forced_argument(
        &self,
        builtin: BuiltinId,
        argument: usize,
        boundary_class: &'static str,
        thunk: &ThunkRef,
    ) -> RuntimeResult<()> {
        if let Some(trace) = &self.evidence_trace {
            let mut trace = trace
                .lock()
                .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
            trace.forced_arguments.push(ForcedArgumentEvidence {
                builtin,
                argument,
                boundary_class,
                thunk: Arc::clone(thunk),
                snapshot_outcome: None,
            });
        }
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_lazy_argument_exit_states(
        &self,
        builtin: BuiltinId,
        arguments: &[ThunkRef],
    ) -> RuntimeResult<()> {
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        let spec = &hell_builtins::registry()[usize::from(builtin.0)];
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        for (argument, (demand, thunk)) in spec.demand.iter().zip(arguments).enumerate() {
            if *demand == hell_builtins::Demand::Lazy {
                trace.forced_arguments.push(ForcedArgumentEvidence {
                    builtin,
                    argument,
                    boundary_class: "lazy-adapter-exit",
                    thunk: Arc::clone(thunk),
                    snapshot_outcome: Some(evidence_thunk_outcome(thunk).0),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_lazy_argument_entry_states(
        &self,
        builtin: BuiltinId,
        arguments: &[ThunkRef],
    ) -> RuntimeResult<()> {
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        let spec = &hell_builtins::registry()[usize::from(builtin.0)];
        let mut trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        for (argument, (demand, thunk)) in spec.demand.iter().zip(arguments).enumerate() {
            if *demand == hell_builtins::Demand::Lazy {
                trace.forced_arguments.push(ForcedArgumentEvidence {
                    builtin,
                    argument,
                    boundary_class: "lazy-adapter-entry",
                    thunk: Arc::clone(thunk),
                    snapshot_outcome: Some(evidence_thunk_outcome(thunk).0),
                });
            }
        }
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_argument_snapshot(
        &self,
        builtin: BuiltinId,
        argument: usize,
        boundary_class: &'static str,
        thunk: &ThunkRef,
    ) -> RuntimeResult<()> {
        let Some(trace) = &self.evidence_trace else {
            return Ok(());
        };
        trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?
            .forced_arguments
            .push(ForcedArgumentEvidence {
                builtin,
                argument,
                boundary_class,
                thunk: Arc::clone(thunk),
                snapshot_outcome: Some(evidence_thunk_outcome(thunk).0),
            });
        Ok(())
    }

    #[cfg(feature = "compat-tracing")]
    fn record_typed_result(
        &self,
        builtin: BuiltinId,
        argument: usize,
        boundary: &'static str,
        thunk: &ThunkRef,
    ) -> RuntimeResult<()> {
        if let Some(trace) = &self.evidence_trace {
            let mut trace = trace
                .lock()
                .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
            if trace
                .typed_result_target
                .is_none_or(|target| target == builtin)
                && trace.typed_results.is_empty()
            {
                trace
                    .typed_results
                    .push((builtin, argument, boundary, Arc::clone(thunk)));
            }
        }
        Ok(())
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
        let callback_argument = usize::from(variant.constructor_index);
        let handler = handlers
            .get(callback_argument)
            .ok_or_else(|| RuntimeError::internal("primitive constructor is out of bounds"))?;
        #[cfg(feature = "compat-tracing")]
        let branch = match (family, variant.constructor_index) {
            (PrimitiveFamily::Either, 0) => "left",
            (PrimitiveFamily::Either, 1) => "right",
            (PrimitiveFamily::These, 0) => "this",
            (PrimitiveFamily::These, 1) => "that",
            (PrimitiveFamily::These, 2) => "these",
            (PrimitiveFamily::Exit, 0) => "success",
            (PrimitiveFamily::Exit, 1) => "failure",
            (PrimitiveFamily::Json, 0) => "null",
            (PrimitiveFamily::Json, 1) => "bool",
            (PrimitiveFamily::Json, 2) => "string",
            (PrimitiveFamily::Json, 3) => "number",
            (PrimitiveFamily::Json, 4) => "array",
            (PrimitiveFamily::Json, 5) => "object",
            _ => {
                return Err(RuntimeError::internal(
                    "primitive callback branch is out of bounds",
                ));
            }
        };
        #[cfg(feature = "compat-tracing")]
        let mut payloads = Vec::with_capacity(variant.payloads.len());
        #[cfg(not(feature = "compat-tracing"))]
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
            #[cfg(feature = "compat-tracing")]
            payloads.push(payload);
            #[cfg(not(feature = "compat-tracing"))]
            {
                selected = Thunk::suspended(Suspension::Apply {
                    function: selected,
                    argument: payload,
                });
            }
        }
        #[cfg(feature = "compat-tracing")]
        let selected = self.callback_application(
            Arc::clone(handler),
            &payloads,
            u16::from(variant.constructor_index),
            branch,
        )?;
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
                                Value::JsonNumber(number) => {
                                    if semantic_mutant_active("json-number-f64-precision") {
                                        let mut exact = String::new();
                                        number.push_json(&mut exact);
                                        output.push_str(
                                            &exact
                                                .parse::<f64>()
                                                .unwrap_or(f64::INFINITY)
                                                .to_string(),
                                        );
                                    } else {
                                        number.push_json(output);
                                    }
                                }
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
                    self.charge_materialization(1)?;
                    self.ensure_not_cancelled()?;
                    elements.push(Arc::clone(head));
                    list = Arc::clone(tail);
                }
                _ => return Err(RuntimeError::internal("expected list")),
            }
        }
    }

    fn charge_materialization(&mut self, amount: u64) -> RuntimeResult<()> {
        self.budget.charge_materialization(amount)?;
        #[cfg(feature = "compat-tracing")]
        if let Some(active) = self.adapter_obligation_stack.last_mut() {
            active.materialized_elements = active.materialized_elements.saturating_add(amount);
        }
        Ok(())
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
                if left.family == right.family
                    && matches!(left.family, PrimitiveFamily::Either | PrimitiveFamily::Exit) =>
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
            (Value::Vector(left), Value::Vector(right)) => self.less_ordered_slices(left, right),
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

#[cfg(feature = "compat-tracing")]
fn evidence_value_children(value: &ValueRef) -> Vec<&ThunkRef> {
    match value.as_ref() {
        Value::CaseInsensitive(value) => vec![&value.original, &value.folded],
        Value::Tree(value) => vec![&value.root, &value.children],
        Value::Tuple(values) | Value::Vector(values) => values.iter().collect(),
        Value::Record { fields, .. } => fields.iter().collect(),
        Value::Variant { payload, .. } | Value::Maybe(payload) => payload.iter().collect(),
        Value::PrimitiveVariant(value) => value.payloads.iter().collect(),
        Value::List(ListCell::Cons { head, tail }) => vec![head, tail],
        Value::Map(value) => value.iter().flat_map(|(key, item)| [key, item]).collect(),
        Value::Set(value) => value.iter().collect(),
        _ => Vec::new(),
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

impl ForceOutcome {
    fn with_evidence_builtin(self, builtin: BuiltinId) -> Self {
        match self {
            Self::Value(value) => match value.as_ref() {
                Value::Io(action) => Self::Value(Arc::new(Value::Io(
                    action.clone().with_evidence_builtin(builtin),
                ))),
                _ => Self::Value(value),
            },
            Self::Alias(thunk) => Self::Alias(thunk),
        }
    }
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

    #[test]
    fn evidence_audit_counts_generic_resources_and_finalizers() {
        let snapshot = scope::ScopeSnapshot {
            child_scopes: 0,
            live_tasks: 0,
            resources: 1,
            finalizers: 1,
            budget: budget::BudgetSnapshot::default(),
        };
        let audit = evidence_resource_audit_contents(&snapshot, 0);
        assert!(audit.contains("\"handles\": 2"));
        assert!(!audit.contains("\"handles\": 0"));
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
        resource.map_or(Ok(()), |resource| {
            if semantic_mutant_active("temporary-resource-cleanup") {
                resource.disarm_without_cleanup_for_mutation();
                Ok(())
            } else {
                resource.cleanup()
            }
        })
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
        ..
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
        ..
    } = &process.stderr
    {
        let already_closed = matches!(
            &process.stdout,
            HostHandle::File {
                handle: stdout,
                close_after_process: true,
                ..
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

#[cfg(feature = "compat-tracing")]
fn record_closed_process_handle_events(
    evaluator: &mut Evaluator,
    builtin: BuiltinId,
    process: &ProcessSpec,
) -> RuntimeResult<()> {
    let mut recorded = Vec::<*const native_handle::FileHandle>::new();
    for stream in [&process.stdout, &process.stderr] {
        let HostHandle::File {
            handle,
            close_after_process: true,
            process_close_builtin,
        } = stream
        else {
            continue;
        };
        let identity = Arc::as_ptr(handle);
        if handle.is_closed() && !recorded.contains(&identity) {
            let lifecycle_builtin = process_close_builtin.map_or(builtin, BuiltinId);
            evaluator.record_resource_event(lifecycle_builtin, identity as usize, "close")?;
            recorded.push(identity);
        }
    }
    Ok(())
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
    run_main_inner(program, context, None, None)
}

/// Executes `main` while retaining its canonical semantic trace at an explicit
/// path instead of consulting process-global environment state.
///
/// # Errors
///
/// Returns any execution error or an error retaining the canonical trace.
#[cfg(feature = "compat-tracing")]
#[allow(clippy::needless_pass_by_value)]
pub fn run_main_with_semantic_trace(
    program: VerifiedProgram,
    context: RuntimeContext,
    trace_path: &Path,
) -> RuntimeResult<()> {
    run_main_inner(program, context, Some(trace_path), None)
}

/// Executes `main` while retaining a canonical typed result for one exact
/// adapter in addition to the ordinary semantic trace.
///
/// # Errors
///
/// Returns any execution error or an error retaining the canonical trace.
#[cfg(feature = "compat-tracing")]
#[allow(clippy::needless_pass_by_value)]
pub fn run_main_with_semantic_trace_target(
    program: VerifiedProgram,
    context: RuntimeContext,
    trace_path: &Path,
    typed_result_target: BuiltinId,
) -> RuntimeResult<()> {
    run_main_inner(
        program,
        context,
        Some(trace_path),
        Some(typed_result_target),
    )
}

#[allow(clippy::needless_pass_by_value)]
fn run_main_inner(
    program: VerifiedProgram,
    context: RuntimeContext,
    #[cfg_attr(not(feature = "compat-tracing"), allow(unused_variables))] trace_path: Option<&Path>,
    #[cfg_attr(not(feature = "compat-tracing"), allow(unused_variables))]
    typed_result_target: Option<BuiltinId>,
) -> RuntimeResult<()> {
    let executable = Arc::new(program.executable().clone());
    let mut evaluator = Evaluator::new(Arc::clone(&executable))
        .with_policy(Arc::clone(&context.policy), Arc::clone(&context.budget));
    #[cfg(feature = "compat-tracing")]
    if trace_path.is_some() || typed_result_target.is_some() {
        evaluator.evidence_trace = Some(Arc::new(Mutex::new(
            EvidenceTrace::from_program_and_typed_target(&executable, typed_result_target),
        )));
    }
    if let Some(max_concurrent_actions) = context.max_concurrent_actions {
        evaluator = evaluator.with_max_concurrent_actions(max_concurrent_actions);
    }
    let audit_scope = evaluator.execution_scope().clone();
    let root_scope = audit_scope.clone().guard();
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
    let body_error = body.as_ref().err().cloned();
    let body_suppressed = body_error
        .as_ref()
        .map_or(0, |error| error.suppressed.len());
    let outcome = match body {
        Ok(()) => root_scope.close().map(|_| ()),
        Err(error) => root_scope.close_with_primary(Some(error)).map(|_| ()),
    };
    let after = audit_scope.snapshot();
    let cleanup_failures = outcome.as_ref().err().map_or(0, |error| {
        if body_error.is_some() {
            error.suppressed.len().saturating_sub(body_suppressed)
        } else {
            1_usize.saturating_add(error.suppressed.len())
        }
    });
    write_evidence_resource_audit(&after, cleanup_failures)?;
    #[cfg(feature = "compat-tracing")]
    if let Some(trace) = &evaluator.evidence_trace {
        let trace = trace
            .lock()
            .map_err(|_| RuntimeError::internal("semantic trace lock was poisoned"))?;
        if let Some(path) = trace_path {
            write_evidence_semantic_trace_to(&trace, path)?;
        } else {
            write_evidence_semantic_trace(&trace)?;
        }
    }
    let budget = &after.budget;
    let leaked = after.child_scopes != 0
        || after.live_tasks != 0
        || after.resources != 0
        || after.finalizers != 0
        || budget.live_tasks != 0
        || budget.live_handles != 0
        || budget.live_processes != 0
        || budget.live_http_connections != 0
        || budget.live_temp_resources != 0;
    match outcome {
        Ok(()) if !leaked => Ok(()),
        Ok(()) => Err(RuntimeError::cancellation_stalled(format!(
            "execution scope did not return to its resource baseline: {after:?}"
        ))),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "compat-tracing")]
fn write_evidence_semantic_trace(trace: &EvidenceTrace) -> RuntimeResult<()> {
    let Some(path) = std::env::var_os("HELL_EVIDENCE_SEMANTIC_TRACE").map(PathBuf::from) else {
        return Ok(());
    };
    write_evidence_semantic_trace_to(trace, &path)
}

#[cfg(feature = "compat-tracing")]
fn write_evidence_semantic_trace_to(trace: &EvidenceTrace, path: &Path) -> RuntimeResult<()> {
    let contents = semantic_trace_contents(trace)?;
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    std::fs::write(&temporary, contents.as_bytes()).map_err(|error| {
        RuntimeError::internal(format!("cannot write semantic evidence trace: {error}"))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        RuntimeError::internal(format!("cannot retain semantic evidence trace: {error}"))
    })
}

#[cfg(feature = "compat-tracing")]
fn semantic_trace_contents(trace: &EvidenceTrace) -> RuntimeResult<String> {
    let [
        parsed,
        resolved,
        specialized,
        entered,
        forced,
        typed,
        effects,
        tasks,
        presentation,
        resources,
        obligations,
    ] = canonical_semantic_event_arrays(trace)?;
    let cleanup_failures = trace
        .resource_events
        .iter()
        .filter(|event| event.3 == "cleanup-failure")
        .count();
    Ok(format!(
        "{{\n  \"schemaVersion\": 9,\n  \"parsedBuiltins\": [{parsed}],\n  \"resolvedBuiltins\": [{resolved}],\n  \"specializedBuiltins\": [{specialized}],\n  \"enteredAdapters\": [{entered}],\n  \"forcedArguments\": [{forced}],\n  \"typedResults\": [{typed}],\n  \"effectEvents\": [{effects}],\n  \"taskEvents\": [{tasks}],\n  \"presentationFields\": [{presentation}],\n  \"resourceEvents\": [{resources}],\n  \"obligationEvents\": [{obligations}],\n  \"finalResourceCounts\": {{\"acquired\": {}, \"live\": {}, \"cleanupFailures\": {cleanup_failures}, \"materializedElements\": {}}}\n}}\n",
        trace.next_resource_id,
        trace.live_resources.len(),
        trace
            .obligation_events
            .iter()
            .map(|event| event.materialized_after)
            .sum::<u64>(),
    ))
}

#[cfg(feature = "compat-tracing")]
struct CanonicalTraceEvent {
    field: usize,
    key: String,
    body: String,
}

#[cfg(feature = "compat-tracing")]
fn canonical_semantic_event_arrays(trace: &EvidenceTrace) -> RuntimeResult<[String; 11]> {
    if trace.typed_result_target.is_some()
        && (trace.typed_result_target_invocations != 1 || trace.typed_results.len() != 1)
    {
        return Err(RuntimeError::internal(
            "typed-result target must be invoked exactly once",
        ));
    }
    let task_ids = canonical_task_ids(trace)?;
    let resource_ids = canonical_resource_ids(trace, &task_ids)?;
    let mut events = Vec::new();
    push_canonical_builtin_events(&mut events, 0, &trace.parsed_builtins);
    push_canonical_builtin_events(&mut events, 1, &trace.resolved_builtins);
    push_canonical_builtin_events(&mut events, 2, &trace.specialized_builtins);
    push_canonical_builtin_events(&mut events, 3, &trace.entered_adapters);
    for event in &trace.forced_arguments {
        let outcome = event
            .snapshot_outcome
            .unwrap_or_else(|| evidence_thunk_outcome(&event.thunk).0);
        events.push(CanonicalTraceEvent {
            field: 4,
            key: format!(
                "{:05}\0{:020}\0{}\0{}",
                event.builtin.0, event.argument, event.boundary_class, outcome
            ),
            body: format!(
                "\"builtinId\": {}, \"argument\": {}, \"boundaryClass\": \"{}\", \"outcome\": \"{}\"",
                event.builtin.0, event.argument, event.boundary_class, outcome
            ),
        });
    }
    for (builtin, argument, boundary, thunk) in &trace.typed_results {
        if let Some(value) = evidence_thunk_outcome(thunk).1 {
            let value = format!(
                "{{\"type\":\"TypedResult\",\"argument\":{argument},\"boundary\":\"{boundary}\",\"value\":{value}}}"
            );
            events.push(CanonicalTraceEvent {
                field: 5,
                key: format!("{:05}\0{value}", builtin.0),
                body: format!("\"builtinId\": {}, \"canonicalValue\": {value}", builtin.0),
            });
        }
    }
    if trace.typed_result_target.is_some()
        && events.iter().filter(|event| event.field == 5).count() != 1
    {
        return Err(RuntimeError::internal(
            "typed-result target did not produce one canonical value",
        ));
    }
    push_canonical_effect_events(&mut events, trace, &task_ids)?;
    push_canonical_task_events(&mut events, trace, &task_ids)?;
    push_canonical_named_events(&mut events, 8, &trace.presentation_fields, "field");
    push_canonical_resource_events(&mut events, trace, &task_ids, &resource_ids)?;
    push_canonical_obligation_events(&mut events, trace, &task_ids)?;
    events.sort_by(|left, right| (left.field, &left.key).cmp(&(right.field, &right.key)));
    let mut arrays: [Vec<String>; 11] = std::array::from_fn(|_| Vec::new());
    for (index, event) in events.into_iter().enumerate() {
        let event_id = u64::try_from(index)
            .map_err(|_| RuntimeError::internal("semantic event count exceeds u64"))?
            .saturating_add(1);
        arrays[event.field].push(format!("{{\"eventId\": {event_id}, {}}}", event.body));
    }
    Ok(arrays.map(|events| events.join(", ")))
}

#[cfg(feature = "compat-tracing")]
fn push_canonical_effect_events(
    output: &mut Vec<CanonicalTraceEvent>,
    trace: &EvidenceTrace,
    task_ids: &HashMap<u64, u64>,
) -> RuntimeResult<()> {
    let cancelled_tasks = trace
        .task_events
        .iter()
        .filter(|event| event.2 == "cancelled")
        .map(|event| event.1)
        .collect::<HashSet<_>>();
    let mut events = trace
        .effect_events
        .iter()
        .map(|event| (event.identity, event.lifecycle))
        .collect::<Vec<_>>();
    let identities = events
        .iter()
        .map(|event| (event.0.owner_task, event.0.sequence))
        .collect::<HashSet<_>>();
    for identity in identities {
        let lifecycle = events
            .iter()
            .filter(|event| (event.0.owner_task, event.0.sequence) == identity)
            .map(|event| event.1)
            .collect::<Vec<_>>();
        if lifecycle == ["started"]
            && identity
                .0
                .is_some_and(|owner| cancelled_tasks.contains(&owner))
        {
            let started = events
                .iter()
                .find(|event| (event.0.owner_task, event.0.sequence) == identity)
                .expect("effect identity came from retained events")
                .0;
            events.push((started, "cancelled"));
        } else if lifecycle.len() != 2
            || lifecycle[0] != "started"
            || !matches!(lifecycle[1], "completed" | "failed" | "cancelled")
        {
            return Err(RuntimeError::internal(format!(
                "semantic effect lifecycle is not start-to-terminal ordered: owner={:?}, sequence={}, lifecycle={lifecycle:?}",
                identity.0, identity.1
            )));
        }
    }
    for (identity, lifecycle) in events {
        let owner_task = identity
            .owner_task
            .map(|task| {
                task_ids.get(&task).copied().ok_or_else(|| {
                    RuntimeError::internal("semantic effect owner is not a retained task")
                })
            })
            .transpose()?;
        if identity
            .parent_sequence
            .is_some_and(|parent| parent >= identity.sequence)
        {
            return Err(RuntimeError::internal(
                "semantic effect parent does not precede its child",
            ));
        }
        let owner = owner_task.map_or_else(|| "null".to_owned(), |task| task.to_string());
        let parent = identity
            .parent_sequence
            .map_or_else(|| "null".to_owned(), |sequence| sequence.to_string());
        output.push(CanonicalTraceEvent {
            field: 6,
            key: format!(
                "{owner:0>20}\0{:020}\0{}\0{:05}",
                identity.sequence,
                lifecycle_rank(lifecycle),
                identity.builtin.0
            ),
            body: format!(
                "\"builtinId\": {}, \"ownerTaskId\": {owner}, \"sequence\": {}, \"parentSequence\": {parent}, \"effect\": \"{}\"",
                identity.builtin.0, identity.sequence, lifecycle
            ),
        });
    }
    Ok(())
}

#[cfg(feature = "compat-tracing")]
fn push_canonical_task_events(
    output: &mut Vec<CanonicalTraceEvent>,
    trace: &EvidenceTrace,
    task_ids: &HashMap<u64, u64>,
) -> RuntimeResult<()> {
    for (event_index, (builtin, task, lifecycle)) in trace.task_events.iter().enumerate() {
        let canonical_task = task_ids.get(task).ok_or_else(|| {
            RuntimeError::internal("semantic task lacks a canonical logical identity")
        })?;
        output.push(CanonicalTraceEvent {
            field: 7,
            key: if task_event_order_sensitive(*builtin) {
                format!("0\0{:05}\0{event_index:020}", builtin.0)
            } else {
                format!(
                    "1\0{canonical_task:020}\0{}\0{:05}",
                    lifecycle_rank(lifecycle),
                    builtin.0
                )
            },
            body: format!(
                "\"builtinId\": {}, \"taskId\": {canonical_task}, \"event\": \"{lifecycle}\"",
                builtin.0
            ),
        });
    }
    Ok(())
}

#[cfg(feature = "compat-tracing")]
fn push_canonical_resource_events(
    output: &mut Vec<CanonicalTraceEvent>,
    trace: &EvidenceTrace,
    task_ids: &HashMap<u64, u64>,
    resource_ids: &HashMap<u64, u64>,
) -> RuntimeResult<()> {
    for (builtin, resource, owner_task, lifecycle) in &trace.resource_events {
        let canonical_resource = resource_ids.get(resource).ok_or_else(|| {
            RuntimeError::internal("semantic resource lacks a canonical logical identity")
        })?;
        let canonical_owner = owner_task
            .map(|owner| {
                task_ids.get(&owner).copied().ok_or_else(|| {
                    RuntimeError::internal("semantic resource owner is not a retained task")
                })
            })
            .transpose()?;
        let owner = canonical_owner.map_or_else(|| "null".to_owned(), |id| id.to_string());
        output.push(CanonicalTraceEvent {
            field: 9,
            key: format!(
                "{canonical_resource:020}\0{}\0{:05}\0{owner}",
                lifecycle_rank(lifecycle),
                builtin.0
            ),
            body: format!(
                "\"builtinId\": {}, \"resourceId\": {canonical_resource}, \"ownerTaskId\": {owner}, \"event\": \"{lifecycle}\"",
                builtin.0
            ),
        });
    }
    Ok(())
}

#[cfg(feature = "compat-tracing")]
fn push_canonical_obligation_events(
    output: &mut Vec<CanonicalTraceEvent>,
    trace: &EvidenceTrace,
    task_ids: &HashMap<u64, u64>,
) -> RuntimeResult<()> {
    let mut children = HashMap::<(Option<u64>, u64), u64>::new();
    for event in &trace.obligation_events {
        if let Some(parent) = event.parent_sequence {
            children
                .entry((event.owner_task, parent))
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
        }
    }
    for event in &trace.obligation_events {
        let owner_task = event
            .owner_task
            .map(|task| {
                task_ids.get(&task).copied().ok_or_else(|| {
                    RuntimeError::internal("semantic adapter owner is not a retained task")
                })
            })
            .transpose()?;
        if event
            .parent_sequence
            .is_some_and(|parent| parent >= event.sequence)
        {
            return Err(RuntimeError::internal(
                "semantic adapter parent does not precede its child",
            ));
        }
        let owner = owner_task.map_or_else(|| "null".to_owned(), |task| task.to_string());
        let parent = event
            .parent_sequence
            .map_or_else(|| "null".to_owned(), |sequence| sequence.to_string());
        let instance_target = event
            .instance_target
            .as_ref()
            .map_or_else(|| "null".to_owned(), |target| format!("\"{target}\""));
        let instance_premises = event
            .instance_premises
            .iter()
            .map(|(target, premise_count)| {
                format!("{{\"target\":\"{target}\",\"premiseCount\":{premise_count}}}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let nested_adapters = children
            .get(&(event.owner_task, event.sequence))
            .copied()
            .unwrap_or(0);
        let callbacks = canonical_callback_invocations(trace, event)?;
        let comparators = canonical_comparator_invocations(trace, event)?;
        output.push(CanonicalTraceEvent {
            field: 10,
            key: format!(
                "{owner:0>20}\0{:020}\0{:05}\0{instance_target}\0{instance_premises}\0{}\0{:020}\0{:020}\0{:020}\0{callbacks}\0{comparators}",
                event.sequence,
                event.builtin.0,
                event.outcome,
                nested_adapters,
                event.materialized_before,
                event.materialized_after
            ),
            body: format!(
                "\"builtinId\": {}, \"ownerTaskId\": {owner}, \"sequence\": {}, \"parentSequence\": {parent}, \"instanceTarget\": {instance_target}, \"instancePremises\": [{instance_premises}], \"outcome\": \"{}\", \"nestedAdapters\": {}, \"materializedBefore\": {}, \"materializedAfter\": {}, \"callbackInvocations\": [{callbacks}], \"comparatorInvocations\": [{comparators}]",
                event.builtin.0,
                event.sequence,
                event.outcome,
                nested_adapters,
                event.materialized_before,
                event.materialized_after
            ),
        });
    }
    Ok(())
}

#[cfg(feature = "compat-tracing")]
fn canonical_comparator_invocations(
    trace: &EvidenceTrace,
    event: &AdapterObligationEvidence,
) -> RuntimeResult<String> {
    let mut comparisons = trace
        .comparator_events
        .iter()
        .filter(|comparison| {
            comparison.parent.owner_task == event.owner_task
                && comparison.parent.sequence == event.sequence
        })
        .collect::<Vec<_>>();
    comparisons.sort_by_key(|comparison| comparison.invocation);
    comparisons
        .into_iter()
        .enumerate()
        .map(|(index, comparison)| {
            let expected = u64::try_from(index)
                .map_err(|_| RuntimeError::internal("comparator count exceeds u64"))?
                .saturating_add(1);
            if comparison.invocation != expected || comparison.parent.builtin != event.builtin {
                return Err(RuntimeError::internal(
                    "comparator identity is not contiguous or target-bound",
                ));
            }
            let left = evidence_thunk_outcome(&comparison.left)
                .1
                .ok_or_else(|| RuntimeError::internal("comparator left value is not canonical"))?;
            let right = evidence_thunk_outcome(&comparison.right)
                .1
                .ok_or_else(|| RuntimeError::internal("comparator right value is not canonical"))?;
            let (observed_outcome, result) = evidence_thunk_outcome(&comparison.result);
            if observed_outcome != comparison.outcome {
                return Err(RuntimeError::internal(
                    "comparator retained outcome disagrees with its result",
                ));
            }
            let result = result.ok_or_else(|| {
                RuntimeError::internal("comparator result is not a canonical typed value")
            })?;
            let mut direct_children = trace
                .obligation_events
                .iter()
                .filter(|child| {
                    child.owner_task == event.owner_task
                        && child.parent_sequence == Some(event.sequence)
                        && matches!(
                            hell_builtins::registry()[usize::from(child.builtin.0)].name,
                            "Ord.lt" | "Ord.gt"
                        )
                })
                .collect::<Vec<_>>();
            direct_children.sort_by_key(|child| child.sequence);
            let direct_child_ordinal = direct_children
                .iter()
                .position(|child| child.sequence == comparison.child_sequence)
                .and_then(|index| u64::try_from(index).ok())
                .map(|index| index.saturating_add(1))
                .ok_or_else(|| {
                    RuntimeError::internal("comparator direct child identity disappeared")
                })?;
            Ok(format!(
                "{{\"invocation\":{},\"directChildOrdinal\":{direct_child_ordinal},\"comparatorBuiltinId\":{},\"canonicalLeftHex\":\"{}\",\"canonicalRightHex\":\"{}\",\"outcome\":\"{}\",\"canonicalResultHex\":\"{}\"}}",
                comparison.invocation,
                comparison.comparator.0,
                evidence_hex(left.as_bytes()),
                evidence_hex(right.as_bytes()),
                comparison.outcome,
                evidence_hex(result.as_bytes()),
            ))
        })
        .collect::<RuntimeResult<Vec<_>>>()
        .map(|comparisons| comparisons.join(","))
}

#[cfg(feature = "compat-tracing")]
fn canonical_callback_invocations(
    trace: &EvidenceTrace,
    event: &AdapterObligationEvidence,
) -> RuntimeResult<String> {
    let apply = hell_builtins::lookup("$")
        .expect("application operator remains registry-backed")
        .id;
    let compose = hell_builtins::lookup(".")
        .expect("composition operator remains registry-backed")
        .id;
    let function_operator =
        matches!(event.builtin, builtin if builtin == apply || builtin == compose);
    let mut callbacks = trace
        .callback_events
        .iter()
        .filter(|callback| {
            callback.identity.parent.owner_task == event.owner_task
                && callback.identity.parent.sequence == event.sequence
        })
        .collect::<Vec<_>>();
    if function_operator {
        callbacks.retain(|callback| {
            callback
                .identity
                .arguments
                .iter()
                .all(|argument| evidence_thunk_outcome(argument).1.is_some())
                && evidence_thunk_outcome(&callback.result).1.is_some()
        });
    }
    callbacks.sort_by_key(|callback| callback.identity.invocation);
    for (index, callback) in callbacks.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(|_| RuntimeError::internal("callback count exceeds u64"))?
            .saturating_add(1);
        if (!function_operator && callback.identity.invocation != expected)
            || callback.identity.parent.builtin != event.builtin
        {
            return Err(RuntimeError::internal(
                "callback identity is not contiguous or target-bound",
            ));
        }
    }
    if event.builtin == compose {
        callbacks.sort_by_key(|callback| {
            trace
                .callback_events
                .iter()
                .position(|candidate| std::ptr::eq(candidate, *callback))
                .expect("retained callback belongs to its source trace")
        });
    }
    callbacks
        .into_iter()
        .enumerate()
        .map(|(index, callback)| {
            let canonical_arguments = callback
                .identity
                .arguments
                .iter()
                .map(|argument| {
                    let (_, canonical) = evidence_thunk_outcome(argument);
                    canonical
                        .map(|value| format!("\"{}\"", evidence_hex(value.as_bytes())))
                        .ok_or_else(|| {
                            RuntimeError::internal(
                                "callback argument is not a canonical typed value",
                            )
                        })
                })
                .collect::<RuntimeResult<Vec<_>>>()?
                .join(",");
            let (observed_outcome, canonical) = evidence_thunk_outcome(&callback.result);
            if observed_outcome != callback.outcome {
                return Err(RuntimeError::internal(format!(
                    "callback {} retained outcome {} disagrees with result outcome {observed_outcome}",
                    callback.identity.branch, callback.outcome,
                )));
            }
            let canonical = canonical.ok_or_else(|| {
                RuntimeError::internal("callback result is not a canonical typed value")
            })?;
            let canonical_hex = evidence_hex(canonical.as_bytes());
            let invocation = if function_operator {
                u64::try_from(index)
                    .map_err(|_| RuntimeError::internal("callback count exceeds u64"))?
                    .saturating_add(1)
            } else {
                callback.identity.invocation
            };
            Ok(format!(
                "{{\"invocation\":{},\"callbackArgument\":{},\"branch\":\"{}\",\"canonicalArgumentHex\":[{canonical_arguments}],\"outcome\":\"{}\",\"canonicalResultHex\":\"{canonical_hex}\"}}",
                invocation,
                callback.identity.callback_argument,
                callback.identity.branch,
                callback.outcome,
            ))
        })
        .collect::<RuntimeResult<Vec<_>>>()
        .map(|callbacks| callbacks.join(","))
}

#[cfg(feature = "compat-tracing")]
fn push_canonical_builtin_events(
    output: &mut Vec<CanonicalTraceEvent>,
    field: usize,
    events: &[BuiltinId],
) {
    output.extend(events.iter().map(|builtin| CanonicalTraceEvent {
        field,
        key: format!("{:05}", builtin.0),
        body: format!("\"builtinId\": {}", builtin.0),
    }));
}

#[cfg(feature = "compat-tracing")]
fn push_canonical_named_events(
    output: &mut Vec<CanonicalTraceEvent>,
    field: usize,
    events: &[(BuiltinId, &'static str)],
    name: &str,
) {
    output.extend(events.iter().map(|(builtin, value)| CanonicalTraceEvent {
        field,
        key: format!("{:05}\0{}\0{value}", builtin.0, lifecycle_rank(value)),
        body: format!("\"builtinId\": {}, \"{name}\": \"{value}\"", builtin.0),
    }));
}

#[cfg(feature = "compat-tracing")]
fn canonical_task_ids(trace: &EvidenceTrace) -> RuntimeResult<HashMap<u64, u64>> {
    let mut tasks = HashMap::new();
    for (builtin, task, _) in &trace.task_events {
        if tasks
            .insert(*task, *builtin)
            .is_some_and(|prior| prior != *builtin)
        {
            return Err(RuntimeError::internal(
                "semantic task changes builtin identity during its lifecycle",
            ));
        }
    }
    let mut signatures = Vec::new();
    for (task, builtin) in tasks {
        let lifecycle = trace
            .task_events
            .iter()
            .filter(|event| event.1 == task)
            .map(|event| format!("{}:{}", lifecycle_rank(event.2), event.2))
            .collect::<Vec<_>>();
        if lifecycle.len() != 2
            || lifecycle.first().is_none_or(|event| event != "0:started")
            || lifecycle.last().is_none_or(|event| {
                !matches!(event.as_str(), "2:completed" | "3:failed" | "4:cancelled")
            })
        {
            return Err(RuntimeError::internal(
                "semantic task lifecycle is not start-to-terminal ordered",
            ));
        }
        let key = if let Some((pooled_builtin, ordinal)) =
            trace.pooled_task_ordinals.get(&task).copied()
        {
            if pooled_builtin != builtin {
                return Err(RuntimeError::internal(
                    "pooled task ordinal changes builtin identity",
                ));
            }
            format!("0\0{:05}\0{ordinal:020}", builtin.0)
        } else if task_event_order_sensitive(builtin) {
            let start = trace
                .task_events
                .iter()
                .position(|event| event.1 == task && event.2 == "started")
                .ok_or_else(|| RuntimeError::internal("semantic task lacks its start event"))?;
            format!("0\0{:05}\0{start:020}", builtin.0)
        } else {
            let mut resources = trace
                .resource_events
                .iter()
                .filter(|event| event.2 == Some(task))
                .map(|event| format!("{}:{}:{}", event.0.0, lifecycle_rank(event.3), event.3))
                .collect::<Vec<_>>();
            resources.sort();
            format!(
                "1\0{:05}\0{}\0{}",
                builtin.0,
                lifecycle.join("\0"),
                resources.join("\0")
            )
        };
        signatures.push((key, task));
    }
    let mut pooled_ordinals = trace
        .pooled_task_ordinals
        .values()
        .copied()
        .collect::<Vec<_>>();
    pooled_ordinals.sort_unstable_by_key(|(builtin, ordinal)| (builtin.0, *ordinal));
    for group in pooled_ordinals.chunk_by(|left, right| left.0 == right.0) {
        for (index, (_, ordinal)) in group.iter().enumerate() {
            let expected = u64::try_from(index)
                .map_err(|_| RuntimeError::internal("pooled task count exceeds u64"))?
                .saturating_add(1);
            if *ordinal != expected {
                return Err(RuntimeError::internal(
                    "pooled task ordinals are not unique and contiguous",
                ));
            }
        }
    }
    signatures.sort();
    Ok(signatures
        .into_iter()
        .enumerate()
        .map(|(index, (_, task))| {
            (
                task,
                u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1),
            )
        })
        .collect())
}

#[cfg(feature = "compat-tracing")]
fn task_event_order_sensitive(builtin: BuiltinId) -> bool {
    hell_builtins::registry()
        .iter()
        .find(|spec| spec.id == builtin)
        .is_some_and(|spec| matches!(spec.name, "Async.concurrently" | "Async.race"))
}

#[cfg(feature = "compat-tracing")]
fn canonical_resource_ids(
    trace: &EvidenceTrace,
    task_ids: &HashMap<u64, u64>,
) -> RuntimeResult<HashMap<u64, u64>> {
    let mut signatures = trace
        .resource_events
        .iter()
        .map(|event| event.1)
        .collect::<HashSet<_>>()
        .into_iter()
        .map(|resource| {
            let events = trace
                .resource_events
                .iter()
                .filter(|event| event.1 == resource)
                .map(|event| {
                    let owner = event
                        .2
                        .and_then(|task| task_ids.get(&task).copied())
                        .unwrap_or(0);
                    format!(
                        "{:05}:{owner:020}:{}:{}",
                        event.0.0,
                        lifecycle_rank(event.3),
                        event.3
                    )
                })
                .collect::<Vec<_>>();
            if events.len() != 2
                || !events
                    .first()
                    .is_some_and(|event| event.contains(":0:acquire"))
                || !events.last().is_some_and(|event| {
                    event.contains(":2:close")
                        || event.contains(":3:cleanup-failure")
                        || event.contains(":4:cancel")
                })
            {
                return Err(RuntimeError::internal(
                    "semantic resource lifecycle is not acquire-to-terminal ordered",
                ));
            }
            Ok((events.join("\0"), resource))
        })
        .collect::<RuntimeResult<Vec<_>>>()?;
    signatures.sort();
    Ok(signatures
        .into_iter()
        .enumerate()
        .map(|(index, (_, resource))| {
            (
                resource,
                u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1),
            )
        })
        .collect())
}

#[cfg(feature = "compat-tracing")]
fn lifecycle_rank(lifecycle: &str) -> u8 {
    match lifecycle {
        "started" | "acquire" => 0,
        "transfer" => 1,
        "completed" | "close" => 2,
        "failed" | "cleanup-failure" => 3,
        "cancelled" | "cancel" => 4,
        _ => u8::MAX,
    }
}

#[cfg(feature = "compat-tracing")]
fn evidence_thunk_outcome(thunk: &ThunkRef) -> (&'static str, Option<String>) {
    let canonical = canonical_evidence_thunk(thunk, &mut HashSet::new(), 0);
    let mut current = Arc::clone(thunk);
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(Arc::as_ptr(&current) as usize) {
            return ("cycle", None);
        }
        let Ok(state) = current.state.lock() else {
            return ("poisoned", None);
        };
        match &*state {
            ThunkState::Evaluated(_) => {
                return ("value", canonical);
            }
            ThunkState::Indirection(next) => {
                let next = Arc::clone(next);
                drop(state);
                current = next;
            }
            ThunkState::Failed(_) => return ("error", canonical),
            ThunkState::Suspended(_) => return ("not-forced", canonical),
            ThunkState::Evaluating { .. } => return ("in-progress", canonical),
        }
    }
}

#[cfg(feature = "compat-tracing")]
fn canonical_evidence_thunk(
    thunk: &ThunkRef,
    stack: &mut HashSet<usize>,
    depth: usize,
) -> Option<String> {
    const MAX_DEPTH: usize = 64;
    if depth >= MAX_DEPTH {
        return Some("{\"type\":\"ForceBoundary\",\"outcome\":\"depth-limit\"}".to_owned());
    }
    let identity = Arc::as_ptr(thunk) as usize;
    if !stack.insert(identity) {
        return Some("{\"type\":\"ForceBoundary\",\"outcome\":\"cycle\"}".to_owned());
    }
    let state = thunk.state.lock().ok()?;
    let output = match &*state {
        ThunkState::Evaluated(value) => {
            let value = Arc::clone(value);
            drop(state);
            canonical_evidence_value(value.as_ref(), stack, depth.saturating_add(1))
        }
        ThunkState::Indirection(next) => {
            let next = Arc::clone(next);
            drop(state);
            canonical_evidence_thunk(&next, stack, depth.saturating_add(1))
        }
        ThunkState::Failed(error) => Some(format!(
            "{{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"{}\"}}",
            error.code
        )),
        ThunkState::Suspended(_) => {
            Some("{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}".to_owned())
        }
        ThunkState::Evaluating { .. } => {
            Some("{\"type\":\"ForceBoundary\",\"outcome\":\"in-progress\"}".to_owned())
        }
    };
    stack.remove(&identity);
    output
}

#[cfg(feature = "compat-tracing")]
fn canonical_evidence_value(
    value: &Value,
    stack: &mut HashSet<usize>,
    depth: usize,
) -> Option<String> {
    if let Some(time) = canonical_time_evidence(value) {
        return Some(time);
    }
    Some(match value {
        Value::Unit => "{\"type\":\"Unit\",\"value\":null}".to_owned(),
        Value::Bool(value) => format!("{{\"type\":\"Bool\",\"value\":{value}}}"),
        Value::Int(value) => format!("{{\"type\":\"Int\",\"value\":\"{value}\"}}"),
        Value::Integer(value) => {
            format!("{{\"type\":\"Integer\",\"value\":\"{value}\"}}")
        }
        Value::Double(value) => format!(
            "{{\"type\":\"Double\",\"ieee754Bits\":\"{:016x}\"}}",
            value.to_bits()
        ),
        Value::Character(value) => format!(
            "{{\"type\":\"Character\",\"codePoint\":{}}}",
            u32::from(*value)
        ),
        Value::CaseInsensitive(value) => canonical_case_insensitive_evidence(value, stack, depth)?,
        Value::Text(value) => format!(
            "{{\"type\":\"Text\",\"utf8Hex\":\"{}\"}}",
            evidence_hex(value.as_bytes())
        ),
        Value::Day(_) | Value::DayOfWeek(_) | Value::TimeOfDay(_) | Value::UtcTime(_) => {
            unreachable!("time values return before the general evidence match")
        }
        Value::ByteString(value) => canonical_byte_evidence("ByteString", value),
        Value::Builder(value) => canonical_byte_evidence("Builder", value),
        Value::Io(_) => "{\"type\":\"IoAction\"}".to_owned(),
        Value::Function(FunctionValue::Guest { body, environment }) => {
            canonical_guest_function_evidence(*body, environment, stack, depth)?
        }
        Value::Tuple(elements) => canonical_thunk_sequence("Tuple", elements, stack, depth)?,
        Value::Record { layout, fields } => {
            canonical_record_evidence(layout, fields, stack, depth)?
        }
        Value::Variant {
            layout,
            constructor_index,
            payload,
        } => {
            let constructor = layout.constructors.get(usize::from(*constructor_index))?;
            let payload = payload.as_ref().map_or_else(
                || Some("null".to_owned()),
                |payload| canonical_evidence_thunk(payload, stack, depth.saturating_add(1)),
            )?;
            format!(
                "{{\"type\":\"Variant\",\"typeNameHex\":\"{}\",\"constructorHex\":\"{}\",\"payload\":{payload}}}",
                evidence_hex(layout.type_name.as_bytes()),
                evidence_hex(constructor.name.as_bytes())
            )
        }
        Value::Maybe(payload) => {
            let payload = payload.as_ref().map_or_else(
                || Some("null".to_owned()),
                |payload| canonical_evidence_thunk(payload, stack, depth.saturating_add(1)),
            )?;
            format!("{{\"type\":\"Maybe\",\"payload\":{payload}}}")
        }
        Value::JsonDocument(document, index) => {
            let materialized = json_document_value(document, *index).ok()?;
            return canonical_evidence_value(&materialized, stack, depth.saturating_add(1));
        }
        Value::Tree(tree) => {
            let root = canonical_evidence_thunk(&tree.root, stack, depth.saturating_add(1))?;
            let children =
                canonical_evidence_thunk(&tree.children, stack, depth.saturating_add(1))?;
            format!("{{\"type\":\"Tree\",\"elements\":[{root},{children}]}}")
        }
        Value::PrimitiveVariant(variant) => {
            let payloads = canonical_thunks(&variant.payloads, stack, depth)?;
            format!(
                "{{\"type\":\"PrimitiveVariant\",\"family\":\"{}\",\"constructor\":\"{}\",\"payloads\":[{}]}}",
                primitive_family_name(variant.family),
                variant.constructor_name()?,
                payloads.join(",")
            )
        }
        Value::List(cell) => canonical_list(cell, stack, depth)?,
        Value::Vector(elements) => canonical_thunk_sequence("Vector", elements, stack, depth)?,
        Value::Map(map) => {
            let entries = map
                .iter()
                .map(|(key, value)| {
                    let key = canonical_evidence_thunk(key, stack, depth.saturating_add(1))?;
                    let value = canonical_evidence_thunk(value, stack, depth.saturating_add(1))?;
                    Some(format!("{{\"key\":{key},\"value\":{value}}}"))
                })
                .collect::<Option<Vec<_>>>()?;
            format!("{{\"type\":\"Map\",\"entries\":[{}]}}", entries.join(","))
        }
        Value::Set(set) => {
            let elements = set.iter().cloned().collect::<Vec<_>>();
            canonical_thunk_sequence("Set", &elements, stack, depth)?
        }
        Value::Process(process) => canonical_process_evidence(process),
        Value::OptionsMod(modifiers) => canonical_options_mod_evidence(modifiers)?,
        Value::OptionsInfoMod(modifiers) => canonical_options_info_mod_evidence(modifiers),
        _ => return canonical_evidence_runtime_enum(value),
    })
}

#[cfg(feature = "compat-tracing")]
fn canonical_guest_function_evidence(
    body: CoreId,
    environment: &[ThunkRef],
    stack: &mut HashSet<usize>,
    depth: usize,
) -> Option<String> {
    let captures = canonical_thunks(environment, stack, depth)?;
    Some(format!(
        "{{\"type\":\"GuestFunction\",\"body\":{},\"captures\":[{}]}}",
        body.0,
        captures.join(",")
    ))
}

#[cfg(feature = "compat-tracing")]
fn canonical_time_evidence(value: &Value) -> Option<String> {
    match value {
        Value::Day(value) => Some(format!(
            "{{\"type\":\"Day\",\"iso8601Hex\":\"{}\"}}",
            evidence_hex(value.to_string().as_bytes())
        )),
        Value::DayOfWeek(value) => {
            Some(format!("{{\"type\":\"DayOfWeek\",\"value\":\"{value}\"}}"))
        }
        Value::TimeOfDay(value) => Some(format!(
            "{{\"type\":\"TimeOfDay\",\"iso8601Hex\":\"{}\"}}",
            evidence_hex(value.to_string().as_bytes())
        )),
        Value::UtcTime(value) => Some(format!(
            "{{\"type\":\"UtcTime\",\"iso8601Hex\":\"{}\"}}",
            evidence_hex(value.to_string().as_bytes())
        )),
        _ => None,
    }
}

#[cfg(feature = "compat-tracing")]
fn canonical_process_evidence(process: &ProcessSpec) -> String {
    let command = Path::new(process.command.as_ref());
    let command = if command.file_stem().and_then(|name| name.to_str()) == Some("hell-test-helper")
    {
        "hell-test-helper"
    } else {
        process.command.as_ref()
    };
    let arguments = process
        .arguments
        .iter()
        .map(|argument| format!("\"{}\"", evidence_hex(argument.as_bytes())))
        .collect::<Vec<_>>()
        .join(",");
    let working_directory = process.working_directory.as_ref().map_or_else(
        || "null".to_owned(),
        |directory| format!("\"{}\"", evidence_hex(directory.as_bytes())),
    );
    let environment = process.environment.as_ref().map_or_else(
        || "null".to_owned(),
        |environment| {
            let entries = environment
                .iter()
                .map(|(name, value)| {
                    format!(
                        "{{\"nameHex\":\"{}\",\"valueHex\":\"{}\"}}",
                        evidence_hex(name.as_bytes()),
                        evidence_hex(value.as_bytes())
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("[{entries}]")
        },
    );
    let stdin = canonical_host_handle_evidence(&process.stdin);
    let stdin_bytes = process.stdin_bytes.as_ref().map_or_else(
        || "null".to_owned(),
        |bytes| format!("\"{}\"", evidence_hex(bytes)),
    );
    let stdout = canonical_host_handle_evidence(&process.stdout);
    let stderr = canonical_host_handle_evidence(&process.stderr);
    format!(
        "{{\"type\":\"Process\",\"commandHex\":\"{}\",\"argumentsHex\":[{arguments}],\"workingDirectoryHex\":{working_directory},\"environment\":{environment},\"stdin\":{stdin},\"stdinHex\":{stdin_bytes},\"stdout\":{stdout},\"stderr\":{stderr}}}",
        evidence_hex(command.as_bytes())
    )
}

#[cfg(feature = "compat-tracing")]
fn canonical_host_handle_evidence(handle: &HostHandle) -> String {
    let kind = match handle {
        HostHandle::Stdin => "stdin",
        HostHandle::Stdout => "stdout",
        HostHandle::Stderr => "stderr",
        HostHandle::Null => "null",
        HostHandle::File {
            close_after_process,
            ..
        } => {
            return format!(
                "{{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":{close_after_process}}}"
            );
        }
    };
    format!("{{\"type\":\"Handle\",\"kind\":\"{kind}\"}}")
}

#[cfg(feature = "compat-tracing")]
fn canonical_options_info_mod_evidence(modifiers: &InfoModifiers) -> String {
    let program_description = modifiers.program_description.as_ref().map_or_else(
        || "null".to_owned(),
        |value| format!("\"{}\"", evidence_hex(value.as_bytes())),
    );
    let header = modifiers.header.as_ref().map_or_else(
        || "null".to_owned(),
        |value| format!("\"{}\"", evidence_hex(value.as_bytes())),
    );
    format!(
        "{{\"type\":\"OptionsInfoMod\",\"fullDescription\":{},\"programDescriptionHex\":{program_description},\"headerHex\":{header}}}",
        modifiers.full_description
    )
}

#[cfg(feature = "compat-tracing")]
fn canonical_options_mod_evidence(modifiers: &OptionModifiers) -> Option<String> {
    let modifiers = modifiers
        .0
        .iter()
        .map(|modifier| {
            let (kind, value) = match modifier {
                typeclasses::OptionModifier::Long(value) => ("long", value),
                typeclasses::OptionModifier::Help(value) => ("help", value),
                typeclasses::OptionModifier::Metavar(value) => ("metavar", value),
                typeclasses::OptionModifier::Default(_)
                | typeclasses::OptionModifier::Command { .. } => return None,
            };
            Some(format!(
                "{{\"kind\":\"{kind}\",\"textHex\":\"{}\"}}",
                evidence_hex(value.as_bytes())
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(format!(
        "{{\"type\":\"OptionsMod\",\"modifiers\":[{}]}}",
        modifiers.join(",")
    ))
}

#[cfg(feature = "compat-tracing")]
fn canonical_record_evidence(
    layout: &RecordLayout,
    fields: &[ThunkRef],
    stack: &mut HashSet<usize>,
    depth: usize,
) -> Option<String> {
    let values = layout
        .fields
        .iter()
        .zip(fields)
        .map(|(field, value)| {
            canonical_evidence_thunk(value, stack, depth.saturating_add(1)).map(|value| {
                format!(
                    "{{\"nameHex\":\"{}\",\"value\":{value}}}",
                    evidence_hex(field.name.as_bytes())
                )
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(format!(
        "{{\"type\":\"Record\",\"typeNameHex\":\"{}\",\"constructorHex\":\"{}\",\"fields\":[{}]}}",
        evidence_hex(layout.type_name.as_bytes()),
        evidence_hex(layout.constructor.as_bytes()),
        values.join(",")
    ))
}

#[cfg(feature = "compat-tracing")]
fn canonical_byte_evidence(kind: &str, value: &[u8]) -> String {
    format!(
        "{{\"type\":\"{kind}\",\"hex\":\"{}\"}}",
        evidence_hex(value)
    )
}

#[cfg(feature = "compat-tracing")]
fn canonical_case_insensitive_evidence(
    value: &CaseInsensitiveValue,
    stack: &mut HashSet<usize>,
    depth: usize,
) -> Option<String> {
    let original = canonical_evidence_thunk(&value.original, stack, depth.saturating_add(1))?;
    let folded = canonical_evidence_thunk(&value.folded, stack, depth.saturating_add(1))?;
    Some(format!(
        "{{\"type\":\"CaseInsensitive\",\"original\":{original},\"folded\":{folded}}}"
    ))
}

#[cfg(feature = "compat-tracing")]
fn canonical_evidence_runtime_enum(value: &Value) -> Option<String> {
    if let Value::Handle(handle) = value {
        return Some(canonical_host_handle_evidence(handle));
    }
    let (kind, variant) = match value {
        Value::BufferMode(mode) => (
            "BufferMode",
            match mode {
                BufferMode::None => "none",
                BufferMode::Line => "line",
                BufferMode::Block => "block",
            },
        ),
        Value::FileMode(mode) => (
            "FileMode",
            match mode {
                FileMode::Read => "read",
                FileMode::Write => "write",
                FileMode::Append => "append",
                FileMode::ReadWrite => "read-write",
            },
        ),
        _ => return None,
    };
    Some(format!("{{\"type\":\"{kind}\",\"value\":\"{variant}\"}}"))
}

#[cfg(feature = "compat-tracing")]
fn canonical_thunk_sequence(
    kind: &str,
    elements: &[ThunkRef],
    stack: &mut HashSet<usize>,
    depth: usize,
) -> Option<String> {
    let elements = canonical_thunks(elements, stack, depth)?;
    Some(format!(
        "{{\"type\":\"{kind}\",\"elements\":[{}]}}",
        elements.join(",")
    ))
}

#[cfg(feature = "compat-tracing")]
fn canonical_thunks(
    elements: &[ThunkRef],
    stack: &mut HashSet<usize>,
    depth: usize,
) -> Option<Vec<String>> {
    elements
        .iter()
        .map(|element| canonical_evidence_thunk(element, stack, depth.saturating_add(1)))
        .collect()
}

#[cfg(feature = "compat-tracing")]
fn canonical_list(cell: &ListCell, stack: &mut HashSet<usize>, depth: usize) -> Option<String> {
    const MAX_ELEMENTS: usize = 1_024;
    let mut current = cell.clone();
    let mut elements = Vec::new();
    let termination = loop {
        match current {
            ListCell::Nil => break "nil".to_owned(),
            ListCell::Cons { head, tail } => {
                if elements.len() == MAX_ELEMENTS {
                    break "element-limit".to_owned();
                }
                elements.push(canonical_evidence_thunk(
                    &head,
                    stack,
                    depth.saturating_add(1),
                )?);
                let state = tail.state.lock().ok()?;
                match &*state {
                    ThunkState::Evaluated(value) => {
                        let Value::List(next) = value.as_ref() else {
                            return None;
                        };
                        current = next.clone();
                    }
                    ThunkState::Indirection(next) => {
                        let encoded =
                            canonical_evidence_thunk(next, stack, depth.saturating_add(1))?;
                        break format!("indirection:{encoded}");
                    }
                    ThunkState::Failed(error) => break format!("error:{}", error.code),
                    ThunkState::Suspended(_) => break "not-forced".to_owned(),
                    ThunkState::Evaluating { .. } => break "in-progress".to_owned(),
                }
            }
        }
    };
    Some(format!(
        "{{\"type\":\"List\",\"elements\":[{}],\"terminationHex\":\"{}\"}}",
        elements.join(","),
        evidence_hex(termination.as_bytes())
    ))
}

#[cfg(feature = "compat-tracing")]
const fn primitive_family_name(family: PrimitiveFamily) -> &'static str {
    match family {
        PrimitiveFamily::Either => "Either",
        PrimitiveFamily::Exit => "Exit",
        PrimitiveFamily::These => "These",
        PrimitiveFamily::Json => "Json",
    }
}

#[cfg(feature = "compat-tracing")]
fn evidence_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul("00".len()));
    for byte in bytes {
        std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"))
            .expect("writing to String cannot fail");
    }
    output
}

fn write_evidence_resource_audit(
    snapshot: &scope::ScopeSnapshot,
    cleanup_failures: usize,
) -> RuntimeResult<()> {
    let Some(path) = std::env::var_os("HELL_EVIDENCE_RESOURCE_AUDIT").map(PathBuf::from) else {
        return Ok(());
    };
    let contents = evidence_resource_audit_contents(snapshot, cleanup_failures);
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    std::fs::write(&temporary, contents.as_bytes()).map_err(|error| {
        RuntimeError::internal(format!("cannot write evidence resource audit: {error}"))
    })?;
    std::fs::rename(&temporary, &path).map_err(|error| {
        RuntimeError::internal(format!("cannot retain evidence resource audit: {error}"))
    })
}

fn evidence_resource_audit_contents(
    snapshot: &scope::ScopeSnapshot,
    cleanup_failures: usize,
) -> String {
    let budget = &snapshot.budget;
    let tasks = snapshot
        .child_scopes
        .saturating_add(snapshot.live_tasks)
        .saturating_add(usize::try_from(budget.live_tasks).unwrap_or(usize::MAX));
    let handles = usize::try_from(budget.live_handles)
        .unwrap_or(usize::MAX)
        .saturating_add(snapshot.resources)
        .saturating_add(snapshot.finalizers);
    let processes = usize::try_from(budget.live_processes).unwrap_or(usize::MAX);
    let http_bodies = usize::try_from(budget.live_http_connections).unwrap_or(usize::MAX);
    let temporary_resources = usize::try_from(budget.live_temp_resources).unwrap_or(usize::MAX);
    format!(
        concat!(
            "{{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"tasks\": {},\n",
            "  \"handles\": {},\n",
            "  \"processes\": {},\n",
            "  \"httpBodies\": {},\n",
            "  \"temporaryResources\": {},\n",
            "  \"cleanupFailures\": {}\n",
            "}}\n"
        ),
        tasks, handles, processes, http_bodies, temporary_resources, cleanup_failures,
    )
}

#[cfg(all(test, feature = "compat-tracing"))]
mod semantic_trace_tests {
    use super::{
        EffectCausalIdentity, EffectEvidence, Evaluator, EvidenceTrace, RuntimeContext, Thunk,
        Value, canonical_semantic_event_arrays, semantic_trace_contents,
    };
    use hell_builtins::lookup;
    use hell_compiler::{CompilerSession, compile_source};
    use hell_core::ExecutableProgram;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("trace writer lock").extend(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn execute_main(
        executable: &Arc<ExecutableProgram>,
        tracing: bool,
        concurrent_actions: usize,
    ) -> (Vec<u8>, Option<String>) {
        let mut evaluator =
            Evaluator::new(Arc::clone(executable)).with_max_concurrent_actions(concurrent_actions);
        evaluator.evidence_trace =
            tracing.then(|| Arc::new(Mutex::new(EvidenceTrace::from_program(executable))));
        let output = Arc::new(Mutex::new(Vec::new()));
        let context = RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&output)));
        let root = evaluator.root_thunk();
        let action = evaluator.force_io(&root).expect("main action");
        let result = action.run(&mut evaluator, &context).expect("main result");
        assert!(matches!(
            evaluator.force(&result).expect("forced result").as_ref(),
            Value::Unit
        ));
        let snapshot = evaluator.execution_scope().snapshot();
        assert_eq!(snapshot.child_scopes, 0);
        assert_eq!(snapshot.live_tasks, 0);
        assert_eq!(snapshot.resources, 0);
        assert_eq!(snapshot.finalizers, 0);
        assert_eq!(snapshot.budget.live_tasks, 0);
        assert_eq!(snapshot.budget.live_handles, 0);
        assert_eq!(snapshot.budget.live_processes, 0);
        assert_eq!(snapshot.budget.live_http_connections, 0);
        assert_eq!(snapshot.budget.live_temp_resources, 0);
        let retained_trace = evaluator.evidence_trace.as_ref().map(|trace| {
            let trace = trace.lock().expect("semantic trace lock");
            assert!(trace.live_resources.is_empty());
            semantic_trace_contents(&trace).expect("retained semantic trace")
        });
        let bytes = output.lock().expect("trace output lock").clone();
        (bytes, retained_trace)
    }

    #[test]
    fn concurrent_event_interleavings_have_one_canonical_trace() {
        let task_builtin = lookup("Async.concurrently")
            .expect("concurrency builtin")
            .id;
        let resource_builtin = lookup("IO.openFile").expect("resource builtin").id;
        let typed = Thunk::evaluated(Value::Int(7));
        let first = EvidenceTrace {
            entered_adapters: vec![resource_builtin, task_builtin],
            typed_results: vec![(task_builtin, 0, "conditional-selected", typed.clone())],
            task_events: vec![
                (task_builtin, 20, "started"),
                (task_builtin, 10, "started"),
                (task_builtin, 10, "completed"),
                (task_builtin, 20, "completed"),
            ],
            resource_events: vec![
                (resource_builtin, 99, Some(10), "acquire"),
                (resource_builtin, 99, Some(10), "close"),
            ],
            next_resource_id: 1,
            ..EvidenceTrace::default()
        };
        let second = EvidenceTrace {
            entered_adapters: vec![task_builtin, resource_builtin],
            typed_results: vec![(task_builtin, 0, "conditional-selected", typed)],
            task_events: vec![
                (task_builtin, 4, "started"),
                (task_builtin, 8, "started"),
                (task_builtin, 8, "completed"),
                (task_builtin, 4, "completed"),
            ],
            resource_events: vec![
                (resource_builtin, 3, Some(8), "acquire"),
                (resource_builtin, 3, Some(8), "close"),
            ],
            next_resource_id: 1,
            ..EvidenceTrace::default()
        };
        assert_eq!(
            canonical_semantic_event_arrays(&first).expect("first canonical trace"),
            canonical_semantic_event_arrays(&second).expect("second canonical trace")
        );

        let terminal_before_start = EvidenceTrace {
            task_events: vec![(task_builtin, 1, "completed"), (task_builtin, 1, "started")],
            ..EvidenceTrace::default()
        };
        assert!(
            canonical_semantic_event_arrays(&terminal_before_start)
                .expect_err("terminal-before-start must be rejected")
                .message
                .contains("start-to-terminal")
        );
        let changed_task_builtin = EvidenceTrace {
            task_events: vec![
                (task_builtin, 1, "started"),
                (resource_builtin, 1, "completed"),
            ],
            ..EvidenceTrace::default()
        };
        assert!(
            canonical_semantic_event_arrays(&changed_task_builtin)
                .expect_err("task builtin alias must be rejected")
                .message
                .contains("changes builtin identity")
        );
        let close_before_acquire = EvidenceTrace {
            resource_events: vec![
                (resource_builtin, 1, None, "close"),
                (resource_builtin, 1, None, "acquire"),
            ],
            next_resource_id: 1,
            ..EvidenceTrace::default()
        };
        assert!(
            canonical_semantic_event_arrays(&close_before_acquire)
                .expect_err("close-before-acquire must be rejected")
                .message
                .contains("acquire-to-terminal")
        );
    }

    #[test]
    fn cancelled_task_closes_its_active_effect_invocations() {
        let source = "main = IO.pure ()\n";
        let program = compile_source(&mut CompilerSession::upstream(), "cancel.hell", source)
            .expect("fixture compiles");
        let executable = Arc::new(program.executable().clone());
        let task_builtin = lookup("Async.race").expect("task builtin").id;
        let effect_builtin = lookup("Concurrent.threadDelay").expect("effect builtin").id;
        let identity = EffectCausalIdentity {
            builtin: effect_builtin,
            owner_task: Some(1),
            sequence: 1,
            parent_sequence: None,
        };
        let trace = Arc::new(Mutex::new(EvidenceTrace {
            task_events: vec![(task_builtin, 1, "started")],
            effect_events: vec![EffectEvidence {
                identity,
                lifecycle: "started",
            }],
            ..EvidenceTrace::from_program(&executable)
        }));
        let mut evaluator = Evaluator::new(executable);
        evaluator.evidence_trace = Some(Arc::clone(&trace));
        evaluator
            .record_task_terminal(task_builtin, 1, "cancelled")
            .expect("cancellation closes active effects");
        let retained = semantic_trace_contents(&trace.lock().expect("trace lock"))
            .expect("cancelled effect trace is canonical");
        assert!(retained.contains("\"effect\": \"cancelled\""));
    }

    #[test]
    fn tracing_enabled_and_disabled_have_identical_typed_results() {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            "trace-control.hell",
            "main = IO.print $ Bool.bool 42 2 Bool.True\n".to_owned(),
        )
        .expect("trace control compiles");
        let executable = Arc::new(program.executable().clone());
        assert_eq!(
            execute_main(&executable, false, 2).0,
            execute_main(&executable, true, 2).0
        );
    }

    #[test]
    fn callback_heavy_execution_is_identical_with_and_without_tracing() {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            "callback-trace-control.hell",
            concat!(
                "main = do\n",
                "  IO.print $ List.map (Int.plus 10) [1,2,3]\n",
                "  values <- Monad.mapM (\\value -> IO.pure (Int.plus value 20)) [4,5]\n",
                "  IO.print values\n",
            ),
        )
        .expect("callback trace control compiles");
        let executable = Arc::new(program.executable().clone());
        assert_eq!(
            execute_main(&executable, false, 2).0,
            execute_main(&executable, true, 2).0
        );
    }

    #[test]
    fn callback_parent_fallback_is_plain_without_trace_and_strict_with_trace() {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            "callback-parent.hell",
            "main = IO.pure ()\n",
        )
        .expect("fixture compiles");
        let executable = Arc::new(program.executable().clone());
        let mut evaluator = Evaluator::new(Arc::clone(&executable));
        let function = Thunk::evaluated(Value::Int(1));
        let argument = Thunk::evaluated(Value::Int(2));
        assert!(
            evaluator
                .callback_application(Arc::clone(&function), &[Arc::clone(&argument)], 0, "test",)
                .is_ok()
        );
        assert!(evaluator.register_current_adapter_child(&argument).is_ok());

        evaluator.evidence_trace = Some(Arc::new(Mutex::new(EvidenceTrace::from_program(
            &executable,
        ))));
        let error = evaluator
            .callback_application(function, &[Arc::clone(&argument)], 0, "test")
            .expect_err("traced callback without a target parent must fail");
        assert!(error.message.contains("no logical target adapter"));
        let error = evaluator
            .register_current_adapter_child(&argument)
            .expect_err("traced deferred child without a target parent must fail");
        assert!(error.message.contains("no logical adapter"));
    }

    #[test]
    fn repeated_real_pooled_runs_have_identical_traces_and_no_leaks() {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            "pooled-trace-control.hell",
            concat!(
                "work = \\value -> do\n",
                "  Concurrent.threadDelay (Int.mult value 100)\n",
                "  IO.pure value\n",
                "main = Monad.bind ",
                "(Async.pooledMapConcurrently Main.work [7, 1, 5, 2, 4, 3, 6]) IO.print\n",
            )
            .to_owned(),
        )
        .expect("pooled trace control compiles");
        let executable = Arc::new(program.executable().clone());
        let expected = execute_main(&executable, true, 3);
        assert_eq!(expected.0, b"[7,1,5,2,4,3,6]\n");
        for _ in 0..12 {
            assert_eq!(execute_main(&executable, true, 3), expected);
        }
    }
}
