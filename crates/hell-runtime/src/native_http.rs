//! HTTP/1 server values and adapters for the WAI-shaped guest API.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hell_http_host::{
    Application as HostApplication, BodyProducer, BodySink, Cancellation as HostCancellation,
    Header as HostHeader, HostError, HostRequest, HostResponse, ResponseBody, ServerConfig,
};

use crate::budget::BudgetPermit;
use crate::concurrency::CancelReason;
use crate::native_integer::BigInteger;
use crate::policy::{Limit, RuntimeProfile};
use crate::scope::{ChildScopePolicy, ResourceKind, ScopeGuard, ScopedResource};
use crate::typeclasses::CaseInsensitiveValue;
use crate::{
    Evaluator, ForceOutcome, FunctionValue, HostFunction, IoAction, RuntimeContext, RuntimeError,
    RuntimeResult, Suspension, Thunk, ThunkRef, Value, list_from_values,
};

const SANDBOX_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_RESPONSE_ID: AtomicU64 = AtomicU64::new(1);

type Header = (Arc<[u8]>, Arc<[u8]>);
type QueryParameter = (Arc<[u8]>, Option<Arc<[u8]>>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    code: u16,
    reason: Arc<[u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePart {
    offset: BigInteger,
    byte_count: BigInteger,
    file_size: BigInteger,
}

#[derive(Debug)]
pub struct Request {
    alive: AtomicBool,
    path: Arc<[Arc<str>]>,
    headers: Arc<[Header]>,
    query: Arc<[QueryParameter]>,
    body: Arc<hell_http_host::RequestBody>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpVersion {
    Http10,
    Http11,
}

#[derive(Debug)]
pub struct Response {
    kind: ResponseKind,
}

#[derive(Debug)]
enum ResponseKind {
    Builder {
        status: ThunkRef,
        headers: ThunkRef,
        builder: ThunkRef,
    },
    File {
        status: ThunkRef,
        headers: ThunkRef,
        path: ThunkRef,
        part: ThunkRef,
    },
    Stream {
        status: ThunkRef,
        headers: ThunkRef,
        callback: ThunkRef,
    },
}

pub(crate) fn apply_native(
    implementation: &str,
    arguments: &[ThunkRef],
    evaluator: &mut Evaluator,
) -> Option<RuntimeResult<ForceOutcome>> {
    let value = |value| Ok(ForceOutcome::Value(Arc::new(value)));
    Some(match implementation {
        "builder_byte_string" => evaluator
            .force_bytes(&arguments[0])
            .and_then(|bytes| value(Value::Builder(bytes))),
        "http_status" => {
            make_status(evaluator, arguments).and_then(|status| value(Value::HttpStatus(status)))
        }
        "http_file_part" => {
            make_file_part(evaluator, arguments).and_then(|part| value(Value::HttpFilePart(part)))
        }
        "http_path_info" => request(evaluator, &arguments[0]).map(|request| {
            ForceOutcome::Alias(list_from_values(
                request
                    .path
                    .iter()
                    .map(|part| Thunk::evaluated(Value::Text(Arc::clone(part))))
                    .collect(),
            ))
        }),
        "http_request_headers" => request(evaluator, &arguments[0]).map(|request| {
            let mut headers = request
                .headers
                .iter()
                .map(|(name, value)| {
                    let original = Thunk::evaluated(Value::ByteString(Arc::clone(name)));
                    let folded = Thunk::evaluated(Value::ByteString(Arc::from(
                        name.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>(),
                    )));
                    Thunk::evaluated(Value::Tuple(
                        [
                            Thunk::evaluated(Value::CaseInsensitive(CaseInsensitiveValue {
                                original,
                                folded,
                            })),
                            Thunk::evaluated(Value::ByteString(Arc::clone(value))),
                        ]
                        .into(),
                    ))
                })
                .collect::<Vec<_>>();
            if crate::semantic_mutant_active("http-duplicate-header-collapse") {
                headers.truncate(2);
            }
            ForceOutcome::Alias(list_from_values(headers))
        }),
        "http_query_string" => request(evaluator, &arguments[0]).map(|request| {
            let query = request
                .query
                .iter()
                .map(|(name, value)| {
                    Thunk::evaluated(Value::Tuple(
                        [
                            Thunk::evaluated(Value::ByteString(Arc::clone(name))),
                            Thunk::evaluated(Value::Maybe(value.as_ref().map(|value| {
                                Thunk::evaluated(Value::ByteString(Arc::clone(value)))
                            }))),
                        ]
                        .into(),
                    ))
                })
                .collect();
            ForceOutcome::Alias(list_from_values(query))
        }),
        "http_get_body_chunk" => request(evaluator, &arguments[0])
            .and_then(|request| value(Value::Io(body_action(request, false)))),
        "http_consume_body" => request(evaluator, &arguments[0])
            .and_then(|request| value(Value::Io(body_action(request, true)))),
        "http_response_builder" => value(Value::HttpResponse(Arc::new(Response {
            kind: ResponseKind::Builder {
                status: Arc::clone(&arguments[0]),
                headers: Arc::clone(&arguments[1]),
                builder: Arc::clone(&arguments[2]),
            },
        }))),
        "http_response_file" => value(Value::HttpResponse(Arc::new(Response {
            kind: ResponseKind::File {
                status: Arc::clone(&arguments[0]),
                headers: Arc::clone(&arguments[1]),
                path: Arc::clone(&arguments[2]),
                part: Arc::clone(&arguments[3]),
            },
        }))),
        "http_response_stream" => value(Value::HttpResponse(Arc::new(Response {
            kind: ResponseKind::Stream {
                status: Arc::clone(&arguments[0]),
                headers: Arc::clone(&arguments[1]),
                callback: Arc::clone(&arguments[2]),
            },
        }))),
        "http_run" => value(Value::Io(run_server(
            Arc::clone(&arguments[0]),
            Arc::clone(&arguments[1]),
        ))),
        _ => return None,
    })
}

fn make_status(evaluator: &mut Evaluator, arguments: &[ThunkRef]) -> RuntimeResult<Status> {
    let code = evaluator.force_int(&arguments[0])?;
    let code = u16::try_from(code)
        .ok()
        .filter(|code| (100..=999).contains(code))
        .ok_or_else(|| RuntimeError::http("Http.mkStatus: status code must be three digits"))?;
    let reason = evaluator.force_text(&arguments[1])?;
    validate_reason(reason.as_bytes(), evaluator.policy.limits.http_reason_bytes)?;
    Ok(Status {
        code,
        reason: Arc::from(reason.as_bytes()),
    })
}

fn make_file_part(evaluator: &mut Evaluator, arguments: &[ThunkRef]) -> RuntimeResult<FilePart> {
    Ok(FilePart {
        offset: (*evaluator.force_integer(&arguments[0])?).clone(),
        byte_count: (*evaluator.force_integer(&arguments[1])?).clone(),
        file_size: (*evaluator.force_integer(&arguments[2])?).clone(),
    })
}

fn request(evaluator: &mut Evaluator, value: &ThunkRef) -> RuntimeResult<Arc<Request>> {
    let value = evaluator.force(value)?;
    let Value::HttpRequest(request) = value.as_ref() else {
        return Err(RuntimeError::internal(
            "HTTP operation received a non-Request value",
        ));
    };
    request.ensure_alive()?;
    Ok(Arc::clone(request))
}

impl Request {
    fn ensure_alive(&self) -> RuntimeResult<()> {
        if self.alive.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(RuntimeError::resource_closed(
                "HTTP request was used after its callback completed",
            ))
        }
    }

    fn close(&self) {
        self.alive.store(false, Ordering::Release);
    }
}

fn body_action(request: Arc<Request>, consume_remainder: bool) -> IoAction {
    IoAction::new(move |evaluator, _| {
        evaluator.ensure_not_cancelled()?;
        request.ensure_alive()?;
        let bytes = if consume_remainder {
            let mut output = Vec::new();
            while let Some(chunk) = request
                .body
                .next_chunk()
                .map_err(|error| RuntimeError::http(error.message()))?
            {
                output.extend_from_slice(&chunk);
            }
            output
        } else {
            request
                .body
                .next_chunk()
                .map_err(|error| RuntimeError::http(error.message()))?
                .map_or_else(Vec::new, |bytes| bytes.to_vec())
        };
        Ok(Thunk::evaluated(Value::ByteString(bytes.into())))
    })
}

struct RuntimeHttpApplication {
    application: ThunkRef,
    evaluator: Mutex<Evaluator>,
    context: RuntimeContext,
    first_error: Arc<Mutex<Option<Arc<RuntimeError>>>>,
}

struct ScopedHttpServer {
    cancellation: HostCancellation,
    cancellation_requested: AtomicBool,
    closed: Arc<AtomicBool>,
}

impl ScopedResource for ScopedHttpServer {
    fn kind(&self) -> ResourceKind {
        ResourceKind::Listener
    }

    fn request_cancel(&self, _reason: &CancelReason) {
        self.cancellation_requested.store(true, Ordering::Release);
        if !crate::semantic_mutant_active("process-stream-cancellation") {
            self.cancellation.cancel();
        }
    }

    fn close(&self) -> RuntimeResult<()> {
        let mutated_cancel_path = crate::semantic_mutant_active("process-stream-cancellation")
            && self.cancellation_requested.load(Ordering::Acquire);
        if !mutated_cancel_path {
            self.cancellation.cancel();
        }
        self.closed.store(true, Ordering::Release);
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl HostApplication for RuntimeHttpApplication {
    fn call(&self, request: HostRequest) -> Result<HostResponse, HostError> {
        let task_permit = self
            .context
            .budget
            .acquire_task()
            .map_err(|error| self.host_error(&error))?;
        let template = self
            .evaluator
            .lock()
            .map_err(|_| HostError::new("HTTP evaluator template mutex was poisoned"))?;
        let request_scope = template
            .execution_scope()
            .child(ChildScopePolicy::default())
            .map_err(|error| self.host_error(&error))?
            .guard();
        let runtime_cancellation = request_scope.cancellation().clone();
        let mut evaluator = template.fork_with_scope((*request_scope).clone());
        drop(template);
        request
            .cancellation
            .on_cancel(move || runtime_cancellation.cancel(CancelReason::ParentCancelled));
        let (path, query) = parse_target(&request.target);
        let version = match request.version {
            hell_http_host::HttpVersion::Http10 => HttpVersion::Http10,
            hell_http_host::HttpVersion::Http11 => HttpVersion::Http11,
        };
        let method = Arc::clone(&request.method);
        let runtime_request = Arc::new(Request {
            alive: AtomicBool::new(true),
            path: path.into(),
            headers: request
                .headers
                .iter()
                .map(|header| (Arc::clone(&header.name), Arc::clone(&header.value)))
                .collect::<Vec<_>>()
                .into(),
            query: query.into(),
            body: Arc::clone(&request.body),
        });
        let response = invoke_application_response(
            &runtime_request,
            Arc::clone(&self.application),
            &mut evaluator,
            &self.context,
        )
        .and_then(|response| {
            prepare_host_response(
                &response,
                evaluator,
                self.context.clone(),
                ascii_eq(&method, b"HEAD"),
                version,
                request.cancellation,
                Arc::clone(&self.first_error),
                task_permit,
                request_scope,
            )
        });
        runtime_request.close();
        response.map_err(|error| self.host_error(&error))
    }
}

impl RuntimeHttpApplication {
    fn host_error(&self, error: &Arc<RuntimeError>) -> HostError {
        if let Ok(mut first_error) = self.first_error.lock()
            && first_error.is_none()
        {
            *first_error = Some(Arc::clone(error));
        }
        HostError::new(error.to_string())
    }
}

fn run_server(port: ThunkRef, application: ThunkRef) -> IoAction {
    IoAction::new(move |evaluator, context| {
        context.require_network("Http.run")?;
        let port = evaluator.force_int(&port)?;
        let port = u16::try_from(port)
            .map_err(|_| RuntimeError::http("Http.run: port must be between 0 and 65535"))?;
        let cancellation = evaluator.child_cancellation();
        let shutdown_cancellation = cancellation.clone();
        let server_cancellation = cancellation.clone();
        let host_shutdown = HostCancellation::new();
        let server_resource = evaluator.execution_scope().register(ScopedHttpServer {
            cancellation: host_shutdown.clone(),
            cancellation_requested: AtomicBool::new(false),
            closed: Arc::new(AtomicBool::new(false)),
        })?;
        let first_error = Arc::new(Mutex::new(None));
        let server_scope = evaluator
            .execution_scope()
            .child(ChildScopePolicy::default())?
            .guard();
        let application = Arc::new(RuntimeHttpApplication {
            application: Arc::clone(&application),
            evaluator: Mutex::new(evaluator.fork_with_scope((*server_scope).clone())),
            context: context.clone(),
            first_error: Arc::clone(&first_error),
        });
        let limits = &context.policy.limits;
        let connection_budget = Arc::clone(&context.budget);
        let cancellation_propagates = !crate::semantic_mutant_active("process-stream-cancellation");
        let mut config = ServerConfig {
            port,
            loopback_only: !context.policy.capabilities.network_external,
            max_connections: limits.http_connections.value(),
            max_headers: limits
                .http_header_count
                .value()
                .and_then(|limit| usize::try_from(limit).ok()),
            max_header_bytes: limits
                .http_header_bytes
                .value()
                .and_then(|limit| usize::try_from(limit).ok()),
            max_body_bytes: limits.http_body_bytes.value(),
            idle_timeout: (context.policy.profile != RuntimeProfile::Upstream)
                .then_some(SANDBOX_SOCKET_TIMEOUT),
            graceful_shutdown: context.policy.cancellation.graceful_shutdown,
            request_limit: context.http_request_limit,
            shutdown_requested: Arc::new(move || {
                cancellation_propagates
                    && (shutdown_cancellation.is_cancelled() || host_shutdown.is_cancelled())
            }),
            acquire_connection: Arc::new(move || {
                connection_budget
                    .acquire_http_connection()
                    .map(|permit| Box::new(permit) as Box<dyn Send>)
                    .map_err(|error| HostError::new(error.to_string()))
            }),
        };
        let result = match context.take_http_listener()? {
            Some((listener, startup, embedding_shutdown)) => {
                let runtime_shutdown = Arc::clone(&config.shutdown_requested);
                config.shutdown_requested = Arc::new(move || {
                    runtime_shutdown() || embedding_shutdown.load(Ordering::Acquire)
                });
                hell_http_host::serve_with_listener(config, application, listener, &startup)
            }
            None => hell_http_host::serve(config, application),
        };
        server_resource
            .resource()
            .closed
            .store(true, Ordering::Release);
        let body = (|| {
            if server_cancellation.is_cancelled() {
                return Ok(Thunk::evaluated(Value::Unit));
            }
            if let Some(error) = first_error
                .lock()
                .map_err(|_| RuntimeError::internal("HTTP server error mutex was poisoned"))?
                .take()
            {
                return Err(error);
            }
            result.map_err(|error| RuntimeError::http(error.message()))?;
            Ok(Thunk::evaluated(Value::Unit))
        })();
        let cleanup = server_scope.close().map(|_| ());
        crate::finish_with_cleanup(body, [cleanup])
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn prepare_host_response(
    response: &Response,
    mut evaluator: Evaluator,
    context: RuntimeContext,
    suppress_body: bool,
    version: HttpVersion,
    cancellation: HostCancellation,
    first_error: Arc<Mutex<Option<Arc<RuntimeError>>>>,
    task_permit: BudgetPermit,
    request_scope: ScopeGuard,
) -> RuntimeResult<HostResponse> {
    match &response.kind {
        ResponseKind::Builder {
            status,
            headers,
            builder,
        } => {
            let status = force_status(&mut evaluator, status)?;
            let headers = force_headers(&mut evaluator, headers)?;
            let bytes = force_builder(&mut evaluator, builder)?;
            validate_response_framing_headers(&headers)?;
            if response_content_length(&headers)?.is_some_and(|length| length != bytes.len()) {
                return Err(RuntimeError::http(
                    "HTTP response Content-Length does not match the builder body",
                ));
            }
            if response_is_chunked(&headers) && version == HttpVersion::Http10 {
                return Err(RuntimeError::http(
                    "HTTP/1.0 response cannot use chunked Transfer-Encoding",
                ));
            }
            let forbidden = status_forbids_body(status.code);
            let mut host_headers = host_headers(headers);
            if suppress_body
                && !forbidden
                && response_content_length_from_host(&host_headers).is_none()
            {
                host_headers.push(content_length_header(bytes.len()));
            }
            let body = if suppress_body || forbidden {
                drop(task_permit);
                request_scope.close()?;
                ResponseBody::Empty
            } else if response_is_chunked_host(&host_headers) {
                ResponseBody::Stream {
                    producer: Box::new(FixedBodyProducer {
                        bytes,
                        cancellation,
                        _task_permit: task_permit,
                        _scope: request_scope,
                    }),
                    content_length: None,
                }
            } else {
                drop(task_permit);
                request_scope.close()?;
                ResponseBody::Fixed(bytes)
            };
            Ok(host_response(status, host_headers, body))
        }
        ResponseKind::File {
            status,
            headers,
            path,
            part,
        } => {
            let status = force_status(&mut evaluator, status)?;
            let headers = force_headers(&mut evaluator, headers)?;
            let path = evaluator.force_text(path)?;
            let path = context.resolve_path("Http.responseFile", &path)?;
            let mut file = File::open(path).map_err(|error| http_io("Http.responseFile", error))?;
            let actual_size = file
                .metadata()
                .map_err(|error| http_io("Http.responseFile", error))?
                .len();
            let part_value = evaluator.force(part)?;
            let (offset, count) = match part_value.as_ref() {
                Value::Maybe(None) => (0, actual_size),
                Value::Maybe(Some(part)) => {
                    let part = evaluator.force(part)?;
                    let Value::HttpFilePart(part) = part.as_ref() else {
                        return Err(RuntimeError::internal(
                            "Http.responseFile received a non-FilePart value",
                        ));
                    };
                    let offset = part.offset.to_u64().ok_or_else(|| {
                        RuntimeError::http(
                            "Http.responseFile: file offset is negative or too large",
                        )
                    })?;
                    let count = part.byte_count.to_u64().ok_or_else(|| {
                        RuntimeError::http("Http.responseFile: byte count is negative or too large")
                    })?;
                    let declared_size = part.file_size.to_u64().ok_or_else(|| {
                        RuntimeError::http("Http.responseFile: file size is negative or too large")
                    })?;
                    let end = offset.checked_add(count).ok_or_else(|| {
                        RuntimeError::http("Http.responseFile: file range overflowed")
                    })?;
                    if end > actual_size || end > declared_size {
                        return Err(RuntimeError::http(
                            "Http.responseFile: file range exceeds the file size",
                        ));
                    }
                    (offset, count)
                }
                _ => {
                    return Err(RuntimeError::internal(
                        "Http.responseFile received a non-Maybe FilePart value",
                    ));
                }
            };
            file.seek(SeekFrom::Start(offset))
                .map_err(|error| http_io("Http.responseFile", error))?;
            let length = usize::try_from(count).map_err(|_| {
                RuntimeError::http("Http.responseFile body is too large for this host")
            })?;
            validate_response_framing_headers(&headers)?;
            if response_content_length(&headers)?.is_some_and(|declared| declared != length) {
                return Err(RuntimeError::http(
                    "HTTP response Content-Length does not match the file body",
                ));
            }
            if response_is_chunked(&headers) && version == HttpVersion::Http10 {
                return Err(RuntimeError::http(
                    "HTTP/1.0 response cannot use chunked Transfer-Encoding",
                ));
            }
            let forbidden = status_forbids_body(status.code);
            let mut host_headers = host_headers(headers);
            if suppress_body
                && !forbidden
                && response_content_length_from_host(&host_headers).is_none()
            {
                host_headers.push(content_length_header(length));
            }
            let body = if suppress_body || forbidden {
                request_scope.close()?;
                ResponseBody::Empty
            } else {
                let content_length = (!response_is_chunked_host(&host_headers)).then_some(count);
                ResponseBody::Stream {
                    producer: Box::new(FileBodyProducer {
                        file,
                        remaining: count,
                        evaluator,
                        first_error,
                        cancellation,
                        _task_permit: task_permit,
                        _scope: request_scope,
                    }),
                    content_length,
                }
            };
            Ok(host_response(status, host_headers, body))
        }
        ResponseKind::Stream {
            status,
            headers,
            callback,
        } => {
            let status = force_status(&mut evaluator, status)?;
            let headers = force_headers(&mut evaluator, headers)?;
            validate_response_framing_headers(&headers)?;
            let forbidden = status_forbids_body(status.code);
            let supplied_length = response_content_length(&headers)?;
            if response_is_chunked(&headers) && version == HttpVersion::Http10 {
                return Err(RuntimeError::http(
                    "HTTP/1.0 response cannot use chunked Transfer-Encoding",
                ));
            }
            let host_headers = host_headers(headers);
            let body = if suppress_body || forbidden {
                request_scope.close()?;
                ResponseBody::Empty
            } else {
                ResponseBody::Stream {
                    producer: Box::new(StreamBodyProducer {
                        callback: Arc::clone(callback),
                        evaluator,
                        context,
                        remaining: supplied_length.map(|length| Arc::new(Mutex::new(length))),
                        cancellation,
                        first_error,
                        _task_permit: task_permit,
                        _scope: request_scope,
                    }),
                    content_length: supplied_length.and_then(|length| u64::try_from(length).ok()),
                }
            };
            Ok(host_response(status, host_headers, body))
        }
    }
}

fn host_response(status: Status, headers: Vec<HostHeader>, body: ResponseBody) -> HostResponse {
    HostResponse {
        status: status.code,
        reason: status.reason,
        headers,
        body,
    }
}

fn host_headers(headers: Vec<Header>) -> Vec<HostHeader> {
    headers
        .into_iter()
        .map(|(name, value)| HostHeader { name, value })
        .collect()
}

fn response_content_length_from_host(headers: &[HostHeader]) -> Option<usize> {
    headers
        .iter()
        .find(|header| ascii_eq(&header.name, b"content-length"))
        .and_then(|header| parse_content_length(&header.value).ok())
}

fn response_is_chunked_host(headers: &[HostHeader]) -> bool {
    headers.iter().any(|header| {
        ascii_eq(&header.name, b"transfer-encoding")
            && header
                .value
                .split(|byte| *byte == b',')
                .map(trim_optional_whitespace)
                .any(|token| ascii_eq(token, b"chunked"))
    })
}

fn content_length_header(length: usize) -> HostHeader {
    HostHeader {
        name: Arc::from(b"Content-Length".as_slice()),
        value: Arc::from(length.to_string().into_bytes()),
    }
}

struct FixedBodyProducer {
    bytes: Arc<[u8]>,
    cancellation: HostCancellation,
    _task_permit: BudgetPermit,
    _scope: ScopeGuard,
}

impl BodyProducer for FixedBodyProducer {
    fn produce(self: Box<Self>, sink: BodySink) -> Result<(), HostError> {
        let result = sink.send(self.bytes.to_vec());
        if result.is_err() && self.cancellation.is_cancelled() {
            Ok(())
        } else {
            result
        }
    }
}

struct FileBodyProducer {
    file: File,
    remaining: u64,
    evaluator: Evaluator,
    first_error: Arc<Mutex<Option<Arc<RuntimeError>>>>,
    cancellation: HostCancellation,
    _task_permit: BudgetPermit,
    _scope: ScopeGuard,
}

impl BodyProducer for FileBodyProducer {
    fn produce(mut self: Box<Self>, sink: BodySink) -> Result<(), HostError> {
        let result = (|| {
            let mut buffer = [0_u8; 16 * 1024];
            while self.remaining != 0 {
                self.evaluator.ensure_not_cancelled()?;
                let amount = usize::try_from(self.remaining.min(buffer.len() as u64))
                    .expect("bounded HTTP file read fits usize");
                let read = self
                    .file
                    .read(&mut buffer[..amount])
                    .map_err(|error| http_io("Http.responseFile", error))?;
                if read == 0 {
                    return Err(RuntimeError::http(
                        "Http.responseFile: file ended before the requested range",
                    ));
                }
                sink.send(buffer[..read].to_vec())
                    .map_err(|error| response_sink_error(&self.cancellation, &error))?;
                self.remaining -= u64::try_from(read).expect("read size fits u64");
            }
            Ok(())
        })();
        finish_body_production(
            result,
            &self.cancellation,
            &self.first_error,
            "HTTP response connection closed while sending a file",
        )
    }
}

struct StreamBodyProducer {
    callback: ThunkRef,
    evaluator: Evaluator,
    context: RuntimeContext,
    remaining: Option<Arc<Mutex<usize>>>,
    cancellation: HostCancellation,
    first_error: Arc<Mutex<Option<Arc<RuntimeError>>>>,
    _task_permit: BudgetPermit,
    _scope: ScopeGuard,
}

impl BodyProducer for StreamBodyProducer {
    fn produce(mut self: Box<Self>, sink: BodySink) -> Result<(), HostError> {
        let alive = Arc::new(AtomicBool::new(true));
        let writer = host_stream_writer(
            sink.clone(),
            Arc::clone(&alive),
            self.remaining.clone(),
            self.cancellation.clone(),
        );
        let flush = host_stream_flush(sink, Arc::clone(&alive), self.cancellation.clone());
        let with_writer = Thunk::suspended(Suspension::Apply {
            function: Arc::clone(&self.callback),
            argument: Thunk::evaluated(Value::Function(FunctionValue::Host(writer))),
        });
        let with_flush = Thunk::suspended(Suspension::Apply {
            function: with_writer,
            argument: Thunk::evaluated(Value::Io(flush)),
        });
        let result =
            (|| {
                let action = self.evaluator.force_io(&with_flush)?;
                let returned = action.run(&mut self.evaluator, &self.context)?;
                if !matches!(self.evaluator.force(&returned)?.as_ref(), Value::Unit) {
                    return Err(RuntimeError::internal(
                        "Http.responseStream callback returned a non-unit value",
                    ));
                }
                if self.remaining.as_ref().is_some_and(|remaining| {
                    remaining.lock().map_or(true, |remaining| *remaining != 0)
                }) {
                    return Err(RuntimeError::http(
                        "HTTP response stream ended before Content-Length bytes were written",
                    ));
                }
                Ok(())
            })();
        alive.store(false, Ordering::Release);
        finish_body_production(
            result,
            &self.cancellation,
            &self.first_error,
            "HTTP response connection closed while streaming",
        )
    }
}

fn host_stream_writer(
    sink: BodySink,
    alive: Arc<AtomicBool>,
    remaining: Option<Arc<Mutex<usize>>>,
    cancellation: HostCancellation,
) -> HostFunction {
    HostFunction::new(move |builder| {
        let sink = sink.clone();
        let alive = Arc::clone(&alive);
        let remaining = remaining.clone();
        let cancellation = cancellation.clone();
        Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
            move |evaluator, _| {
                ensure_stream_alive(&alive)?;
                evaluator.ensure_not_cancelled()?;
                if cancellation.is_cancelled() {
                    return Err(RuntimeError::cancelled());
                }
                let bytes = force_builder(evaluator, &builder)?;
                if let Some(remaining) = &remaining {
                    let mut remaining = remaining.lock().map_err(|_| {
                        RuntimeError::internal("HTTP stream-length mutex was poisoned")
                    })?;
                    if bytes.len() > *remaining {
                        return Err(RuntimeError::http(
                            "HTTP response stream exceeded Content-Length",
                        ));
                    }
                    sink.send(bytes.to_vec())
                        .map_err(|error| response_sink_error(&cancellation, &error))?;
                    *remaining -= bytes.len();
                } else {
                    sink.send(bytes.to_vec())
                        .map_err(|error| response_sink_error(&cancellation, &error))?;
                }
                Ok(Thunk::evaluated(Value::Unit))
            },
        )))))
    })
}

fn host_stream_flush(
    sink: BodySink,
    alive: Arc<AtomicBool>,
    cancellation: HostCancellation,
) -> IoAction {
    IoAction::new(move |evaluator, _| {
        ensure_stream_alive(&alive)?;
        evaluator.ensure_not_cancelled()?;
        if cancellation.is_cancelled() {
            return Err(RuntimeError::cancelled());
        }
        sink.flush()
            .map_err(|error| response_sink_error(&cancellation, &error))?;
        Ok(Thunk::evaluated(Value::Unit))
    })
}

fn response_sink_error(cancellation: &HostCancellation, error: &HostError) -> Arc<RuntimeError> {
    if cancellation.is_cancelled() {
        RuntimeError::cancelled()
    } else {
        RuntimeError::http(error.message())
    }
}

fn finish_body_production(
    result: RuntimeResult<()>,
    cancellation: &HostCancellation,
    first_error: &Mutex<Option<Arc<RuntimeError>>>,
    cancellation_message: &'static str,
) -> Result<(), HostError> {
    match result {
        Ok(()) => Ok(()),
        Err(error)
            if error.kind == crate::RuntimeErrorKind::Cancelled && cancellation.is_cancelled() =>
        {
            Ok(())
        }
        Err(error) => {
            let error = if error.kind == crate::RuntimeErrorKind::Cancelled {
                RuntimeError::http(cancellation_message)
            } else {
                error
            };
            Err(record_host_runtime_error(first_error, &error))
        }
    }
}

fn record_host_runtime_error(
    first_error: &Mutex<Option<Arc<RuntimeError>>>,
    error: &Arc<RuntimeError>,
) -> HostError {
    if let Ok(mut first_error) = first_error.lock()
        && first_error.is_none()
    {
        *first_error = Some(Arc::clone(error));
    }
    HostError::new(error.to_string())
}

fn invoke_application_response(
    request: &Arc<Request>,
    application: ThunkRef,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
) -> RuntimeResult<Arc<Response>> {
    let response_id = NEXT_RESPONSE_ID.fetch_add(1, Ordering::Relaxed);
    let response_slot = Arc::new(Mutex::new(None::<Arc<Response>>));
    let response_used = Arc::new(AtomicBool::new(false));
    let responder = {
        let response_slot = Arc::clone(&response_slot);
        let response_used = Arc::clone(&response_used);
        HostFunction::new(move |response| {
            let response_slot = Arc::clone(&response_slot);
            let response_used = Arc::clone(&response_used);
            Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
                move |evaluator, _| {
                    if response_used.swap(true, Ordering::AcqRel) {
                        return Err(RuntimeError::http(
                            "HTTP responder may be invoked exactly once",
                        ));
                    }
                    let response_value = evaluator.force(&response)?;
                    let Value::HttpResponse(response) = response_value.as_ref() else {
                        return Err(RuntimeError::internal(
                            "HTTP responder received a non-Response value",
                        ));
                    };
                    *response_slot.lock().map_err(|_| {
                        RuntimeError::internal("HTTP response mutex was poisoned")
                    })? = Some(Arc::clone(response));
                    Ok(Thunk::evaluated(Value::HttpResponseReceived(response_id)))
                },
            )))))
        })
    };
    let with_request = Thunk::suspended(Suspension::Apply {
        function: application,
        argument: Thunk::evaluated(Value::HttpRequest(Arc::clone(request))),
    });
    let with_responder = Thunk::suspended(Suspension::Apply {
        function: with_request,
        argument: Thunk::evaluated(Value::Function(FunctionValue::Host(responder))),
    });
    let action = evaluator.force_io(&with_responder)?;
    let received = action.run(evaluator, context)?;
    match evaluator.force(&received)?.as_ref() {
        Value::HttpResponseReceived(id) if *id == response_id => {}
        Value::HttpResponseReceived(_) => {
            return Err(RuntimeError::internal(
                "HTTP application returned a token for another request",
            ));
        }
        _ => {
            return Err(RuntimeError::internal(
                "HTTP application returned a non-ResponseReceived value",
            ));
        }
    }
    response_slot
        .lock()
        .map_err(|_| RuntimeError::internal("HTTP response mutex was poisoned"))?
        .take()
        .ok_or_else(|| RuntimeError::http("HTTP application did not send a response"))
}

#[allow(clippy::too_many_lines)]
fn parse_target(target: &[u8]) -> (Vec<Arc<str>>, Vec<QueryParameter>) {
    let (path, query) = target
        .iter()
        .position(|byte| *byte == b'?')
        .map_or((target, None), |index| {
            (&target[..index], Some(&target[index + 1..]))
        });
    let path = path.strip_prefix(b"/").unwrap_or(path);
    let path = if path.is_empty() {
        Vec::new()
    } else {
        path.split(|byte| *byte == b'/')
            .map(|part| Arc::from(String::from_utf8_lossy(&percent_decode(part, false)).as_ref()))
            .collect::<Vec<_>>()
    };
    let query = query.map_or_else(Vec::new, |query| {
        if query.is_empty() {
            return Vec::new();
        }
        query
            .split(|byte| *byte == b'&')
            .map(|field| {
                field.iter().position(|byte| *byte == b'=').map_or_else(
                    || (Arc::from(percent_decode(field, true)), None),
                    |index| {
                        (
                            Arc::from(percent_decode(&field[..index], true)),
                            Some(Arc::from(percent_decode(&field[index + 1..], true))),
                        )
                    },
                )
            })
            .collect()
    });
    (path, query)
}

fn percent_decode(input: &[u8], plus_as_space: bool) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'+' if plus_as_space => {
                output.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < input.len() => {
                if let (Some(high), Some(low)) = (hex(input[index + 1]), hex(input[index + 2])) {
                    output.push(high * 16 + low);
                    index += 3;
                } else {
                    output.push(input[index]);
                    index += 1;
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    output
}

fn ensure_stream_alive(alive: &AtomicBool) -> RuntimeResult<()> {
    if alive.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(RuntimeError::resource_closed(
            "HTTP stream callback was used after the response completed",
        ))
    }
}

fn force_status(evaluator: &mut Evaluator, value: &ThunkRef) -> RuntimeResult<Status> {
    match evaluator.force(value)?.as_ref() {
        Value::HttpStatus(status) => Ok(status.clone()),
        _ => Err(RuntimeError::internal(
            "HTTP response status is not a Status",
        )),
    }
}

fn force_builder(evaluator: &mut Evaluator, value: &ThunkRef) -> RuntimeResult<Arc<[u8]>> {
    match evaluator.force(value)?.as_ref() {
        Value::Builder(bytes) => Ok(Arc::clone(bytes)),
        _ => Err(RuntimeError::internal(
            "HTTP response body is not a Builder",
        )),
    }
}

fn force_headers(evaluator: &mut Evaluator, value: &ThunkRef) -> RuntimeResult<Vec<Header>> {
    let elements = evaluator.force_list_elements(value)?;
    let mut headers = Vec::with_capacity(elements.len());
    for element in elements {
        let element = evaluator.force(&element)?;
        let Value::Tuple(fields) = element.as_ref() else {
            return Err(RuntimeError::internal("HTTP header is not a pair"));
        };
        let [name, value] = fields.as_ref() else {
            return Err(RuntimeError::internal("HTTP header is not a pair"));
        };
        let name = evaluator.force(name)?;
        let Value::CaseInsensitive(name) = name.as_ref() else {
            return Err(RuntimeError::internal(
                "HTTP header name is not case-insensitive bytes",
            ));
        };
        let original = Arc::clone(&name.original);
        let name = evaluator.force_bytes(&original)?;
        let value = evaluator.force_bytes(value)?;
        validate_header(&name, &value)?;
        headers.push((name, value));
    }
    Ok(headers)
}

fn validate_reason(reason: &[u8], limit: Limit<u64>) -> RuntimeResult<()> {
    let too_long = limit
        .value()
        .is_some_and(|maximum| u64::try_from(reason.len()).unwrap_or(u64::MAX) > maximum);
    if too_long || reason.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        Err(RuntimeError::http(
            "HTTP status reason is too long or contains a forbidden byte",
        ))
    } else {
        Ok(())
    }
}

fn validate_header(name: &[u8], value: &[u8]) -> RuntimeResult<()> {
    if name.is_empty() || !name.iter().copied().all(is_token_byte) {
        return Err(RuntimeError::http("HTTP response header name is invalid"));
    }
    if value.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(RuntimeError::http(
            "HTTP response header value contains a forbidden byte",
        ));
    }
    Ok(())
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn header_values<'a>(headers: &'a [Header], wanted: &[u8]) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|(name, _)| ascii_eq(name, wanted))
        .map(|(_, value)| value.as_ref())
        .collect()
}

fn parse_content_length(value: &[u8]) -> RuntimeResult<usize> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(RuntimeError::http("HTTP Content-Length is invalid"));
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| RuntimeError::http("HTTP Content-Length is too large"))
}

fn validate_response_framing_headers(headers: &[Header]) -> RuntimeResult<()> {
    if !header_values(headers, b"content-length").is_empty()
        && !header_values(headers, b"transfer-encoding").is_empty()
    {
        return Err(RuntimeError::http(
            "HTTP response cannot contain both Transfer-Encoding and Content-Length",
        ));
    }
    if !header_values(headers, b"transfer-encoding").is_empty() && !response_is_chunked(headers) {
        return Err(RuntimeError::http(
            "HTTP response has an unsupported Transfer-Encoding",
        ));
    }
    Ok(())
}

fn response_content_length(headers: &[Header]) -> RuntimeResult<Option<usize>> {
    let values = header_values(headers, b"content-length");
    if values.is_empty() {
        return Ok(None);
    }
    let lengths = values
        .iter()
        .flat_map(|value| value.split(|byte| *byte == b','))
        .map(trim_optional_whitespace)
        .map(parse_content_length)
        .collect::<RuntimeResult<Vec<_>>>()?;
    let Some(length) = lengths.first().copied() else {
        return Err(RuntimeError::http("HTTP Content-Length is empty"));
    };
    if lengths.iter().any(|candidate| *candidate != length) {
        return Err(RuntimeError::http(
            "HTTP response has conflicting Content-Length values",
        ));
    }
    Ok(Some(length))
}

fn response_is_chunked(headers: &[Header]) -> bool {
    let values = header_values(headers, b"transfer-encoding");
    let codings = values
        .iter()
        .flat_map(|value| value.split(|byte| *byte == b','))
        .map(trim_optional_whitespace)
        .collect::<Vec<_>>();
    codings.len() == 1 && ascii_eq(codings[0], b"chunked")
}

fn status_forbids_body(status: u16) -> bool {
    (100..200).contains(&status) || matches!(status, 204 | 304)
}

const fn ascii_eq(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

const fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn http_io(operation: &str, error: impl std::fmt::Display) -> Arc<RuntimeError> {
    RuntimeError::http(format!("{operation}: {error}"))
}
