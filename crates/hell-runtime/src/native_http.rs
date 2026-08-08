//! HTTP/1 server values and adapters for the WAI-shaped guest API.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::native_integer::BigInteger;
use crate::typeclasses::CaseInsensitiveValue;
use crate::{
    Evaluator, ForceOutcome, FunctionValue, HostFunction, IoAction, RuntimeContext, RuntimeError,
    RuntimeResult, Suspension, Thunk, ThunkRef, Value, list_from_values,
};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_COUNT: usize = 256;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const BODY_CHUNK_BYTES: usize = 8 * 1024;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
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
    method: Arc<str>,
    path: Arc<[Arc<str>]>,
    headers: Arc<[Header]>,
    query: Arc<[QueryParameter]>,
    body: Mutex<RequestBody>,
}

#[derive(Debug)]
struct RequestBody {
    stream: TcpStream,
    pending: VecDeque<u8>,
    mode: BodyMode,
    consumed: usize,
}

#[derive(Clone, Copy, Debug)]
enum BodyMode {
    Empty,
    ContentLength(usize),
    Chunked,
    Finished,
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
            let headers = request
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
                .collect();
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
    validate_reason(reason.as_bytes())?;
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
        let mut body = request
            .body
            .lock()
            .map_err(|_| RuntimeError::internal("HTTP request-body mutex was poisoned"))?;
        let bytes = if consume_remainder {
            body.consume_remainder()?
        } else {
            body.next_chunk()?.unwrap_or_default()
        };
        Ok(Thunk::evaluated(Value::ByteString(bytes.into())))
    })
}

impl RequestBody {
    fn next_chunk(&mut self) -> RuntimeResult<Option<Vec<u8>>> {
        let next = match self.mode {
            BodyMode::Empty | BodyMode::Finished => None,
            BodyMode::ContentLength(remaining) => {
                let amount = remaining.min(BODY_CHUNK_BYTES);
                let chunk = self.read_exact(amount)?;
                self.mode = if remaining == amount {
                    BodyMode::Finished
                } else {
                    BodyMode::ContentLength(remaining - amount)
                };
                Some(chunk)
            }
            BodyMode::Chunked => self.read_chunked()?,
        };
        if let Some(bytes) = &next {
            self.consumed = self.consumed.checked_add(bytes.len()).ok_or_else(|| {
                RuntimeError::http("HTTP request body length overflowed host limits")
            })?;
            if self.consumed > MAX_BODY_BYTES {
                return Err(RuntimeError::http(format!(
                    "HTTP request body exceeded the {MAX_BODY_BYTES}-byte limit"
                )));
            }
        }
        Ok(next)
    }

    fn consume_remainder(&mut self) -> RuntimeResult<Vec<u8>> {
        let mut output = Vec::new();
        while let Some(chunk) = self.next_chunk()? {
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    fn read_chunked(&mut self) -> RuntimeResult<Option<Vec<u8>>> {
        let line = self.read_line(MAX_HEADER_BYTES)?;
        let size = line
            .split(|byte| *byte == b';')
            .next()
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| usize::from_str_radix(digits.trim(), 16).ok())
            .ok_or_else(|| RuntimeError::http("HTTP request has an invalid chunk size"))?;
        if size == 0 {
            loop {
                if self.read_line(MAX_HEADER_BYTES)?.is_empty() {
                    break;
                }
            }
            self.mode = BodyMode::Finished;
            return Ok(None);
        }
        if size > MAX_BODY_BYTES.saturating_sub(self.consumed) {
            return Err(RuntimeError::http(format!(
                "HTTP request body exceeded the {MAX_BODY_BYTES}-byte limit"
            )));
        }
        let chunk = self.read_exact(size)?;
        if self.read_exact(2)? != b"\r\n" {
            return Err(RuntimeError::http(
                "HTTP request chunk was not terminated by CRLF",
            ));
        }
        Ok(Some(chunk))
    }

    fn read_line(&mut self, limit: usize) -> RuntimeResult<Vec<u8>> {
        let mut output = Vec::new();
        while output.len() <= limit {
            output.push(self.read_byte()?);
            if output.ends_with(b"\r\n") {
                output.truncate(output.len() - 2);
                return Ok(output);
            }
        }
        Err(RuntimeError::http("HTTP request line exceeded its limit"))
    }

    fn read_byte(&mut self) -> RuntimeResult<u8> {
        if let Some(byte) = self.pending.pop_front() {
            return Ok(byte);
        }
        let mut byte = [0_u8; 1];
        self.stream
            .read_exact(&mut byte)
            .map_err(|error| http_io("read request body", error))?;
        Ok(byte[0])
    }

    fn read_exact(&mut self, amount: usize) -> RuntimeResult<Vec<u8>> {
        let mut output = Vec::with_capacity(amount);
        while output.len() < amount {
            if let Some(byte) = self.pending.pop_front() {
                output.push(byte);
            } else {
                let old_len = output.len();
                output.resize(amount, 0);
                self.stream
                    .read_exact(&mut output[old_len..])
                    .map_err(|error| http_io("read request body", error))?;
            }
        }
        Ok(output)
    }
}

fn run_server(port: ThunkRef, application: ThunkRef) -> IoAction {
    IoAction::new(move |evaluator, context| {
        context.require_network("Http.run")?;
        let port = evaluator.force_int(&port)?;
        let port = u16::try_from(port)
            .map_err(|_| RuntimeError::http("Http.run: port must be between 0 and 65535"))?;
        let listener = TcpListener::bind(("0.0.0.0", port))
            .map_err(|error| http_io("Http.run: listen", error))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| http_io("Http.run: configure listener", error))?;
        let mut workers: Vec<JoinHandle<RuntimeResult<()>>> = Vec::new();
        let mut accepted = 0_usize;
        loop {
            evaluator.ensure_not_cancelled()?;
            match listener.accept() {
                Ok((stream, _address)) => {
                    accepted = accepted.saturating_add(1);
                    let callback = Arc::clone(&application);
                    let worker_context = context.clone();
                    let mut child =
                        evaluator.fork_with_cancellation(evaluator.child_cancellation());
                    workers.push(std::thread::spawn(move || {
                        handle_connection(stream, callback, &mut child, &worker_context)
                    }));
                    if context
                        .http_request_limit
                        .is_some_and(|limit| accepted >= limit)
                    {
                        break;
                    }
                    reap_workers(&mut workers);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    reap_workers(&mut workers);
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => return Err(http_io("Http.run: accept", error)),
            }
        }
        for worker in workers {
            join_worker(worker)??;
        }
        Ok(Thunk::evaluated(Value::Unit))
    })
}

fn reap_workers(workers: &mut Vec<JoinHandle<RuntimeResult<()>>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ignored = join_worker(worker);
        } else {
            index += 1;
        }
    }
}

fn join_worker<T>(worker: JoinHandle<T>) -> RuntimeResult<T> {
    worker.join().map_err(|payload| {
        let message = payload
            .downcast_ref::<&str>()
            .map_or("HTTP worker panicked", |message| *message);
        RuntimeError::panic_contained(message)
    })
}

fn handle_connection(
    mut stream: TcpStream,
    application: ThunkRef,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
) -> RuntimeResult<()> {
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .map_err(|error| http_io("configure HTTP read timeout", error))?;
    stream
        .set_write_timeout(Some(SOCKET_TIMEOUT))
        .map_err(|error| http_io("configure HTTP write timeout", error))?;
    let request = parse_request(&stream)?;
    let result = invoke_application(
        Arc::clone(&request),
        application,
        evaluator,
        context,
        &mut stream,
    );
    request.close();
    result
}

fn invoke_application(
    request: Arc<Request>,
    application: ThunkRef,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
    stream: &mut TcpStream,
) -> RuntimeResult<()> {
    let response_id = NEXT_RESPONSE_ID.fetch_add(1, Ordering::Relaxed);
    let suppress_body = request.method.eq_ignore_ascii_case("HEAD");
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
        argument: Thunk::evaluated(Value::HttpRequest(request)),
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
    let response = response_slot
        .lock()
        .map_err(|_| RuntimeError::internal("HTTP response mutex was poisoned"))?
        .take()
        .ok_or_else(|| RuntimeError::http("HTTP application did not send a response"))?;
    send_response(&response, evaluator, context, stream, suppress_body)
}

#[allow(clippy::too_many_lines)]
fn parse_request(stream: &TcpStream) -> RuntimeResult<Arc<Request>> {
    let mut reader = stream
        .try_clone()
        .map_err(|error| http_io("clone HTTP request stream", error))?;
    let mut input = Vec::new();
    let header_end = loop {
        if let Some(index) = find_bytes(&input, b"\r\n\r\n") {
            break index + 4;
        }
        if input.len() >= MAX_HEADER_BYTES {
            return Err(RuntimeError::http(format!(
                "HTTP request headers exceeded the {MAX_HEADER_BYTES}-byte limit"
            )));
        }
        let mut buffer = [0_u8; 4096];
        let read = reader
            .read(&mut buffer)
            .map_err(|error| http_io("read HTTP request headers", error))?;
        if read == 0 {
            return Err(RuntimeError::http(
                "HTTP connection closed before request headers completed",
            ));
        }
        input.extend_from_slice(&buffer[..read]);
    };
    let pending = VecDeque::from(input.split_off(header_end));
    let head = &input[..header_end - 4];
    let mut lines = head.split(|byte| *byte == b'\n').map(trim_cr);
    let request_line = lines
        .next()
        .ok_or_else(|| RuntimeError::http("HTTP request line is missing"))?;
    let request_line = std::str::from_utf8(request_line)
        .map_err(|_| RuntimeError::http("HTTP request line is not valid ASCII"))?;
    let mut pieces = request_line.split(' ');
    let method = pieces.next().filter(|part| !part.is_empty());
    let target = pieces.next().filter(|part| !part.is_empty());
    let version = pieces.next();
    if pieces.next().is_some()
        || method.is_none()
        || target.is_none()
        || !matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
    {
        return Err(RuntimeError::http("HTTP request line is malformed"));
    }
    let method = method.expect("request method was checked");
    if !method.bytes().all(is_token_byte) {
        return Err(RuntimeError::http("HTTP request method is invalid"));
    }
    let target = target.expect("request target was checked");
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(RuntimeError::http(format!(
                "HTTP request exceeded the {MAX_HEADER_COUNT}-header limit"
            )));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| RuntimeError::http("HTTP request header is malformed"))?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().copied().all(is_token_byte) {
            return Err(RuntimeError::http("HTTP request header name is invalid"));
        }
        let value = trim_optional_whitespace(&line[colon + 1..]);
        if value.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(RuntimeError::http("HTTP request header value is invalid"));
        }
        headers.push((Arc::from(name), Arc::from(value)));
    }
    let transfer_encoding = header_value(&headers, b"transfer-encoding");
    let content_length = header_value(&headers, b"content-length");
    let mode = if transfer_encoding.is_some_and(|value| ascii_eq(value, b"chunked")) {
        if content_length.is_some() {
            return Err(RuntimeError::http(
                "HTTP request cannot contain both chunked encoding and Content-Length",
            ));
        }
        BodyMode::Chunked
    } else if let Some(length) = content_length {
        let length = std::str::from_utf8(length)
            .ok()
            .and_then(|length| length.parse::<usize>().ok())
            .filter(|length| *length <= MAX_BODY_BYTES)
            .ok_or_else(|| RuntimeError::http("HTTP Content-Length is invalid or too large"))?;
        BodyMode::ContentLength(length)
    } else {
        BodyMode::Empty
    };
    let (path, query) = parse_target(target.as_bytes());
    Ok(Arc::new(Request {
        alive: AtomicBool::new(true),
        method: Arc::from(method),
        path: path.into(),
        headers: headers.into(),
        query: query.into(),
        body: Mutex::new(RequestBody {
            stream: reader,
            pending,
            mode,
            consumed: 0,
        }),
    }))
}

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
            .map(|part| {
                Arc::from(String::from_utf8_lossy(&percent_decode(part, false)).into_owned())
            })
            .collect()
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

fn send_response(
    response: &Response,
    evaluator: &mut Evaluator,
    context: &RuntimeContext,
    stream: &mut TcpStream,
    suppress_body: bool,
) -> RuntimeResult<()> {
    match &response.kind {
        ResponseKind::Builder {
            status,
            headers,
            builder,
        } => {
            let status = force_status(evaluator, status)?;
            let headers = force_headers(evaluator, headers)?;
            let bytes = force_builder(evaluator, builder)?;
            write_head(stream, &status, &headers, &BodyHeader::Length(bytes.len()))?;
            if !suppress_body {
                stream
                    .write_all(&bytes)
                    .map_err(|error| http_io("write HTTP response", error))?;
            }
            Ok(())
        }
        ResponseKind::File {
            status,
            headers,
            path,
            part,
        } => send_file(
            status,
            headers,
            path,
            part,
            ResponseTarget {
                evaluator,
                context,
                stream,
                suppress_body,
            },
        ),
        ResponseKind::Stream {
            status,
            headers,
            callback,
        } => send_stream(
            status,
            headers,
            callback,
            ResponseTarget {
                evaluator,
                context,
                stream,
                suppress_body,
            },
        ),
    }
}

struct ResponseTarget<'a> {
    evaluator: &'a mut Evaluator,
    context: &'a RuntimeContext,
    stream: &'a mut TcpStream,
    suppress_body: bool,
}

fn send_file(
    status: &ThunkRef,
    headers: &ThunkRef,
    path: &ThunkRef,
    part: &ThunkRef,
    target: ResponseTarget<'_>,
) -> RuntimeResult<()> {
    let ResponseTarget {
        evaluator,
        context,
        stream,
        suppress_body,
    } = target;
    let status = force_status(evaluator, status)?;
    let headers = force_headers(evaluator, headers)?;
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
                RuntimeError::http("Http.responseFile: file offset is negative or too large")
            })?;
            let count = part.byte_count.to_u64().ok_or_else(|| {
                RuntimeError::http("Http.responseFile: byte count is negative or too large")
            })?;
            let declared_size = part.file_size.to_u64().ok_or_else(|| {
                RuntimeError::http("Http.responseFile: file size is negative or too large")
            })?;
            let end = offset
                .checked_add(count)
                .ok_or_else(|| RuntimeError::http("Http.responseFile: file range overflowed"))?;
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
    let length = usize::try_from(count)
        .map_err(|_| RuntimeError::http("Http.responseFile body is too large for this host"))?;
    write_head(stream, &status, &headers, &BodyHeader::Length(length))?;
    if suppress_body {
        return Ok(());
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| http_io("Http.responseFile", error))?;
    let mut remaining = count;
    let mut buffer = [0_u8; 16 * 1024];
    while remaining != 0 {
        evaluator.ensure_not_cancelled()?;
        let amount = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded HTTP file read fits usize");
        let read = file
            .read(&mut buffer[..amount])
            .map_err(|error| http_io("Http.responseFile", error))?;
        if read == 0 {
            return Err(RuntimeError::http(
                "Http.responseFile: file ended before the requested range",
            ));
        }
        stream
            .write_all(&buffer[..read])
            .map_err(|error| http_io("write HTTP file response", error))?;
        remaining -= u64::try_from(read).expect("read size fits u64");
    }
    Ok(())
}

fn send_stream(
    status: &ThunkRef,
    headers: &ThunkRef,
    callback: &ThunkRef,
    target: ResponseTarget<'_>,
) -> RuntimeResult<()> {
    let ResponseTarget {
        evaluator,
        context,
        stream,
        suppress_body,
    } = target;
    let status = force_status(evaluator, status)?;
    let headers = force_headers(evaluator, headers)?;
    write_head(stream, &status, &headers, &BodyHeader::Chunked)?;
    if suppress_body {
        return Ok(());
    }
    let output = Arc::new(Mutex::new(
        stream
            .try_clone()
            .map_err(|error| http_io("clone HTTP response stream", error))?,
    ));
    let alive = Arc::new(AtomicBool::new(true));
    let writer = stream_writer(Arc::clone(&output), Arc::clone(&alive));
    let flush = stream_flush(Arc::clone(&output), Arc::clone(&alive));
    let with_writer = Thunk::suspended(Suspension::Apply {
        function: Arc::clone(callback),
        argument: Thunk::evaluated(Value::Function(FunctionValue::Host(writer))),
    });
    let with_flush = Thunk::suspended(Suspension::Apply {
        function: with_writer,
        argument: Thunk::evaluated(Value::Io(flush)),
    });
    let result = (|| {
        let action = evaluator.force_io(&with_flush)?;
        let returned = action.run(evaluator, context)?;
        match evaluator.force(&returned)?.as_ref() {
            Value::Unit => Ok(()),
            _ => Err(RuntimeError::internal(
                "Http.responseStream callback returned a non-unit value",
            )),
        }
    })();
    alive.store(false, Ordering::Release);
    result?;
    stream
        .write_all(b"0\r\n\r\n")
        .map_err(|error| http_io("finish HTTP response stream", error))?;
    Ok(())
}

fn stream_writer(output: Arc<Mutex<TcpStream>>, alive: Arc<AtomicBool>) -> HostFunction {
    HostFunction::new(move |builder| {
        let output = Arc::clone(&output);
        let alive = Arc::clone(&alive);
        Ok(ForceOutcome::Value(Arc::new(Value::Io(IoAction::new(
            move |evaluator, _| {
                ensure_stream_alive(&alive)?;
                evaluator.ensure_not_cancelled()?;
                let bytes = force_builder(evaluator, &builder)?;
                if !bytes.is_empty() {
                    let mut output = output.lock().map_err(|_| {
                        RuntimeError::internal("HTTP stream-writer mutex was poisoned")
                    })?;
                    write!(output, "{:X}\r\n", bytes.len())
                        .and_then(|()| output.write_all(&bytes))
                        .and_then(|()| output.write_all(b"\r\n"))
                        .map_err(|error| http_io("write HTTP response stream", error))?;
                }
                Ok(Thunk::evaluated(Value::Unit))
            },
        )))))
    })
}

fn stream_flush(output: Arc<Mutex<TcpStream>>, alive: Arc<AtomicBool>) -> IoAction {
    IoAction::new(move |evaluator, _| {
        ensure_stream_alive(&alive)?;
        evaluator.ensure_not_cancelled()?;
        output
            .lock()
            .map_err(|_| RuntimeError::internal("HTTP stream-writer mutex was poisoned"))?
            .flush()
            .map_err(|error| http_io("flush HTTP response stream", error))?;
        Ok(Thunk::evaluated(Value::Unit))
    })
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

enum BodyHeader {
    Length(usize),
    Chunked,
}

fn write_head(
    stream: &mut TcpStream,
    status: &Status,
    headers: &[Header],
    body: &BodyHeader,
) -> RuntimeResult<()> {
    validate_reason(&status.reason)?;
    write!(stream, "HTTP/1.1 {} ", status.code)
        .and_then(|()| stream.write_all(&status.reason))
        .and_then(|()| stream.write_all(b"\r\n"))
        .map_err(|error| http_io("write HTTP response status", error))?;
    let mut has_connection = false;
    let mut has_length = false;
    let mut has_transfer_encoding = false;
    for (name, value) in headers {
        validate_header(name, value)?;
        has_connection |= ascii_eq(name, b"connection");
        has_length |= ascii_eq(name, b"content-length");
        has_transfer_encoding |= ascii_eq(name, b"transfer-encoding");
        stream
            .write_all(name)
            .and_then(|()| stream.write_all(b": "))
            .and_then(|()| stream.write_all(value))
            .and_then(|()| stream.write_all(b"\r\n"))
            .map_err(|error| http_io("write HTTP response header", error))?;
    }
    match *body {
        BodyHeader::Length(length) if !has_length && !has_transfer_encoding => {
            write!(stream, "Content-Length: {length}\r\n")
                .map_err(|error| http_io("write HTTP Content-Length", error))?;
        }
        BodyHeader::Chunked if !has_length && !has_transfer_encoding => stream
            .write_all(b"Transfer-Encoding: chunked\r\n")
            .map_err(|error| http_io("write HTTP Transfer-Encoding", error))?,
        BodyHeader::Length(_) | BodyHeader::Chunked => {}
    }
    if !has_connection {
        stream
            .write_all(b"Connection: close\r\n")
            .map_err(|error| http_io("write HTTP Connection header", error))?;
    }
    stream
        .write_all(b"\r\n")
        .map_err(|error| http_io("finish HTTP response headers", error))?;
    Ok(())
}

fn validate_reason(reason: &[u8]) -> RuntimeResult<()> {
    if reason.len() > 1024 || reason.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
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

fn is_token_byte(byte: u8) -> bool {
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

fn header_value<'a>(headers: &'a [Header], wanted: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(name, _)| ascii_eq(name, wanted))
        .map(|(_, value)| value.as_ref())
}

fn ascii_eq(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
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

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn hex(byte: u8) -> Option<u8> {
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
