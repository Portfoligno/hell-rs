# HTTP host dependency record

The HTTP host uses Hyper 1.11.0 for maintained HTTP/1 server parsing and
connection state, Hyper-util 0.1.20 only for Tokio I/O adaptation, Tokio 1.53.1
for cross-platform asynchronous sockets, scheduling, bounded channels, and
deadlines, and Bytes 1.12.1 for body frames. Default features are disabled;
HTTP/2, clients, TLS, macros, filesystem, process, signal, and tracing support
are not enabled.

The resolved normal dependency inventory is: atomic-waker 1.1.2, bytes 1.12.1,
futures-channel 0.3.33, futures-core 0.3.33, http 1.5.0, http-body 1.1.0,
httparse 1.10.1, httpdate 1.0.3, hyper 1.11.0, hyper-util 0.1.20, itoa 1.0.18,
libc 0.2.189, mio 1.2.2, pin-project-lite 0.2.17, smallvec 1.15.2, socket2
0.6.5, tokio 1.53.1, target-only wasi 0.11.1, windows-link 0.2.1, and
windows-sys 0.61.2.

All dependencies are MIT or MIT/Apache-2.0 licensed and are compatible with
the workspace BSD-3-Clause license. Their declared minimum Rust versions are
at most 1.71, below the workspace toolchain. Hyper 1.11 includes the HTTP/1
half-close busy-loop correction merged as hyperium/hyper#4086. Any version or
feature change invalidates HTTP request-target, framing, keep-alive, streaming,
backpressure, cancellation, and three-platform evidence and requires a fresh
license and RustSec review.
