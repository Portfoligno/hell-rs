# Runtime and compiler profiles

The normal CLI and differential candidate use the `upstream` runtime and
compiler profiles. Embeddings may opt into `sandboxed`; tests use the named
`deterministic-test` profile. Guest-visible limits are serialized by
`RuntimePolicy` or `CompilerConfig`, and budget failures name the profile,
operation, configured limit, and observed amount.

`CompilerLimits` accounts for source bytes, tokens, syntax nodes, nesting,
type constraints, and core nodes. The upstream profile leaves all six
unlimited; the sandbox profile applies explicit typed limits and reports
operation, profile, configured limit, and observed use in structured
diagnostics. `--build-info` serializes the complete `CompilerConfig` and
`RuntimePolicy`, so evidence shards bind the active profiles and limits.

## Semantic-limit inventory

| Source and identifier | Classification | Profile behavior |
|---|---|---|
| `crates/hell-runtime/src/native_http.rs`: `SANDBOX_SOCKET_TIMEOUT` | Sandbox policy implementation | Applied only outside the upstream profile. |
| `crates/hell-runtime/src/native_handle.rs`: `BLOCK_BUFFER_BYTES` | Buffering implementation | An 8 KiB flush boundary bounds pending bytes without rejecting guest data. |
| `crates/hell-http-host/src/lib.rs`: `ENGINE_POLL_INTERVAL` | Cancellation implementation | Poll interval only; no guest input is rejected. |
| `crates/hell-http-host/src/lib.rs`: `BODY_CHANNEL_CAPACITY` | Backpressure implementation | Bounded channel capacity only; the stream remains lossless. |
| `crates/hell-http-host/src/lib.rs`: `HYPER_MINIMUM_BUFFER_SIZE` | Transport implementation | Hyper allocation floor, not a request limit. |
| `crates/hell-runtime/src/native_json.rs`: `MAX_DEPTH` | Test-only fixture | Compiled only under `cfg(test)`; production uses `RuntimePolicy.limits.json_depth`. |

The former temporary-resource collision count is
`RuntimePolicy.cleanup.temp_create_retries`: upstream is unlimited and the
sandbox uses 1,024 attempts. HTTP reason length is
`RuntimePolicy.limits.http_reason_bytes`: upstream is unlimited and the
sandbox uses 1,024 bytes. Parser/compiler nesting traversals use explicit
worklists, and ordered Map/Set values use persistent balanced trees rather
than vector insertion, so neither area relies on a hidden compatibility cap.
