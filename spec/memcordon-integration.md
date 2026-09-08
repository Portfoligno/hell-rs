# MemCordon integration

This specification defines the `hell-rs` consumer contract for MemCordon
`0.5.2-rc.23`. It is normative for Linux x86-64 and Windows x86-64 candidate
root operations. The dependency is a released external runtime, not vendored
source and not a provider implementation owned by this repository.

## Authority boundary

`hell-rs` owns the candidate revision, executable, native arguments, working
directory, closed environment, candidate identity and writable-root policy,
operation id, deadlines, streams, and evidence admission. MemCordon owns the
sealed native process-tree boundary, startup gating, guardian lifetime,
aggregate monitoring, termination, emptiness proof, and retirement.

The only production provider invocation is the digest-pinned `memcordon`
frontend with native arguments equivalent to:

```text
memcordon --sealed --quiet --report ABSOLUTE_REPORT +MILLISECONDSms --deadline-scope attempt --wait-for command --command-exit-grace 0ms -- TARGET ARGUMENT...
```

Arguments are constructed as `OsString` values. No shell interprets them. A
candidate root is wrapped once; descendants cannot self-assert or recursively
request another provider boundary.

## Pinned distribution

`ci/memcordon-runtime-v1.toml` is the sole runtime acquisition authority. It
pins release id `384239676`, source identity
`67aa1f74d9a76713ab343ea2afbe6403da7429b7`, schema versions, metadata assets,
and the Linux and Windows archive sizes and SHA-256 digests. A version string,
release URL, `SHA256SUMS`, or publication `passed` field is corroboration only;
downloaded bytes must match the committed lock before parsing or execution.

Linux requires `memcordon` and `memcordon-sealed-agent`. Windows requires all
four packaged executables: `memcordon.exe`, `memcordon-sealed-agent.exe`,
`memcordon-target-desktop-bootstrap.exe`, and
`memcordon-session-broker.exe`. The verified runtime manifest controls their
relative paths. Components are not renamed or assembled into a smaller local
package.

Acquisition and extraction are unprivileged. Archive entries that are linked,
absolute, traversing, duplicated after platform normalization, unsupported, or
over their reviewed bounds are rejected. Only a verified packaged agent may
perform installation or removal.

## Provider lease

A native job owns one provider lease. The normal state sequence is:

```text
absent -> acquired -> package_inspected -> installing -> qualified -> running
       -> draining -> uninstalling -> removed
```

Any ambiguous state becomes `failed_dirty`, closes admission, and fails the
platform. A pre-existing installation is not replaced or removed. Package
inspection, installation, verification, `doctor --require sealed`, execution,
drain, uninstall, and absence verification use the shipped public commands.
Run-local qualification and installed privileged state are never cached.

Windows root admission is bounded below the upstream eight-slot guardian pool.
A permit is retained until provider retirement, not merely until frontend exit.
Capacity rejection is infrastructure failure and never selects an unsealed
fallback.

## Platform policy

On Linux, MemCordon encloses the existing trusted
`sudo -> candidate adapter -> command` transition. The runner frontend gains
only the reviewed supplementary provider group, retains its primary gid, has no
capabilities, and does not impose `no_new_privs` when that would prevent the
inner sudo transition. A trusted readback verifies the exact frontend envelope.
Successful provider retirement does not replace the independent candidate-uid
quiescence check.

On Windows, MemCordon owns the outer non-breakaway Job, guardian, accounting,
and tree retirement. The trusted `hell-rs` identity adapter retains restricted
token construction, ACL and writable-root policy, exact command/environment,
restricted stdio, pre-release identity checks, native child status, and direct
child reaping. It creates no competing production Job and cannot accept a Job,
guardian slot, service, provider pipe, or raw launch plan as caller input.
Windows evidence includes a protected identity-adapter receipt and preserves a
full `u32` native status.

MacOS aarch64 keeps the existing native process-group/watchdog and uid-wide
quiescence policy. Its evidence says `existing-macos-native`; it never claims a
MemCordon sealed boundary.

## Deadlines, frontend, and streams

The precomputed absolute `hell-rs` execution and completion deadlines remain
authoritative. The MemCordon attempt duration is the positive remaining
execution budget minus the committed cleanup reserve. Provider setup has its
own job budget and cannot extend the candidate deadline.

`FrontendChild` owns bounded output draining, direct kill, wait/reap, and
retained cleanup of the trusted frontend. Frontend exit or reaping is not
workload-emptiness evidence. Missing terminal provider evidence after frontend
loss is a failed operation even when later host recovery succeeds.

Stdout and stderr remain byte streams. Empty output is zero bytes, and binary
bytes, NUL, CRLF, invalid UTF-8, partial final lines, byte count, full digest,
bounded prefix/suffix, omitted count, and the original I/O failure are retained
without trimming or lossy conversion. Wrapper diagnostics from an invalid
execution are not candidate semantic output.

## Evidence and independent admission

The runner creates an unpredictable protected report reservation outside every
candidate writable root. Linux uses a runner-owned `0700` parent. Windows uses
an ACL verified against the actual restricted token, including denial of
replace, truncate, rename, delete, and DACL changes. Safe reads reject links,
reparse substitution, non-regular files, unstable identity, and oversized data.

Raw execution reports use upstream schema 8. `hell-memcordon` performs primary
strict parsing and emits a `Schema8ProjectionV1`. The independent
`hell-release-verifier` does not depend on MemCordon or on the primary parser;
it closes unknown-field inventories, validates exact native arguments and
status provenance, requires every generic and platform-native launch and
retirement predicate, and proves raw-to-projection equality.

The normalized projection has exactly these snake-case fields:
`schema_version`, `tool_version`, `requested_boundary`,
`effective_boundary`, `mechanism`, `target_argv`, `attempt_count`,
`restart_count`, `sealed_boundary_retired`, `wrapper_status`, `target_status`,
`terminal`, and `native_predicates`. Each native argument is exactly
`{"display": STRING, "raw": null}` or carries
`raw: {"encoding": STRING, "data": STRING}`. The tagged terminal is exactly
`candidate_exit` with its full-width `native_status`, `candidate_signal` with
its nonzero `signal`, or `inner_deadline`. `target_status` is present only for
candidate exits and must equal the terminal's full native value. The native
predicate object contains the exact mechanism-specific key inventory, with no
missing, extra, or false predicate.

Each Linux or Windows candidate-root operation has exactly one sorted
`OperationLedgerEntryV1`. The trusted plan supplies the required operation ids;
the producer cannot derive required coverage from the reports it happened to
observe. Missing, extra, duplicate, unbound, standard-boundary, or unfinished
entries fail. A candidate exit such as 123 remains an ordinary candidate result
when its typed report proves safe retirement; wrapper deadlines and failures
remain distinct.

Finalization occurs after provider cleanup. An admitted
`FinalizationReceiptV1` binds the candidate and workflow commits, runtime lock,
acquisition, lifecycle, cleanup, operation ledger, exact inventory, and equal
required/observed operation sets. Both final verifiers independently recompute
the raw, normalized, adapter, cleanup, ledger, and inventory bindings.

## Artifact layout

The fixed job-local namespace is:

```text
platform-out/memcordon/
  acquisition.json
  release-manifest.json
  publication-report.json
  runtime-manifest.json
  package-inspect.json
  package-verify.json
  doctor.json
  canaries.json
  operations.json
  provider-lease.json
  provider-cleanup.json
  finalization.json
  inventory.sha256
  raw/<operation-id>.json
  normalized/<operation-id>.json
  adapters/<operation-id>.json
  frontend/<operation-id>.json
  qualification-artifacts/...
```

Raw reports cannot choose paths. The finalized inventory uses fixed normalized
relative names and SHA-256 digests. A success artifact is never finalized or
uploaded before cleanup affects the platform result.

For Linux and Windows readiness/release jobs, native execution writes
`platform-report.provisional.json`. After a successful cleanup-aware
`FinalizationReceiptV1`, the finalizer atomically creates the sole schema-v3
`platform-report.json`, binding `memcordon/finalization.json`,
`memcordon/inventory.sha256`, the runtime-lock digest, and the exact operation
set, and removes the provisional file. macOS writes schema v3 with an explicit
null MemCordon binding. Release assembly retains the complete finalized Linux
and Windows MemCordon subtrees in the conformance evidence subject so both
offline verifiers consume the same bytes.

## Commands and local operation

The committed task manifest is `ci/memcordon-tasks-v1.toml`. The supported Rust
driver commands are:

```text
hell-ci memcordon acquire --task ci/memcordon-tasks-v1.toml --operation OPERATION
hell-ci memcordon prepare --task ci/memcordon-tasks-v1.toml --operation OPERATION
hell-ci memcordon canary --task ci/memcordon-tasks-v1.toml --operation OPERATION
hell-ci memcordon cleanup --task ci/memcordon-tasks-v1.toml --operation OPERATION
hell-ci memcordon finalize --task ci/memcordon-tasks-v1.toml --operation OPERATION
```

`OPERATION` is one of `readiness`, `release`, `nightly`, `mutation`,
`regression-corpus`, `regression-subject`, or `fuzz`. Native provider work
requires an ephemeral Linux x86-64 or elevated Windows x86-64 host satisfying
the pinned provider prerequisites. Cleanup must still run after preparation or
candidate failure. A cancelled/crashed host without cleanup proof cannot
produce an admissible platform result; runner destruction is not a receipt.

Raw download caching may contain only verified pinned distribution bytes.
Every restore is rehashed and freshly extracted. Provider installation,
qualification, services, sockets, guardian state, candidate identities, and
pass/fail receipts are never cached. Final verification is offline and does not
install or execute MemCordon.

## Failure and upgrade policy

There is no Linux or Windows fallback to standard/process-group supervision.
Provider loss, qualification failure, slot exhaustion, missing or candidate-
writable reports, raw/projection disagreement, adapter disagreement, frontend
cleanup uncertainty, uid/Job survivor evidence, or uninstall ambiguity fails
the gate and poisons further admission.

An upgrade requires a reviewed lock change, exact wire and capability diff,
complete component/package verification, native Linux and Windows adoption
canaries, both verifier mutation corpora, and regenerated workflows. A later
`0.5.2-rc.*` is never selected automatically.
