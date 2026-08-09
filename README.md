# Hell in Rust

This workspace is an independent Rust implementation of the Hell scripting
language targeting the pinned `2026-05-29` baseline. It keeps source handling,
syntax, type inference, independent core verification, call-by-need evaluation,
host adapters, and the CLI behind separate crate boundaries.

This is not yet a complete replacement for the pinned implementation. All
355/355 registry entries now have executable compiler/runtime adapters, and the
current compiler smoke suite accepts 44/44 pinned upstream examples with
`--check`. Wiring is not a semantic compatibility claim: the dimensioned
compatibility report conservatively records behavior as unverified until a
retained oracle-versus-candidate evidence record supports promotion.
Records, user sums/cases, laziness regressions, global expansion, the core
verification boundary, process/file/temp adapters, JSON, time, concurrency, and
a bounded collection/type-class surface have direct regressions. Compatibility
coverage is still incomplete: executable adapters need broader differential
edge-case, cancellation, platform, and resource-behavior evidence.

The executable supports:

```text
hell FILE [SCRIPT-ARGUMENTS...]
hell --check FILE
hell --version
```

The upstream Haskell implementation is a read-only differential-test oracle.
The Rust executable does not invoke GHC or an upstream `hell` process.

## Continuous integration

Build the Rust CI driver:

```text
cargo build --locked --profile ci --package hell-ci --bin hell-ci
```

Run repository policy checks:

```text
target/ci/hell-ci policy --report ci-out/policy.json
```

Reproduce Linux verification:

```text
target/ci/hell-ci verify --report ci-out/verify-local.json
```

Run the portability suite:

```text
target/ci/hell-ci portability --report ci-out/portability-local.json
```

Run release and stress gates:

```text
target/ci/hell-ci dependency-attestation --output ci-out/dependency-policy.json --report ci-out/dependency-policy-report.json
target/ci/hell-ci nightly --oracle /path/to/pinned/hell --oracle-sha256 5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9 --dependency-attestation ci-out/dependency-policy.json --report ci-out/nightly-local.json
```

The nightly command validates and retains one evidence shard. Its shard summary
records `promotionReady: false` because no single platform can establish global
readiness. Missing reviewed claim mappings and required platform records remain
truthful counters without becoming collection failures. Build, differential,
policy, resource, and dependency failures still fail the command.

After all three native shard artifacts have been retained and reviewed, apply
the distinct fail-closed promotion gate explicitly:

```text
target/ci/hell-ci promotion-gate --input ci-out/native-shards --explain --report ci-out/promotion-gate.json
```

This command is read-only with respect to its retained input, revalidates shard
digests, bundle contents, claim mappings, resource audits, dependency policy,
and native provenance, and fails until every required counter is clean. It
writes `promotion-gate.sha256` beside the report. The committed review record
must still declare fresh collection required and must not pre-claim a gate
pass; the report is the record of the eventual explicit pass.

Generate the deterministic review worklist without changing claim source:

```text
target/ci/hell-ci promotion-worklist --profile upstream --output ci-out/promotion-worklist.csv --report ci-out/promotion-worklist-report.json
```

The repository intentionally ships with every compatibility claim unverified,
the macOS and Windows oracle records unavailable, and the promotion review
pending. Promotion requires an independent reviewer to download and hash the
bootstrap artifacts, inspect their inner manifests and native provenance,
retain a durable copy, commit reviewed metadata, and then collect fresh shards
for that exact commit. Do not replace review placeholders or availability
states with inferred values.

The reviewed Linux amd64 oracle is the `hell-linux-amd64` asset from the
upstream `2026-05-29` release. Its source, executable digest, and pinned build
inputs are recorded in `crates/hell-ci/oracle/linux-amd64.toml`; verify the
downloaded executable against that record before invoking the gate.

On Windows, invoke the built driver directly as
`target\ci\hell-ci.exe`, using the same subcommands and arguments.
