# Hell in Rust

This workspace is an independent Rust implementation of the Hell scripting
language targeting the pinned `2026-05-29` baseline. It keeps source handling,
syntax, type inference, independent core verification, call-by-need evaluation,
host adapters, and the CLI behind separate crate boundaries.

This is not yet a complete replacement for the pinned implementation. All
355/355 registry entries have executable compiler/runtime adapters, and the
current compiler smoke suite accepts 44/44 pinned upstream examples with
`--check`. Wiring and smoke tests are not semantic compatibility claims. The
release workflow separately requires a candidate-bound conformance partition
to admit the candidate. Records, user sums/cases,
laziness regressions, global expansion, process/file/temp adapters, JSON, time,
concurrency, and a limited collection/type-class surface have direct
regressions; broader differential edge-case and resource-behavior coverage is
still required.

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

Run repository policy and Linux verification:

```text
target/ci/hell-ci policy --report ci-out/policy.json
target/ci/hell-ci verify --report ci-out/verify-local.json
```

Run the portability suite:

```text
target/ci/hell-ci portability --report ci-out/portability-local.json
```

CI runs on pushes to every branch except tag pushes and on pull requests.
Extended, mutation, and regression workflows run directly on the pushed commit.
For a branch push, the complete green check suite means that exact pushed
commit satisfies the technical release-readiness predicate: full blocker-zero
conformance on all three native platforms, confinement, mutation, tests,
documentation, dependency policy, evidence reconstruction, and package smoke.
The readiness run creates no release state and performs no version, changelog,
tag, attestation, or publication operation. No workflow is relayed through
another workflow's completion, and no Actions workflow uses a scheduled
trigger.

The reviewed Linux x86_64 oracle is the `hell-linux-amd64` asset from the
upstream `2026-05-29` release. Its source, executable digest, and pinned build
inputs are recorded in `crates/hell-ci/oracle/linux-amd64.toml`.

On Windows, invoke the built driver directly as `target\ci\hell-ci.exe`, using
the same subcommands and arguments.

## Release

The GitHub **Release** workflow is the sole manual release gate. It must be run
from the protected default branch and accepts one required input: the name of a
same-repository candidate branch. The trusted workflow resolves that branch to
an exact commit, derives its version and tag, independently reruns every
technical readiness gate on
Linux, macOS, and Windows, assembles an exact release bundle, creates GitHub
artifact attestations, and publishes an immutable GitHub Release.

Candidate code runs only in read-only jobs without OIDC permissions. The final
publisher checks out only the trusted default-branch automation and downloads
the verified bundle by numeric artifact ID. No repository secret, AWS resource,
SSH key, personal access token, deploy key, self-hosted signer, or GitHub
Environment approval is part of this path.

Before dispatching:

1. Set a coherent workspace version on the candidate branch.
2. Add a non-empty exact-version section to `CHANGELOG.md`.
3. Open **Actions → Release → Run workflow** on the default branch.
4. Enter the candidate branch name and dispatch once.

The release is evaluated against `upstream-release-v1`: every required
upstream-profile cell on Linux x86-64, macOS ARM64, and Windows x86-64 must be
verified or covered by one exact, candidate-bound, expiring reviewed exemption.
Unknown applicability, missing evidence, semantic mismatches, invalid evidence,
and generated mismatches block publication. The sandboxed profile is explicitly
excluded and is never counted as verified.

Inspect `conformance-plan.json`, `conformance-report.json`,
`conformance-acceptance.json`, and `conformance-evidence.tar.gz` for the exact
scope, partition, decision, and retained raw evidence. Excluded,
not-applicable, and exempted cells remain distinct from verified cells. The
cell model and evidence rules are documented in
[`spec/compatibility.md`](spec/compatibility.md).

Verify a published release and an asset with GitHub CLI:

```text
gh release verify v0.1.0
gh release verify-asset v0.1.0 hell-v0.1.0-linux-x86_64.tar.gz
```

Also compare the published checksums, inspect `release-manifest.json`, and
verify the artifact attestations against `Portfoligno/hell-rs`. The complete
trust boundary, failure behavior, and operator procedure are documented in
[`spec/release-assurance.md`](spec/release-assurance.md).
