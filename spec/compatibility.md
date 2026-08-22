# Compatibility and release conformance

Compatibility is evaluated independently across eight dimensions: parse,
static semantics, pure runtime, effects, concurrency, presentation, platform,
and resource behavior. Executable wiring and smoke-test coverage do not imply
semantic equivalence.

## Canonical cells and release scope

A conformance cell is the exact tuple `(builtin, dimension, profile,
platform)`. Component identifiers have canonical lowercase textual forms, and
the trusted builtin registry, dimension order, profile order, and release
platform order define the complete ordered universe.

`upstream-release-v1` evaluates the `upstream` profile on Linux x86-64, macOS
ARM64, and Windows x86-64. The `sandboxed` profile is present in the universe
but explicitly `Excluded` from this standard. Exclusion makes no compatibility
claim and never contributes to verified coverage.

For the current registry, the universe contains `355 × 8 × 2 × 3 = 17,040`
cells. The standard therefore begins with 8,520 upstream cells subject to
applicability evaluation and 8,520 excluded sandboxed cells. Required and
not-applicable totals are derived from the plan rather than hard-coded.

Applicability is fail-closed. A trusted exact rule may classify a cell
`NotApplicable` only when the dimension has no meaningful application to that
cell. Unknown builtin families, missing metadata, and ambiguous decisions are
`Required`. `NotApplicable` is distinct from both `Excluded` and verified.

## Requirements and evidence obligations

The status-free requirements catalog describes scope, applicability rules,
evidence strategies, cases, normalizers, and obligations. It does not author a
final result. An empty or unresolved evidence mapping produces a required cell
whose obligation cannot be satisfied; it is not a releasable “unverified”
status.

The plan schema names native oracle comparison, portable static evidence,
structural invariants, a committed differential corpus, and reviewed
cross-platform relations. The current release evaluator admits native-oracle
and committed-corpus records; portable-static, structural-invariant, and
cross-platform-relation obligations fail closed as invalid until their trusted
codecs and evaluators are implemented. Native runtime obligations require evidence from the
matching native job. Portable or multi-cell evidence is accepted only when the
trusted requirement explicitly enumerates its covered cells.

Each committed evidence record binds the candidate commit and executable,
source inventory, upstream oracle commit and executable, platform, profile,
release and conformance plan digests, cell key, obligation, committed case, and
raw observation digests. Producers may report observations and requested
normalizers, but never an authoritative `verified`, `accepted`,
`releaseEligible`, or `outOfScope` result.

Raw observations retain exit status, complete bounded stdout and stderr, and
canonical diagnostic, filesystem, semantic, and resource representations.
Those latter fields are currently opaque diagnostic encodings rather than a
typed release claim. Truncation or overflow is
invalid evidence. Candidate and oracle processes are invoked through structured
argument vectors with isolated working directories and a scrubbed environment.

## Normalization and mismatches

A normalizer is intended to be a trusted, versioned, deterministically ordered transformation
with an exact cell scope and exact observation fields it may change. Assembly
loads raw observations, obtains the approved closure from the planned
obligation, replays every normalizer, hashes the normalized observations, and
then compares canonical bytes. A producer-supplied normalized verdict has no
authority. The current catalog entries deliberately fail closed because trusted
normalizer replay implementations are not yet available; therefore normalized
verification cannot admit a cell in the current release implementation.

A known semantic difference is not verification. It may be admitted only as an
exact, candidate-bound, expiring `known-divergence` exemption whose expected
mismatch digest matches the trusted recomputation. A missing committed case may
use only an exact `evidence-gap` exemption. Invalid or misbound evidence cannot
be exempted. An exemption on an already verified, excluded, or not-applicable
cell is contradictory and blocks release.

Generated stress cases are exploratory. Agreement does not satisfy a committed
obligation or increase verified counts. A generated mismatch always creates an
unclassified global blocker with replay data; it remains blocked until a later
review promotes it to a committed case, a precise known-divergence exemption,
or a justified applicability decision.

## Derived partition

Trusted assembly derives exactly one final disposition for every planned cell:

- `VerifiedExact`
- `VerifiedNormalized`
- `VerifiedPlatformEquivalent`
- `NotApplicable`
- `Excluded`
- `Exempted`
- `BlockedMissingEvidence`
- `BlockedMismatch`
- `BlockedInvalidEvidence`

If `U` is the planned universe and `V`, `N`, `X`, `E`, and `B` are the verified,
not-applicable, excluded, exempted, and blocked sets, the verifier proves:

```text
U = V disjoint-union N disjoint-union X disjoint-union E disjoint-union B
```

Release admission requires an exact universe and complete partition, an empty
blocked set, no unclassified generated mismatch, all required obligations
consumed, every exemption exact and consumed once, and all artifact digests and
inventories cross-bound. Counts are outputs derived from the partition; no
producer-supplied count is trusted.

## Release claims and artifacts

The authoritative machine-readable artifacts are `conformance-plan.json`, the
content-addressed `conformance-evidence.tar.gz`, `conformance-report.json`, and
`conformance-acceptance.json`. Assembly and both read-only verifier
implementations derive the same partition from the plan and raw evidence
without executing candidate code in a privileged job.

Release notes may say every required cell was verified only when there are no
exemptions. Otherwise they disclose the exact exemption count and the report
retains every exemption ID, cell, issue, rationale, and expiry. Excluded,
not-applicable, and exempted cells are never described or counted as verified.
The workflow trust boundary and publication procedure are specified in
[`release-assurance.md`](release-assurance.md).

## Independent release reconstruction

Release admission is specified by
[`release-admission-protocol-v1.md`](release-admission-protocol-v1.md). The
primary verifier and `hell-release-verifier` independently enumerate cells,
consume evidence, evaluate exact dispositions and exemptions, derive the
ledger, and bind the final subject set. They share declarative obligation rules
and adversarial vectors as specification data, but no decisive Rust parser,
model, archive, canonicalization, ledger, exemption, or admission code.

Counts and producer-authored acceptance fields are consistency observations
only. Missing, duplicate, unused, contradictory, relabeled, or replayed
authority fails in both implementations. A release proceeds only when both
decisions are admitted and every authoritative semantic field agrees exactly.
