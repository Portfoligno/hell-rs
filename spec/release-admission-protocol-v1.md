# Release admission protocol v1

This document is normative for `release-admission-v1`. The key words MUST, MUST NOT,
REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY are requirements terms.

The protocol decides whether one exact `hell-rs` candidate may become one exact release.
It does not decide which branch to release, mutate release evidence, attest subjects, or
publish a GitHub release. Trusted workflow control performs those operations around the
protocol.

## Bound authority

An admission binds all of the following:

- numeric repository identity, owner, and repository name;
- trusted workflow commit and exact candidate commit;
- CI and release-admission protocol identities;
- release plan, conformance plan, obligation rules, and trusted-input inventory;
- governance declaration, observed governance profile, and residual assumptions;
- external-input lock and one native-environment receipt per required platform;
- source inventory, conformance ledger, release gate, and exact subject manifest; and
- primary and independent verifier decisions.

The trusted plan constructor selects the protocol version. Candidate input cannot select
an older version and a verifier MUST NOT retry another protocol after a failure.

## Protocol inputs

The normative input set consists of this file, the canonical JSON form of
`compat/release-obligation-rules-v1.json`, and the canonical JSON form of
`ci/release-protocol/v1/projection.json` with `protocolSha256` omitted.

`protocolSha256` is:

```text
SHA256(
  "hell-rs:release-admission-inputs:1" || NUL ||
  canonical-projection-without-protocolSha256 || NUL ||
  canonical-obligation-rules || NUL ||
  raw-bytes-of-this-file
)
```

The checked-in projection declares parser and archive limits. A verifier MUST recompute
the digest before using the projection. Unknown projection keys or versions fail closed.

## Domain-separated objects

New protocol-object digests use:

```text
SHA256("hell-rs:" || object-type || ":" || schema-version || NUL || canonical-bytes)
```

The object types are `verifier-decision`, `verifier-agreement`,
`publication-envelope`, `governance-profile`, `native-environment`, and
`native-environment-set`. File payloads in `SUBJECTS.sha256` use ordinary SHA-256.

All hexadecimal digests are exactly 64 lowercase ASCII hexadecimal characters.

## Strict JSON

Every authoritative JSON object MUST:

- be UTF-8;
- contain exactly one JSON value and one trailing newline;
- use its declared schema version;
- contain every required field and no unknown field;
- contain no duplicate object key;
- contain no floating-point number;
- use unsigned integers only where the schema says unsigned;
- use the shortest decimal integer spelling;
- stay within the projection limits; and
- serialize to the protocol canonical form.

The canonical form sorts object keys by UTF-8 byte order, preserves array order, emits no
insignificant whitespace, uses JSON escaping only where required, and appends one newline
on disk. A verifier parses to exact typed values and independently renders the canonical
form. Trailing bytes, excessive nesting, invalid Unicode, and unpaired surrogate escapes
fail closed.

Producer-authored acceptance summaries, counts, and booleans are never iteration bounds
or admission authority. A verifier MAY compare them only after deriving its own result.

## Canonical archive subset

Release packages use one gzip member containing GNU tar v1 records. The archive permits
regular files and directories only. It forbids symbolic links, hard links, devices, PAX
headers, GNU long-name records, sparse files, multiple gzip members, and trailing bytes.

Archive paths:

- use `/` separators;
- are relative;
- are nonempty;
- contain no empty, `.`, or `..` component;
- contain no NUL or platform separator alias; and
- are unique after exact protocol normalization.

Header checksums, numeric fields, ownership, modes, source-derived modification time,
member padding, end markers, gzip CRC, and expanded size MUST validate. The member set is
exact and bounded. Extraction MUST NOT precede complete path and inventory validation.

The primary and independent verifiers MUST NOT share archive-reader implementation code.

## Conformance cell ledger

A cell key is the tuple:

```text
(builtin, dimension, profile, platform)
```

Each verifier independently:

1. validates the plan and obligation-rule digest;
2. enumerates every declared cell in canonical key order;
3. rejects duplicate or noncanonical keys;
4. derives the required disposition class from the declarative rules;
5. indexes raw evidence by every bound identity;
6. consumes each required record exactly once;
7. evaluates agreement, platform equivalence, not-applicable, exclusion, or exemption;
8. rejects unused authoritative evidence;
9. rejects missing or contradictory evidence;
10. derives exactly one final disposition per cell;
11. derives counts from the ledger;
12. requires zero blocked cells; and
13. derives the canonical ledger digest.

Evidence identity includes cell, obligation, case, candidate, executable, oracle,
profile, platform, source inventory, and plan digest. Relabeling or replaying any of those
fields fails.

Evidence input order is not authority. When the protocol permits arbitrary input order,
the verifier sorts by canonical key before deriving the ledger. Duplicate evidence still
fails rather than collapsing during sorting.

## Obligation rules

The obligation language permits only exact field equality, membership in a fixed set,
conjunction, disjunction, explicit platform/profile selection, exact case requirements,
explicit evidence-kind requirements, and bounded date comparison with the plan evaluation
instant. It has no recursion, scripting, regular expressions, dynamic file access, or wall
clock access.

Both verifiers parse and evaluate the same declarative rules with independent types and
implementation code.

## Exemptions

An exemption is valid only when every bound selector matches exactly, its mismatch
fingerprint matches the independently derived mismatch, and its expiry is not before the
plan evaluation instant. Wildcards and omitted selectors are forbidden. The verifier does
not read wall-clock time. An unused exemption fails.

## Subject manifest

`SUBJECTS.sha256` is a newline-terminated sequence of lowercase SHA-256, two ASCII spaces,
and one safe relative path. Entries are in canonical path order. Duplicate paths or
digests, unsafe paths, omitted required subjects, and extra files fail.

The manifest does not contain itself or any object that recursively binds its own file
digest. The release gate binds the subject-manifest digest. Artifact transport digests are
bound through workflow outputs and checked downloads rather than inserted into the
artifact that produced the digest.

## Verifier decision

Both implementations emit schema version 1 with exactly these fields:

```text
schemaVersion
implementation
protocolVersion
protocolSha256
candidateSha
workflowSha
releasePlanSha256
conformancePlanSha256
sourceInventorySha256
trustedInputsSha256
obligationRulesSha256
governanceDeclarationSha256
governanceProfileSha256
governanceResolveSha256
governancePostAssemblySha256
governancePreAttestationSha256
residualAssumptionSetSha256
externalInputsSha256
nativeEnvironmentSetSha256
cellLedgerSha256
subjectManifestSha256
releaseGateSha256
requiredCellCount
verifiedCellCount
exemptedCellCount
blockedCellCount
admitted
```

`implementation` is `hell-ci` for the primary verifier and
`hell-release-verifier` for the independent verifier. Every other authoritative field is
derived from lower-level evidence. Admission requires complete evidence, zero blocked
cells, exact subjects, and every bound identity matching.

Unknown decision fields, duplicate keys, malformed identities, forged counts, and trailing
bytes fail.

## Agreement

Agreement parses both decisions independently and compares protocol, candidate, workflow,
all plan and inventory digests, ledger digest, subject digest, release-gate digest, counts,
and admitted state. Implementation identifiers MUST differ as specified. Agreement does
not rerun conformance logic.

Any semantic difference produces stable diagnostic `release.verifier-disagreement`, writes
a canonical non-admitted agreement report where feasible, and returns failure. Both
decisions MUST be admitted before the agreement may be admitted.

## Publication envelope

Read-only final verification creates schema version 1
`publication-envelope.json`. It binds:

- repository numeric identity, owner, and name;
- workflow and candidate commits;
- version, tag, source-date epoch, and plan evaluation instant;
- protocol, release-plan, conformance-plan, and trusted-input digests;
- governance declaration/profile and residual-assumption-set digests;
- the canonical resolve, post-assembly, and pre-attestation governance receipt digests;
- native-environment-set digest;
- both verifier-decision digests;
- conformance ledger, subject manifest, and release-gate digests; and
- admitted state.

It contains no verifier wall-clock timestamp. A shallow verifier rehashes the exact subject
set and checks every envelope binding without parsing package archives or conformance
evidence.

## Privilege boundary

Deep parsing occurs only in `final-verify`, which has read-only `actions` and `contents`
permissions and no token environment. `attest` may obtain OIDC and attestation permissions
but has no contents-write permission. `publish` may obtain contents-write permission but
has no OIDC or attestation permission. Candidate code never executes in those jobs.

Attestation and publication perform shallow envelope, subject, attestation-inventory, and
remote-state checks only. The publisher accepts only absent state, the exact machine-owned
draft, or an exact already-published immutable release. It never overwrites an unexpected
asset, tag, draft, or published release.

## Governance and native environment

Governance observations have statuses `observed`, `unavailable`, or `not-applicable` and
evaluations `matched`, `mismatched`, `residual-assumption`, or `not-applicable`.
Unavailable is never matched. Observed security-relevant mismatch blocks. Residual
assumptions are exact declared, digest-bound, disclosed identifiers, not synthesized values.

The finalized release plan is created before the resolve governance snapshot. The resolve
snapshot is stored beside that plan and uploaded in the same authenticated artifact. A
dedicated read-only governance job runs only trusted automation after assembly. It downloads
the plan artifact by numeric artifact ID, records the post-assembly snapshot against the
resolve baseline, then records the pre-attestation snapshot against both the resolve baseline
and the post-assembly predecessor. It uploads the receipt chain and the authority-bearing
37-vector corpus with separate numeric artifact IDs and transport digests.

Token-free `final-verify` downloads both artifacts, verifies the raw canonical
resolve-to-post-assembly-to-pre-attestation digest chain, and binds all three receipt digests
into each verifier decision and the publication envelope. Before publication, the publisher
job records a pre-publish receipt against the resolve baseline and downloaded pre-attestation
predecessor. The publisher consumes that receipt directly. Governance command reports are
outcome records and never substitute for the signed/bound receipts.

Each required platform report binds one native-environment receipt and the external-input
lock. The receipt includes the logical platform, OS, architecture, hosted image identity,
toolchain and linker/SDK identities, tool and executable digests, oracle identity, archive
protocol, and external-input-lock digest. A cache hit never substitutes for hashing the
restored executable.

These receipts provide identity control and drift diagnosis, not a claim of hermetic or
offline reproducibility.

## Bounded processing and diagnostics

All size, depth, member, evidence, and diagnostic limits come from the bound projection.
Limit arithmetic uses checked integer operations. A limit failure is a rejection, not a
partial result.

Diagnostics contain a stable code, protocol object path, expected and observed summaries,
relevant non-secret digests, and a bounded human message. Credentials, authorization
headers, and secret values never appear.

## Implementation independence

The primary and independent verifiers may share this specification, declarative rules,
fixed identifiers, cryptographic algorithm identifiers, and protocol fixtures. They MUST
NOT share Rust models, parsers, canonical serializers, digest wrappers, archive readers,
universe construction, evidence consumption, exemption matching, acceptance derivation,
or bundle-inventory implementation.

Automated dependency-boundary tests enforce this rule. Common Rust compiler, workspace
lockfile, and SHA-256 algorithm are disclosed residual common-mode dependencies.

## Regression corpus

Both verifiers run every vector in `ci/release-protocol/v1/manifest.toml`. Valid vectors
must be accepted with identical semantics. Invalid vectors must be rejected with the
declared stable diagnostic. The corpus covers strict JSON, identity binding, evidence
replay, ledger completeness, exemptions, archive structure and limits, subject inventory,
governance/environment binding, downgrade rejection, forged producer summaries, and both
directions of verifier disagreement.

Fuzz or mutation failures are minimized and promoted into this deterministic corpus. No
project-authored test infrastructure uses regular expressions.
