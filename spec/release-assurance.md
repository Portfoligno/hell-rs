# Release assurance

## Authority and operator model

One manual dispatch of `.github/workflows/release.yml` from the protected
default branch is the sole final operator gate. The only operator input is the
name of a same-repository candidate branch. Trusted automation resolves that
branch to an exact commit, records the immutable actor and workflow identity,
and evaluates the complete release decision. There is no later approval,
promotion workflow, signing handoff, or publication action.

The workflow derives the version, tag, changelog section, source inventory,
trusted conformance inputs, conformance plan, and platform assignments from
committed inputs. It checks candidate-head stability again before publication.
Prior CI results never authorize a release; dispatch independently reconstructs
and reruns the technical decision before any publication authority is granted.

## Automatic push readiness

Every branch push, with tag pushes excluded, runs one unfiltered readiness DAG
for the exact `github.sha`. The planning job resolves the repository's current
default branch to an immutable trusted-automation SHA, binds that SHA into the
plan, and every downstream job checks out that exact automation revision. The
candidate branch remains arbitrary. The Linux, macOS, and Windows jobs execute
the same technical gate inventories used by release, and the final trusted
verifier reconstructs the complete evidence partition without executing
candidate code. A green aggregate push check suite therefore means that exact
commit is technically eligible to become a release under that bound control
plane.

Automatic readiness includes conformance policy and plan binding,
applicability and evidence catalogs, native oracle evidence, confinement,
formatting, linting, tests, documentation, dependency policy, examples,
mutation, release builds, archive verification, and package smoke. It excludes
release intent and remote writes: release version and changelog admission, tag
and release conflict checks, attestations, and publication. It neither creates
nor reuses release authority.

## Trust boundary

The protected default-branch workflow and Rust release driver are the trusted
control plane. Candidate code executes only in unprivileged GitHub-hosted Linux,
macOS, and Windows jobs with read-only repository permissions. Those jobs
receive neither repository write permission nor OIDC attestation permission.
Candidate and oracle processes run with a
scrubbed environment, structured argument vectors, bounded output, and bounded
execution time.

The workflow remains active. Every dispatch reruns the fixed hosted-runner
gates, and any unresolved conformance cell, invalid evidence, confinement
failure, or publication precondition fails the run before publication. There
is no separate workflow enablement or cutover toggle. Pre/post source hashing
is defense in depth, not a substitute for the distinct-principal and ACL/DACL
boundary.

Assembly runs trusted automation and treats every platform artifact as
untrusted data. Publication checks out only `github.workflow_sha`, downloads
the assembled bundle and plan by numeric artifact ID, and never executes the
candidate binary, package scripts, or candidate build code.

Only the publication job has `contents: write`, `id-token: write`,
`attestations: write`, and `artifact-metadata: write`. The job-scoped GitHub
token is used only after local verification succeeds.

## Candidate-specific conformance decision

The release standard is `upstream-release-v1`. It requires the `upstream`
profile on `linux-x86_64`, `macos-aarch64`, and `windows-x86_64`; it explicitly
excludes the `sandboxed` profile. Exclusion states what this release standard
does not claim. It is not evidence that the excluded behavior conforms.

Trusted resolution materializes every canonical cell identified by builtin,
compatibility dimension, profile, and platform. Every cell has exactly one
scope disposition:

- `Required`: evidence obligations must be satisfied.
- `NotApplicable`: an exact trusted rule proves that the dimension has no
  meaningful application to this cell.
- `Excluded`: the named release standard makes no claim for this scope.

Unknown, missing, or ambiguous applicability is `Required`. Every required cell
must end as verified or carry an exact reviewed exemption. An exemption binds
one candidate commit, standard, baseline, cell, obligation, failure class, and
expiry. Wildcards are forbidden. Exemptions are visible release debt and never
count as verification. An invalid evidence record cannot be rescued by an
exemption.

Platform jobs emit raw observations and digest-bound evidence records; they do
not emit authoritative acceptance labels or partition counters. Assembly
replays trusted normalizers, consumes the planned obligations, derives the
complete partition, and rejects missing, extra, duplicate, contradictory, or
misbound evidence. Generated agreements remain exploratory. Any generated
mismatch is an unclassified blocker until it is triaged into committed control
data.

Release admission requires a complete partition with no blocked cell, no
unclassified mismatch, all obligations consumed, and every planned exemption
consumed exactly once. `NotApplicable`, `Excluded`, and `Exempted` remain
distinct and are never added to verified totals.

## Blocking gates and evidence retention

The ordered Linux gate inventory is `runner-identity`, `candidate-checkout`,
`oracle-checkout`, `conformance-policy`, `conformance-plan-binding`,
`case-catalog`, `normalizer-catalog`, `divergence-catalog`, `verify`, `format`,
`clippy`, `workspace-tests`, `documentation`, `dependency-policy`,
`release-examples`, `release-mutation-catalog`,
`linux-release-oracle-digest`, `conformance-evidence`,
`divergence-prototypes`, `release-build`, `archive-verification`, and
`package-smoke`.

The ordered macOS and Windows inventory is `runner-identity`,
`candidate-checkout`, `oracle-checkout`, `conformance-plan-binding`,
`portability`, `workspace-tests`, `release-build`, `native-oracle-build`,
`conformance-evidence`, `divergence-prototypes`, `archive-verification`, and
`package-smoke`. Missing, duplicate, additional, reordered, or false gates fail
the release.

Assembly creates a deterministic evidence archive and authoritative
`conformance-report.json` and `conformance-acceptance.json` artifacts. The
publisher safely extracts the archive and independently reconstructs the plan,
evidence index, partition, counts, report, and acceptance bytes from its trusted
checkout. It does not use producer counters or report cells as decision inputs.
All non-attestation publishable assets except `release-gate.json` are bound into
`SUBJECTS.sha256`. The gate is necessarily excluded from that subject list to
avoid a self-referential digest cycle; it is still a required published asset
and v2 attestation predicate, and it binds the exact digest of the final
`SUBJECTS.sha256` bytes. The manifest and gate cross-bind every conformance
plan, evidence, report, and acceptance digest.

## Publication and recovery

After independent verification, pinned GitHub actions attest the exact subject
list with build provenance and the
`https://github.com/Portfoligno/hell-rs/attestations/release-gate/v2`
predicate. The Rust publisher verifies the staged bundles, candidate head, tag
state, asset inventory, and immutable-release capability before publishing.

The publisher is idempotent: an exact machine-marked draft can be resumed and
an exact already-published immutable release can be verified after an ambiguous
timeout. Human-created or conflicting state fails closed. A published immutable
release is never rewritten; corrections use a new version.

GitHub Actions, GitHub OIDC/Sigstore attestations, and GitHub immutable releases
are the trust domain. This model does not claim off-GitHub custody, independent
storage-provider acquisition, a second signer, a second builder identity, or
availability during a GitHub outage. No AWS account, SSH key, personal access
token, deploy key, repository secret, self-hosted signer, or environment
reviewer is required.

Historical collection activation, provenance, campaign scope, and review-group
files are audit material only. They never create release exclusions or
exemptions. Only a scope decision materialized in the trusted conformance plan
or an exact record in the trusted release-exemption catalog can affect release
admission.

## Operator procedure

1. Prepare a same-repository branch with a coherent workspace version and an
   exact non-empty `CHANGELOG.md` section.
2. Ensure the required conformance policy and evidence mappings are already in
   the protected default-branch control plane.
3. Open **Actions → Release → Run workflow** on the default branch.
4. Enter the candidate branch name and dispatch once.
5. If the run succeeds, inspect the immutable release, `SUBJECTS.sha256`, the
   conformance plan/report/acceptance, evidence archive, and GitHub
   attestations. If it fails, correct the candidate or reviewed control data
   and begin a new run; do not manually publish or repair a draft.
