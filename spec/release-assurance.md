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
for the exact `github.sha`. The planning job checks out both the readiness
driver and repository under test at that immutable candidate SHA. The plan
requires their Git identities to match, binds that identity into every plan,
report, and evidence artifact, and every downstream job checks out that exact
revision. The Linux, macOS, and Windows jobs execute the same technical gate
inventories used by release, and the final exact-SHA verifier reconstructs the
complete evidence partition. A stale default-branch driver cannot participate
in this branch-independent preparation path, and a substituted driver or plan
fails identity and digest validation. A green aggregate push check suite
therefore means that exact commit is technically eligible to become a release
under its candidate-bound control plane.

Automatic readiness includes conformance policy and plan binding,
applicability and evidence catalogs, native oracle evidence, confinement,
formatting, linting, tests, documentation, dependency policy, examples,
mutation, release builds, archive verification, and package smoke. It excludes
release intent and remote writes: release version and changelog admission, tag
and release conflict checks, attestations, and publication. It neither creates
nor reuses release authority.

## Trust boundary

Automatic readiness is an exact-SHA, candidate-bound preparation path; it has
no release or attestation authority. The protected default-branch workflow and
Rust release driver remain the trusted publication control plane and
independently rerun readiness before publishing. Candidate code executes only
in unprivileged GitHub-hosted Linux, macOS, and Windows readiness jobs with
read-only repository permissions. Those jobs receive neither repository write
permission nor OIDC attestation permission. Candidate and oracle processes run with a
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
`attestations: write`, and `artifact-metadata: write`. GitHub API authority is
exposed only through the standard step-local `GITHUB_TOKEN` name to five exact
trusted commands: candidate resolution, plan creation, the post-assembly remote
check, the pre-attestation remote check, and final publication. Candidate jobs,
assembly, and independent bundle verification have no token mapping.

## Workflow data and credential boundaries

The release path separates four data planes. Dispatch inputs, step and job
outputs, `needs`, action inputs, permissions, and numeric artifact IDs form the
workflow-control plane. Canonical plans, reports, evidence, archives, checksums,
and attestations form the artifact plane. GitHub-defined paths and metadata such
as `GITHUB_EVENT_PATH`, `GITHUB_OUTPUT`, `GITHUB_API_URL`, `GITHUB_WORKSPACE`,
and `RUNNER_TEMP` form the runner-contract plane. The automatic job token is the
credential plane and is never copied into an argument, output, artifact, cache,
or project-specific environment alias.

Workflow and job environment mappings are forbidden. A step environment is
either absent or is the exact one-entry `GITHUB_TOKEN: ${{ github.token }}`
mapping on one of the five trusted commands above. The typed Rust workflow
policy enforces the exact command, job, mapping, count, and ordering, so a new
custom environment key fails without requiring a denylist update. Contributors
should carry operator data through workflow inputs, internal scalars through
step or job outputs, action configuration through `with:`, and process-visible
structured data through canonical artifact files.

Assembly and bundle reconstruction are deterministic and credential-free.
Remote branch and tag state is checked after assembly before bundle upload,
again after independent reconstruction before attestation, and finally inside
publication to close the remaining race. A missing or invalid token, API
failure, moved candidate branch, or existing tag fails closed at the applicable
remote checkpoint.

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

Each pinned attestation action appends its generated bundle path to
`RUNNER_TEMP/created_attestation_paths.txt`. The trusted Rust staging command
requires exactly two ordered entries, verifies that the registry and source
files are bounded real files beneath `RUNNER_TEMP`, rejects duplicates and
pre-existing destinations, parses the JSON, and preserves the signed bytes
under the two fixed release-bundle names. Missing, extra, reordered, external,
or malformed entries fail closed. Workflow policy requires the two exact
attestation actions to remain adjacent to staging, and publication independently
validates their subject and predicate semantics.

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
