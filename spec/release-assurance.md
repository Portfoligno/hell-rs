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

The terminal `summary` job runs under `!cancelled()` after the plan, all three
platform producers, and the read-only verifier. Each predecessor is represented
by an exact typed job-state record: success binds the uploaded artifact's
nonzero numeric ID and lowercase transport digest, while failure or skip binds
explicit null artifact identity. The summarizer authenticates the fixed
artifact inventory and layout rather than trusting workflow result strings.
Missing, extra, malformed, forged, failed, or skipped producer state therefore
still creates a canonical blocked readiness summary and a failing check. Its
artifact IDs, absent-artifact list, first available source diagnostics, and
typed reproduction argv make failure evidence durable without turning a
producer failure into an apparent green aggregate.

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
untrusted data. The read-only `final-verify` job downloads the exact assembled
bundle and plan by numeric artifact ID, executes both independently implemented
verifiers, requires exact semantic agreement, and creates the canonical
publication envelope. It never executes the candidate binary, package scripts,
or candidate build code.

Privilege is split. `final-verify` has read-only `actions` and `contents`
permissions and performs every deep archive and conformance parse. `attest` has
OIDC, attestation, and artifact-metadata permissions but no `contents: write`.
`publish` has `contents: write` but no OIDC or attestation permission and uses
the minimal publisher. GitHub API authority is exposed only through the
standard step-local `GITHUB_TOKEN` on exact trusted resolution, governance,
remote-state, and publication commands. Candidate jobs and deep verification
have no token mapping.

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
mapping on one of the protocol-approved trusted commands. The typed Rust workflow
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

## Typed workflow and admission protocols

`ci/protocol/v1.toml` is the typed source of truth for all six checked-in
workflows. It defines triggers, concurrency, the exact job graph and permission
classes, native platform gate order, action pins, approved credential exposure,
artifact flows, and cache inputs. `hell-ci protocol render` deterministically
renders the workflows; `hell-ci protocol check` rejects byte drift. The
separately implemented `hell-workflow-auditor` parses the YAML and
`ci/protocol/v1.audit.json` with independent types and checks the same security
properties. Neither path permits a free-form gate list, custom CI environment
data plane, explicit shell, multiline `run:`, or more than one invocation per
run step.

The normative evidence protocol is `release-admission-v1`, documented in
[`release-admission-protocol-v1.md`](release-admission-protocol-v1.md). Its
content digest binds the canonical limits projection, declarative obligation
rules, and protocol text. The primary `hell-ci` verifier and independent
`hell-release-verifier` share specification data and vectors but not model,
parser, archive, canonicalization, ledger, exemption, or admission code.
Disagreement is stable diagnostic `release.verifier-disagreement` and blocks.

Every release-protocol vector is a complete materialized plan, conformance
plan, bundle, and expected outcome. Both implementations execute the same
known-good fixture and all 36 one-mutation invalid fixtures. A catalog-only,
identifier-only, or prewritten-decision-only check is not accepted as vector
evidence. After assembly, the dedicated read-only governance job records the
post-assembly and pre-attestation receipt chain, then materializes those
physical fixture trees from the authenticated resolution, admitted bundle,
and three native platform artifacts. It uploads the governance receipts and
corpus separately, each with numeric artifact ID and transport digest.
Token-free `final-verify` downloads those exact artifacts and executes both
vector runners before it can admit the release candidate. No offline synthetic
governance or native-runner receipt is substituted for these inputs.

Trusted resolution also records the repository's nonzero numeric identity from
the authenticated workflow context. The resolve receipt, governance profile,
release plan, and publication envelope bind that numeric identity together
with the owner and name. Post-assembly, pre-attestation, and pre-publication
snapshots must reproduce the exact receipt. The governance policy contains no
committed numeric substitute, and an unavailable numeric identity blocks
rather than becoming a residual assumption.

Governance snapshots use three observation states: `observed`, `unavailable`,
and `not-applicable`. An observed value is compared with the declaration and is
either matched or mismatched. Unavailable data is never rewritten as a match;
the control either blocks or binds one exact residual-assumption ID declared in
`ci/governance-policy.toml`. Not-applicable is accepted only when the policy
defines the disabling condition, such as merge queue being disabled. The
resolve baseline and the post-assembly, pre-attestation, and pre-publish
profiles bind the policy, API contract, release plan, repository identity,
candidate head, planned annotated tag, observations, and residual set, so later
phases cannot silently gain a more permissive interpretation.

The resolve receipt is a sibling of `release-plan.json` in the plan artifact.
The governance job compares post-assembly directly with that baseline and
compares pre-attestation with both the resolve baseline and the post-assembly
predecessor. The materializer receives both later receipts explicitly.
`final-verify` downloads their artifact by numeric ID, verifies the raw
canonical receipt chain, and binds the resolve, post-assembly, and
pre-attestation digests into both decisions and the publication envelope. The
pre-publish command compares the same resolve baseline and the downloaded
pre-attestation predecessor; the publisher consumes its resulting receipt.
Command reports are retained diagnostics, not authority-bearing receipts.

## Native environment identity and external inputs

Every required platform records a canonical native-environment receipt after
runner identity and before candidate or oracle execution. The receipt binds the
logical platform, operating-system and architecture identity, hosted-runner
image metadata when supplied, compiler and package-tool versions, executable
digests, linker or SDK identity, oracle source and executable identities,
candidate executable identity, archive protocol, and the digest of
`ci/external-inputs.toml`. Raw tool output is bounded and represented by its
digest; it is not treated as an unbounded diagnostic field.

Platform reports bind `nativeEnvironmentSha256` and `externalInputsSha256`.
Assembly requires exactly one authenticated receipt for Linux, macOS, and
Windows, constructs the canonical native-environment set, and carries its
digest through the release gate and publication envelope. Restoring a cache
does not prove executable identity: restored executables are resolved and
hashed again before their receipt can be admitted.

The external-input lock gives every network-acquired oracle, tool, or source a
typed identity, size bound, timeout, acquisition phase, and content digest (or
an exact source commit/version where that is the authoritative identity). The
Rust acquisition path verifies those properties before exposing bytes to a
later argv process. This is identity-controlled native validation, not an
offline or hermetic-build claim. GitHub-hosted image operation, network
availability, and the named upstream providers remain disclosed residual
dependencies; a later offline reproducibility phase would require separately
mirrored inputs and repeatable byte-identical builds.

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

The ordered Linux gate inventory is `runner-identity`,
`native-environment-identity`, `candidate-checkout`, `oracle-checkout`,
`conformance-policy`, `conformance-plan-binding`,
`case-catalog`, `normalizer-catalog`, `divergence-catalog`, `verify`, `format`,
`clippy`, `workspace-tests`, `documentation`, `dependency-policy`,
`release-examples`, `release-mutation-catalog`,
`linux-release-oracle-digest`, `conformance-evidence`,
`divergence-prototypes`, `release-build`, `archive-verification`, and
`package-smoke`.

The ordered macOS and Windows inventory is `runner-identity`,
`native-environment-identity`, `candidate-checkout`, `oracle-checkout`,
`conformance-plan-binding`,
`portability`, `workspace-tests`, `release-build`, `native-oracle-build`,
`conformance-evidence`, `divergence-prototypes`, `archive-verification`, and
`package-smoke`. Missing, duplicate, additional, reordered, or false gates fail
the release.

Assembly creates a deterministic evidence archive and primary
`conformance-report.json` and `conformance-acceptance.json` artifacts. The
read-only verifier reconstructs the plan, evidence index, partition, counts,
report, and acceptance bytes from its trusted checkout. A separately
implemented verifier reconstructs the same semantics through independent code,
and exact agreement is required. Neither uses producer counters or report cells
as decision inputs. Privileged jobs parse only the bounded publication envelope,
subject manifest, and attestation inventory.
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

The publish invocation also receives the attested artifact's nonzero GitHub
artifact ID and lowercase transport digest as separate whole-token job outputs.
Its canonical success report binds both `inputArtifactId` and
`inputArtifactDigest`; neither value is transported through the environment or
written into the artifact whose transport digest it describes.

Each pinned attestation action exposes one typed `bundle-path` output. The
trusted Rust staging command receives those whole-token outputs through the
distinct `--build-provenance-bundle` and `--release-gate-bundle` arguments,
requires two bounded regular JSON bundle files beneath the trusted runner
temporary directory, rejects identical or pre-existing destinations, and
preserves the signed bytes under the two fixed release-bundle names. Missing,
swapped, external, or malformed bundles fail closed. Workflow policy requires
the two exact attestation actions to remain adjacent to staging, and
publication independently validates their subject and predicate semantics.

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
