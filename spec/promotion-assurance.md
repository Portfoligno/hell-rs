# Promotion assurance and operations

Promotion is a content-addressed review of one candidate, one collection epoch,
and one proposal. A successful three-platform collection is necessary but does
not by itself establish artifact authenticity, native-oracle provenance,
semantic sufficiency, durable custody, reviewer independence, or acceptable
residual risk.

The repository therefore distinguishes four mechanical outcomes:

- `verified`: the named deterministic check passed for the exact bound input;
- `rejected`: the input violated policy;
- `requires-human-judgment`: mechanics prepared a bounded decision but cannot
  make it;
- `not-collected`: required evidence does not exist.

Human decisions are signed, digest-bound statements. A Boolean, workflow
success, environment approval, or artifact hash copied from its producing run
cannot stand in for a review statement.

## Source locks and collection epochs

[`compat/locks/catalog-digests.json`](../compat/locks/catalog-digests.json)
locks the declarative assurance catalogs. The lock digest covers canonical,
sorted `(path, SHA-256)` records, so changing a path is significant even when
its bytes are unchanged.

[`compat/locks/assurance-epoch.json`](../compat/locks/assurance-epoch.json)
locks every evidence-relevant source, policy, toolchain, case, generator,
normalizer, verifier, and workflow input. Review statements, custody receipts,
promotion-review output, and the locks themselves are excluded because they are
outputs of an epoch. The candidate Git commit is bound at collection time; it
is deliberately not embedded in its own committed lock, which would make the
commit self-referential.

Regenerate and verify the locks with direct argv-based commands:

```text
target/ci/hell-ci catalog-lock write
target/ci/hell-ci catalog-lock verify
```

Lock drift requires recollection. It must not be repaired by copying an old
digest into a new file. To explain epoch changes, generate both manifests and
use `evidence-epoch diff`:

```text
target/ci/hell-ci evidence-epoch write --output ci-out/epoch-before.json
target/ci/hell-ci evidence-epoch write --output ci-out/epoch-after.json
target/ci/hell-ci evidence-epoch diff --from ci-out/epoch-before.json --to ci-out/epoch-after.json --output ci-out/epoch-diff.txt
```

## Review packet

The deterministic packet narrows the human questions to:

1. whether the named repository, release, workflow, and acquisition channels
   are trusted for this promotion;
2. whether macOS and Windows build plans faithfully represent the selected
   upstream baseline;
3. whether claim applicability and required scope cells are semantically
   correct;
4. whether the obligation set and boundary cases are representative;
5. whether each typed normalizer removes only irrelevant nondeterminism;
6. whether each exact, fingerprinted divergence is acceptable;
7. whether independently retrieved custody copies and their retention policy
   are acceptable;
8. whether authorization and separation of duties are satisfied; and
9. whether the visible residual risk is acceptable under the bounded public
   statement.

Reviewers inspect raw and normalized observations, target-reachability events,
missing obligations, mutation results, provenance findings, custody receipts,
and unresolved findings. Every packet page enumerates its matching exception
records—or an explicit zero—and the machine-readable queue binds the exact
source path and SHA-256. The queues cover ambiguous applicability, normalizer
applications, accepted divergences, high-risk semantic families, weak mutation families, platform-result
differences, source-build warnings, custody/identity warnings, one-case groups,
and heuristic groups. The packet producer partitions every claim cell by the
full assurance-equivalence tuple: implementation, scheme, semantic family,
applicability, obligations, evidence/behavior references, normalizer set,
profile/platform, and disposition. It retains each exact cell and evidence-set
digest. High-risk-family entries are derived from the reviewed builtin catalog's
source reachability, capability, and environment-sensitivity metadata and bind
the exact finalized cell digests and claim-group identifiers. Four
independently authorized semantic reviews feed a deterministic pre-custody
review set, not a role graph or completed packet. After custody, the protected
graph stage derives the policy-required operational and review actions from the
retained envelopes, builds the custody-complete packet, publishes the unsigned
graph subject, and has an independent review-graph reviewer sign the exact group
set, final role-graph digest, and offline packet digest. The graph remains
promotion-blocking until every action required by the current policy is present
and verified. Applicable normalizer authorship is derived and verified from the
retained normalizer provenance; the graph is not represented as a fixed role
count.
`FollowUpRequired`, an old epoch, unauthorized identity,
prohibited role overlap, or a missing artifact remains a blocker.

## Promotion runbook

1. Verify catalogs, locks, applicability, case contracts, normalizer contracts,
   divergence records, reviewer policy, and mutation-policy syntax. Keep claims
   unverified and review records pending while implementing controls.
2. Collect Linux, macOS, and Windows evidence for the exact candidate and
   collection epoch. Each observation must bind the exercised executables,
   case contract, profile, platform, claim target, and closed normalizer set.
3. Verify independent acquisition receipts and native provenance. Record absent
   attestations and unresolved build findings as review-required; do not infer
   success from a digest match.
   The independent-acquisition producer is external to the ordinary repository
   runner trust domain. It downloads the declared bytes through its own channel,
   emits `receipt-independent.json`, and signs that receipt with its authorized
   acquisition principal. It then submits the exact
   `artifact-independent-acquisition` artifact. The current workflow retains the
   independently downloaded external provider object and its extracted source
   tree alongside the signed independent receipt and directory digest. The
   protected finalizer therefore retains two independently acquired byte copies:
   the separately selected primary-provider tree and the independent-provider
   object/tree. It rehashes and compares both against their receipt cores before
   the later authenticity-review workflow supplies the exact-set trust review.
   Repository collection jobs must not manufacture or self-approve the
   independent receipt.
4. Merge exactly three valid shards. Reject mixed candidates, epochs, catalogs,
   policies, executables, profiles, or platform identities.
5. Generate semantic coverage, normalizer audit, divergence, mutation, and
   residual-risk reports. Every mandatory claim obligation must resolve to a
   retained causal observation.
6. Run the claim, normalizer, divergence, and residual-risk reviews under
   distinct protected environments. `promotion-evidence-review.yml`
   cryptographically verifies those exact reviews and retained authorization API
   facts, writes a deterministic semantic-review set, and publishes the
   exact-ID-composed `promotion-review-ready-evidence` artifact for custody. It
   does not manufacture or sign a preliminary role graph.
7. Package evidence deterministically, upload the policy-required immutable
   copies, and retrieve them using an independent identity. Rehash the outer
   package and every inner manifest. Only after both retrieval receipts exist,
   materialize the exact package and assemble the deterministic Appendix-C
   directory (`index.html`, pages `01` through `10`, machine-readable packet,
   attachment tree, and `packet.sha256`). Before an explicit-zero exception
   queue is rendered, re-run the production verifiers for the finalized
   mutation report, both native provenance records, and the custody receipt.
   Mechanically derive the final policy-required action graph from the retained
   authoring, acquisition, oracle, platform, semantic, mutation,
   custody-provider, upload, and custody-review evidence. Missing required
   actions remain explicit blockers rather than being filled by fallback
   identities. Upload the unsigned
   graph subject first. A separate protected graph-review job downloads that
   exact provider artifact ID, verifies its run/attempt/archive digest, approves
   and signs the exact claim groups, graph, and packet, binds `role-graph.json`,
   and emits the proposal-ready `promotion-final-reviewed-evidence` artifact. No
   reduced or fixed-count graph is accepted as a promotion input.
8. Assemble one canonical promotion proposal. Its blocker map must contain all
   required blocker names and every value must be zero. This proposal cannot
   include its own approval without becoming cyclic.
9. Run the separate protected proposal-approval workflow for that exact proposal
   digest. Generate an exact-set `promotion-approver` packet, sign it, verify it,
   and attach the resulting `promotion-proposal-approval.dsse.json` to the gate
   input. The statement must cover the proposal, merged manifest, and every
   component record digest; a statement over a subset is invalid.
10. Manually dispatch the protected gate with the exact candidate SHA, assurance
   epoch SHA-256, and proposal SHA-256. The gate checks out the named commit,
   recomputes the epoch, verifies signatures and custody offline, revalidates
   merged evidence, and writes a read-only report.
11. Retain the gate report in durable custody and publish only the generated
    bounded compatibility report.

Step 11 is a second, non-circular invocation of `evidence-custody.yml` with
`artifact_class = final-promotion-record`. Its exact `promotion-record`
artifact contains the proposal, proposal approval, gate report, bounded public
report, and the first-pass custody receipt. The resulting second-pass custody
receipt proves durable retention of the final report but is not inserted back
into the already approved proposal. The record remains
`pending-durable-custody` until two provider-specific activation receipts and
their signatures are committed. Only verification of both active provider
contexts derives the separate `promotion-current-state.json` as `promoted`.

The protected oracle environments must provision different primary and
independent builder SSH keys, Sigstore identities, runner identities, Stack
compiler caches, and Stack Pantry caches. Each builder writes and transports
the canonical `ci-out/assurance-epoch.json` and its `.sha256` sibling with its
receipt; a source-input lock digest is not an assurance epoch.
Each build also retains `source-files.json`, a sorted inventory of every
git-tracked regular source file and its SHA-256. The collector rejects symlinks,
non-normal paths, paths outside the reviewed tree, Stack package/extra-dependency
overrides, mutable lock-package entries, and unreviewed flag overrides. The
build plan and provenance-policy verdict both bind the source inventory digest,
the reviewed Stack GHC options, resolver, executable target, and default local
package rooted at the reviewed tree.

Each custody OIDC role must be limited to one provider account and expose the
encrypted AWS Systems Manager parameter `/hell-rs/custody/provider-context`.
It is strict TOML containing only `schema_version = 1`, `provider`,
`trust_domain`, `bucket`, `active_candidate`, `active_epoch`, `active_manifest`, the exact active
receipt locator/version/digest, the exact activation record/packet/DSSE
locator/version/digest triples, and—after surveillance—the corresponding exact
current-transition triples. These fields select immutable S3 object versions;
partial locator triples are rejected. Upload, retrieval, maintenance,
activation, state-publication, and custody-review environments use distinct SSH
signer secrets. The custody workflow packages the provider-verified pre-review
evidence artifact; the later proposal review consumes the signed custody gate
record, so custody does not depend on the proposal review that it helps gate.

The gate does not modify claims, create a release, or publish source. Promotion
metadata changes and release publication remain separate reviewed operations.

## Residual-risk visibility

The generated bounded report lists:

- exact, normalized, platform-dependent, deliberate-divergence, unverified, and
  out-of-scope claim cells;
- tested profiles, platforms, toolchains, and runner identities;
- missing semantic obligations and undetected critical mutants;
- custody state, residual-risk tier, and open compatibility issues; and
- the explicit statement that finite corpus evidence is not universal proof.

`Low`, `Moderate`, `High`, and `Unacceptable` are policy tiers, not numerical
probabilities. An unacceptable group blocks promotion. A lower tier does not
permit the public report to omit corpus, environment, or temporal limits.

## Surveillance and incident response

[`compat/surveillance-policy.toml`](../compat/surveillance-policy.toml) is the
machine-readable cadence and transition policy. It requires:

- monthly custody retrieval and native-provenance rebuild checks;
- weekly divergence expiry, mutation, differential exploration,
  runner/toolchain drift, and trust-identity checks;
- divergence warnings 30, 14, and 7 days before expiry; and
- mutation reports no older than 14 days.

Scheduled producers cover mutation, custody scrub/recovery, macOS/Windows native
rebuilds, and the weekly composite promotion-surveillance workflow. The weekly
workflow retrieves exact active versions from both protected providers,
revalidates repository assurance and review revocations, runs the differential,
property, stress, regression, and mutation checks, compares runner/toolchain
identity, and derives a signed transition from digested component records.
Missing, corrupt, or unparseable components become typed failure evidence and
force an `at-risk` transition; the observation and signing path runs even after
collection failures. The signed transition is retained as a run artifact,
published immutably to every still-available custody provider, and a failing run
upserts the repository incident issue. The workflow also derives
`regression-impact.json`, joining retained mismatch bundles to exact claim cells,
evidence references, review groups, public statements, and approved divergence
fingerprints. Unchanged and unexpired approved divergences remain accepted;
new, changed, or expired mismatches force review and `at-risk`.

An independently scheduled daily watchdog queries the typed GitHub Actions run
and artifact records for the weekly surveillance workflow. It requires the exact
run attempt, current head SHA, scheduled event, workflow path and local workflow
blob, unexpired artifact ID/provider digest, signed transition, and digested
objective record. The cadence boundary is compared in seconds, including the
exact deadline instant. A missing, stale, incomplete, failed, wrong-head, or
no-op expected run creates a signed at-risk transition, retains it as an
immutable run artifact, upserts the incident, and fails the watchdog run. When
the last signed weekly record establishes the active candidate and epoch, the
watchdog supersedes that record and publishes the at-risk state to both durable
providers. If no subject can be authenticated, it emits the narrower
`observer-source-only` incident without claiming to mutate an unknown
promotion. A late weekly run also detects stale retained evidence, so a missed
deadline is an assurance failure on both producer and watchdog paths.

When both provider contexts are unavailable or corrupt, the emergency transition
uses `subjectState = observer-source-only`: its candidate and epoch fields name
the checked-out surveillance code used to produce the incident, not a claimed
promotion subject. It is still signed, retained, and alerted through the
workflow, but cannot be written back as a promotion state to an unavailable or
nonmatching provider. Restoration requires recovery of a signed activation
context before that provider can accept another current-state record.

A promotion becomes `at-risk` when required custody cannot be retrieved, a
signing identity is revoked, an attestation is invalidated, a critical mutant
becomes undetected, a divergence expires, a promoted claim regresses, or a
supported platform/toolchain expires. Alerts identify affected claim cells,
stale evidence and review groups, and public statements requiring qualification.

Revocation requires a signed governance action because the committed policy has
no automatic critical-revocation events. Until that action, the public report
must expose `at-risk`; it must never continue to present the record as current.
Old baseline records remain immutable and are superseded rather than rewritten.

Provider or API outages are classified as retryable collection failures only
before a policy deadline. Once freshness, custody, authorization, or retention
requirements are missed, the state is a compatibility assurance failure rather
than a silently ignored infrastructure warning.
