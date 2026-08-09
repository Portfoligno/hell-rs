# Compatibility policy

Compatibility is measured independently across parse, static semantics, pure
runtime, effects, concurrency, presentation, platform, and resource behavior.
Each claim names its execution profiles, platforms, evidence, normalizers, and
rationale. Executable wiring never implies semantic equivalence; absent current
pinned-oracle evidence, a dimension remains `Unverified`.

The pinned executable is a test oracle, not a runtime dependency. Evidence must
identify the baseline and both executables, and release gates count actual
oracle-versus-candidate comparisons separately from candidate-only stress.
Known baseline quirks and deliberate sandbox divergences are versioned rather
than silently corrected.

Promotion is governed by the digest-bound `compat/promotion-policy.toml` and a
strict human review record. Only the `upstream` execution profile is currently
in scope. Every retained summary and merged manifest names that required
profile and counts unverified out-of-scope profile cells so an upstream result
cannot be represented as universal compatibility.

Claim evidence is eligible only when a committed case catalog entry names the
exact builtin, dimension, profile, platform scope, and closed normalizer set.
Generated stress cases are never claim evidence. Observation bundles use a
nested schema-v2 layout whose manifest covers every retained byte; merge
revalidates the bundle inventory, source, case descriptor, observation
normalizers, and zero-count candidate resource audit. Reviewed deliberate
divergences are counted separately from unexplained or implementation
mismatches and require a current, identity-bound expected-mismatch entry.

The global gate is intentionally fail-closed and read-only. A pending review,
unavailable native oracle, placeholder digest, expired exception, missing or
extra artifact, provenance mismatch, dependency-attestation mismatch, or any
typed evidence failure keeps promotion unavailable. An accepted pre-gate
review requests fresh evidence and does not claim that the later explicit gate
already passed.
