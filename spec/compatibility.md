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
