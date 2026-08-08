# Hell in Rust

This workspace is an independent Rust implementation of the Hell scripting
language targeting the pinned `2026-05-29` baseline. It keeps source handling,
syntax, type inference, independent core verification, call-by-need evaluation,
host adapters, and the CLI behind separate crate boundaries.

This is not yet a complete replacement for the pinned implementation. All
355/355 registry entries now have executable compiler/runtime adapters, and the
current compatibility matrix accepts 44/44 upstream examples with `--check`.
Records, user sums/cases, laziness regressions, global expansion, the core
verification boundary, process/file/temp adapters, JSON, time, concurrency, and
a bounded collection/type-class surface have direct regressions. Compatibility
coverage is still incomplete: several newly executable adapters need broader
differential edge-case, cancellation, and resource-limit coverage.

The executable supports:

```text
hell FILE [SCRIPT-ARGUMENTS...]
hell --check FILE
hell --version
```

The upstream Haskell implementation is a read-only differential-test oracle.
The Rust executable does not invoke GHC or an upstream `hell` process.
