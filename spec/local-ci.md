# Local CI parity

This document is the local runbook for the repository-verifiable work performed
by every required branch-push workflow. Run each displayed line as a separate
process invocation from the repository root. None of these gates uses a
project-specific environment variable as an input; paths, identities, and
artifacts travel through typed arguments and files.

## Push workflow inventory

Tag pushes are excluded. The required branch-push workflows are:

| Workflow | Jobs and required gate inventory |
| --- | --- |
| `CI` | `plan`; Linux `runner-identity`, `candidate-checkout`, `oracle-checkout`, `conformance-policy`, `conformance-plan-binding`, `case-catalog`, `normalizer-catalog`, `divergence-catalog`, `verify`, `format`, `clippy`, `workspace-tests`, `documentation`, `dependency-policy`, `release-examples`, `release-mutation-catalog`, `linux-release-oracle-digest`, `conformance-evidence`, `divergence-prototypes`, `release-build`, `archive-verification`, `package-smoke`; macOS and Windows `runner-identity`, `candidate-checkout`, `oracle-checkout`, `conformance-plan-binding`, `portability`, `workspace-tests`, `release-build`, `native-oracle-build`, `conformance-evidence`, `divergence-prototypes`, `archive-verification`, `package-smoke`; final `verify` reconstruction |
| `Nightly` | Linux dependency attestation, pinned-oracle acquisition, extended oracle suite, generated-regression exploration, and divergence prototypes; five bounded fuzz targets and seed-corpus cleanliness; native macOS and Windows portability, dependency attestation, and pinned-source oracle shards |
| `Exploratory mutation` | The complete release-required mutant catalog |
| `Regression subject` | `typed_corpus` and `oracle_regressions` for every branch push |
| `Regression corpus` | The same two tests when the committed corpus, testkit, CLI regression tests, or its workflow changes |

`.github/workflows/release.yml` is not a push gate. Its branch resolution,
remote-state checks, GitHub attestations, and immutable publication are manual,
hosted-only release operations and are not part of local CI parity.

## Deterministic local gates

Build the checked-in Rust driver and its process-capable conformance helper
together first:

```text
cargo build --locked --profile ci --package hell-ci --bin hell-ci --package hell-testkit --bin hell-test-helper
```

Run the repository policy, compiler, test, documentation, dependency, example,
release-build, mutation, and committed-regression gates with explicit argv:

```text
target/ci/hell-ci policy --report ci-out/policy.json
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo install cargo-deny --locked --version 0.20.2 --force --target-dir ci-tool-cache/cargo-deny-target
cargo-deny --all-features check all
target/ci/hell-ci examples --profile release --report ci-out/release-examples.json
cargo build --release --locked --package hell-cli --bin hell
target/ci/hell-ci mutation run --output ci-out/mutation/mutation-score.json
cargo test --locked --package hell-testkit --test typed_corpus
cargo test --locked --package hell-cli --test oracle_regressions
target/ci/hell-ci case-catalog verify
target/ci/hell-ci normalizer-audit verify
target/ci/hell-ci divergence-verify verify
target/ci/hell-ci divergence-prototype verify
```

The Linux readiness command below is the exact local documentation gate. It
runs workspace documentation through the driver with the standard
`RUSTDOCFLAGS` tool contract set to deny warnings; the weaker direct `cargo
doc` invocation is intentionally not listed as an equivalent gate.

## Extended Linux and fuzz gates

The Linux oracle acquisition is a bounded HTTPS read of one pinned upstream
release and verifies the recorded SHA-256 before use. It is locally runnable
with network access:

```text
target/ci/hell-ci dependency-attestation --output ci-out/dependency-policy.json --report ci-out/dependency-policy-report.json
target/ci/hell-ci oracle-acquire acquire --artifact ci-out/linux-release-oracle --provider-response ci-out/linux-release-provider.json --receipt ci-out/linux-release-oracle-receipt.json
target/ci/hell-ci nightly --oracle ci-out/linux-release-oracle --oracle-sha256 5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9 --dependency-attestation ci-out/dependency-policy.json --report ci-out/nightly-linux.json
target/ci/hell-ci regression-import explore-generated --input ci-out --output ci-out/regression-exploration
target/ci/hell-ci divergence-prototype verify
```

The fuzz job uses the pinned nightly toolchain and `cargo-fuzz` version:

```text
rustup toolchain install nightly-2026-07-31 --profile minimal
cargo +nightly-2026-07-31 install cargo-fuzz --version 0.13.2 --locked --force --target-dir ci-tool-cache/cargo-fuzz-target
target/ci/hell-ci fuzz-corpus prepare --input crates/hell-ci/fuzz/corpus --output ci-out/fuzz-corpora --to ci-out/fuzz-artifacts
cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz requirement_toml ci-out/fuzz-corpora/requirement_toml -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/requirement_toml/
cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz normalizer_toml ci-out/fuzz-corpora/normalizer_toml -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/normalizer_toml/
cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz divergence_toml ci-out/fuzz-corpora/divergence_toml -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/divergence_toml/
cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz normalizer_replay ci-out/fuzz-corpora/normalizer_replay -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/normalizer_replay/
cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz semantic_trace ci-out/fuzz-corpora/semantic_trace -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/semantic_trace/
target/ci/hell-ci fuzz-corpus verify-clean --input crates/hell-ci/fuzz/corpus
```

Use fresh output paths when repeating artifact-producing commands.

## Native and hosted boundaries

Use a clean committed candidate checkout on each native operating system and a
separate checkout of `chrisdone/hell` at exact commit
`8e952cf9de4ab25d7716982a9ca234f9bdcf1bff`. macOS ARM64 and Windows x86-64
also require Stack 3.11.1.

The macOS host additionally requires Homebrew LLVM `llvm-ar`. The driver
accepts exactly Homebrew LLVM 18.1.8 (the `macos-15` hosted image) or 22.1.8
(the locally exercised toolchain), proves response-file and nested-archive
flattening semantics, and exposes only its typed adapter to the Stack child.
On the hosted image, expose the preinstalled pinned formula with one static
invocation before the platform command:

```text
brew link --force llvm@18
```

For the standalone Nightly equivalents, build the candidate explicitly in the
profile consumed by that shard:

```text
cargo build --locked --package hell-cli --bin hell --features compat-tracing
cargo build --release --locked --package hell-cli --bin hell --features compat-tracing
```

The first candidate command is for the Linux Nightly suite; the release build
is for the macOS and Windows native shards. The `compat-tracing` feature is a
required part of each differential candidate because its semantic evidence is
otherwise unavailable. Readiness and manual release platform commands build
their own equivalently featured candidate as a required gate. Create the
shared plan once, move its four files to the other machines without changing
their bytes, then run the matching native platform command:

```text
target/ci/hell-ci readiness plan --repository-root . --output ci-out/readiness-plan
target/ci/hell-ci readiness platform --platform linux-x86_64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-policy,conformance-plan-binding,case-catalog,normalizer-catalog,divergence-catalog,verify,format,clippy,workspace-tests,documentation,dependency-policy,release-examples,release-mutation-catalog,linux-release-oracle-digest,conformance-evidence,divergence-prototypes,release-build,archive-verification,package-smoke --plan ci-out/readiness-plan/readiness-plan.json --conformance-plan ci-out/readiness-plan/conformance-plan.json --repository-root . --oracle-source ci-out/oracle-source --output ci-out/readiness-platforms/linux-x86_64
target/ci/hell-ci readiness platform --platform macos-aarch64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-plan-binding,portability,workspace-tests,release-build,native-oracle-build,conformance-evidence,divergence-prototypes,archive-verification,package-smoke --plan ci-out/readiness-plan/readiness-plan.json --conformance-plan ci-out/readiness-plan/conformance-plan.json --repository-root . --oracle-source ci-out/oracle-source --output ci-out/readiness-platforms/macos-aarch64
target\ci\hell-ci.exe readiness platform --platform windows-x86_64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-plan-binding,portability,workspace-tests,release-build,native-oracle-build,conformance-evidence,divergence-prototypes,archive-verification,package-smoke --plan ci-out\readiness-plan\readiness-plan.json --conformance-plan ci-out\readiness-plan\conformance-plan.json --repository-root . --oracle-source ci-out\oracle-source --output ci-out\readiness-platforms\windows-x86_64
target/ci/hell-ci readiness verify --plan ci-out/readiness-plan/readiness-plan.json --conformance-plan ci-out/readiness-plan/conformance-plan.json --input ci-out/readiness-platforms --output ci-out/readiness-result
```

The three platform invocations are the exact candidate-bound conformance,
evidence, archive-verification, package-smoke, and documentation gates. The
three machines must then consolidate their unchanged platform output
directories under the exact `ci-out/readiness-platforms/<platform>` paths on
the machine that holds the plan. The final command reconstructs blocker-zero
eligibility from those three result directories. `target/ci/hell-ci
portability --report PATH` remains a useful direct native diagnostic but does
not substitute for this readiness DAG.

Cross-target compilation can catch conditional-compilation regressions from a
non-native host after installing the named standard-library target. It does not
claim to exercise native process confinement, Windows DACLs, the hosted image,
Stack, or native oracle execution:

```text
rustup target add x86_64-unknown-linux-gnu
cargo check --workspace --all-targets --all-features --locked --target x86_64-unknown-linux-gnu
rustup target add x86_64-pc-windows-msvc
cargo check --workspace --all-targets --all-features --locked --target x86_64-pc-windows-msvc
```

GitHub checkout, cache, artifact upload/download, hosted-runner selection, and
check presentation are transport and execution-plane services; they do not
replace a technical gate or authorize a release.

Only the manual Release workflow uses hosted write authority. Its five trusted
API calls receive the standard step-local `GITHUB_TOKEN`; GitHub's two
attestation actions and immutable Release publication cannot be reproduced as
repository-only local gates and are intentionally outside this runbook.
