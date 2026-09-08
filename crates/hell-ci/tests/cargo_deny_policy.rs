// This is a policy drift guard, not a substitute for the pinned cargo-deny parser
// and graph audit in CI. Keep the accepted declaration deliberately exact so
// future dependency versions and policy changes require an explicit review.
const POLICY: &str = include_str!("../../../deny.toml");
const EXPECTED: &str = r#"
[graph]
all-features = true
targets = [
  "aarch64-apple-darwin",
  "x86_64-pc-windows-msvc",
  "x86_64-unknown-linux-gnu",
]
[advisories]
ignore = []
[licenses]
allow = [
  "Apache-2.0",
  "Apache-2.0 WITH LLVM-exception",
  "BSD-3-Clause",
  "CDLA-Permissive-2.0",
  "ISC",
  "MIT",
  "Unicode-3.0",
]
confidence-threshold = 0.8
unused-license-exception = "deny"
[[licenses.exceptions]]
name = "zlib-rs"
version = "=0.6.7"
allow = ["Zlib"]
[licenses.private]
ignore = false
registries = []
[bans]
multiple-versions = "deny"
wildcards = "deny"
highlight = "all"
[[bans.skip]]
name = "getrandom"
version = "=0.2.17"
reason = "hell-ci and ring 0.17.14 (rustls/ureq) require 0.2; hell-memcordon and tempfile 3.27.0 (memcordon-core 0.5.2-rc.23) require 0.4.3. Review on graph changes."
[[bans.skip]]
name = "winnow"
version = "=0.7.15"
reason = "toml 0.9.12+spec-1.1.0 requires 0.7.15 directly and 1.0.4 through toml_parser 1.1.3+spec-1.1.0. Review on graph changes."
[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
"#;

fn declarations(document: &str) -> Vec<&str> {
    document
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[test]
fn compatibility_policy_is_exact_and_keeps_global_denials() {
    assert_eq!(declarations(POLICY), declarations(EXPECTED));
}

#[test]
fn compatibility_policy_rejects_wider_or_stale_declarations() {
    for (before, after) in [
        ("version = \"=0.6.7\"", "version = \"=0.6.8\""),
        ("name = \"zlib-rs\"", "name = \"another-zlib-crate\""),
        ("version = \"=0.6.7\"", "version = \"0.6.7\""),
        ("version = \"=0.2.17\"", "version = \"=0.2.18\""),
        ("version = \"=0.7.15\"", "version = \"=0.7.16\""),
        ("version = \"=0.2.17\"", ""),
        ("version = \"=0.7.15\"", ""),
        ("\"Unicode-3.0\",", "\"Unicode-3.0\",\n  \"Zlib\","),
        (
            "multiple-versions = \"deny\"",
            "multiple-versions = \"allow\"",
        ),
        (
            "unused-license-exception = \"deny\"",
            "unused-license-exception = \"allow\"",
        ),
        ("[[bans.skip]]", "[[bans.skip-tree]]"),
        ("Review on graph changes.", ""),
    ] {
        assert!(POLICY.contains(before), "mutation target missing: {before}");
        let mutation = POLICY.replace(before, after);
        assert_ne!(
            declarations(&mutation),
            declarations(EXPECTED),
            "accepted policy mutation: {before} -> {after}"
        );
    }
}
