# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-08-13

### Added

- Independent Rust implementation of the pinned Hell language baseline.
- A single-dispatch, GitHub-native release gate for exact same-repository branches.

### Changed

- Removed custom GitHub Actions environment interfaces; trusted API commands now
  use only a narrow standard token bridge while bundle assembly and verification
  remain credential-free.

### Compatibility

- Compatibility remains bounded: verified evidence and deliberate divergences are reported, while unverified behavior is not presented as equivalent.
