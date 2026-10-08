# Changelog

## Unreleased

### Added

- Initial SPARC package structure and shared immutable model records.
- Persistent Ed25519 identities and explicit remembered-peer trust.
- Bounded TCP framing and signed AES-256-GCM text records with directional keys, replay checks and public inspection details.

### Security

- Shared limits reject invalid policy values at construction.
- Restrict existing Linux private stores on load and block trust operations after persistence failure.

### Fixed

- Include SHA-256 digest finalization in sender and receiver hash timings.
