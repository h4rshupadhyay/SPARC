# Changelog

## Unreleased

### Added

- Initial SPARC package structure and shared immutable model records.
- Persistent Ed25519 identities and explicit remembered-peer trust.
- Bounded TCP framing and signed AES-256-GCM text records with directional keys, replay checks and public inspection details.

- Mutually authenticated X25519 handshake with fingerprint approval, bounded cancellation and fresh sessions.

### Security

- Shared limits reject invalid policy values at construction.
- Restrict existing Linux private stores on load and block trust operations after persistence failure.

### Fixed

- Advance the responder deadline after client authentication so both peers receive their approved pairing budgets.

- Include SHA-256 digest finalization in sender and receiver hash timings.
