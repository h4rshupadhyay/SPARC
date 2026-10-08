# Changelog

## Unreleased

### Added

- Initial SPARC package structure and shared immutable model records.
- Persistent Ed25519 identities and explicit remembered-peer trust.
- Bounded TCP framing and signed AES-256-GCM text records with directional keys, replay checks and public inspection details.

- Mutually authenticated X25519 handshake with fingerprint approval, bounded cancellation and fresh sessions.

- Signed hash-chain audit logs, durable append and independently verifiable checkpoints with honest deletion-relative reports.

- Accountable peer messaging service with manual IPv4 listeners, fingerprint pairing, bounded delivery receipts and operation metrics.

### Security

- Shared limits reject invalid policy values at construction.
- Restrict existing Linux private stores on load and block trust operations after persistence failure.

- Verify and durably audit received messages and signed acknowledgments before reporting delivery.
- Retain signed zero-head audit checkpoints before service startup.

### Fixed

- Preserve verified-prefix counts when checkpoint verification fails after scanning.
- Preserve existing export-directory permissions while keeping private application stores restricted.

- Advance the responder deadline after client authentication so both peers receive their approved pairing budgets.

- Include SHA-256 digest finalization in sender and receiver hash timings.

- Wake idle writers on either queue and isolate stale-session receipt cleanup.
- Share cancellation across session workers and service event producers to prevent full-queue shutdown deadlocks.
