# Changelog

## Unreleased

### Added

- Reproducible synthetic AES-256 sensitivity trials and bounded 50-case batches with separate bit, byte and hexadecimal metrics and cancellable partial results.

- Initial SPARC package structure and shared immutable model records.
- Persistent Ed25519 identities and explicit remembered-peer trust.
- Bounded TCP framing and signed AES-256-GCM text records with directional keys, replay checks and public inspection details.

- Mutually authenticated X25519 handshake with fingerprint approval, bounded cancellation and fresh sessions.

- Signed hash-chain audit logs, durable append and independently verifiable checkpoints with honest deletion-relative reports.

- Accountable peer messaging service with manual IPv4 listeners, fingerprint pairing, bounded delivery receipts and operation metrics.
- Rolling connection limits, paced authenticated records, signed idle heartbeats and finite authenticated reconnection.
- Runnable Connection, Chat and Audit desktop tabs with explicit fingerprint approval, Unicode and multiline chat, public record inspection, and cancellable checkpoint verification.

- Independent-process secure simulation with observed bidirectional delivery evidence, retained audit checkpoints and honest finite cleanup reports.
- Separate lab-only plaintext comparison tool and demonstration/evidence guides mapping five security goals and thirteen acceptance criteria.

### Security

- Shared limits reject invalid policy values at construction.
- Restrict existing Linux private stores on load and block trust operations after persistence failure.

- Verify and durably audit received messages and signed acknowledgments before reporting delivery.
- Retain signed zero-head audit checkpoints before service startup.
- Keep retries bound to the original authenticated identity and never automatically replay text.
- Durably audit retry outcomes and stop networking after availability-audit failure.

### Fixed

- Preserve verified-prefix counts when checkpoint verification fails after scanning.
- Preserve existing export-directory permissions while keeping private application stores restricted.

- Advance the responder deadline after client authentication so both peers receive their approved pairing budgets.

- Include SHA-256 digest finalization in sender and receiver hash timings.

- Wake idle writers on either queue and isolate stale-session receipt cleanup.
- Share cancellation across session workers and service event producers to prevent full-queue shutdown deadlocks.

- Latch audit failures before diagnostics and stop inbound handshakes even when cancellation races cleanup.
- Keep authenticated retry progression and Stop responsive when the ordinary event queue is full.
- Clear stale authenticated-peer details after disconnect; keep chat history bounded and in memory, and ignore late worker results when tabs close.
- Scope audit verification to a captured committed prefix, with cancellation across reads and checkpoint publication.
- Keep public identity fingerprints and existing protocol/security version semantics unchanged.
