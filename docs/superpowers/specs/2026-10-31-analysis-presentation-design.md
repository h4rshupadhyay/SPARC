# Analysis presentation improvements

The user approved both audit recommendation sets in this conversation. Implement
them in the existing Python/Tkinter progress-check worktree, solo, preserving the
dark appearance and unrelated work. The approved audits are
`docs/audits/2026-10-31-analysis/README.md` and `graph-review.md`.

## Approach

Extend the existing engines and native widgets. A separate web redesign would
duplicate a functioning application; patching labels alone would leave the
custom-input and export requirements unsatisfied. The selected approach adds a
small message-laboratory domain module and public artifact module, while keeping
the existing seeded sensitivity, benchmark, hash-search and traffic APIs.

## Contracts

- Add a custom UTF-8 message experiment, up to 16,384 encoded bytes. Show original
  text, AES-256-GCM ciphertext/nonce/tag, recovered text and exact equality,
  SHA-256 digest/recomputed equality, Ed25519 signature/public key and generation,
  verification, hash, encryption and decryption timings. Use independent lab keys;
  exclude key creation/encoding/I/O from primitive timers. A new key/nonce per run
  is the default. Optional custom AES keys must contain exactly 32 bytes.
- Add a custom AES sensitivity input option beside seeded trials. Accept exactly
  16 input bytes (UTF-8 or hexadecimal) and exactly 32 key bytes (hexadecimal),
  with explicit validation and bit bounds. Keep seeded batches reproducible.
- Export the currently displayed result, never a previous unrelated result.
  Public JSON artifacts support message results, single trials and signature
  specimens; they exclude private keys. Signature artifacts load with bounded
  size/schema validation and are reverified rather than trusting stored validity.
  Existing benchmark, batch, resource and hash CSV exports remain available.
- Signature verification measures verification-only time and preserves signing
  time only when public key/signed bytes/signature still match the generated
  specimen. Editing a specimen must not retain an unrelated signing measurement.
- Replace ambiguous states with Not run yet / Not reported / Not applicable /
  No match found within the budget. Hash outcomes/witnesses remain in Details;
  message digest equality is distinct from hash-security searching.
- Allow more local benchmark sizes (64–16,384 bytes, up to 9 distinct sizes),
  retaining the old defaults and network's existing limits. Graphs identify the
  algorithm and measured operand. Signing throughput uses operations/s, not
  original-message MiB/s. Add empirical timing spread, explicit numeric change
  counts, a full-width expectation reference for single trials, and optional
  conditional input/output-bit frequencies. Preserve original measured data.
- Keep graph legends, units, sample counts and essential scope visible at 800×640
  and 1200×900; full run provenance remains available in SVG/report exports.
  Provide direct, clearly named experiment actions and appropriate table sizing
  and vertical scrolling. Keep the incumbent type/color/navigation vocabulary.
- PCAP captured-byte rates, verified network goodput and primitive throughput
  retain distinct definitions. Add a capture-time rate view only with honest
  bin widths and source timestamps; do not imply plaintext or cryptographic
  security from a traffic graph. IP configuration remains in Connection.
- Full SHA-256 searches remain bounded, cancellable and explicitly inconclusive
  as cryptographic proofs. No forced non-linear performance curves or invented
  resistance percentages.

## Validation

Tests first for new domain behavior and reproduced export/timing/state bugs.
Exercise actual GUI jobs, JSON round trips/tampering, custom Unicode/invalid
lengths, existing CLI/export compatibility, numerical graph transforms, bounded
cancel/close, and two viewport sizes. Finish with the full suite, real native
synthetic smoke, one batched visual review/fix round and dependency checks.
Commit only owned files locally; retain the branch and worktree.
