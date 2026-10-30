# SPARC image transfer and analysis completion

Date: 2026-10-30 (Asia/Kolkata)
Status: Proposed design for review; implementation not started.
Execution: Solo, as requested. Existing unfinished traffic-analysis changes are preserved.

## Intent and decisions

Complete the remaining objectives from the user's checklist: encrypted image
transfer between peers with visible original/recovered content and ciphertext,
performance graphs, and explicit avalanche/character metric definitions.
The user selected encrypted image transfer between peers over a local-only
image encryption laboratory. This supersedes the earlier text-only restriction
for this feature, without expanding the request to audio or video.
The user further specified that images must be sent within Chat itself.

The existing text application already provides authenticated sessions, signed
AES-GCM records, audit evidence, sensitivity trials, operation benchmarks,
hash experiments, and signature timings. Extend those facilities.

## Approaches

1. Local image encryption laboratory: a smaller change that demonstrates file
   round trips but does not send images. Recommended initially for minimal
   protocol impact; the user chose peer transfer instead.
2. Image transfer using the existing authenticated session: selected. Reuse
   the deferred chunked-transfer design, with an image-focused interface and
   bounded previews. This requires application-schema, service, audit, and GUI
   work but uses the existing encryption, signatures, and peer approvals.

For graphs, use native Tk Canvas rendering with SVG export. This is the
builder's recommendation: no plotting dependency or embedded browser is needed
for the small, bounded datasets already produced by Analysis.

## User-visible image workflow

Integrate image attachments into the existing Chat tab and its conversation
history. Add an **Attach image** button beside the text composer.

- Sender selects a PNG, JPEG, GIF, or WebP image using Attach image. Show a
  removable attachment preview with a **Send image** action, keeping any text
  draft intact. Show a bounded original
  preview, detected format, byte size, dimensions, and full SHA-256 digest.
  Animated formats show their first frame; preserve all original file bytes.
- Send image is available only on an authenticated connection. Sending creates
  an outgoing image entry in the same chronological history as text messages.
  The receiver sees an incoming attachment offer in Chat with the peer
  fingerprint, filename, size, and digest, and chooses **Accept and save** or
  **Reject** there. Accept and save opens the destination chooser. Receiving
  never trusts the sender's path.
- Each image entry shows progress, Cancel, and explicit offered/accepted/
  transferring/verified/rejected/canceled/failed/unconfirmed states. Keep text
  composition and sending usable while an image transfer runs.
- Receiver displays the recovered preview only after authentication, final
  digest/size checks, and successful publication, inline in the corresponding
  Chat entry. Transfer does not re-encode
  the image; the receiver's SHA-256 must match the sender's original bytes.
- Selecting a text or image entry opens its details in Chat's existing security
  inspector. For images, display the latest chunk's Base64 ciphertext, nonce,
  authentication tag, signature, chunk hash, and local operation timings.
  Limit displayed ciphertext to 4 KiB with a visible truncation notice.
  Ciphertext is binary data, not a purported viewable encrypted image file.
- Original/recovered image previews and ciphertext are visibly labeled.
  Retain at most 100 transfer summaries and one latest chunk inspection for
  each active transfer. Bound the shared conversation to 500 entries, preserving
  active transfer controls when pruning completed history. Keep at most 16
  decoded thumbnails in an eviction cache, loading from local files on demand.
  Do not retain whole images or every chunk in GUI state.
- Distinguish local encryption/decryption timings from full transfer duration
  and verified file goodput. Do not compare clocks on separate devices.

The current text-only Listbox cannot render image previews or attachment
controls. Replace that history surface with a scrollable conversation component
that handles both entry types, preserves keyboard selection and inspector
access, and keeps a reader's scroll position when new entries arrive while they
are reading older messages. Preserve existing text delivery reconciliation,
history bounds, inspector behavior, and cleanup semantics. The builder may
extract this component from `gui/chat.py` into a focused helper module.

## Transfer contract

Use the schemas and workflow in
[the deferred transfer notes](2026-10-08-sparc-media-transfer-future-notes.md),
made concrete here for images:

- Maximum file size: 100 MiB. Chunk size: 65,536 bytes. Outstanding window:
  four chunks. At most one outgoing plus one incoming transfer per connection.
  Empty or undecodable files are not selectable images.
- Add the seven exact application kinds from those notes: `file_offer`,
  `file_decision`, `file_chunk`, `file_chunk_ack`, `file_complete`, `file_result`,
  and `file_cancel`. Validate exact fields, canonical Base64, integer bounds,
  identifier syntax, allowed decisions/statuses, and digest syntax.
- Use existing type-6 signed AES-256-GCM records and sequence/nonce rules.
  Chunk data is bound to its hash by recomputation, and its signing projection
  contains all metadata and that hash while omitting the bulky Base64 data.
  Other transfer projections include all unsigned fields.
- Keep the existing 128-KiB frame bound. A 64-KiB chunk plus Base64, metadata,
  signature, and record overhead must fit; verify this with an exact-size test.
- Sender opens the source once, hashes it in bounded reads, rewinds, then
  hashes the streamed bytes again to detect changes. No whole-file buffer.
- Offers expire after 120 seconds; decisions and acknowledgments are checked
  against the exact active transfer/session. Chunk and final-result deadlines
  are 10 seconds, measured with a monotonic clock.
- Receiver accepts sequential chunks with the expected index, offset, length,
  and digest. Write to a private unique temporary file in the chosen directory.
  A chunk acknowledgment means written to that temporary file, not verified
  final delivery.
- Check total bytes and full-file digest, flush/fsync, and publish without
  overwriting any existing destination. Never construct a destination from a
  remote filename. Publication failures must not produce a verified result.
- Durably record receiver completion before sending the signed final result.
  Sender reports verified delivery only after checking and durably logging
  that result. A lost result leaves the sender unconfirmed; an already
  published receiver file is not rolled back or deleted.
- Cancellation, rejection, disconnect, timeout, source change, or storage
  failure closes handles and removes owned partial files. Keep at most 128
  recently canceled IDs for 30 seconds to discard in-flight valid records;
  unexpected IDs outside that set are protocol errors. Digest/size or
  authenticated state violations fail the session closed.
- Reconnection cancels old transfers. Retrying starts a new transfer ID and
  fresh session; no automatic file resume or resend.
- Prioritize existing control/chat traffic over bulk chunks. Bound transfer
  work queues and preserve heartbeat maintenance while source hashing,
  destination selection, or disk work is pending. Workers do not call Tk.

Text wire schemas and existing audit records remain valid. Images require
updated SPARC on both peers; older peers reject unsupported application kinds.
The setup/demo documentation must state this compatibility requirement.

## Image decoding and dependencies

Use Pillow for format detection and bounded previews. Pin a maintained release
compatible with the repository's Python 3.10 minimum during implementation
planning. Keep its imports lazy so the text/check CLI still works independently
of preview support. Expose actionable setup errors for unavailable formats.

Restrict decoding to PNG, JPEG, GIF, and WebP, check actual format and dimensions,
and limit previews to images with at most 20 million pixels and 384 by 256 output
pixels. Do not enable truncated-image loading or disable decompression-bomb
checks. Do expensive decoding outside the Tk thread; create Tk image handles
on the main thread. Verify incoming supported-image content before publication;
a file with a misleading extension must not trigger an unrestricted decoder.
These preview bounds are builder choices, not user-prescribed limits.

Pillow documents explicit decoder format restrictions and image dimension
checks in its [Image API](https://pillow.readthedocs.io/en/stable/reference/Image.html).

## Performance graphs

Add a Graphs area within Analysis using the existing completed benchmark data.

- Plot encryption and decryption mean duration in microseconds against payload
  bytes, and their local cryptographic throughput in MiB/s against payload bytes.
- Include optional operation selection for hash/sign/verify measurements;
  labels must retain each operation's timing scope.
- Plot network verified receipt duration/goodput separately from local primitive
  results. Never put network goodput and primitive throughput in one series.
- Show axes, units, legends, and the run's completion state. Sort workloads
  numerically; show absent measurements as unavailable, not zero.
- Preserve existing tables and CSV export. Add SVG export with the same plotted
  data, labels, units, and completion information. Resize without rerunning a
  benchmark or scheduling unbounded redraws. A new non-graphable result clears
  stale charts.

## Avalanche and character metric definitions

Retain the original spec's scientifically explicit definitions:

- Plaintext-bit avalanche illustrates diffusion; key-bit avalanche illustrates
  confusion. Neither is a proof or universal numerical score for those concepts.
- Bit change is differing bits / 128 times 100; ideal model expectation 50%.
- Label the existing byte metric **Byte change (character-level proxy)**:
  differing ciphertext bytes / 16 times 100. Display the coursework's 100%
  ideal target separately from the independent-byte expectation of 99.609375%.
  Individual trials can reach 100%; do not force measured values to that target.
- Label hexadecimal change explicitly: differing lowercase hex positions / 32
  times 100, with expectation 93.75%. It is not a Unicode-character metric.
- Keep formulas, observed values, sample counts, summary statistics, and CSV
  units consistent. Add a sensitivity chart comparing observed averages with
  their correctly labeled expectations; no misleading common ideal line.

No change to live GCM keys/nonces or reuse of live records for sensitivity
experiments. Do not add a plaintext Unicode metric for binary ciphertext.

## Boundaries and implementation order

1. Transfer protocol validation, record inspections, and public audit evidence.
2. A focused peer transfer coordinator integrated with service/session lifecycle.
   Avoid embedding all transfer state and file I/O in the already large service.
3. Chat attachment composer, mixed text/image conversation history, bounded
   preview helpers, and inline transfer controls.
4. Reusable chart data/rendering/export helpers and Analysis integration.
5. Metric labels, documentation, end-to-end demonstration, and regression gate.

The builder owns exact class/function names and module seams in the subsequent
implementation plan. Work stays in the existing linked worktree. Do not change
or complete the paused traffic-index/export milestone as part of this request.
No merge, push, or physical Linux-to-Mac completion claim is implied.

## Acceptance and validation

- Tests first for schemas, signing projections, digest checks, exact frame
  bounds, chunk boundaries, source changes, deadlines, bounded windows, and
  stale-session isolation.
- Real loopback peers transfer representative images byte-for-byte in both
  directions while chat and heartbeat remain functional. Verify full hashes
  and retained signed audit evidence.
- Exercise rejection, cancellation, destination collisions, disk/audit failure,
  tampered content, interrupted final confirmation, disconnect, and shutdown.
  No partial file is presented as a recovered/verified image.
- Real Tk tests cover attaching and sending an image from Chat, interleaved
  text/image ordering, preserved text drafts, inline offer acceptance, progress,
  verified recovered previews, keyboard selection, stable scroll position,
  thumbnail/history eviction, ciphertext/timing inspection, resizing, and close
  during work. The normal text chat workflow must continue to pass.
- Chart tests verify plotted coordinates/data, units, sorted workloads, absent
  values, incomplete runs, stale-chart clearing, and faithful SVG exports.
- Refresh affected text, handshake, audit, identity, availability, analysis,
  CLI, and GUI tests, then run the complete suite. Distinguish missing optional
  external-decoder tests from required image/analysis tests.
- Recheck the earlier pairing setup error/Tk finalizer warning when the full
  run completes; do not claim a clean regression gate if either remains.

GUI completion refers to this agreed objective set and requires demonstrated
image transfer plus graphs and metrics. Native macOS/physical-device behavior
remains unverified until actually exercised on those devices.
