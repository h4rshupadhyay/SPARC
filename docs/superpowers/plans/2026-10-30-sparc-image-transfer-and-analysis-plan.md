# Chat image transfer and analysis implementation plan

> **For agentic workers:** Use superpowers:executing-plans; execution is solo.
> Steps use checkbox syntax for tracking. User approved the corrected design
> and requested implementation; continue through all tasks without check-ins.

**Goal:** Send authenticated image attachments in Chat and complete graphical
performance/sensitivity analysis with explicit metric definitions.

**Architecture:** Extend the type-6 record codec with strict file messages and
bounded public inspections. A per-session transfer coordinator owns file I/O,
deadlines, cancellation, and verification. Chat renders mixed entries; Analysis
uses independent plot models shared by native Canvas and SVG export.

**Tech Stack:** Python >=3.10, Tk/ttk, existing cryptography/PyCryptodome,
compatible pinned Pillow; standard-library queues, hashing, files, and SVG.

**Spec:** `docs/superpowers/specs/2026-10-30-sparc-image-transfer-and-analysis-design.md`

## Global Constraints

- Existing linked worktree; preserve all pre-existing dirty traffic/docs files.
- Solo implementation and review; no subagents, merge, push, or device claims.
- 100 MiB file bound; 65,536-byte chunks; at most four outstanding chunks;
  one outgoing plus one incoming transfer per session.
- Offer deadline 120 seconds; chunk/final-result deadlines 10 seconds.
- Existing 128-KiB frame bound, cryptographic primitives, nonce/sequence rules,
  and text wire format remain unchanged.
- PNG/JPEG/GIF/WebP only; first-frame previews <=384x256, <=20 million pixels.
- Ciphertext display <=4 KiB; <=100 transfer summaries; <=500 mixed history
  entries; <=16 decoded thumbnails. Never log image bytes/private keys.
- Distinguish verified publication, chunk storage, unconfirmed sender delivery,
  primitive timings, network goodput, and synthetic sensitivity expectations.
- Expensive I/O/decoding stays off Tk; Tk handles stay on the main thread.

## Review Focus

- Cancellation/disconnect while disk work or final publication runs must not
  delete a published image, leak a partial file, or resurrect an old session.
- Duplicate/late/cross-direction transfer IDs must not mutate another transfer.
- Existing destination files, symlinks, and remote filenames cannot be overwritten
  or followed when publishing received content.
- Slow/full event or bulk queues must not stop heartbeat/control/text handling.
- Preview eviction, new analysis results, and queued worker completions must not
  display stale content, retain unbounded memory, or call destroyed Tk objects.

## Task 1: File schemas, records, and retained audit evidence

**Files:** Create `src/sparc/protocol/files.py`;
modify `protocol/messages.py`, `protocol/records.py`, `audit_format.py`;
test `tests/unit/test_file_protocol.py`.

**Interfaces:** `FILE_KINDS: frozenset[str]`, `CHUNK_BYTES=65536`,
`MAX_FILE_BYTES=104857600`, `validate_file(payload: dict, *, projection=False)`;
file-chunk signing projections omit data and signatures. `Inspection.message_id`
is the transfer ID for chunks; sender/receiver chunk inspections contain bounded
ciphertext plus total ciphertext length for visible truncation.
Audit accepts `image_received` evidence from `file_complete` and `image_delivered`
evidence from `file_result`, binding transfer ID, full hash, and size.

- [ ] Write tests for all seven unsigned/signed schemas, strict types/bounds,
  unsafe names, canonical Base64, chunk hash/length, and projected fields.
- [ ] Run `.venv/bin/python -m pytest tests/unit/test_file_protocol.py -q`;
  expect missing file API/unsupported kinds before implementation.
- [ ] Implement strict schemas, chunk hash recomputation, signing projections,
  bounded record inspections, and evidence validation without changing text.
- [ ] Verify a maximum-size chunk round-trips through real paired codecs under
  128 KiB; tampered hash/signature fails closed; retained completion evidence
  verifies and mismatched metadata is rejected.
- [ ] Run the new tests plus existing messages/records/audit-format tests;
  expect all pass. Commit only task-owned files.

## Task 2: Bounded image decoding and file publication

**Files:** Create `src/sparc/images.py`; modify `pyproject.toml`;
test `tests/unit/test_images.py`.

**Interfaces:** `ImageInfo(format: str, width: int, height: int, media_type: str)`;
`inspect_image(source) -> ImageInfo`, `make_thumbnail(path) -> PIL.Image.Image`;
imports Pillow lazily, strict decoder whitelist, bounded first-frame decode.
Pin a maintained Python-3.10-compatible release after checking package metadata.

- [ ] Write tests using small actual PNG/JPEG/GIF/WebP fixtures for detection,
  preserved source bytes, thumbnail aspect ratio, malformed/truncated formats,
  pixel bounds, and optional-dependency failure.
- [ ] Run `.venv/bin/python -m pytest tests/unit/test_images.py -q`; expect missing API.
- [ ] Implement decoder/thumbnail helpers with actual format checks and limits.
- [ ] Run that file; expect all pass. Commit task files/dependency pin.

## Task 3: Per-session transfer coordinator and real-peer delivery

**Files:** Create `src/sparc/peer/transfers.py`; modify `peer/service.py`,
`peer/session.py`; test `tests/unit/test_image_transfers.py`,
`tests/integration/test_image_transfer.py`, `tests/unit/test_session_writer.py`.

**Interfaces:** `TransferManager(session, emit, audit, peer_fingerprint)` owns
`send_image(path)->str`, `respond(transfer_id, destination: Path|None)`,
`cancel(transfer_id)`, `handle(record, evidence)`, `written(payload, protected)`,
`poll()`, `close()`, and `join(timeout=2)`.
Expose `PeerService.send_image(path)->str`,
`respond_to_image(transfer_id, destination: Path|None)`, `cancel_image(transfer_id)`.
Emit `ServiceEvent('image_transfer', data)` including transfer_id, origin,
filename, size, sha256, status, bytes_done, local path when available,
peer fingerprint, latest inspection, and timing/goodput when available.
Add `ActiveSession.enqueue_bulk(payload)` with a four-item low-priority queue;
control, text, then bulk ordering preserves interactive traffic.

- [ ] Write tests for whole-file streaming/chunk boundaries, four-chunk window,
  rejection/cancel/timeouts, unknown/duplicate IDs, tombstone bounds, source
  changes, hash/size mismatch, destination collision/symlink, disk/audit failures,
  publication uncertainty, stale session callbacks, and finite cleanup.
- [ ] Run new tests; expect missing coordinator/service APIs and bulk queue.
- [ ] Implement coordinator and atomic no-overwrite publication using exclusive
  temporary files and link/unlink publication; directory-sync failure leaves
  published data unconfirmed, never deleted. Sender completion waits for result.
- [ ] Wire exact-session ownership into public APIs, payload/writer/poll/close
  hooks. Keep disk work off reader/writer threads and progress events coalesced
  or bounded without blocking liveness. Reserve mandatory terminal events.
- [ ] Real loopback test sends representative images both ways, checks complete
  byte equality/hashes/audit evidence, and sends text during transfer. Cover lost
  final result, cancel, collision, and disconnect with no partial-file leakage.
- [ ] Run new tests plus existing writer/service/heartbeat/availability tests;
  expect all pass. Commit only task files.

## Task 4: Chat image attachments and mixed conversation

**Files:** Create `src/sparc/gui/conversation.py`, `src/sparc/gui/image_chat.py`;
modify `src/sparc/gui/chat.py`; test `tests/gui/test_chat_images.py` and existing
chat tests (adjust representation assertions only where the approved UI changes).

**Interfaces:** `Conversation(parent, on_select)` provides list-compatible
selection/read helpers used by Chat plus mixed message cards, image previews,
inline transfer controls, and stable scrolling. `ImageChat` owns the attachment
composer, bounded preview workers/cache, image events and inspector data;
Chat owns chronological mixed entries and routes state/image events.

- [ ] Write real Tk tests for Attach image/Send image, preserved text drafts,
  interleaved ordering, accept/reject/cancel, progress, verified preview gating,
  keyboard selection, scroll preservation, history/cache bounds and close safety.
- [ ] Run new tests; expect absent attachment/conversation behavior.
- [ ] Implement native themed controls consistent with existing Chat. Selection
  remains keyboard accessible; send-text and attachment workers are independent.
  Active image controls survive history pruning; one latest inspection is shown.
- [ ] Run new and existing chat/app/scrolling tests; expect all pass. Commit.

## Task 5: Analysis graph models, Canvas/SVG, and metric labels

**Files:** Create `analysis/plots.py`, `gui/plot_view.py`;
modify `gui/analysis_view.py`, `analysis/export.py`;
test `tests/unit/test_analysis_plots.py`, `tests/gui/test_analysis_plots.py`.

**Interfaces:** Immutable `Plot` and `Series` records; `benchmark_plots(result,
operations)->list[Plot]`, `sensitivity_plots(result)->list[Plot]`,
`plot_svg(plot, width=900, height=360)->str`. Shared geometry includes labels,
axes, legend, incomplete state, and gaps for missing data. `PlotView` renders
plots and offers operation selection + SVG export without rerunning benchmarks.

- [ ] Write tests for numeric workload sorting, microseconds/MiB conversions,
  absent/zero values, local/network separation, escaping, SVG labels/data,
  correct sensitivity expectation lines, and invalid/incomplete values.
- [ ] Run new unit tests; expect missing plot API.
- [ ] Implement shared plot data/geometry and SVG; implement Canvas view using
  the same geometry, coalesced resize, and native labels/operation controls.
- [ ] Add a Graphs area in Analysis and clear stale plots on unrelated results.
  Label byte metric as character-level proxy; retain raw CSV fields for backward
  compatibility and expand definitions with coursework vs model expectations.
- [ ] Real Tk tests cover rendered plot contents, operation filtering, stale
  clearing, export, resizing/close, and existing analysis tables. Expect pass;
  commit task files.

## Task 6: Demonstration, documentation, and final regression

**Files:** Update README and approved spec status; create
`docs/image-transfer-and-analysis-evidence.md`. Keep existing dirty ledgers intact.

- [ ] Run an actual two-peer GUI/loopback smoke with text and images and inspect
  screenshots of Chat and graphs. Exercise resize and close during work.
- [ ] Document install/update requirements, attachment flow, verification states,
  definitions and graph exports; record actual commands/results and limits.
- [ ] Run `.venv/bin/python -m pytest -q --tb=short` with available TShark path;
  inspect the complete result. Investigate reproduced failures before claiming
  completion. Run `git diff --check` and dependency consistency checks.
- [ ] Review the complete feature diff against this plan/spec solo, particularly
  the Review Focus conditions. Add RED/GREEN regressions for confirmed defects.
- [ ] Commit only feature/evidence files. Report results, known platform limits,
  and any unresolved failures; no merge or push.
