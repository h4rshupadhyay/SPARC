# SPARC deferred media-transfer notes

Date: 2026-10-08 (Asia/Kolkata)
Status: Deferred reference draft. Image/audio/video transfer is outside the current text-only progress check, following the teacher's scope guidance. These notes preserve the earlier proposal; they are not an approved implementation specification.

The current milestone is defined in [the progress-check specification](2026-10-08-sparc-progress-check-design.md). Revisit these notes when media transfer is scheduled, including its wire schemas, signature projection, audit events, UI, and availability behavior. The text-only protocol should reject file-transfer record kinds until a later protocol design explicitly adds them.

### Chunked image/audio/video files

Treat media as opaque binary files; the transfer path is shared for images, audio, video, and other user-selected binary files. No codec, transcoding, or live-streaming subsystem is needed to transfer files. Use 64-KiB chunks, a four-chunk outstanding window, a 100-MiB maximum file size, and at most one outgoing plus one incoming transfer at a time. These limits are visible in the GUI and bound memory/disk use.

Every file control/chunk envelope is signed and encrypted through application-record type 6, using the same directional sequences and nonce rules as text. Transfer IDs are fresh 32-character lowercase hexadecimal strings. Exact unsigned schemas are:

| Kind | Fields in addition to `kind` |
| --- | --- |
| `file_offer` | `transfer_id`, `filename`, `size`, `sha256`, `media_type`, `chunk_size` |
| `file_decision` | `transfer_id`, `decision` (`accept` or `reject`), `reason` |
| `file_chunk` | `transfer_id`, `index`, `offset`, `byte_count`, `sha256`, `data` (canonical Base64) |
| `file_chunk_ack` | `transfer_id`, `index`, `sha256`, `status="stored"` |
| `file_complete` | `transfer_id`, `size`, `sha256` |
| `file_result` | `transfer_id`, `size`, `sha256`, `status="verified"` |
| `file_cancel` | `transfer_id`, `reason` |

`size`, `chunk_size`, `index`, `offset`, and `byte_count` are bounded nonnegative integers. `chunk_size` is exactly 65,536. SHA-256 values have 64 lowercase hexadecimal characters. Filename and media type are informational, bounded to 255 UTF-8 bytes and 128 ASCII characters respectively. Filename is a basename; reject separators, NUL/control characters, and traversal components. The receiver chooses the actual destination using a save dialog; never concatenate a sender-provided path into a destination directory. MIME type is a hint, not proof of file format, and does not control execution.

Workflow:

1. Sender opens the source once, streams it to calculate the whole-file SHA-256, rewinds, and offers its metadata. File hashing includes file-I/O time and is reported separately from in-memory text hashing.
2. Receiver validates the offer and limits, presents its signed metadata, and explicitly accepts with a chosen destination or rejects. The offer expires after 120 seconds. Other traffic and heartbeats continue while the prompt is open.
3. Receiver creates a unique temporary file in the destination directory. Sender streams bounded chunks. Require sequential indices, `offset=index*chunk_size`, the advertised expected length, matching chunk hash, and a valid signature. Receiver incrementally hashes and writes only validated bytes and acknowledges each chunk. "Stored" means written to the temporary file, not final durable file acceptance.
4. Sender checks the digest of its streamed bytes against the offered digest, detects source changes, and sends `file_complete` after all chunk acknowledgments. Receiver checks total byte count and final hash, flushes/fsyncs, and publishes to a unique final destination without overwriting an existing file. Zero-length files have no chunks and use SHA-256 of the empty byte string.
5. Receiver durably logs completion before sending `file_result`. Sender reports verified completion only after validating the matching signed result. A file awaiting that result is unconfirmed rather than verified.

Chunk acknowledgments expire after 10 seconds. Cancellation, rejection, disk failure, source changes, hash/size failure, or disconnect clean up partial files and update the transfer state. A received content hash/size failure closes the session as a security failure; local cancellation/disk failure can cancel just the transfer. Retain at most 128 recently canceled IDs for 30 seconds so already queued, otherwise valid chunks can be discarded safely after cancellation; unexpected IDs outside that bounded set are protocol errors. No partial file is presented as a verified media file. Reconnect offers a fresh transfer ID and restarts the file with fresh session keys.

Prioritize pending control/acknowledgment and chat records between chunks so a large video does not monopolize the writer. Do not retain every chunk's ciphertext in the GUI or log. The transfer inspector shows signed offer/result metadata, whole-file sender/receiver hashes, the most recent chunk security details, byte progress, elapsed transfer time, and plaintext-file goodput. Do not automatically open or play received files.

## Deferred validation and measurements

When this feature is designed and approved, test chunk boundaries, empty files, whole-file hashes, size limits, source changes, out-of-order chunks, destination safety, cancellation cleanup, and signed final results. Demonstrate representative valid image/audio/video files between peers.

Measure source hashing separately and file goodput from protecting the first chunk after acceptance to verifying the final result. Record media category, file size, chunk count, hash match, frame bytes, and peak outstanding chunks. Add a bounded Transfers view and file lifecycle audit events at that time.
