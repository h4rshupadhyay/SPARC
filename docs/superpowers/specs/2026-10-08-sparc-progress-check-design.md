# SPARC progress-check design

> **Demo target update — 2026-10-09:** The user replaced the Windows laptop with a borrowed MacBook. Current required demo platforms are Linux and macOS; Windows compatibility is no longer required. Earlier Windows-specific text below records the original brief and is superseded for platform scope. Physical Linux↔macOS evidence remains distinct from loopback simulation and is not yet recorded.

Date: 2026-10-08 (Asia/Kolkata)
Status: Text-only written specification approved by the user on 2026-10-08. Signed audit logs and the clarified security/analysis requirements are retained. The teacher permitted limiting the progress check to text. Implementation planning is authorized; implementation has not begun. The user subsequently selected GPT-6.1 Sol for reasoning/planning, Luna for coding, and direct tools for commands; the linked implementation plans have been revised to that workflow.

## 1. Purpose and agreed requirements

SPARC is an Information Security project for direct, secure communication between local devices without a central service. Its eventual scope includes UDP peer discovery, text and media transfers, signed hash-chain logs, availability mechanisms, and controlled security demonstrations.

This specification covers the text-only first progress check: two laptops, one running Windows and one Linux, exchange **text messages** on the same LAN through manually configured IP addresses and TCP ports. The teacher has permitted this narrower content scope for now. Image, audio, and video file transfer is deferred to a later milestone. Each laptop runs the same Python application with a Tkinter GUI. The course permits other Python libraries as well as PyCryptodome and `cryptography`; the library choices here are implementation recommendations, not a course restriction. Packet capture happens externally in Wireshark.

The application must demonstrate:

- AES-256 encryption and authenticated decryption.
- SHA-256 hashing, with digests displayed and compared.
- Ed25519 signature generation and verification, with signatures and results displayed.
- First-contact fingerprint comparison and remembered peer identities.
- Signed hash-chain local audit logs and audit verification for accountability.
- Bounded/rate-limited processing, authenticated heartbeats, and reconnect with fresh keys for availability.
- AES key sensitivity, plaintext sensitivity, bit-change, byte-change, and character-change analysis with explicit formulas.
- Individual operation timings and a small throughput analysis.
- Reproducible exports and a Wireshark demonstration procedure.

The teacher supplied no formulas for confusion, diffusion, or character analysis. Section 6 defines the project's measurements and their limits. The user selected Tkinter and external Wireshark capture. Direct TCP remains the chosen transport; WebRTC was discussed as an alternative but was not selected.

### Additional full-project requirements (clarified after the first draft)

The broader project brief covers Confidentiality, Integrity, Authentication, Accountability, and Availability, with security and efficiency analysis, and secure transfer of text, images, audio files, and video files. Demonstration must use at least two actual devices or a simulation of independent peers. Under the teacher's latest guidance, the current progress check demonstrates these security goals with text communication; media remains a future feature. Signed audit logs remain included as requested.

The supplied assessment checklist names external Wireshark, PyShark, PCAP/PCAPNG-to-XML, and PCAP/PCAPNG-to-SQLite. The user's preference is to omit redundant work. This design uses a single offline pipeline: Wireshark captures/manual inspection; PyShark provides automated summaries and SQLite import; TShark provides PDML XML export. No second Python dissector or duplicate analysis path is added. These outputs are distinct assessment deliverables, so the pipeline remains included in the proposed milestone. Section 8 specifies its behavior.

| Security goal | Planned mechanism | Security evidence | Efficiency evidence |
| --- | --- | --- | --- |
| Confidentiality | AES-256-GCM for all transmitted content | Controlled plaintext/encrypted capture comparison; authenticated decryption tests | Encryption/decryption time, goodput, transmitted-byte overhead |
| Integrity | GCM authentication plus displayed SHA-256 digests; whole-file hashes when media is added | Altered records rejected; receiver hashes match sender hashes | Hash/check time and per-record overhead |
| Authentication | Signed ephemeral handshake and independently verified Ed25519 fingerprints | Impersonation, transcript substitution, and changed-key rejection | Signing/verification and handshake time |
| Accountability | Signed hash-chain local audit logs retaining peer-signed message/acknowledgment evidence | Detect altered records, broken chains, and invalid signatures | Logging/signing and audit-verification time; storage per event |
| Availability | Bounded frames/queues, connection/rate limits, authenticated heartbeats, and reconnect with fresh keys | Controlled malformed/flood tests, disconnect detection, successful recovery | Resource use under the defined workload, detection/recovery time, goodput |

Accountability is attributable to authenticated device keys. An unanchored local hash chain does not alone detect deletion of an entire log or its tail; retained or independently stored signed checkpoints are needed for those claims. Availability claims must be limited to the tested failure/flood conditions, not unrestricted protection from network denial of service.

Two-peer simulation means two independent processes with distinct identities, data directories, and listener ports, communicating over actual sockets. Label loopback simulation and physical Windows-to-Linux results separately. Both are permitted evidence under the clarified brief; simulation does not become a claim of physical cross-platform validation.

### Success scenario

Both users start SPARC and enable their TCP listeners. One enters the other's reachable LAN IP and port and connects. Both compare fingerprints and approve first pairing. They exchange text, inspect security details and message hashes, verify signed audit logs, run analysis and benchmarks, and save measurement CSVs. A Wireshark capture shows communication with encrypted application payloads; its XML and SQLite exports support automated analysis. The application rejects invalid records and unexpected identity changes and demonstrates disconnect detection and authenticated recovery.

## 2. Scope and trust assumptions

The first milestone protects message content against passive LAN observation and rejects modified records, unauthenticated handshake substitution, replay, and unexpected changes to a remembered peer identity. Initial pairing depends on users correctly comparing fingerprints through an independent channel, such as looking at both laptop screens in person.

The operating systems, local application processes, and local identity/trust files are trusted. Traffic timing, packet sizes, addresses, and public handshake keys are visible on the network. Benchmark results describe the tested devices and workload; neither a PCAP nor avalanche measurements prove the complete protocol secure.

This is an educational application protocol using established cryptographic implementations. Later milestones add UDP discovery, media file transfer, broader controlled attack experiments, and advanced transfer recovery. This milestone includes text communication, local signed logs, heartbeat, and bounded reconnection. Every reconnect creates a fresh session; unconfirmed text is not automatically resent.

## 3. Architecture and module boundaries

Use Python 3.10 or newer, Tkinter/ttk, `cryptography` for live cryptography, PyCryptodome for isolated AES block experiments, PyShark/TShark for the single offline capture pipeline, and psutil for interface enumeration and resource samples. Use the standard library for sockets, hashing, timing, JSON, CSV, SQLite, and queues. Dependencies must be pinned to compatible releases during implementation and installed in a virtual environment on both laptops. Availability in the current workspace does not substitute for a Windows validation run.

| Module | Responsibility and interface | Dependencies |
| --- | --- | --- |
| Identity store | Load/create the local Ed25519 identity; list, pin, and explicitly forget peer public keys | Serialization and OS user configuration directories |
| Crypto | Sign/verify canonical data, derive directional keys, seal/open records | `cryptography`, `hashlib` |
| Protocol | Validate message schemas and canonical encoding; frame TCP data; authenticate the handshake and records | Crypto, bounded socket I/O |
| Peer service | Start/stop listener, connect, pair, send, disconnect, and publish typed events | Protocol, identity store, worker threads |
| Audit | Append signed hash-chain events, retain signed metadata evidence, verify logs/checkpoints | Identity, canonical encoding, durable filesystem writes |
| Analysis | Run isolated sensitivity experiments and local operation benchmarks | PyCryptodome, crypto primitives, timing |
| Measurement/export | Aggregate timings and network benchmark results; write CSVs with metadata | Standard library |
| Offline traffic analysis | Stream saved captures into analysis summaries and XML/SQLite exports | PyShark, external TShark, `sqlite3` |
| GUI | Render connection, chat, inspection, and analysis state; invoke service operations | Tkinter/ttk and an event queue |

The GUI imports the service interfaces rather than manipulating cryptographic keys or socket frames. Protocol and analysis modules must be usable without importing Tkinter. TCP workers and analysis workers never call Tkinter widgets directly; the main thread drains their event queue with `after()`. Bound the queue to 1,024 events; producers apply backpressure with cancellation-aware waits rather than accumulating unbounded events or silently dropping security results.

There is one active connection and one peer per application instance. A second incoming connection is declined while connecting, pairing, or connected. Both instances can listen, but users initiate one connection at a time. Simultaneous cross-connections produce a clear busy/retry result rather than competing sessions.

## 4. Identity, pairing, and handshake

### Local state

Create a persistent Ed25519 identity in the user's application configuration directory: `%LOCALAPPDATA%/SPARC` on Windows, or `$XDG_CONFIG_HOME/sparc` with `~/.config/sparc` as the Linux fallback. Support an explicit `--data-dir` override for isolated lab instances and automated tests. Do not put identity files in the repository or exports. Linux directories/files use owner-only permissions; Windows uses the user's inherited profile access controls. The private key is stored without a passphrase for this milestone, under the trusted-endpoint assumption.

Write identity and trust updates atomically. A corrupt existing identity must cause a visible startup error, not silent key replacement. Trust-store corruption must not be interpreted as an empty trust store. Exported measurements never contain real identity private keys or live session keys.

The public-key fingerprint is SHA-256 of the 32 raw Ed25519 public-key bytes, displayed in full hexadecimal groups. Show **Your fingerprint** and **Peer fingerprint** separately. A user verifies that the received peer fingerprint equals the other laptop's own fingerprint. Each side approves independently.

Store a verified public key with a user-visible label and its last configured endpoint. Connecting to a remembered endpoint with a different key is blocked until the user explicitly forgets/re-pairs that entry. IP addresses are hints, not identities. A remembered public key can be recognized at a new endpoint. Never replace a trusted key automatically.

### Canonical encoding and schemas

For signed JSON, use UTF-8 encoding of `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`. Signed schemas contain only objects, strings, and explicitly bounded integers; no floats, booleans in integer fields, or null values. Preserve message Unicode exactly; do not normalize it silently.

Reject duplicate JSON keys, missing or unknown fields, wrong types, invalid UTF-8, noncanonical binary encodings, and out-of-range values. Base64 fields use the standard alphabet with padding and strict decoding. IDs and digests use lowercase hexadecimal with exact lengths. Canonicalize validated parsed objects before verification.

### Handshake construction

The TCP connector is the **initiator**; the accepted connection is the **responder**. Each creates a fresh X25519 ephemeral key pair and fresh 32-byte random value for every connection attempt. The identity key remains separate from the ephemeral exchange key.

1. **Client hello:** initiator sends exactly `kind="client_hello"`, `protocol="SPARC"`, integer `version=1`, `identity_key`, `ephemeral_key`, and `random`. The last three fields are canonical Base64 strings, each decoding to exactly 32 bytes.
2. **Server hello:** responder constructs the equivalent unsigned hello with `kind="server_hello"`. Let `T` be the canonical encoding of an object containing the complete client hello and unsigned server hello under the keys `client_hello` and `server_hello`. The responder sends its hello plus a `signature` field containing its Ed25519 signature over `b"SPARC-v1 handshake responder\x00" + T`. All handshake and message signatures decode from canonical Base64 to exactly 64 bytes.
3. Initiator validates the server signature and pinned identity. An unknown identity requires fingerprint approval before continuing. It sends a client-auth object containing `kind="client_auth"` and its signature over `b"SPARC-v1 handshake initiator\x00" + T`.
4. Responder validates the client signature and pinned identity. An unknown identity requires local fingerprint approval. This approval applies to the immutable public key in that handshake, not to a mutable display name.
5. Both calculate the X25519 shared secret. Reject malformed keys and an invalid/all-zero exchange. Define `session_id = SHA256(b"SPARC-v1 session\x00" + T)`. Derive 64 bytes with HKDF-SHA256, salt `SHA256(T)`, and info `b"SPARC-v1 traffic\x00" + session_id`. The first 32 bytes are the initiator-to-responder AES key; the remaining 32 are the responder-to-initiator AES key.
6. Responder sends an encrypted finished record; initiator verifies it and sends its encrypted finished record. Their plaintext is canonical JSON containing `kind="finished"` and `transcript_sha256=SHA256(T).hexdigest()`. These records confirm possession of the derived keys.
7. Initiator becomes connected after validating the responder finished and successfully sending its own; responder becomes connected after validating the initiator finished. Save newly approved trust only at those successful completion points. Chat is disabled until connected.

Signing the full transcript binds the identities, roles, protocol version, randomness, and ephemeral exchange keys together. The two role-specific signature prefixes prevent reflecting one side's signature as the other's. No fallback version or algorithm negotiation is allowed in version 1.

## 5. TCP framing and encrypted messages

### Framing and limits

Each frame is a four-byte unsigned big-endian length `N`, followed by a one-byte type and `N-1` bytes of body. Length excludes the four-byte prefix and must be at least one. Types are: 1 client hello, 2 server hello, 3 client auth, 4 responder finished, 5 initiator finished, and 6 application record. Types 1-3 contain JSON; types 4-6 contain encrypted binary records. An encrypted record must have room for its 40-byte session/sequence header, its 16-byte tag, and a nonempty ciphertext.

Handshake JSON frames are limited to 8 KiB; every frame is limited to 128 KiB. Validate lengths before allocation or reading the body. A text payload is at most 16 KiB in UTF-8; the larger frame bound accommodates JSON escaping and signatures. Read-exactly loops handle partial TCP reads. Serialize writes through one writer so records cannot interleave.

Socket reads poll cancellation at least once per second. Initial hello exchange has a 20-second deadline. Client-auth and responder-finished waits each allow up to 150 seconds to accommodate pairing. Each local pairing prompt allows 120 seconds. The overall handshake limit is 300 seconds; the final client-finished wait is 10 seconds. An incomplete frame on a connected session times out after 10 seconds, while an idle connection can wait for new data. Stop/disconnect closes the sockets and unblocks workers.

### Record authentication and nonce construction

An encrypted body contains 32 raw session-ID bytes, an eight-byte unsigned big-endian sequence number, and AES-GCM ciphertext with its 16-byte tag appended. Each direction has its own key and counter. Sequence zero is consumed by that direction's finished record; application records start at one. Nonce is four zero bytes followed by the eight sequence bytes.

Associated authenticated data is exactly:

`b"SPARC-v1 record\x00" + type_byte + session_id + direction_byte + sequence_bytes + length_bytes`

Here `direction_byte` is zero for initiator-to-responder and one for the reverse direction, and `length_bytes` is the original four-byte frame prefix. Check the expected session ID, type, direction, and next sequence; reject gaps and duplicates. Counter exhaustion closes the session before reuse. New sessions use new ephemeral keys, so restarting counters does not reuse a key/nonce pair.

### Signed application envelopes

A chat object contains `kind="chat"`, a fresh 32-character hexadecimal `message_id`, the exact `text`, integer `byte_count`, and `sha256` of its UTF-8 bytes. Define the signing projection as the unsigned object with the `text` field removed for chat/benchmark records. Acknowledgment and heartbeat records sign their full unsigned object. The retained size/hash fields bind the omitted text after the receiver checks them. This permits retaining verifiable signed metadata in the audit log without retaining plaintext. Sign the canonical projection with:

`b"SPARC-v1 message\x00" + session_id + direction_byte + sequence_bytes + canonical_signing_projection`

Add a Base64 `signature` field and encrypt the complete envelope, including its text. The receiver authenticates/decrypts, validates the schema and bounds, recomputes text size/hash where present, verifies the signature using the authenticated peer identity, and only then publishes a received-message event. Signature verification alone is insufficient without the content hash/size checks.

A successful text receipt is durably audited before producing a similarly signed and encrypted acknowledgment object with `kind="ack"`, the matching `message_id`, `sha256`, and `status="verified"`. Only valid acknowledgments matching an outstanding ID and digest count as delivery confirmation. Acknowledgments are not themselves acknowledged. Bound pending requests to 100; further sends receive a visible busy result. Pending messages expire after 10 seconds; timeout is shown as unconfirmed rather than delivered. Unconfirmed text is not automatically resent after reconnect, avoiding duplicate application delivery.

Network benchmark records use `kind="benchmark"`, a 32-character hexadecimal `run_id`, and the same message fields/signing rules as chat. They receive the same acknowledgments but produce progress counters rather than hundreds of chat bubbles. Bound a run to 1,000 records and 16 MiB of plaintext per connection; invalid or excessive benchmark records end the session.

Wrong tags, signatures, digests, session IDs, sequences, types, or schemas fail closed: report the validation category, terminate the session, and do not display unverified content. Disconnect marks outstanding messages unconfirmed. Do not include secret data in error messages.

### Deferred media transfer

Image, audio, and video file transfer belongs to a later milestone under the teacher's guidance. The current protocol accepts only text/benchmark, acknowledgment, and authenticated control records; it rejects file-transfer kinds. Preserve the earlier proposal in [deferred media-transfer notes](2026-10-08-sparc-media-transfer-future-notes.md) for later design review. The current GUI, tests, and acceptance criteria cover text only.

### Signed hash-chain audit log

Store append-only JSON-lines logs in the application data directory. Each canonical record body contains `log_id` (fresh at creation), `record_number` (starting at one), UTC timestamp, event kind, local identity fingerprint, optional peer fingerprint/endpoint expressed as strings, event metadata, and `previous_hash` (64 zeros for the first record). Define `record_hash=SHA256(b"SPARC-v1 audit\x00" + canonical_body)`. Sign `b"SPARC-v1 audit-signature\x00" + record_hash_bytes` with the local Ed25519 identity. The outer stored record contains `body`, hexadecimal `record_hash`, and Base64 `signature`.

Log pairing outcomes and trust changes, session establishment/closure, text send attempts and verified receipts/delivery, rejected security checks, and reconnect outcomes. Store message hashes and bounded metadata, not plaintext, private keys, or live session keys. Retain peer signed metadata evidence as the authenticated public key, session ID, direction, sequence, canonical signing projection, and signature. This independently verifies the peer's digest/receipt statements; verifying actual supplied text also requires recomputing its digest.

Append, flush, and fsync before a successful receipt acknowledgment. Audit send attempts before writing data; log verified delivery separately. Failure to durably append pauses sending and closes the affected session with an audit-storage error. Do not report successful accountable delivery after a logging failure. Aggregate repeated connection/rate-limit rejections at most once per five seconds to avoid creating a log-flood mechanism.

On startup, verify the retained log and last signed checkpoint using the trusted local public key before appending. Check record numbers, log ID, hashes, previous links, signatures, and expected identity. Corruption produces an explicit blocked state; do not truncate, repair, replace, or silently skip invalid records.

Export a signed checkpoint containing log ID, last record number/hash, and identity fingerprint. The audit verifier optionally compares a checkpoint retained outside the writable log store to detect rollback or tail deletion relative to that checkpoint. Without an independent retained checkpoint, report verification of the available chain only; full log/tail deletion cannot be disproved. A checkpoint missing its expected log is a failure, not a fresh empty log.

The Audit view displays verification status, verified record count, first failed record/reason, current head/checkpoint, Export checkpoint, and Verify log controls. Measure append/fsync/signing duration, bytes per event, and verification duration/records per second. Network completion timing includes required durable audit work; local primitive benchmarks exclude it and label that distinction.

## 6. Analysis definitions

### AES experiments

Live communication uses AES-256-GCM. Sensitivity experiments instead invoke the AES-256 block primitive on exactly one 16-byte block, using PyCryptodome's ECB API for this isolated analysis only. ECB is not a communication mode. This separation is necessary because GCM's counter-mode ciphertext comparison under a fixed key/nonce does not expose AES block-input avalanche behavior. Never reuse a live GCM nonce to conduct an experiment.

Use a synthetic 32-byte key and 16-byte input block, completely separate from live keys and messages. A single-trial view lets users select either an input bit (0-127) or key bit (0-255); bit zero is the most significant bit of byte zero. Display original/modified laboratory operands and ciphertexts. Label synthetic laboratory keys explicitly.

The batch default uses 50 base cases. For reproducible public laboratory data, derive each case's key as SHA-256 of the UTF-8 string `SPARC-LAB-v1:key:<seed>:<index>` and its block as the first 16 bytes of SHA-256 of `SPARC-LAB-v1:block:<seed>:<index>`. Seed is a decimal integer and indices are 0-49. This deterministic generation is exclusively for public analysis data; production keys come from the cryptographic library's secure generator.

For each case, encrypt the baseline once, then independently flip each of the 128 input bits and each of the 256 key bits. Every trial starts from the unmodified baseline. Report the 6,400 input-bit trials and 12,800 key-bit trials separately.

"Explicit formulas" means documented calculations for every reported metric, rather than unexplained scores or a promise that an observed result equals an ideal percentage. For example, if 64 of 128 output bits change, the measured bit-change percentage is `64 / 128 * 100 = 50%`. These definitions are chosen by the project because the teacher did not prescribe formulas; they do not require handwritten AES mathematics or a handwritten AES implementation.

Let `C` and `C'` be the two 16-byte ciphertexts:

- **Bit-change percentage:** `100 * sum(popcount(a XOR b) for paired bytes) / 128`.
- **Byte-change percentage:** `100 * count(a != b for paired bytes) / 16`.
- **Hex-character-change percentage:** compare their 32-character lowercase hexadecimal encodings at equal positions; `100 * differing positions / 32`.

Display key sensitivity as **Key-bit avalanche (confusion illustration)**. It illustrates key sensitivity and is not a universal score for Shannon confusion. Display input sensitivity as **Plaintext-bit avalanche (diffusion illustration)**. Average bit-change is expected near 50% for an ideal avalanche model, not exactly 50% on every trial. The mean alone does not establish the strict avalanche criterion or prove security.

Byte change is a clearly labeled proxy for the course's character-level discussion, because ciphertext is binary. Under an ideal independent-byte comparison model, the expected differing-byte percentage is `100 * 255/256 = 99.609375%`. An individual trial can reach 100%, but that is not a guarantee. Hexadecimal characters have a different model expectation, `100 * 15/16 = 93.75%`; do not conflate them with raw bytes or Unicode plaintext characters.

Display observed values, trial count, mean, minimum, maximum, and population standard deviation. Export the per-trial data and a separate summary CSV. Never hardcode an observed result or force an output to reach a target.

### Per-message cryptographic timings

Use `time.perf_counter_ns()` around individual operations. Sender reports UTF-8 hashing, Ed25519 signing, and AES-GCM encryption. Receiver reports authenticated decryption, hash recomputation, and signature verification. Store times as nanoseconds and display microseconds. Label sender and receiver timings separately; do not subtract wall-clock timestamps across devices.

Signature generation times exclude identity generation. Encryption/decryption timings exclude GUI rendering, socket I/O, encoding, and key derivation. Operation timers include the cost of the individual cryptographic call and timer overhead. Failed operations are marked as failures, not mixed into successful averages.

### Local benchmark

Default workloads are 64, 1,024, and 16,384 UTF-8 bytes, generated as ASCII text so character and byte counts are known. Perform 10 warmups and 1,000 measured calls per operation/workload. Use synthetic benchmark keys. Encryption uses a fresh nonce for every invocation, including warmups. Decryption can repeatedly verify an already generated ciphertext. Signing/verification operate on the defined context-and-digest signing projection; hashing is measured separately. Explain that signature input stays approximately constant as content grows because it contains the digest, while encrypted envelopes contain the actual text and grow with it. Key generation is outside measured spans.

Report count, arithmetic mean, median, and nearest-rank p95 (`sorted_times[ceil(0.95*n)-1]`) for each operation. Local operation throughput is measured plaintext bytes processed divided by the sum of that operation's measured durations. Label it **local cryptographic throughput**, not network speed.

### Network benchmark and delivery measurements

An opt-in network run requires an authenticated connected peer. For each of the three payload sizes, run 10 warmups and 100 measured sequential request/acknowledgment exchanges. Generate valid signed/encrypted benchmark envelopes. Begin each exchange timer immediately before hashing; stop after authenticating/decrypting and verifying its matching acknowledgment on the sender. This is application round-trip completion time, not one-way latency.

For each workload, count only confirmed measured messages. Network goodput is the sum of their original UTF-8 plaintext bytes divided by the measured elapsed interval from starting the first measured message to accepting the last acknowledgment. Character rate uses the sum of Python `len(text)` over that same interval (Unicode code points, not grapheme clusters). If a run fails or is canceled, label its results incomplete and do not silently report full-run goodput.

These measurements include application cryptography, protocol encoding, TCP, receiver processing, required audit writes, configured pacing, and acknowledgment overhead; handshake and GUI rendering are excluded. Benchmark records receive the same durable receipt/delivery auditing as text, while their GUI presentation is aggregated. Report plaintext byte count and actual application-frame byte count separately. Actual Ethernet/IP/TCP overhead is measured through Wireshark, not inferred from application frame lengths.

Availability/efficiency experiments use psutil samples of the SPARC process at one-second intervals to report CPU percent and resident memory during baseline, text benchmarks, and controlled-flood workloads. Record sampling interval and peak observed memory; do not describe sampled values as exact instantaneous maxima. Measure handshake completion, peer-loss detection, reconnect completion, audit append/verification, and frame/log storage overhead separately. TCP connection/record limits are part of the measured policy and displayed with results.

CSV metadata includes run ID, UTC timestamp, test type, payload size, sample count, Python/library versions, and platform. Preserve raw timings and definitions so results can be recomputed. Label loopback-simulation and physical-device results explicitly.

## 7. GUI behavior

Use ttk styling and a resizable application window with Connection, Chat, Analysis, Audit, and Traffic Analysis tabs. Prioritize readable labels, tables, and clear status over decorative animation.

**Connection:** prominently show **Your device IP addresses** with network-interface labels and **Your listening TCP port** (default 47655), with Copy controls for reachable IP/port pairs. Show listener status separately so a configured port is not represented as actively listening before startup. If a laptop has Wi-Fi, Ethernet, or VPN addresses, list the IPv4 candidates and let the user choose the reachable LAN address to share. Show local hostname, editable bind IP and port, explicit Start listening/Stop listening controls, editable peer IPv4 address/port, Connect/Disconnect, own fingerprint, peer fingerprint, and state. Default listening address is `0.0.0.0`; explicitly label it as listening on all IPv4 interfaces rather than displaying it as the peer's destination. Port must be 1-65535. Manual peer input accepts a literal reachable IPv4 address. Users choose the correct LAN interface; do not silently overwrite their configuration. The GUI also displays the connected peer endpoint; neither laptop has a permanent central-host role.

**Pairing:** show full fingerprints with Copy controls and explanatory text. An unknown peer presents Approve/Reject after the relevant signature is validated. A changed remembered identity presents a blocked state and explicit Forget peer action. Disable send and network benchmark controls during pairing.

**Chat:** multiline input with an explicit Send button; preserve Unicode and line breaks; reject empty or oversized messages with a clear error. Show message direction and pending/verified/unconfirmed status. A message inspector shows original/recovered text for validated messages, digest, signature, ciphertext in Base64, nonce, GCM tag, byte count, and available operation timings. Show the sender's and receiver's digest on received messages with a match indicator. Do not show private identity keys or session keys. Keep at most 500 messages in memory and explain when older entries are removed. Text history is not persisted in this milestone.

**Analysis:** single-trial key/input sensitivity, batch sensitivity, local benchmark, optional network benchmark, progress/cancel controls, result tables, and CSV export via a save dialog. A signature-verification specimen demonstrates a valid signature and rejection after an edit to message/signature bytes. This is an isolated verification exercise; the protected live message is never edited in place. Limit detail widgets and event queues so incoming records do not create unbounded memory growth.

Application states are stopped, listening, connecting, handshaking, awaiting approval, connected, disconnecting, and error. Listening may remain active while a session is connected, but new connections are refused. Closing the window cancels work and closes sockets; workers use bounded waits and terminate without accessing destroyed widgets.

## 8. Wireshark demonstration and exported evidence

Document Windows and Linux setup: finding the reachable LAN IP, starting the listener, configuring the inbound TCP firewall rule for the chosen port, checking router client isolation, and selecting the correct capture interface. External capture permissions remain OS/user responsibilities; SPARC does not run with administrator privileges to capture traffic.

For default port 47655, use a capture filter `tcp port 47655` and a display filter `tcp.port == 47655`. Capture both directions, complete pairing, send a distinctive known text, and inspect the reassembled TCP stream. Explain that public handshake material and framing are visible while encrypted chat envelopes are not readable as plaintext. Check the full reassembled stream rather than interpreting an individual TCP segment as a complete application message.

Provide a separate, clearly labeled lab-only plaintext TCP baseline sender/receiver on port 47656 for comparison with synthetic demonstration text. It does not share a connection, toggle, or fallback with secure SPARC. Capture that baseline separately and show that its text is readable. This satisfies the original project's plaintext-versus-encrypted evidence goal without making the secure protocol downgradeable.

The evidence checklist comprises two PCAP/PCAPNG files, a successful two-peer exchange and security-inspector screenshots, analysis CSVs, timing/goodput CSVs, and documented validation-failure demonstrations. The primary target is Windows-to-Linux; explicitly identified two-process simulation is also permitted by the clarified brief. The final-project evidence additionally includes PDML XML, the packet-index SQLite database, PyShark traffic summaries, and security/efficiency measurements for each of the five goals. Include a report outline mapping artifacts to each requirement. Keep private keys and real session keys out of evidence bundles.

### Required packet-conversion and traffic-analysis pipeline

The full-project workflow is `Wireshark capture -> saved PCAP/PCAPNG -> offline analysis and exports`. Saving a capture remains an external Wireshark action. Python processes the saved file without needing live-capture administrator privileges.

- **PCAP to XML:** export Wireshark/TShark Packet Details Markup Language (PDML), which is XML containing decoded packet fields. Use TShark with a structured argument list equivalent to `tshark -n -r capture.pcapng -T pdml`, writing stdout to the selected XML file. Do not use a shell or construct executable command strings from user paths. Preserve the original capture as the source; XML export does not decrypt encrypted SPARC application content.
- **PCAP to SQLite:** use PyShark to stream packets from a saved capture into a SQLite database. This creates a queryable packet index, not a lossless replacement for the original capture. Keep the original capture and identify it with a SHA-256 source-file digest in import metadata. Use transactions and parameterized inserts. Store packet number, timestamp as exact source text, captured/wire lengths, highest decoded protocol, available IPv4/IPv6 addresses, TCP/UDP ports, TCP stream ID and flags, and retransmission indicators. Missing fields are SQL NULL. A metadata table records source name/digest, parser versions, applied filter, import count, and completion status. Index packet number, stream ID, and timestamp. Preserve unfiltered captures for verification; record any filter on the derived dataset.
- **PyShark traffic analysis:** report packet and captured-byte totals, duration, protocol counts, TCP conversations, directional bytes, packet-size distribution, and TCP retransmission indicators. Define captured-byte rate as included captured-frame bytes divided by the first-to-last included packet interval; label it separately from application plaintext goodput. For a zero-duration or fewer-than-two-packet sample, rate is unavailable rather than division by zero. A single sender capture does not establish end-to-end loss or one-way latency. Retransmission indicators are dissector/capture observations, not proof of an attack.
- **Conversion efficiency:** measure elapsed import/export time, input file size, included packet count, output size, and packets processed per second. Record the host/tool versions. These processing measurements are distinct from communication throughput.

PyShark invokes TShark; installing the Python package alone is insufficient. Setup must install or locate TShark on Windows and Linux, optionally accepting an explicit executable path. The current workspace has Wireshark but no TShark executable available. A missing TShark dependency results in an actionable offline-analysis error while ordinary secure chat remains usable.

Offline processing runs in a worker with progress and cancellation, bounded memory (`keep_packets=False` for streaming PyShark reads), guaranteed capture/subprocess cleanup, and temporary output files. Publish final XML/database outputs only after successful completion. Reject accidental input/output overwrite and mark failed/canceled imports incomplete. The offline **Traffic Analysis** view has Open capture, Analyze, Export XML, and Export SQLite actions. Validate exports against the source capture: packet counts and known fields, well-formed PDML, and SQLite integrity/query checks.

## 9. Error handling and validation

Errors have actionable categories: invalid IP/port, bind failure, refused/timed-out connection, busy peer, malformed frame, unsupported version, pairing rejection/timeout, changed identity, handshake signature failure, invalid key exchange, GCM authentication failure, digest mismatch, message signature failure, sequence/replay failure, delivery timeout, audit corruption/storage failure, rate limit, peer inactivity, missing TShark, export error, and disconnected peer.

A network error closes the affected session, drops its keys/counters, marks outstanding text unconfirmed, and leaves manual reconnect available. It must not crash the GUI or silently substitute a plaintext channel. A failed export leaves results available for retry. A canceled analysis run remains labeled canceled and cannot appear as a completed benchmark.

### Availability controls

- Accept no more than 20 TCP connection attempts per source IPv4 address per minute and 60 globally per minute, using rolling monotonic-time windows. Track at most 256 source buckets, evicting expired entries. A busy application refuses additional sockets before performing expensive handshakes. Connection deadlines and one-handshake-at-a-time bound idle-handshake resource use.
- Apply a 200-application-records/second token bucket per direction with a burst of 400. The local writer paces its records to this policy, including acknowledgments and control traffic, so normal text exchanges and benchmarks do not trigger the receiver's limit. A peer exceeding the permitted receive burst is disconnected and the event aggregated in the audit log. Include these settings in efficiency results; they are application policy, not unlimited flood protection.
- When no outgoing traffic has been sent for five seconds, send an authenticated `ping` application object with a fresh 32-character hexadecimal `ping_id`. Respond with a signed/encrypted `pong` containing that ID. Any valid incoming record refreshes the peer-activity timer. Fifteen seconds without valid incoming activity closes the session. Pings/pongs are not recursively acknowledged; only liveness state changes are audited.
- Only the original initiator automatically reconnects after eligible TCP loss, delivery timeout, or inactivity, and only to the previously authenticated configured endpoint/key. Try at most three times with delays of one, two, and four seconds. Each attempt uses fresh ephemeral keys, nonces, and the full handshake. An unexpected key, signature/authentication failure, local audit failure, explicit Disconnect/Stop, or application shutdown cancels automatic reconnect. The responder keeps its listener available but does not initiate competing reconnects.
- Do not automatically resend unconfirmed text. The GUI permits deliberate resend after a new authenticated session. Cancellation wakes rate-limit/reconnect waits and prevents background work after shutdown.

Demonstrate these controls with bounded lab workloads using two instances: stale/oversized frames, excessive connection attempts, an authenticated test peer deliberately exceeding the record burst, abrupt socket loss, and receiver restart. Record rejection counts, resource samples, detection/recovery times, and valid-message goodput. A large unrelated network flood can still exhaust the LAN or OS; do not claim to prevent that from application-only experiments.

Required automated verification focuses on security and cross-module behavior:

- Canonical encoding/schema rejection, byte/character formulas, and timing aggregation.
- Identity persistence, explicit trust pinning, corrupt-store handling, and changed-key rejection.
- Transcript tampering, invalid signatures, role substitution, and stale client-auth rejection.
- Directional key agreement/separation, finished verification, and fresh keys across sessions.
- Unicode messages, signed acknowledgments, partial TCP reads, bounded lengths, and sequential message exchanges.
- Audit chain/signature verification, peer signed metadata evidence, altered records, checkpoint-relative rollback, append failure, and corrupt-log startup.
- Modified ciphertext/tag/AAD, replayed/out-of-order frames, and valid-GCM envelopes with invalid signatures or hashes.
- Cancellation, listener stop, disconnect during pairing, and delivery timeout.
- Writer pacing versus receive limits, finite source tracking, liveness timeouts, bounded reconnect with fresh keys, and no automatic retry after identity/authentication failures.
- CSV exports that can reconstruct summaries and contain no real secret-key material.
- Source-capture versus PyShark/XML/SQLite counts and fields, well-formed PDML, SQLite integrity, missing-TShark handling, streaming cleanup, and zero-duration capture statistics.

Use local sockets for real integration exchanges, with separate temporary identity stores and explicit pairing events. GUI smoke checks verify responsiveness and event delivery on Linux; the final Windows-to-Linux demonstration is a separate required manual check. Do not claim cross-platform network validation until it has actually been performed.

## 10. Acceptance checklist

1. Both platforms can install dependencies and start the same Tkinter application.
2. Users can configure IP/port, connect, approve fingerprints once, and recognize the peer on reconnect.
3. Both directions exchange Unicode text and show confirmed delivery.
4. Encryption is AES-256-GCM with fresh session keys and nonreused directional nonces.
5. GUI displays SHA-256 values, signatures, and actual validation outcomes.
6. Tampering, signature failures, replay, and changed peer identities are rejected as specified.
7. Audit logs verify their signatures/chain and detect modifications; checkpoint-relative deletion claims are demonstrated with independently retained checkpoints.
8. Heartbeat, rate limits, and bounded reconnect behave as specified, with measured availability outcomes.
9. Sensitivity experiments expose their operands, formulas, observed data, and aggregate results.
10. Local, network, audit, resource, and conversion performance results are clearly distinguished and exportable.
11. External Wireshark evidence includes encrypted communication and a separate plaintext baseline; XML, SQLite, and automated traffic summaries agree with their source captures.
12. Two physical devices or explicitly identified independent-process simulation provide justified end-to-end evidence for all five goals.
13. Application shutdown, canceled work, and failed connections leave no hanging GUI operations.

## 11. Review and implementation handoff

The user approved the initial conversational design on 2026-10-08 and subsequently clarified the broader permitted libraries, five mandatory security goals, two-device/simulation evidence, and packet-conversion/analysis requirements. Signed audit logs were added, with a preference to avoid redundant analysis tools. The teacher's latest guidance permits limiting the current milestone to text, so media transfer is deferred and its earlier design retained separately as future notes. The user approved this revised text-only written specification on 2026-10-08. It retains the five-goal security framework and one offline pipeline for distinct checklist deliverables. Spec approval authorizes implementation planning; implementation begins after the plan is reviewed and its execution method selected.

The workspace currently has planning documents and no source files. Git was initialized on 2026-10-08 at the user's request, with SSH origin `git@github.com:h4rshupadhyay/SPARC.git`. SSH access was verified; the remote returned no refs. No commits or pushes have been made. The current session has unrestricted filesystem/network access and approval policy `never`; command tools perform Git operations directly without an escalation path. This is current environment status, not a change to the project scope.

## 12. Primary references

- [NIST FIPS 197: AES](https://csrc.nist.gov/pubs/fips/197/final): AES key and block sizes.
- [NIST SP 800-38D: GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf): counter-mode encryption and authenticated encryption construction.
- [Cryptography AES-GCM API](https://cryptography.io/en/stable/hazmat/primitives/aead/): key lengths, nonces, tags, and failed authentication.
- [Cryptography X25519 API](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/x25519/): ephemeral key exchange and subsequent key derivation.
- [Cryptography Ed25519 API](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/): signature generation and verification.
- [Cryptography HKDF API](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/#hkdf): derivation inputs and output lengths.
- [PyCryptodome AES API](https://www.pycryptodome.org/src/cipher/aes): block-encryption laboratory interface.
- [Li and Cusick: Strict Avalanche Criterion over Finite Fields](https://eprint.iacr.org/2005/361.pdf): the probabilistic bit-change criterion.
- [RFC 8826, section 9.3](https://www.rfc-editor.org/rfc/rfc8826.html#section-9.3): the need to authenticate a peer's key through an independent trust mechanism.
- [Python Tkinter documentation](https://docs.python.org/3/library/tkinter.html): GUI portability and threading model.
- [Wireshark export documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html): PDML XML packet export.
- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html): offline capture reads, filters, and decoded output formats.
- [PyShark upstream project](https://github.com/KimiNewt/pyshark): the Python wrapper around TShark and saved-file capture interface.
- [psutil official documentation](https://psutil.io/): cross-platform interface enumeration and process resource samples.

The bespoke transcript, framing, and application envelope are SPARC design choices; these references support the underlying primitives and concepts, not an independent audit of this protocol.
