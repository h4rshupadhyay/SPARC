# SPARC Secure Text Application Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build authenticated encrypted text chat, durable signed audit logs, and availability controls with a runnable Tkinter interface.

**Architecture:** Pure encoding/crypto modules feed a signed handshake and record codec. One peer service serializes outbound records, verifies inbound records, and durably audits delivery; GUI widgets consume its events without accessing sockets or keys.

**Tech Stack:** Python 3.10+, cryptography 50.0.2, psutil 7.2.2, Tkinter/ttk, pytest 8.4.2.

**Spec:** [Approved specification](../specs/2026-10-08-sparc-progress-check-design.md).

## Global Constraints

Inherit every exact global constraint and conditional commit/environment rule from the [master plan](2026-10-08-sparc-progress-check-plan.md). No media, discovery server, WebRTC, trust-any option, or chat plaintext in persistent logs.

## Review Focus

Master items 1-4 are pinned by C1-C7 below; item 5 belongs to the traffic plan. Preserve the master list as the single review checklist.

---

## File structure and shared contracts

Create `src/sparc/` with `models.py` (immutable cross-module records), `encoding.py`, `identity.py`, `crypto.py`, `protocol/{framing,messages,handshake,records}.py`, `audit.py`, `peer/{service,session,policy}.py`, and `gui/{app,connection,chat,audit_view}.py`. All package directories have `__init__.py`; `src/sparc/__main__.py` owns CLI arguments and GUI launch. Keep implementation details behind the contracts below; split long files by their named responsibilities.

C1 defines: `Endpoint(ip: str, port: int)`, `Role` enum with INITIATOR/RESPONDER, `SparcError(code: str, message: str)`, `Identity(private_key, public_bytes: bytes, fingerprint: str)`, and frozen `Limits` with all master-plan defaults. `Limits` permits test injection of timeouts/clocks, not a GUI trust bypass. Service listener port zero is permitted internally for ephemeral test sockets; GUI/CLI input validation still requires 1-65535.

C2 defines `Timings(hash_ns, sign_ns, encrypt_ns, decrypt_ns, verify_ns)` with optional integer fields; `Inspection(message_id, sequence, sha256, computed_sha256, signature, ciphertext, nonce, tag, plaintext_bytes, timings)` with public bytes/metadata only; `ProtectedRecord(frame: bytes, inspection: Inspection | None)` and `OpenedRecord(payload: dict, inspection: Inspection | None, sequence: int | None = None, direction: int | None = None)`. Finished/control records may omit an inspector; chat/benchmark records supply it. C5f adds defaulted authenticated coordinates for every application kind, including acknowledgments; finished records retain None coordinates and older construction remains compatible.

C5 defines `ServiceEvent(kind: str, data: dict)` and `DeliveryReceipt(message_id: str, started_ns: int, finished_ns: int, plaintext_bytes: int, characters: int, frame_bytes: int)`. Message events carry `message_id`, `text`, `inspection`, wire direction, and local `origin` (`outgoing` from the writer or `incoming` from the reader); pairing events carry `request_id`, candidate fingerprint, and own fingerprint. State events carry state/reason/endpoint. `operation_metrics` events carry `operation`, `elapsed_ns`, `success`, `encoded_bytes` (optional), and public `context` metadata for handshake, loss detection, reconnect and audit spans. Handshake spans state whether user approval time is included; loss detection measures last valid activity to declared loss. No event carries private/session keys. Later tabs consume these names unchanged.

## Execution workflow

Use the [master plan's authoritative ownership, small-task cycle, dispatch, history and environment rules](2026-10-08-sparc-progress-check-plan.md#model-ownership-and-small-task-workflow). Reuse a task-local Luna worker for related units and red/green phases; the controller verifies each phase separately and runs the milestone gate below. Unit interfaces, allowed files, assertions and exclusions remain binding. Documentation changes use content/link checklists without documentation-mirroring tests. Commands use the master virtual environment; GUI checks require a display and unavailable checks stay explicit.

## Fixed integration decisions for the coding packets

C1a owns every shared type above. `Limits` is frozen. Public APIs below retain the approved names. New helpers live behind those APIs; they do not alter wire schemas.

Concurrency is fixed by Sol here: `PeerService` owns one state lock and a session-generation number. Listener, handshake coordinator and active session are separate workers; only one handshake/session slot may be occupied. `ActiveSession` owns two bounded FIFO deques under one Condition, with maximum 1,024 ordinary outbound payloads and a separate control capacity of 100; writer drains control first, is the only caller of `protect` and `sendall`, and never holds service state lock across I/O/fsync/event backpressure. Reader alone calls `open`. Receipt state owns its own lock/condition. All queue puts use cancellation-aware bounded waits; shutdown closes sockets, sets cancel and wakes conditions before joining workers. Lock order is service state then receipt state; no reverse acquisition. Session-generation checks discard stale completions/pairing approvals. After a failed write the codec/session is discarded. Event puts use the public queue bound 1,024; backpressure never silently drops verification results. Sol must resolve any contradiction before Luna implements it.

`SessionHooks(on_payload: Callable[[OpenedRecord], None], on_closed: Callable[[SparcError], None], emit: Callable[[ServiceEvent], None], on_written=None, on_poll=None)` is C5a's internal callback record. `ActiveSession(sock, established: EstablishedSession, hooks: SessionHooks, limits: Limits, *, cancel: Event | None = None)` exposes `start() -> None`, `enqueue(payload: dict, control: bool = False) -> None`, `close() -> None`, `join(timeout: float = 2) -> bool`, and `session_id: bytes`. Ordinary enqueue rejects full queues with a visible busy domain error; bounded control producers wait with cancel checks. C5e adds the optional before-write callback; C5g adds optional sole-writer polling for receipt deadlines and supplies the exact attempt cancellation event. C6 adds availability policy; no second socket writer is introduced. Terminal state delivery uses the ordinary bounded event queue plus one key-free pending state snapshot, coalesced by generation and consumed by unchanged get/get_nowait calls; ordinary verification events are retained. C6 also routes reconnect scheduling and recovered connection status through that same single snapshot. Retry handshake/audit spans and audit-failure diagnostics use nonblocking exact-owner publication and may be omitted when ordinary capacity is full.

The service records outbound audit attempts **before** writer enqueue. Incoming verified audit append is completed **before** acknowledgment enqueue or received-message publication. C5b's pending record must be inserted before enqueue so a fast acknowledgment cannot race it. Public `wait_for_receipt` operates off the Tk thread. Completed receipt cache is bounded to 100 entries; pending remains bounded to 100. Evicted completed receipts give a clear unavailable-receipt error, never manufactured timings.

C6 preserves clock-only helper construction with optional keyword-only `limits=Limits()`. Denied connection attempts count in capped rolling windows. All outgoing application records use one per-direction bucket before protection; authenticated incoming records are charged before dispatch. Rejection summaries use bounded counters and at least five seconds between durable summaries; audit failure stops the captured channel and disables new networking. The audit-failure latch precedes diagnostics, survives cancellation, and guards inbound reservation, coordinator entry, durable operations and adoption. The failure helper closes an assigned session's transport without setting its shared cancel or releasing its occupied slot; the existing owner then completes terminal cleanup. Handshake-only owners may be canceled immediately. Listener teardown uses captured resources and never invokes public Stop to cancel an assigned recovered session accidentally.

C6c reuses signed session establishment and closure events for liveness state changes. `Liveness.loss_elapsed_ns` carries the duration from the same monotonic sample that declares loss. The winning inactivity transition publishes an optional key-free metric through a nonblocking exact-owner callback before terminal cleanup; a full ordinary event queue may omit that diagnostic. `RecordBucket.wait(cancel, *, maintenance=None)` permits maintenance outside the bucket lock with waits capped at one second when supplied. `Liveness.tick(*, allow_ping=True)` permits loss-only polling while a frame is selected or pacing. Idle pings become the sole writer's current paced frame after FIFO/control selection, without another queue or worker.

C6d retains the original initiator's configured endpoint and authenticated fingerprint throughout one finite retry chain. The sole slot remains reserved during cancel-aware delays and fresh handshakes. Unknown or forgotten peers cannot trigger automatic approval or repinning; the returned fingerprint is checked before successful audits, pinning or adoption. Only established eligible loss starts a chain; later handshake TCP failures consume its remaining budget. Disconnect, Stop and shutdown revoke delayed work even without an active listener. Successful closure audit is required, and text is never automatically replayed.

## Fixed audit and store schema decisions

These internal persistence formats are Sol decisions; they do not change the approved wire protocol. Identity file `identity.json` contains exactly `version=1`, `private_key` (canonical Base64 raw32), `public_key` (canonical Base64 raw32). The loaded public key must equal the private key's derived public key. Trust file `trusted_peers.json` contains `version=1` and `peers`, an object keyed by fingerprint; each value has canonical32byte `public_key`, string `label`, `ip` literal IPv4 and integer `port` 1-65535. First use may create missing stores; invalid existing stores are never replaced. A valid pinned key recognized at a new endpoint is `known`; different key at a remembered endpoint is `changed`.

Audit metadata accepts only these public keys: `code`, `reason`, `phase`, `state`, `message_id`, `sha256`, `run_id`, `fingerprint`, `endpoint`, `approval_time_included`, `evidence_mode` (strings); `sequence`, `direction`, `byte_count`, `frame_bytes`, `attempt`, `count`, `elapsed_ns`, `record_count`, `encoded_bytes` (nonnegative integers, direction 0/1, existing protocol hex/length constraints apply); and `peer_evidence`, an object with exactly `public_key` Base64 raw32, `session_id` lowercase64hex, `direction` 0/1, `sequence` uint64, `projection` an unsigned signing-projection object and `signature` Base64 raw64. Chat/benchmark projections omit `text` and must pass metadata schema/size/hash validation; acknowledgments/control projections have their fixed C2b unsigned fields. Optional top-level peer fingerprint/endpoint in audit body are copied from validated metadata fields when present. No arbitrary nesting or plaintext is accepted. Strings are bounded to 1,024 UTF-8 bytes except canonical evidence projection, bounded to 8 KiB. Required metadata follows event purpose: message send/receipt/delivery includes ID/hash/byte_count; rejection/closure includes code/reason; pairing/trust includes fingerprint/endpoint/outcome in `state`; session/reconnect includes endpoint/state and attempt when relevant. Labels in evidence refer to authenticated device keys, not people.

Signed checkpoint outer object contains exactly `body` and canonical Base64 `signature`; body contains exactly `log_id`, `last_record_number`, `last_record_hash`, `identity_fingerprint`. Sign `b"SPARC-v1 checkpoint\x00" + canonical(body)` using the local Ed25519 key. All hashes/IDs obey the existing lowercase-hex rules; record number is nonnegative and zero means an empty log with zero hash. Retain last checkpoint as `audit-checkpoint.json`; external export can independently anchor a chain. Log file is `audit.jsonl`. Verification is implemented in C4b before C4c startup consumes it; C4d only creates/publishes checkpoints.

### C1: Executable package, canonical encoding, identity and trust store

#### C1a: Package and shared immutable types

**Files:** Create `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `.gitignore`, `src/sparc/__init__.py`, `src/sparc/models.py`, `CHANGELOG.md`, `docs/implementation-status.md`; test `tests/unit/test_models.py`

**Prerequisites:** approved master constraints.

**Interfaces:** Produce all C1/C2/C5 cross-module records listed above. `Identity.private_key: Ed25519PrivateKey`; `Inspection` fields other than `message_id: str`, `sequence: int`, `plaintext_bytes: int`, `timings: Timings` are digest strings or public bytes (`sha256/computed_sha256: str`, remaining binary fields `bytes`). `ServiceEvent.data: dict`; frozen `Limits` defaults match master

- [x] **Fixed test oracle:** `test_limits_are_frozen_and_match_spec`: assert `text_bytes == 16384`, `frame_bytes == 131072`, queue 1024 and production deadlines match master; mutation raises `FrozenInstanceError`. `test_event_and_inspection_have_no_secret_fields`: compare dataclass field names to the listed schema
- [x] **Luna implementation:** Set setuptools src layout, Python>=3.10; core pins cryptography50.0.2/psutil7.2.2; analysis pycryptodome3.24.0, traffic pyshark0.6, dev pytest8.4.2. Requirements install editable extras as previously defined. Ignore identities, `.venv`, `.demo`, nonfixture captures/databases/exports. Create package markers when each later task creates its package. Set the single package-version source in pyproject.toml to `0.1.0.dev0`; create the master-defined Unreleased changelog and compact task/milestone ledger
- [x] **Controller red/green:** `python -m pytest tests/unit/test_models.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.
- [x] **History content checklist:** `CHANGELOG.md` has Unreleased categories for significant/security changes; the ledger references all existing task IDs/milestones, status/test-evidence/commit-ref fields and concise unresolved decisions. Verify file contents/links directly; no new tests merely mirror these documents.

**Exclusions:** identity I/O, GUI, crypto implementations.

#### C1b: Strict canonical JSON

**Files:** Create `src/sparc/encoding.py`; test `tests/unit/test_encoding.py`

**Prerequisites:** C1a.

**Interfaces:** Produce `canonical(value: dict) -> bytes`, `parse_object(raw: bytes) -> dict`

- [x] **Fixed test oracle:** `test_canonical_exact_bytes`: `canonical({"b":2,"a":"✓"}) == b'{"a":"\\u2713","b":2}'`. `test_rejects_invalid_json_types` parameterizes duplicate keys, NaN, floats, booleans, null, nonobjects, invalid UTF-8; all raise `SparcError`
- [x] **Luna implementation:** Use the exact signed JSON options in spec §4. Strict duplicate hook and recursive accepted-type validation; no silent normalization. Preserve Unicode when parsing
- [x] **Controller red/green:** `python -m pytest tests/unit/test_encoding.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** message schemas or base64 rules (C2b).

#### C1c: Persistent identity storage

**Files:** Create `src/sparc/storage.py`, `src/sparc/identity.py`; test `tests/unit/test_identity.py`

**Prerequisites:** C1a-C1b.

**Interfaces:** Produce `resolve_data_dir(override: Path | None) -> Path`, `load_identity(data_dir: Path) -> Identity`; internal `atomic_write(path: Path, data: bytes, private: bool = True) -> None` for later stores

- [x] **Fixed test oracle:** `test_identity_is_persistent`: repeated load equal raw32 public keys and full64hex SHA256 fingerprint. `test_corrupt_identity_is_not_replaced`: preserve original corrupt bytes and raise. `test_platform_paths_and_owner_modes`: Windows LOCALAPPDATA/SPARC, XDG/fallback Linux paths, override precedence and Linux0700dir/0600file
- [x] **Luna implementation:** Create keys only if absent, serialize cryptography Ed25519 raw keys in validated persistent schema, atomic same-directory temp replace, owner-only Linux modes. Windows inherited user-profile ACL assumption stays explicit
- [x] **Controller red/green:** `python -m pytest tests/unit/test_identity.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** peer trust or audit initialization.

#### C1d: Explicit trust pins and diagnostic CLI

**Files:** Modify `src/sparc/identity.py`; create `src/sparc/__main__.py`, `README.md`; test `tests/unit/test_trust.py`, `tests/integration/test_check_cli.py`

**Prerequisites:** C1c.

**Interfaces:** Produce `TrustStore(data_dir).check(public_key: bytes, endpoint: Endpoint) -> str`, `.pin(public_key: bytes, endpoint: Endpoint, label: str = "") -> None`, `.forget(fingerprint: str) -> None`; `python -m sparc --check --data-dir PATH`

- [x] **Fixed test oracle:** `test_changed_endpoint_key_is_blocked`: initial unknown, pin known, substitute changed, original recognized at new endpoint; store unchanged until explicit forget. `test_corrupt_trust_is_not_empty`: bytes preserved, startup raises. `test_check_needs_no_tk_or_packet_tools`: public fingerprint persists between subprocesses; no private bytes/output, no GUI/PyShark import
- [x] **Luna implementation:** Reuse atomic storage and strict schemas. Diagnose versions/public fingerprint on --check. Reserve normal GUI launch for C7e; no premature GUI dependency
- [x] **Controller red/green:** `python -m pytest tests/unit/test_trust.py tests/integration/test_check_cli.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** implicit trust replacement or automatic re-pair.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_models.py tests/unit/test_encoding.py tests/unit/test_identity.py tests/unit/test_trust.py tests/integration/test_check_cli.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: add SPARC package and persistent peer identities`.

### C2: Bounded frames and authenticated signed record codec

#### C2a: Bounded TCP framing

**Files:** Create `src/sparc/protocol/framing.py`; test `tests/unit/test_framing.py`

**Prerequisites:** C1a.

**Interfaces:** Produce `Frame(kind: int, body: bytes, length: int)`, `pack_frame(kind: int, body: bytes) -> bytes`, `read_frame(sock: socket.socket, cancel: Event, deadline: float | None, limits: Limits) -> Frame`

- [x] **Fixed test oracle:** `test_partial_reads_round_trip` uses socket pair/split writes; original kind/body/length exact. `test_prefix_rejected_before_body_read`: zero or >128KiB prefix rejected without oversized body read/allocation. `test_json_frame_8k_limit`, `test_cancel_and_partial_frame_timeout`: bounded 1s cancel polling and connected partial10s test via shortened Limits
- [x] **Luna implementation:** uint32 big-endian N, one byte type1-6, enforce 8KiB handshake JSON and128KiB total before body allocation. An idle connected socket starts incomplete-frame deadline only after first prefix byte
- [x] **Controller red/green:** `python -m pytest tests/unit/test_framing.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** record cryptography or socket writes outside serialized writer.

#### C2b: Validated messages and signing projection

**Files:** Create `src/sparc/protocol/messages.py`; test `tests/unit/test_messages.py`

**Prerequisites:** C1b.

**Interfaces:** Produce `prepare_text(text: str, message_id: str, run_id: str | None = None) -> tuple[dict, int]`, `validate_application(payload: dict, signed: bool = True) -> None`, `signing_projection(payload: dict) -> dict`, `decode_base64(value: str, length: int) -> bytes`

- [x] **Fixed test oracle:** `test_unicode_hash_and_byte_bound`: exact UTF8 SHA256/byte_count, 16384 valid/16385 invalid. `test_lone_surrogate_is_local_error`: domain error. `test_empty_text_rejected`. `test_schema_rejections`: unknown fields/kinds/file records, bool integers, noncanonical b64 or lowercase hex length mismatch rejected. `test_projection_omits_only_text`: chat/benchmark exclude text/signature, ack/ping/pong include all unsigned fields
- [x] **Luna implementation:** Fixed schemas §5: chat,benchmark(runid),ack(status verified),ping,pong; exact field names and length bounds. Canonical strict base64. Hash call span only; no hash timing includes encoding. Empty/lone-surrogate locally rejected
- [x] **Controller red/green:** `python -m pytest tests/unit/test_messages.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** AES or live signatures.

#### C2c: Directional key derivation and record context

**Files:** Create `src/sparc/crypto.py`; test `tests/unit/test_crypto.py`

**Prerequisites:** C1b.

**Interfaces:** Produce `derive_traffic_keys(secret: bytes, transcript: bytes) -> tuple[bytes,bytes,bytes]`; `record_aad(kind: int, session_id: bytes, direction: int, sequence: int, length: int) -> bytes`; `message_context(session_id: bytes, direction: int, sequence: int, projection: dict) -> bytes`

- [x] **Fixed test oracle:** `test_hkdf_exact_inputs` compares independent cryptography HKDF SHA256 length64/saltSHA256T/info domain+sid; keys32+32 unequal, sid=SHA256sessiondomain+T. `test_aad_and_message_context_exact_bytes` assert domains andBE sequence/length plus canonical projection
- [x] **Luna implementation:** Implement fixed spec domain prefixes and integer/range validation. Nonce construction remains four zero bytes plus the eight-byte sequence. No key exports
- [x] **Controller red/green:** `python -m pytest tests/unit/test_crypto.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** handshake state or codec counters.

#### C2d: Codec state and finished records

**Files:** Create `src/sparc/protocol/records.py`; test `tests/unit/test_record_finished.py`

**Prerequisites:** C2a-C2c.

**Interfaces:** Produce public `SessionCodec(identity: Identity, peer_key: bytes, role: Role, keys: tuple[bytes,bytes], session_id: bytes)` with `.protect(payload: dict, frame_type: int = 6) -> ProtectedRecord`, `.open(frame: Frame) -> OpenedRecord`; implement types4/5 first. Define read-only `.session_id: bytes`, counters send/receive next=0

- [x] **Fixed test oracle:** `test_finished_consumes_sequence_zero`: role-specific type4/5 opens finished, each counter then1, inspector None. `test_finished_role_or_sequence_mismatch`: reject wrong finished kind/direction/gap/duplicate and insufficient encrypted body. `test_counter_exhaustion_never_reuses_nonce`
- [x] **Luna implementation:** Store per-direction keys/counters, role mapping and AESGCM helpers privately. No app record accepted before matching finished. Public app methods explicitly reject unsupported-unimplemented app until C2e/f. Failed validation never advances receive counter; failed session unusable
- [x] **Controller red/green:** `python -m pytest tests/unit/test_record_finished.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** live handshake or application implementation.

#### C2e: Outbound signed application records

**Files:** Modify `src/sparc/protocol/records.py`; test `tests/unit/test_records_protect.py`

**Prerequisites:** C2d.

**Interfaces:** Implement application branch of `SessionCodec.protect`; consumes `signing_projection`, `message_context`, `record_aad`; returns existing `ProtectedRecord`

- [x] **Fixed test oracle:** `test_protect_exact_signature_context_and_nonce`: independently verify Ed signature over domain/sid/dir/seq/projection; noncezero4+seq8 andseq starts1. `test_inspection_contains_digest_ciphertext_tag_and_timings`: SHA256 exact, AESGCM ct/tag independent decrypt, no key fields. `test_separate_direction_keys`
- [x] **Luna implementation:** Validate unsigned payload, Edsign canonical projection, addcanonical64bytesigb64, encrypt complete canonical envelope, pack bounded frame. N included inAAD before seal. Time sign/encrypt primitive calls only
- [x] **Controller red/green:** `python -m pytest tests/unit/test_records_protect.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** receive branch or socket writes.

#### C2f: Inbound validated application records

**Files:** Modify `src/sparc/protocol/records.py`; test `tests/unit/test_records.py`

**Prerequisites:** C2e.

**Interfaces:** Complete application branch of `.open(frame) -> OpenedRecord`; consumes signed schema/hash/signature context

- [x] **Fixed test oracle:** `test_unicode_round_trip_and_receiver_inspector`: exact text/digest/size+computed hash match. `test_replay_is_rejected`: opening same frame twice raises. Parameterized `test_tamper_fails_closed`: altered tag,ciphertext,AAD,sid,seq and independently validGCM with badsig/hash/size each error; no plaintext event or receive counter advance. `test_out_of_order_fails`
- [x] **Luna implementation:** Check session/type/next seq, AESGCM decrypt, strictparse/schema, recomputehash/size, Ed verify, thenadvance counter and produce inspector. Failed crypto timings labeled failure, never successful average; buffers not published before all checks
- [x] **Controller red/green:** `python -m pytest tests/unit/test_records.py tests/unit/test_records_protect.py tests/unit/test_record_finished.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** GUI publication or application receipts.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_framing.py tests/unit/test_messages.py tests/unit/test_crypto.py tests/unit/test_record_finished.py tests/unit/test_records_protect.py tests/unit/test_records.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: add bounded signed AES-GCM records`.

### C3: Mutual signed handshake and immutable pairing requests

#### C3a: Handshake transcript helpers

**Files:** Create `src/sparc/protocol/handshake_types.py`, `src/sparc/protocol/handshake_transcript.py`; test `tests/unit/test_handshake.py`

**Prerequisites:** C2.

**Interfaces:** Produce `PeerCandidate(public_key: bytes, fingerprint: str, endpoint: Endpoint)`, `EstablishedSession(codec: SessionCodec, peer: PeerCandidate, newly_approved: bool, transcript_hash: str)`; `make_hello(identity: Identity, kind: str) -> tuple[dict, X25519PrivateKey]`; `validate_hello(payload: dict, signed: bool) -> None`; `transcript(client: dict, server_unsigned: dict) -> bytes`; `approve_candidate(candidate: PeerCandidate, trust: TrustStore, approve: Callable[[PeerCandidate],bool]) -> bool`

- [x] **Fixed test oracle:** `test_transcript_exact_canonical_fields`, `test_roles_do_not_share_signature_domain`, `test_fresh_hello_random_and_ephemeral`, `test_changed_pin_never_prompts`: full schemas strict, keys/random each 32 bytes, peer fingerprint SHA256 of raw 32 public bytes; changed blocked before callback
- [x] **Luna implementation:** Immutable candidates; strip only server signature for T, strict hello and client auth schema; unknown callback after signature validation enforced by role units. Fresh X25519 keys plus secure 32-byte random values each call. `approve_candidate` returns whether newly approved, no writes
- [x] **Controller red/green:** `python -m pytest tests/unit/test_handshake.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** network choreography, persistent pins.

#### C3b: Initiator handshake sequence

**Files:** Create `src/sparc/protocol/handshake_initiator.py`; test `tests/unit/test_handshake_initiator.py`

**Shared-helper allowance:** C3b also modifies `handshake_transcript.py` only for `_check_deadline`, `_bounded_approval`, `_send_frame` and their imports. Its test file owns bounded approval, late-result, cancellation and partial-send checks. C3c consumes these helpers unchanged.

**Prerequisites:** C3a.

**Interfaces:** Produce `run_initiator(sock: socket.socket, identity: Identity, trust: TrustStore, approve: Callable[[PeerCandidate],bool], cancel: Event, limits: Limits, overall_deadline: float) -> EstablishedSession`; consume C2/C3a

- [x] **Fixed test oracle:** `test_initiator_validates_before_approval` fake protocol peer asserts a bad server signature never prompts; `test_initiator_rejects_changed_key`, `test_initiator_rejects_reflected_signature`, `test_finished_hash_matches_transcript`, `test_rejected_or_canceled_pairing_never_pins`
- [x] **Luna implementation:** Exact §4 connector steps CH→validated server hello→approved client auth→derived codec→verify responder finished→send initiator finished. Match transcript hash. Initial exchange deadline 20 seconds; responder-finished wait 150 seconds; local pairing 120 seconds; overall 300 seconds; cancel polling at most 1 second. No own pin writes
- [x] **Controller red/green:** `python -m pytest tests/unit/test_handshake_initiator.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** responder or service connected state.

#### C3c: Responder handshake sequence

**Files:** Create `src/sparc/protocol/handshake_responder.py`; test `tests/unit/test_handshake_responder.py`

**Prerequisites:** C3a.

**Interfaces:** Produce `run_responder(sock: socket.socket, identity: Identity, trust: TrustStore, approve: Callable[[PeerCandidate],bool], cancel: Event, limits: Limits, overall_deadline: float) -> EstablishedSession`

- [x] **Fixed test oracle:** `test_responder_rejects_stale_client_auth` signatures from other T fail before approval; `test_zero_exchange_is_rejected`; `test_client_finished_requires_correct_keys_and_hash`; `test_responder_timeout_and_cancel_no_pin`
- [x] **Luna implementation:** Exact CH→signed server hello→verified client auth→approval→derive→responder finished→verify initiator finished. Deadlines: initial 20, client-auth 150, local pairing 120, final finished 10 and overall 300 seconds; reject all-zero shared secrets. Callback receives immutable candidate
- [x] **Controller red/green:** `python -m pytest tests/unit/test_handshake_responder.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** initiator or trust store writes.

#### C3d: Public handshake dispatcher and socket integration

**Files:** Create `src/sparc/protocol/handshake.py`; test `tests/integration/test_handshake_sockets.py`

**Prerequisites:** C3b-C3c.

**Interfaces:** Produce preserved `perform_handshake(sock: socket.socket, role: Role, identity: Identity, trust: TrustStore, approve: Callable[[PeerCandidate],bool], cancel: Event, limits: Limits) -> EstablishedSession`; re-export C3a types

- [x] **Fixed test oracle:** `test_known_and_unknown_real_socket_handshakes`: role workers socket pair, matching sid/hash and separate directional keys, unknown each callback, known none. `test_hello_field_tampering_fails`, `test_all_failure_paths_leave_no_pins`, `test_reconnect_uses_fresh_session`
- [x] **Luna implementation:** Dispatcher computes monotonic overall deadline once then role function; no fallback or algorithm negotiation. Handle cancel/error clearly; no service events or trust commit
- [x] **Controller red/green:** `python -m pytest tests/unit/test_handshake.py tests/unit/test_handshake_initiator.py tests/unit/test_handshake_responder.py tests/integration/test_handshake_sockets.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** service or gui integration.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_handshake.py tests/unit/test_handshake_initiator.py tests/unit/test_handshake_responder.py tests/integration/test_handshake_sockets.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: authenticate peer handshakes and pairing`.

### C4: Durable signed hash-chain audit and checkpoint verification

#### C4a: Audit schemas, hashes and peer evidence

**Files:** Create `src/sparc/audit_format.py`; test `tests/unit/test_audit_format.py`

**Prerequisites:** C2.

**Interfaces:** Produce `build_audit_record(identity: Identity, body: dict) -> dict`; `verify_audit_record(record: dict, public_key: bytes, expected_previous: str, expected_number: int, expected_log_id: str) -> None`; `verify_peer_evidence(metadata: dict) -> None`; `AuditAppend(record: dict, elapsed_ns: int, encoded_bytes: int)` and `AuditReport(valid: bool, verified_records: int, first_failed_record: int | None, reason: str, checkpoint_checked: bool, elapsed_ns: int)`

- [x] **Fixed test oracle:** `test_exact_audit_hash_signature_domains`: SHA256 audit domain+canonical body, Ed signature audit-signature domain+hash bytes. `test_peer_evidence_reconstructs_context`: independent C2 signature verifies, edited projection fails. `test_plaintext_or_secret_metadata_rejected`
- [x] **Luna implementation:** Exact body/outer fields from spec§5 audit; record 1 starts with previous_hash of 64 zero characters; reject unknown secret/plaintext fields in bounded metadata. Allowed metadata retains public key,sid,direction,sequence,canonical projection,sig; no text. Use the fixed metadata allowlist above; missing or contradictory event data is BLOCKED_CONTRACT, not an invitation to invent fields
- [x] **Controller red/green:** `python -m pytest tests/unit/test_audit_format.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** disk I/O or checkpoints.

#### C4b: Existing chain verification

**Files:** Create `src/sparc/audit.py`; test `tests/unit/test_audit_verify.py`

**Prerequisites:** C4a.

**Interfaces:** Produce `verify_log(path: Path, public_key: bytes, checkpoint: Path | None = None) -> AuditReport`; checkpoint validation implemented here against C4a fixed schema/domain

- [x] **Fixed test oracle:** `test_intact_chain_and_first_failure`: exact verified count, modified body/link/hash/sig/owner/logid/number fails at correct index. `test_truncated_final_line_rejected`. `test_missing_log_with_checkpoint_fails`. `test_chain_only_cannot_assert_tail_absence`
- [x] **Luna implementation:** Stream line by line validated canonical records against trusted own key, report elapsed nanoseconds and honest chain-only reason. Validate the retained checkpoint signature, log ID, local identity, record number and corresponding hash. Checkpoint-relative tail removal, owner/hash mismatch or missing expected log fails. No truncate/repair/replacement. Treat retained checkpoint request without log as failure
- [x] **Controller red/green:** `python -m pytest tests/unit/test_audit_verify.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** append or checkpoint export.

#### C4c: Durable append and startup fail closed

**Files:** Modify `src/sparc/audit.py`; test `tests/unit/test_audit.py`

**Prerequisites:** C4b,C1c.

**Interfaces:** Produce `AuditLog(data_dir: Path, identity: Identity).append(kind: str, metadata: dict) -> AuditAppend`

- [x] **Fixed test oracle:** `test_append_flushes_and_fsyncs_before_return`: injected fsync failure raises, no success. `test_corrupt_startup_preserves_bytes`:an existing bad log blocks append. `test_log_contains_no_plaintext_or_private_keys`: known plaintext/private-key specimens are absent. `test_append_measurement_not_stored_fields`: outer keys body/hash/sig only, elapsed and encoded bytes return values
- [x] **Luna implementation:** Verify log/last signed checkpoint before append; create fresh log id only when absent without retained checkpoint. One append lock serializes head/record number durable flush fsync. Any failure blocks log and fails closed; no automatic repair. Return measurement spans without altering stored schema
- [x] **Controller red/green:** `python -m pytest tests/unit/test_audit.py tests/unit/test_audit_verify.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** receipt or gui logic.

#### C4d: Signed checkpoints and rollback proof

**Files:** Modify `src/sparc/audit.py`; test `tests/unit/test_audit_checkpoint.py`

**Publication allowance:** C4d may extend `storage.atomic_write` with keyword-only `secure_parent=True` and add focused storage-mode tests. Retained stores keep defaults; external selected copies use `secure_parent=False` to preserve existing parent permissions while keeping private files at 0600. Reject checkpoint destinations resolving to the live audit, identity or trust files before publishing either copy. Later CSV/SQLite/PDML exports preserve selected directory permissions too.

**Prerequisites:** C4c.

**Interfaces:** Produce `.export_checkpoint(path: Path) -> None`; consume C4b completed checkpoint validation

- [x] **Fixed test oracle:** `test_tail_removal_fails_against_checkpoint`: append two records/export independently/remove last→invalid. `test_checkpoint_signature_owner_or_log_id_mismatch_fails`; `test_checkpoint_with_missing_log_fails`; `test_unanchored_tail_removal_is_chain_only`
- [x] **Luna implementation:** Use C4a fixed checkpoint schema/domain; signing and export are the only new behavior. Atomically retain latest checkpoint and export selected copy. Never claim complete absence/deletion detection from an unanchored chain
- [x] **Controller red/green:** `python -m pytest tests/unit/test_audit_checkpoint.py tests/unit/test_audit.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** automatic remote checkpoint service.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_audit_format.py tests/unit/test_audit_verify.py tests/unit/test_audit.py tests/unit/test_audit_checkpoint.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: add verifiable durable audit logs`.

### C5: Peer service, serialized messaging and accountable acknowledgments

#### C5a: Active-session writer and lifecycle skeleton

**Files:** Create `src/sparc/peer/session.py`; test `tests/unit/test_session_writer.py`

**Prerequisites:** C3,C4.

**Interfaces:** Produce the fixed `SessionHooks` and `ActiveSession` APIs above. `start` launches writer first; reader implementation arrives in C5f. Writer consumes payload queues and C2 codec

- [x] **Fixed test oracle:** `test_one_writer_serializes_sequences_and_bytes`: concurrent enqueues produce unique sequential counters and complete frames without interleaving. `test_control_queue_has_priority`: queued control is written before ordinary queued payload. `test_write_failure_discards_session`: failure cancels worker and invokes on_closed once, never retries same sequence
- [x] **Luna implementation:** Implement fixed queue ownership/cancellation from integration decisions. Started session has a finite join/close and writer only. Writes occur after caller-owned audit work. No state lock held across queue waits or socket I/O
- [x] **Controller red/green:** `python -m pytest tests/unit/test_session_writer.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** reader, public service, reconnect or thresholds.

#### C5b: Bounded pending messages and receipt ledger

**Files:** Create `src/sparc/peer/receipts.py`; test `tests/unit/test_receipts.py`

**Prerequisites:** C1a.

**Interfaces:** Produce `PendingMessage(message_id: str, sha256: str, started_ns: int, plaintext_bytes: int, characters: int, frame_bytes: int)`; `ReceiptLedger(limit: int = 100).reserve(pending: PendingMessage) -> None`, `.validate_ack(message_id: str, digest: str) -> PendingMessage`, `.confirm(message_id: str, digest: str, finished_ns: int) -> DeliveryReceipt`, `.wait(message_id: str, timeout: float, cancel: Event | None) -> DeliveryReceipt`, `.fail_one(message_id: str, reason: str) -> None`, `.fail_all(reason: str) -> None`, `.expire(now_ns: int) -> list[str]`, `.update_frame_bytes(message_id: str, frame_bytes: int) -> None`

- [x] **Fixed test oracle:** `test_pending_101_is_busy`: pending cap 100. `test_receipt_must_match_id_and_digest`: wrong ack cannot confirm. `test_timeout_or_disconnect_is_unconfirmed`: expiry 10 seconds and canceled wait never return receipt. `test_completed_cache_is_bounded`: retain at most 100, explicit unavailable error for evicted ID. `test_fail_one_preserves_other_pending_messages`: one failed enqueue invalidates only its ID. `test_validate_ack_does_not_notify_success`: validation returns matching pending metadata without releasing a receipt waiter
- [x] **Luna implementation:** Fixed receipt lock/condition, no service-lock acquisition. Reserve before enqueue; confirm only authenticated validated ack passed from C5f. Exact supplied start/finish durations. Frame-byte update before write prevents fast ack race
- [x] **Controller red/green:** `python -m pytest tests/unit/test_receipts.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** signatures, socket I/O, resend.

#### C5c: Service initialization and listener slot

**Files:** Create `src/sparc/peer/service.py`; test `tests/integration/test_service_listener.py`

**Prerequisites:** C4,C5a-C5b.

**Interfaces:** Produce `PeerService(data_dir: Path, limits: Limits = Limits())`, `.events: Queue[ServiceEvent]`, thread-safe `.state: str`, `.start_listener(bind_ip: str, port: int) -> Endpoint`, `.stop_listener() -> None`, initial `.close() -> None` that cancels queue waits and closes the listener; `.own_fingerprint: str`, `.trusted_peers() -> list[dict]` returning fingerprint/label/endpoint public records; internal `_emit(event: ServiceEvent) -> None`. Later methods added by owning tasks

- [x] **Fixed test oracle:** `test_listener_reports_actual_port_and_stop`: internal port 0 returns actual socket address, stop releases it. `test_second_connection_is_busy_before_handshake`: one slot only. `test_event_queue_cancel_wakes_producer`: maximum 1,024, close cancellation wakes blocked producer. `test_bad_startup_audit_blocks_service`
- [x] **Luna implementation:** Load identity/trust/audit once; listener and session states separate. Allowed states from spec §7. Reserve one occupied handshake/session slot under state lock; accept loop rejects additional sockets before crypto. Publish endpoint/status as events, no private keys
- [x] **Controller red/green:** `python -m pytest tests/integration/test_service_listener.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** handshake coordinator, send/receive, automatic retries.

#### C5d: Connecting, immutable approval and authenticated adoption

**Files:** Modify `src/sparc/peer/service.py`; create `src/sparc/peer/pairing.py`; test `tests/integration/test_service_pairing.py`

**Prerequisites:** C5c,C3.

**Interfaces:** Produce `.connect(endpoint: Endpoint) -> None`, `.respond_to_pairing(request_id: str, approved: bool) -> None`; `PairingRequests.ask(candidate: PeerCandidate, own_fingerprint: str, generation: int, cancel: Event, timeout: float) -> bool`, `.respond(request_id: str, approved: bool, generation: int) -> None`, `.cancel_all() -> None`

- [x] **Fixed test oracle:** `test_stale_pairing_response_cannot_approve_new_session`: cancel A, start B, response A leaves B pending. `test_both_unknown_peers_approve_exact_fingerprints`: snapshots immutable. `test_failed_handshake_or_audit_never_connects`: no trust pin/connected state. `test_known_peer_skips_prompt_and_changed_peer_blocks`
- [x] **Luna implementation:** Run C3 in coordinator worker; pairing events use fresh request IDs and generation snapshots. After successful handshake durably audit pairing/session outcomes, then pin newly approved key, append signed trust_changed for the actual pin, then adopt session and publish connected. A failed audit or pin write closes socket; no active session until all succeed
- [x] **Controller red/green:** `python -m pytest tests/integration/test_service_pairing.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** GUI prompts, messaging, reconnect.

#### C5e: Outbound text reservation and accountable attempts

**Files:** Modify `src/sparc/peer/service.py`, `src/sparc/peer/session.py`; test `tests/unit/test_service_send.py`

**Prerequisites:** C5d,C5b,C2.

**Interfaces:** Produce `.send_text(text: str, *, run_id: str | None = None) -> str`, `.wait_for_receipt(message_id: str, timeout: float = 10, cancel: Event | None = None) -> DeliveryReceipt`; writer invokes this optional hook when present, supplying protected frame inspection via added `SessionHooks.on_written: Callable[[dict, ProtectedRecord], None] | None = None` before sendall

- [x] **Fixed test oracle:** `test_send_requires_connected`: invalid states fail. `test_send_attempt_audited_before_enqueue`: fsync failure causes no wire payload. `test_timer_starts_before_hash`: controlled clock call order proves start precedes prepare_text. `test_pending_reserved_before_fast_ack`: no race. `test_frame_bytes_are_actual_encoded_bytes`
- [x] **Luna implementation:** Fresh message ID, start ns before hash, validated prepare_text, pending reservation, durable send attempt audit, enqueue. On writer protection record actual full frame bytes before socket write, then emitted public inspection. Bound outbound benchmark totals 1,000/16MiB per connection. Failed enqueue calls ledger.fail_one(message_id, reason) and surfaces the error
- [x] **Controller red/green:** `python -m pytest tests/unit/test_service_send.py tests/unit/test_receipts.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** receiver, heartbeat, automatic text resend.

#### C5f: Verified receive dispatch and durable receipts

**Files:** Modify `src/sparc/peer/session.py`, `src/sparc/peer/service.py`; test `tests/integration/test_peer_service.py`; create `tests/integration/conftest.py`

**Prerequisites:** C5e,C4.

**Interfaces:** Complete reader worker; private owner-aware service `_handle_payload(attempt, session, established, record: OpenedRecord) -> None`. Fixture `peer_pair` yields alice/bob services/endpoints with explicit expected-fingerprint approvals; helper `wait_event(service, kind, message_id=None)` has finite waits

- [x] **Fixed test oracle:** `test_bidirectional_unicode_delivery_is_audited`: both directions text/hash exact, matching signed receipts and valid logs. `test_failed_receive_audit_prevents_ack_and_display`: no ack/no message event before durable append. `test_ack_is_not_recursively_acknowledged`, `test_bad_record_closes_without_plaintext_event`, `test_benchmark_cap_rejects_excess`:1000 records/16MiB per connection, aggregate progress instead of chat bubbles
- [x] **Luna implementation:** Reader alone opens bounded frames; dispatch chat/benchmark→durable verified receipt audit→ack control enqueue→validated message/progress event. Ack→ledger.validate_ack without notification→durable verified delivery audit→ledger.confirm and waiter notification→confirmation event. Ack storage failure invalidates session/receipt; no successful accountability claim. Retain peer-signed metadata evidence. Reject wrong signatures/hash/tag/schema/replay and close
- [x] **Controller red/green:** `python -m pytest tests/integration/test_peer_service.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** availability policy or GUI.

#### C5g: Shutdown, loss and operation events

**Files:** Modify `src/sparc/peer/service.py`, `src/sparc/peer/session.py`; test `tests/integration/test_service_shutdown.py`

**Prerequisites:** C5f.

**Interfaces:** Produce `.disconnect() -> None`, `.close() -> None`; emit established `operation_metrics` event schema; all previously public methods remain stable

- [x] **Fixed test oracle:** `test_disconnect_during_pairing_cancels_workers`, `test_close_unblocks_io_and_queues`, `test_delivery_timeout_is_unconfirmed`, `test_session_generation_discards_late_completion`: finite cleanup, no reused codec and no late connected state. `test_operation_events_have_units_success_and_public_context`: handshake and audit spans recorded, approval inclusion explicitly labeled
- [x] **Luna implementation:** Fixed cancellation order from integration decisions: signal/wake/close before bounded joins; mark all pending unconfirmed, retain listener on eligible session loss, disable it on stop/close. Closure audit errors surfaced without infinite retry. Include actual audit encoded bytes and elapsed time, handshake span, no keys. Do not implement reconnect here
- [x] **Controller red/green:** `python -m pytest tests/integration/test_service_shutdown.py tests/integration/test_peer_service.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** rate policies or GUI close handling.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_session_writer.py tests/unit/test_receipts.py tests/unit/test_service_send.py tests/integration/test_service_listener.py tests/integration/test_service_pairing.py tests/integration/test_peer_service.py tests/integration/test_service_shutdown.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: add accountable peer messaging service`.

### C6: Rate limits, authenticated liveness and finite reconnect

C5 review amendments: C5c narrowly adds public TrustStore.snapshot and its trust tests; C5f adds backward-compatible OpenedRecord coordinates and the corresponding codec/model tests. Post-pin trust auditing records the actual authorized outcome before adoption; an already committed pin may remain after audit failure or cancellation, with no rollback or adoption. Terminal cleanup keeps ownership through audit work, and generation checks protect confirmation, expiry, and delayed send failures. Controller full suite: 404 passed; Sol scoped milestone review passed.

#### C6a: Connection rolling-window limiter

**Files:** Create `src/sparc/peer/policy.py`; test `tests/unit/test_connection_policy.py`

**Prerequisites:** C1a.

**Interfaces:** Produce `ConnectionLimiter(clock: Callable[[],float]).allow(ip: str) -> bool`

- [x] **Fixed test oracle:** `test_source_and_global_limits`: deny21st source/61st global in rolling60s. `test_source_buckets_never_exceed_256`: expired eviction, full unexpired table rejects new source. No fixed-minute rollover loophole
- [x] **Luna implementation:** Monotonic deque windows, at most256 source buckets, spec 20/source/minute 60/global/minute. Decisions deterministic under injected clock; no disk or sockets
- [x] **Controller red/green:** `python -m pytest tests/unit/test_connection_policy.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** record bucket, listener integration.

#### C6b: Record token bucket and sender/receiver integration

**Files:** Modify `src/sparc/peer/policy.py`, `src/sparc/peer/session.py`, `src/sparc/peer/service.py`; test `tests/unit/test_policy.py`, `tests/integration/test_record_pacing.py`

**Prerequisites:** C6a,C5.

**Interfaces:** Produce `RecordBucket(clock: Callable[[],float]).allow() -> bool`, `.wait(cancel: Event) -> bool`; wireC6a into listener and bucket into existing sole writer/reader

- [x] **Fixed test oracle:** `test_record_burst_401_is_denied`:200/s burst 400 and refill with injected time. `test_sender_paces_acks_controls_and_data`: normal benchmark remains within receiver limit. `test_flood_rejections_audited_at_most_every_five_seconds`: connection/record rejects aggregated, storage bounded
- [x] **Luna implementation:** Separate per-direction buckets. Writer waits cancel-aware before protection/send; reader counts authenticated app records then rejects excessive burst. Busy handling still before handshake. This bounded integration patch adds policies to existing workers, no new concurrency structure
- [x] **Controller red/green:** `python -m pytest tests/unit/test_policy.py tests/integration/test_record_pacing.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** heartbeat or retry.

#### C6c: Signed idle heartbeat and loss detection

**Files:** Create `src/sparc/peer/liveness.py`; modify `src/sparc/peer/session.py`, the maintenance callback in `src/sparc/peer/policy.py`, and the exact-owner metric callback in `src/sparc/peer/service.py`; test `tests/unit/test_liveness.py`, `tests/integration/test_heartbeat.py`

**Prerequisites:** C6b.

**Interfaces:** Produce `Liveness(clock: Callable[[],float]).sent() -> None`, `.received() -> None`, `.tick() -> tuple[dict | None, bool]`, `.accept_pong(ping_id: str) -> None`; tickreturns optional unsigned ping and lost flag

- [x] **Fixed test oracle:** `test_ping_after_five_seconds_and_loss_after_fifteen`: valid incoming refresh, signed pong matching ID, no recursive ack. `test_idle_healthy_session_survives` actual sockets with shortened injected limits; loss metric is last valid activity to declared loss
- [x] **Luna implementation:** Existing writer loop polls liveness no less often than1s; tick uses5s outgoing idle/15s valid incoming inactivity. Secure32hex ping IDs, bounded outstanding ping set; protocol projection signs ping/pong. Reader validates matching pong and updates valid activity. Audit liveness state changes only
- [x] **Controller red/green:** `python -m pytest tests/unit/test_liveness.py tests/integration/test_heartbeat.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** automatic reconnection.

#### C6d: Finite authenticated reconnect policy and coordinator

**Files:** Modify `src/sparc/peer/policy.py`, `src/sparc/peer/service.py`; test `tests/unit/test_reconnect_policy.py`, `tests/integration/test_availability.py`

**Prerequisites:** C6c,C5g.

**Interfaces:** Produce `ReconnectPolicy.delays(error_code: str, explicit_stop: bool) -> tuple[float,...]`; extend existing coordinator only

- [x] **Fixed test oracle:** `test_eligible_loss_delays_exactly_1_2_4`: only original initiator retries prior pinned endpoint/key, max3 attempts. `test_auth_changed_audit_or_stop_never_retries`. `test_reconnect_fresh_keys_and_no_resend`: actual sessionIDs differ, pending remains unconfirmed, no automatic duplicate text. `test_reconnect_cancel_wakes_wait`
- [x] **Luna implementation:** Eligible TCP loss/delivery timeout/inactivity only. Cancel-aware waits, fresh C3 full handshake each attempt; expected pinned fingerprint checked. No concurrent cross-connects. Emit elapsed recovery/attempt outcomes and actual policy settings; audit failure disables retries
- [x] **Controller red/green:** `python -m pytest tests/unit/test_reconnect_policy.py tests/integration/test_availability.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** new retry thresholds or automatic resend.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_connection_policy.py tests/unit/test_policy.py tests/unit/test_liveness.py tests/unit/test_reconnect_policy.py tests/integration/test_record_pacing.py tests/integration/test_heartbeat.py tests/integration/test_availability.py tests/integration/test_peer_service.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: bound peer load and recover authenticated sessions`.

### C7: Runnable Connection, Chat and Audit GUI

#### C7a: Main-thread app shell and reusable bounded jobs

**Files:** Create `src/sparc/gui/app.py`, `src/sparc/gui/jobs.py`; test `tests/gui/test_app.py`, `tests/unit/test_jobs.py`

**Prerequisites:** C5g.

**Interfaces:** Produce `SparcApp(root: Tk, service: PeerService)` with `.notebook`, `.add_tab(title: str, widget: ttk.Frame) -> None`, `.handle_event(event: ServiceEvent) -> None`, `.close() -> None`; `JobController(root: Tk, on_result: Callable[[str,object],None]).start(work: Callable[[Event,Callable[[str,object],None]],object]) -> None`, `.cancel() -> None`, `.close() -> None`

- [x] **Fixed test oracle:** `test_close_ignores_late_worker_events`: no destroyed-widget access or new callbacks. `test_jobs_one_active_and_queue_bound_64`: reject concurrent start, bounded cancel-aware result puts; close wakes worker. `test_event_dispatch_stays_on_tk_thread`
- [x] **Luna implementation:** Main-thread after polling only, app tab.handle_event forwarding and tab.close before service/root teardown, idempotent close. Jobs use result queue64, one thread, per-run generation, reject stale results; no worker widget calls. Polling100ms, joins2s after cancellation; Sol reviews any worker that cannot meet finite cancellation
- [x] **Controller red/green:** C7 gate `540 passed` in 95.55s without warnings; C7 review re-run and GUI layout/interaction evidence recorded below.

**Exclusions:** tab contents or cryptography.

#### C7b: Connection tab and pairing snapshot

**Files:** Create `src/sparc/gui/connection.py`; modify `src/sparc/peer/service.py`; test `tests/gui/test_connection_view.py`

**Prerequisites:** C7a,C5d.

**Interfaces:** Produce `ConnectionTab(parent: ttk.Notebook, service: PeerService).handle_event(event: ServiceEvent) -> None`, `.close() -> None`; consume publicservice and psutil.net_if_addrs; `connected_peer() -> dict | None` supplies a copied current authenticated fingerprint and Endpoint, without identity inference from remembered IPs

- [x] **Fixed test oracle:** `test_listening_port_is_not_configured_port_until_started`: active status separate. `test_interfaces_have_labels_and_copyable_endpoints`: full IP/port, hostname, allinterface0.0.0.0 label. `test_pairing_shows_immutable_own_and_peer_fingerprints`: correctrequestID approve/reject, changedblocked. `test_literal_ipv4_and_port_validation`:1-65535, no silent configuration override. `test_forget_peer_requires_explicit_action_and_audit`: audit failure preserves pin; active peer forgetting is refused
- [x] **Luna implementation:** BindIP default0.0.0.0 port47655, editable reachablepeerIPv4/port; Start/Stop/Connect/Disconnect and explicit Forget control. Use immutable ServiceEvent pairing snapshots and fingerprint Copy; invalidate approval on every non-approval state. Display the connected identity from `connected_peer()`, never infer it from IP. Add fixed service `.forget_peer(fingerprint: str) -> None` wrapper; an idle-only private reservation excludes concurrent networking, and existing `trust_changed` records capture `forget_requested` before TrustStore.forget and `forgotten` after success. Refuse occupied sessions/handshakes/retries or listener startup; never hold the state lock across storage. Audit failures remain sticky, with no rollback claim after removal
- [x] **Controller red/green:** C7 gate `540 passed` in 95.55s without warnings; focused layout checks: 3 passed in 0.79s.

**Exclusions:** GUI socket access or trust-any.

#### C7c: Chat history and security inspector

**Files:** Create `src/sparc/gui/chat.py`; test `tests/gui/test_chat_view.py`

**Prerequisites:** C7a,C5f.

**Interfaces:** Produce `ChatTab(parent: ttk.Notebook, service: PeerService).handle_event(event: ServiceEvent) -> None`, `.close() -> None`

- [x] **Fixed test oracle:** `test_send_disabled_until_connected`, `test_unicode_and_line_breaks_preserved`, `test_history_evicts_after_500`: memory count500 with notice. `test_inspector_shows_hash_match_signature_ciphertext_and_microseconds`: publicnonce/tag/b64ct/sig,size, sender/receiverdigests, no keyfields. `test_pending_verified_unconfirmed_states`
- [x] **Luna implementation:** Multiline input explicitSend, errors from prepare/send surfaced. Display only validated incomingevents, original/recoveredtext in-memory inspector. Classify using local message origin, index by origin plus message ID, and reconcile early writer/delivery events with the returned send ID without duplication or downgrading verified status. Evict associated detail objects alongside history. No text persistence; aggregate benchmarkprogress does not become chat bubbles
- [x] **Controller red/green:** C7 gate `540 passed` in 95.55s without warnings; Chat inspector reachability covered by focused layout and interaction evidence.

**Exclusions:** analysis or audit tab.

#### C7d: Audit verification and checkpoint view

**Files:** Create `src/sparc/gui/audit_view.py`; modify `src/sparc/peer/service.py`; test `tests/gui/test_audit_view.py`

**Prerequisites:** C7a,C4.

**Interfaces:** Produce `AuditTab(parent: ttk.Notebook, service: PeerService).handle_event(event: ServiceEvent) -> None`, `.close() -> None`; add service `verify_audit(checkpoint: Path | None = None) -> AuditReport`, `export_audit_checkpoint(path: Path) -> None` wrappers without exposing identity keys

- [x] **Fixed test oracle:** `test_audit_view_reports_first_failure_and_checkpoint_status`: validcount/head/reason visible. `test_verify_runs_off_tk_thread_and_close_cancels`: JobController and late-result rejection. `test_audit_timings_and_bytes_are_separate_metrics`
- [x] **Luna implementation:** Worker-backed verify/export using publicwrappers and file dialogs. Display available-chain-only vs independently anchoredstatus; show verification records/s, appendelapsedns→us, bytes/event. Checkpoint choice explicit
- [x] **Controller red/green:** C7 gate `540 passed` in 95.55s without warnings; audit snapshot scope and minimum-window reachability verified.

**Exclusions:** automatic audit repair or raw private identity access.

#### C7e: GUI entry point and platform setup

**Files:** Modify `src/sparc/gui/app.py`, `src/sparc/__main__.py`; create `docs/setup.md`; test `tests/integration/test_gui_cli.py`

**Prerequisites:** C7b-C7d.

**Interfaces:** Normal `python -m sparc [--data-dir PATH]` creates root/service and threecoretabs; --check remains lazy and GUI-free

- [x] **Fixed test oracle:** `test_default_launch_wires_three_core_tabs` patched launch asserts the core names Connection/Chat/Audit are present (additional registered tabs are allowed). `test_missing_tk_is_actionable`: clear dependency error, not opaque traceback. `test_check_remains_usable_without_tk_or_tshark`
- [x] **Luna implementation:** Wire normallaunch and close. Document Windows/Linux venv/pinnedpackages, Tk install, literalLANIP, firewall chosenport, clientisolation and two instancesdistinctdata directories. Controller visuallychecks resizing, pairing, Unicode/newlines, listenerstatus/error, close duringwork with appropriate GUI permission
- [x] **Controller red/green:** C7 gate `540 passed` in 95.55s without warnings. Single-process localhost GUI smoke covered bidirectional Unicode/newline messages, audit operations, resizing, and close during work.

**Exclusions:** analysis/traffic tabs until owning plans.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_jobs.py tests/integration/test_gui_cli.py tests/gui -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: add Tkinter connection chat and audit views`.

**C7 verification record:** Sol's C7 re-review passed. Controller reports 540 tests passed in 95.55s without warnings and 3 focused layout tests passed in 0.79s. Direct-window captures confirmed Approve/Reject at 800×640, audit actions and wrapped head, and Chat security details through its scrollbar. This was a single-process localhost GUI smoke, not independent-process or physical-device evidence; Windows behavior remains unverified. C7 commit reference: pending C7 commit.

### C8: Two-process simulation, plaintext baseline and evidence guide

#### C8a: Independent-process secure simulation

**Files:** Create `scripts/simulate_peers.py`; test `tests/integration/test_simulation.py`

**Prerequisites:** C6,C7.

**Interfaces:** Produce `run_simulation(data_root: Path, port_a: int = 0, port_b: int = 0, text: str = "SPARC ✓") -> dict`; CLI --data-root/--report

- [ ] **Fixed test oracle:** `test_simulation_is_two_processes_and_two_identities`: differentPIDs/fingerprints/data dirs, actualTCP bothdirections, matchinghashes/receipts and validlogs; reportevidence_mode simulation. `test_child_failure_is_incomplete_and_cleanup_finite`
- [ ] **Luna implementation:** multiprocessing spawn, knownfingerprints obtained bylabcoordinator andexplicitcomparison beforeapprove. No production trust bypass. Boundcoordinator/childwaits and cleanup. Report genuine elapsed durations/failures, never inventsuccess
- [ ] **Controller red/green:** `python -m pytest tests/integration/test_simulation.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** physical-device verification or packet capture.

#### C8b: Separate plaintext comparison baseline

**Files:** Create `scripts/plaintext_baseline.py`; test `tests/integration/test_plaintext_baseline.py`

**Prerequisites:** C2a.

**Interfaces:** Produce standalone lab CLI `python scripts/plaintext_baseline.py listen --ip IP --port 47656` and `send --ip IP --port 47656 --text TEXT`; no import into secure runtime

- [ ] **Fixed test oracle:** `test_baseline_wire_contains_synthetic_text`: realTCP receiver reads distinctiveUTF8plaintext. `test_baseline_is_not_secure_runtime_toggle`: secure CLI has no baselineorplaintextfallback flag. InvalidIP/port/textbounded; finitecancel/exit
- [ ] **Luna implementation:** Independent sender/receiver for syntheticdata on47656, clear lab-only labels, boundedread/write and cleanexit. Reuse parameter validation only; no production session switching
- [ ] **Controller red/green:** `python -m pytest tests/integration/test_plaintext_baseline.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** ARP interception or Wireshark capture privileges.

#### C8c: Evidence instructions and security/efficiency mapping

**Files:** Create `docs/progress-check-demo.md`, `docs/progress-check-evidence.md`; modify `README.md`; no new test file for reversible documentation

**Prerequisites:** C8a-C8b.

**Interfaces:** Produce checklist and report outline mapping all13acceptance criteria and5goals to specificartifacts; no applicationAPI

- [ ] **Fixed test oracle:** Controller document review: verify all five named security goals and all 13 acceptance criteria map to concrete artifacts, secure 47655/baseline 47656 capture/display filters and Follow TCP Stream; simulation and physical-device evidence have separate labels. No redundant documentation-mirroring test
- [ ] **Luna implementation:** Write command recipes, separately retainedcheckpoint/tamper examples, boundedconnection/recordflood tests, abruptloss/restart, expectedpublicobservations and measuredresource/goodput/detection/recoveryfields. LaterA3/T3 addtheir artifacts. Mark actualphysicalWindows/Linuxrun unverified untilperformed; no secretkeys inbundles
- [ ] **Controller documentation/regression check:** `python -m pytest tests/integration/test_simulation.py tests/integration/test_plaintext_baseline.py -q`; existing runtime assertions PASS, plus the stated content/link/acceptance checklist. No forced red failure for this documentation-only unit.

**Exclusions:** fabricated screenshots/captures/performance.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/integration tests/unit -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `test: add two-peer demonstration and security evidence guide`.

## Completion boundary

Core acceptance covers encrypted text and three GUI tabs. Analysis and Traffic Analysis are added by linked plans. Controller records real test/visual/simulation evidence; Sol reviews security integration before release. No simulated test is a claim of physical Windows-to-Linux validation.
