# SPARC Offline Traffic Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Analyze externally saved captures and publish validated XML, SQLite and traffic summaries without blocking chat.

**Architecture:** A lazy PyShark adapter streams normalized rows into a transactional SQLite index; summaries query that index. A structured TShark subprocess writes PDML. Both publish temporary outputs only after success; CLI and background GUI jobs share these APIs.

**Tech Stack:** Python 3.10+, PyShark 0.6, external TShark/Wireshark, sqlite3, Decimal, Tkinter/ttk, pytest.

**Spec:** [Approved specification, section 8 and acceptance criteria 10-13](../specs/2026-10-08-sparc-progress-check-design.md).

## Global Constraints

Inherit the [master plan](2026-10-08-sparc-progress-check-plan.md), including conditional commits. External Wireshark saves captures; no privileged live capture in SPARC. Stream with `keep_packets=False`; preserve originals and SHA-256 source digest. Missing fields are SQL NULL. No shell, no input overwrite; atomic outputs. Captured-byte rate is distinct from plaintext goodput and unavailable with fewer than two packets or a nonpositive interval.

## Review Focus

Master item 5 receives missing-layer and zero/nonpositive-duration tests in T1/T2. Also test missing tools, malformed captures, source/output aliasing, cancellation, subprocess cleanup, and late results after GUI close.

---

## File structure and result types

Create `src/sparc/traffic/{__init__,__main__,models,capture,sqlite_index,summary,pdml}.py`, `src/sparc/gui/traffic_view.py`, and synthetic capture fixtures/generator. T1/T2 depend on C1 package setup; T3 consumes C7's tab lifecycle.

`traffic/models.py` owns:

- `PacketRow(number: int, timestamp: str, captured_length: int, wire_length: int, highest_protocol: str, src: str | None, dst: str | None, src_port: int | None, dst_port: int | None, tcp_stream: int | None, tcp_flags: str | None, retransmission: bool | None)`.
- `ConversionResult(complete: bool, packet_count: int, elapsed_ns: int, source_bytes: int, output_bytes: int, packets_s: float | None, versions: dict, metadata: dict)`.
- `TrafficReport(metadata: dict, packet_count: int, captured_bytes: int, duration_s: Decimal | None, captured_bytes_s: Decimal | None, protocol_counts: dict[str, int], directional_bytes: list[dict], tcp_conversations: list[dict], packet_size_distribution: dict, retransmission_indications: int, conversion: ConversionResult)`.

Display at most top 100 directional pairs/conversations and record truncation; complete data stays in SQLite. Size bins: 0-63, 64-127, 128-511, 512-1023, 1024-1518, 1519+ captured bytes. Metadata records source name/hash, filter, parser versions, evidence type, completion and definitions. Timestamps remain exact source text; rate arithmetic uses Decimal.

## Execution workflow

Use the [master plan's authoritative ownership, small-task cycle, dispatch, history and environment rules](2026-10-08-sparc-progress-check-plan.md#model-ownership-and-small-task-workflow). Reuse a task-local Luna worker for related units and red/green phases; the controller verifies each phase separately and runs the milestone gate below. Unit interfaces, allowed files, assertions and exclusions remain binding. Documentation changes use content/link checklists without documentation-mirroring tests. Commands use the master virtual environment; GUI checks require a display and unavailable checks stay explicit.

### T1: Lazy tool discovery and bounded capture streaming

#### T1a: Normalized packet records

**Files:** Create `src/sparc/traffic/models.py`, `src/sparc/traffic/capture.py`; test `tests/unit/test_capture_normalization.py`

**Prerequisites:** C1.

**Interfaces:** Produce shared TrafficReport/ConversionResult/PacketRow types above; `normalize_packet(packet) -> PacketRow`

- [ ] **Fixed test oracle:** `test_missing_layers_normalize_to_none`: frame-only packet preserves exact timestamp text, all unavailable IP/port/stream/flags/retransmission fields None. `test_ipv4_ipv6_tcp_udp_fields`: actual strings/integers correct. `test_invalid_frame_lengths_rejected`: negative/bool/invalid numeric values domain errors
- [ ] **Luna implementation:** Typed extraction from PyShark packet-shaped input without importing PyShark at module import. No TCP fields assumed on ARP/UDP; absent retransmission indicator None, present marker True. Do not infer end-to-end loss from missing packets
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_capture_normalization.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** TShark startup or storing packet objects.

#### T1b: Explicit tool discovery and actionable errors

**Files:** Modify `src/sparc/traffic/capture.py`; test `tests/unit/test_tshark_discovery.py`

**Prerequisites:** T1a.

**Interfaces:** Produce `find_tshark(explicit: Path | None = None) -> Path`; explicit verified executable wins over PATH

- [ ] **Fixed test oracle:** `test_explicit_path_before_path_search`: spaces/metacharacters retained as path, no shell. `test_missing_tshark_is_actionable`: categorized error naming standalone dependency. `test_chat_import_does_not_import_pyshark`: fresh subprocess --check works with missing PyShark/TShark
- [ ] **Luna implementation:** Use shutil.which for PATH and executable existence check for explicit path, Windows extension support. Lazy optional imports only in iteration. Report missing PyShark separately from missing TShark, ordinary chat usable
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_tshark_discovery.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** installing OS tools or launching capture.

#### T1c: Cancelable lazy capture iterator

**Files:** Modify `src/sparc/traffic/capture.py`; test `tests/unit/test_capture_adapter.py`

**Prerequisites:** T1b.

**Interfaces:** Produce `iter_capture(path: Path, tshark: Path, cancel: Event, display_filter: str | None = None) -> Iterator[PacketRow]`

- [ ] **Fixed test oracle:** `test_stream_closes_capture_after_cancel_or_parse_error`: constructor keep_packets False, cleanup once, no retained list. `test_stream_filter_and_no_resolution_arguments`: display filter/explicit tool path passed as structured values, -n enabled. `test_missing_python_dependency_is_domain_error`
- [ ] **Luna implementation:** The adapter owns one producer thread in addition to the calling job worker. Producer creates and sets its own event loop (`asyncio.ProactorEventLoop()` on Windows; `asyncio.new_event_loop()` elsewhere), passes it explicitly as `FileCapture(eventloop=loop, keep_packets=False, tshark_path=..., display_filter=...)`, and runs public `packets_from_tshark(callback)` on that loop. The supported synchronous callback normalizes one packet and puts one row into a bounded `Queue[PacketRow | SparcError | None]` of 128 entries. On a full queue, use bounded `queue.put(..., timeout=0.1)` attempts and check BOTH caller cancellation and the private adapter-stop event before every attempt and after every Full exception. Either flag raises PyShark v0.6's supported `pyshark.capture.capture.StopCapture`, unwinding the packet reader so its finally block can await capture cleanup. No packet object is retained. Do not supply an async callback: v0.6 invokes its callback synchronously and does not await it. Consumer generator waits on that queue with 100-ms timeouts, checks cancellation and yields rows. A concurrent producer-loop cancel watcher checks BOTH the caller cancel event and private adapter-stop event every 100 ms, cancels the async read task and awaits `close_async()` with a 2-second timeout; always closes capture, shuts down loop tasks and closes its owned loop in finally. On ordinary EOF producer emits None; on error it emits categorized error; error/cancel markers cannot block indefinitely on a full queue because consumer cancellation also signals producer and drains/abandons bounded data. Generator close signals the private adapter-stop event (does not set caller's shared event) and joins producer for up to 2 seconds. While the synchronous callback is waiting on a full queue, the async watcher cannot run; external event flags are therefore checked directly by that callback and unblock it within 100 ms. While the decoder awaits data with no callback active, the watcher performs cancellation. After the reader unwinds, flags are checked again so canceled/closed iteration cannot emit a completed EOF result. Explicit path arguments remain structured; default PyShark `-n` already disables name resolution. No private PyShark parser/process API is introduced. Add `test_worker_owns_and_closes_event_loop` and `test_cancel_while_decoder_has_no_packets` to assert explicit loop ownership and finite cancellation, including mocked Windows Proactor construction. Add `test_generator_close_unblocks_full_queue_without_caller_cancel`: fill the 128-row queue, leave caller cancel unset, signal generator close, and assert callback exits, capture/owned loop close and producer join finishes within the declared bound. Add `test_supported_callback_is_synchronous`: the supplied callback is a regular function, not an unawaited coroutine. These public APIs are verified against [PyShark v0.6 FileCapture source](https://github.com/KimiNewt/pyshark/blob/v0.6/src/pyshark/capture/file_capture.py) and [Capture source](https://github.com/KimiNewt/pyshark/blob/v0.6/src/pyshark/capture/capture.py).
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_capture_adapter.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** new dissector or privileged live capture.

#### T1d: Independent synthetic PCAP fixture and decoding checks

**Files:** Create `tests/fixtures/build_capture.py`, `tests/fixtures/README.md`, `tests/fixtures/traffic-small.pcap`, `tests/fixtures/traffic-small-manifest.json`; test `tests/integration/test_capture_stream.py`

**Prerequisites:** T1c.

**Interfaces:** Produce stdlib-only `build_fixture(destination: Path) -> dict` and fixed five-packet manifest; no production API

- [ ] **Fixed test oracle:** `test_fixture_decode_matches_manifest`: packet count 5, independent exact frame lengths/timestamps/IPs/ports; ARP fields None. `test_fixture_source_hash_matches_manifest`: SHA256 recorded source. Mark actual decoder tests tshark, skip only absent executable
- [ ] **Luna implementation:** Sol-fixed fixture: Ethernet PCAP little-endian microseconds; packets at 1/2/3/4/5 seconds. IPv4 TCP SYN 10.0.0.1:12345→10.0.0.2:47655 and reverse SYN-ACK, each 54 bytes; IPv4 UDP same hosts1111→2222 with payload ABCD, 46 bytes; Ethernet ARP request, 42 bytes; IPv6 UDP 2001:db8::1→::2 ports 3333→4444 payload ABCD, 66 bytes. Correct header lengths/checksums, no padding or user traffic. Expected captured/wire total 262 and capture file length 366 (24+5*16+262); protocol display labels are decoder observations, not hardcoded attack interpretations
- [ ] **Controller red/green:** `python -m pytest tests/integration/test_capture_stream.py -m tshark -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** mocked decoding as evidence of TShark functionality.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_capture_normalization.py tests/unit/test_tshark_discovery.py tests/unit/test_capture_adapter.py tests/integration/test_capture_stream.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: stream offline captures with lazy tool discovery`.

### T2: SQLite summaries and PDML publication

#### T2a: Transactional packet index import

**Files:** Create `src/sparc/traffic/sqlite_index.py`; test `tests/unit/test_sqlite_index.py`

**Prerequisites:** T1.

**Interfaces:** Produce `import_sqlite(source: Path, destination: Path, tshark: Path, cancel: Event, display_filter: str | None = None) -> TrafficReport`; private `_write_index(rows: Iterator[PacketRow], destination: Path, metadata: dict, cancel: Event) -> int` supplies tested staging; final report facade completed T2d

- [ ] **Fixed test oracle:** `test_sqlite_nulls_fields_indexes_and_parameters`: missing fields sql null, packet number/stream/timestamp indexes; quoted source/filter safe. `test_cancel_preserves_existing_output`: original/prior index unchanged, temporary files cleaned. `test_source_alias_is_rejected`: same path/symlink/hardlink rejected before output open. `test_streaming_batch_bound`: no packet collection, transaction batches of 500 rows
- [ ] **Luna implementation:** metadata(key text PRIMARY KEY,value text canonical JSON) and packets columns exact PacketRow types, number integer primarykey, timestamp text, remaining ints/text nullable. Capture original SHA256 streaming chunks of 64 KiB, source file size/tool versions/filter. Same-directory temporary DB, atomic replace only after complete commit+integrity check. Set completion true only successful final index; failed job reports incomplete progress and publishes nothing. Deferred report wrapper calls T2b after it exists; task tests use private writer and public error paths until then
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_sqlite_index.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** summary SQL, PDML or whole-capture materialization.

#### T2b: Bounded traffic summaries from indexed data

**Files:** Create `src/sparc/traffic/summary.py`; modify `src/sparc/traffic/sqlite_index.py`; test `tests/unit/test_traffic_summary.py`

**Prerequisites:** T2a.

**Interfaces:** Produce `summarize_database(database: Path) -> TrafficReport`; complete T2a public return report composition

- [ ] **Fixed test oracle:** `test_nonpositive_interval_has_no_rate`: one packet/equal/backward timestamps rate None. `test_captured_rate_uses_all_included_bytes`:180 bytes over 2 seconds → Decimal 90. `test_group_counts_direction_bytes_bins_and_retransmissions`: exact sql counts and six bins, top 100 outputs with metadata truncated label. `test_exact_timestamp_decimal_preserved`
- [ ] **Luna implementation:** Duration last-first included packet in capture order, all captured frame bytes numerator; Decimal exact arithmetic. SQL groups protocol counts,TCP stream conversations,directional bytes, six approved size bins: 0-63/64-127/128-511/512-1023/1024-1518/1519+. Retransmission indications count True only. Bounded presentation top 100, complete indexed data retained. Import conversion measurement includes duration/output size and rate None on nonpositive processing time
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_traffic_summary.py tests/unit/test_sqlite_index.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** plaintext goodput, end-to-end loss or one-way latency.

#### T2c: Structured subprocess PDML export

**Files:** Create `src/sparc/traffic/pdml.py`; test `tests/unit/test_traffic_exports.py`

**Prerequisites:** T1b.

**Interfaces:** Produce `export_xml(source: Path, destination: Path, tshark: Path, cancel: Event) -> ConversionResult`

- [ ] **Fixed test oracle:** `test_pdml_uses_argument_list_without_shell`: exact [tool,"-n","-r",source,"-T","pdml"], shell False. `test_cancel_or_tool_error_preserves_existing_output`: sources/prior outputs unchanged, finite cleanup. `test_xml_count_and_well_formedness_before_publish`: incremental parser correct count, invalid xml cannot publish. `test_source_alias_is_rejected`
- [ ] **Luna implementation:** Popen stdout tempfile, stderr tempfile with last 8 KiB read for error (bounded RAM), cancel poll every 100 ms, terminate, wait up to 2 seconds, then kill. Incremental XML iterparse counts packet and clears nodes, never load all xml. Unfiltered source pdml even if a SQLite filter is selected. SHA256/size/tool versions/count/elapsed/output size in result metadata; publish after success+parse only
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_traffic_exports.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** shell commands, decrypted SPARC content.

#### T2d: Analysis facade and real source/export agreement

**Files:** Modify `src/sparc/traffic/sqlite_index.py`; test `tests/integration/test_capture_exports.py`

**Prerequisites:** T2a-T2c.

**Interfaces:** Produce `analyze_capture(source: Path, tshark: Path, cancel: Event, display_filter: str | None = None) -> TrafficReport` using temporary index; public import_sqlite returns summary with conversion

- [ ] **Fixed test oracle:** `test_fixture_exports_agree_with_source`: five pdml packets/five DB rows and 262 captured bytes, known fields, ARP null, PRAGMA integrity_check ok, source hash unchanged. `test_analysis_temp_index_cleanup`: success/cancel/error all cleanup. `test_filtered_index_labels_filter_and_pdml_is_unfiltered`
- [ ] **Luna implementation:** One PyShark index pass supplies summary; analyze-only temporary DB cleaned in finally. Reuse exact source fixture independent manifest; real-tool tests marked tshark, skips unverified. Genuine pcapng repeat belongs actual evidence workflow, not fabricated fixture claim
- [ ] **Controller red/green:** `python -m pytest tests/integration/test_capture_exports.py -m tshark -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** new parsing path or packet-object retention.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_sqlite_index.py tests/unit/test_traffic_summary.py tests/unit/test_traffic_exports.py tests/integration/test_capture_exports.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: export validated packet indexes and PDML evidence`.

### T3: Offline CLI, fifth GUI tab and evidence workflow

#### T3a: Offline analysis/export CLI

**Files:** Create `src/sparc/traffic/__main__.py`; test `tests/integration/test_traffic_cli.py`

**Prerequisites:** T2.

**Interfaces:** Produce `main(argv: list[str] | None = None) -> int`; CLI `python -m sparc.traffic analyze CAPTURE --report REPORT.json [--sqlite INDEX.sqlite] [--xml DETAILS.xml] [--tshark PATH] [--display-filter FILTER]`

- [ ] **Fixed test oracle:** `test_missing_tool_exits_2`: actionable tshark message. `test_malformed_capture_exits_1`. `test_success_exits_0_and_report_matches_index`: count/source hash/definitions. `test_alias_or_duplicate_output_rejected_before_mutation`. `test_later_output_failure_reports_completed_artifacts_but_not_complete_bundle`
- [ ] **Luna implementation:** One sqlite import provides index+summary or temporary index for analysis-only; distinct pdml pass only if requested. JSON decimal exact strings; output alias validation covers source and duplicate output destinations before all work. Artifacts published independently, incomplete bundle honest; existing completed artifacts reported if later export fails
- [ ] **Controller red/green:** `python -m pytest tests/integration/test_traffic_cli.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** live capture, whole-subsystem rewrite or model-run shell.

#### T3b: Traffic Analysis tab using existing job controller

**Files:** Create `src/sparc/gui/traffic_view.py`; modify `src/sparc/gui/app.py`; test `tests/gui/test_traffic_view.py`

**Prerequisites:** C7,T3a.

**Interfaces:** Produce `TrafficTab(parent: ttk.Notebook, tshark_path: Path | None = None).close() -> None`; `register_traffic(app: SparcApp, tshark_path: Path | None = None) -> None`; consume C7 JobController

- [ ] **Fixed test oracle:** `test_missing_tools_leave_chat_usable`: tab action error only, no startup PySharkimport. `test_traffic_close_ignores_late_result`: no destroyed widget. `test_cancel_terminates_and_export_error_keeps_results_for_retry`. `test_single_job_bounded_queue_and_rates_labeled`
- [ ] **Luna implementation:** Open Capture,Analyze,Export XML,Export SQLite,explicit tool path selector and progress/cancel. JobController queue of 64 reused, one main thread table update, no overlapping jobs. Fifth-tab lazy registration must not alter secure-chat startup. Explain captured bytes/s vs plaintext goodput and conversion packets/s; retransmission observation not attack proof
- [ ] **Controller red/green:** `python -m pytest tests/gui/test_traffic_view.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** new threadpool or packet capture administrator privileges.

#### T3c: Platform/evidence documentation and offline workflow integration

**Files:** Modify `docs/setup.md`, `docs/progress-check-demo.md`, `docs/progress-check-evidence.md`, `README.md`; no application files

**Prerequisites:** T3b,C8,A3.

**Interfaces:** Produce documented offline workflow external Wireshark→capture→PyShark SQLite/summary+TShark pdml, source verification and conversion efficiency checklist

- [ ] **Fixed test oracle:** Controller document review: all five security goals and 13 acceptance criteria mapped; install/location tshark Windows/Linux, absent tool actionable; capture filters for secure port 47655/baseline port 47656 and Follow TCP Stream; independent fixture vs real capture labels. Runtime agreement assertion remains T2d/T3a, no tests that mirror reversible documentation
- [ ] **Luna implementation:** Document actual command recipes, source SHA256,count/known field/XML well formed/SQLite integrity checks and conversion metrics with host versions. Controller runs CLI on fixture and, when available, genuine pcapng secure/baseline captures, visually checks fifth tab. No real tool/capture success claimed from mocks or skips; cross platform verification separate
- [ ] **Controller documentation/regression check:** `python -m pytest tests/integration/test_traffic_cli.py tests/integration/test_capture_exports.py -q`; existing runtime assertions PASS, plus the stated content/link/acceptance checklist. No forced red failure for this documentation-only unit.

**Exclusions:** invented captures/screenshots or rewriting approved scope.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit tests/integration tests/gui -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: add offline traffic interface and assessment exports`.

## Completion boundary

The fifth tab cannot affect chat startup. Controller completes the master release checks and records actual tool/capture/visual evidence; Sol reviews source-to-export agreement and all acceptance coverage before declaring completion.
