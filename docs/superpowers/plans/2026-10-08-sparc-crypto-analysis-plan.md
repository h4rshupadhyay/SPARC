# SPARC Cryptographic Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce reproducible AES sensitivity experiments, operation/network measurements, and an interactive Analysis tab.

**Architecture:** A pure laboratory uses public synthetic operands. Local benchmarks measure cryptographic calls; the network runner consumes verified secure-service receipts. Bounded background jobs feed the GUI and export raw measurements plus definitions.

**Tech Stack:** Python 3.10+, Py Cryptodome 3.24.0, cryptography 50.0.2, psutil 7.2.2, Tkinter/ttk, CSV, pytest.

**Spec:** [Approved specification, sections 6-7 and 9-10](../specs/2026-10-08-sparc-progress-check-design.md).

## Global Constraints

Inherit the [master plan](2026-10-08-sparc-progress-check-plan.md), including conditional commits. Sensitivity: 50 cases, 128 input flips and 256 key flips per case. Local workloads: 64/1,024/16,384 bytes, 10 warmups, 1,000 measured calls. Network: the same sizes, 10 warmups, 100 sequential measured exchanges. No live-key export, live GCM nonce reuse, or fabricated measurements.

## Review Focus

Master item 1 is tested at C2. Additionally test cancellation without a completed-result label, unique nonces including warmups, and exports that reconstruct their summary. Master item 3 is exercised again by A3's close-during-analysis test.

---

## File structure and result types

Create `src/sparc/analysis/{__init__,__main__,models,sensitivity,benchmark,network,resources,export}.py` and `src/sparc/gui/analysis_view.py`. C1 provides package setup, C2 signing definitions, and C5/C7 network/GUI integration. A1/A2 tools run without a peer.

`analysis/models.py` owns these records:

- `Difference(bit_percent: float, byte_percent: float, hex_percent: float)`.
- `Trial(case_index: int, mode: str, bit_index: int, key: bytes, block: bytes, modified_key: bytes, modified_block: bytes, baseline_ciphertext: bytes, modified_ciphertext: bytes, difference: Difference)`; mode is `plaintext` or `key`.
- `LabResult(seed: int, cases: int, trials: list[Trial], summary: dict, complete: bool)`; summaries group mode/metric with count, mean, min, max, population standard deviation.
- `SampleStats(count: int, mean_ns: float | None, median_ns: float | None, p95_ns: int | None, throughput_bytes_s: float | None)`.
- `BenchmarkResult(metadata: dict, samples: list[dict], summary: list[dict], complete: bool)`; samples use `operation`, `payload_bytes`, `elapsed_ns`, `success`, and network-only `message_id`, `characters`, `frame_bytes`. Network summaries additionally include `confirmed_count`, `elapsed_interval_ns`, `goodput_bytes_s`, `characters_s`. Unavailable quantities are `None`. Metadata includes run ID, UTC, workload counts, host/library versions, evidence mode, units, definitions, and policy limits.
- `ResourceSample(monotonic_ns: int, cpu_percent: float, rss_bytes: int)` and `ResourceResult(samples: list[ResourceSample], interval_s: float, peak_observed_rss_bytes: int, window_truncated: bool = False)`.

## Execution workflow

Use the [master plan's authoritative ownership, small-task cycle, dispatch, history and environment rules](2026-10-08-sparc-progress-check-plan.md#model-ownership-and-small-task-workflow). Reuse a task-local Luna worker for related units and red/green phases; the controller verifies each phase separately and runs the milestone gate below. Unit interfaces, allowed files, assertions and exclusions remain binding. Documentation changes use content/link checklists without documentation-mirroring tests. Commands use the master virtual environment; GUI checks require a display and unavailable checks stay explicit.

### A1: Single-trial and batch AES laboratory

#### A1a: Analysis result types and difference formulas

**Files:** Create `src/sparc/analysis/models.py`, `src/sparc/analysis/sensitivity.py`; test `tests/unit/test_sensitivity_metrics.py`

**Prerequisites:** C1.

**Interfaces:** Produce all analysis result types listed above and `compare_ciphertexts(left: bytes, right: bytes) -> Difference`

- [ ] **Fixed test oracle:** `test_one_bit_difference_has_distinct_units`: zero16 vs zero15+01 gives `bit_percent == 100/128`, `byte_percent == 100/16`, `hex_percent == 100/32`. `test_all_bits_differ`: zeros vs FF16 gives each100. `test_bad_block_lengths`: lengths other than16 raise domain errors
- [ ] **Luna implementation:** Exact popcount XOR/128, changed bytes/16, unequal lowercase hex positions/32. Preserve separate names/model expectations50%,99.609375%,93.75%; never convert an expectation to observed data. Result types match shared schema, immutable metadata conventions
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_sensitivity_metrics.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** AES call, batch loops, GUI.

#### A1b: Synthetic operands and single-bit trial

**Files:** Modify `src/sparc/analysis/sensitivity.py`; test `tests/unit/test_sensitivity_trial.py`

**Prerequisites:** A1a.

**Interfaces:** Produce `sensitivity_trial(seed: int, case_index: int, mode: str, bit_index: int) -> Trial`; private operand generator belongs in this same file

- [ ] **Fixed test oracle:** `test_deterministic_operands_and_msb_bit_zero`: independently SHA256 exact strings `SPARC-LAB-v1:key:<seed>:<index>` and block equivalent; bit0 changes only byte0 XOR0x80. `test_trial_modes_and_bounds`: plaintext0-127/key0-255, case0-49, integer seed, no bool. `test_each_trial_starts_from_baseline`: one flip only
- [ ] **Luna implementation:** Public synthetic32-byte key/16-byte block, isolated `AES.new(key, AES.MODE_ECB).encrypt(block)` only. Display original/modified key/block and ciphertext fields. No production identity/session material accepted by the API
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_sensitivity_trial.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** batch aggregation, live AESGCM.

#### A1c: Bounded reproducible batch and statistics

**Files:** Modify `src/sparc/analysis/sensitivity.py`; test `tests/unit/test_sensitivity.py`

**Prerequisites:** A1b.

**Interfaces:** Produce `run_sensitivity(seed: int = 42, cases: int = 50, cancel: Event | None = None, progress: Callable[[int,int],None] | None = None) -> LabResult`

- [ ] **Fixed test oracle:** `test_batch_counts_and_recomputed_summary`: two cases gives256 plaintext/512 key trials, independent count/mean/min/max/populationstd recomputation. `test_default_counts`: default50 gives6400/12800. `test_canceled_batch_is_incomplete`: stop at callback boundary, no completed label. Reject cases0/>50
- [ ] **Luna implementation:** Baseline once per case, each independent input/key flip starts from it; reuse A1b operand/flip logic without re-encrypting baseline for every trial. Max19200 retained trials. Group each metric by mode, partial results complete False. Progress current/total only
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_sensitivity.py tests/unit/test_sensitivity_trial.py tests/unit/test_sensitivity_metrics.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** CSV or GUI implementation.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_sensitivity_metrics.py tests/unit/test_sensitivity_trial.py tests/unit/test_sensitivity.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: add reproducible AES sensitivity laboratory`.

### A2: Local benchmarks, signature specimen and CSV CLI

#### A2a: Timing aggregation

**Files:** Create `src/sparc/analysis/benchmark.py`; test `tests/unit/test_benchmark_stats.py`

**Prerequisites:** A1a.

**Interfaces:** Produce `summarize(samples_ns: list[int], payload_bytes: int) -> SampleStats`

- [ ] **Fixed test oracle:** `test_stats_use_nearest_rank_and_operation_time`: [1,2,3,4] gives count4/mean2.5/median2.5/p954, throughput16*4*1e9/10. `test_empty_or_nonpositive_duration_is_unavailable`: count0 produces unavailable durations/throughput in the optional fields defined above; summed0 gives throughput None. Negative/bool timings rejected
- [ ] **Luna implementation:** Nearest rank ceil(.95*n)-1; sum call durations only, bytes*n/time, no GUI/network labels. Use optional fields to avoid manufactured empty averages. All nonempty successful timing rows retain raw integer nanoseconds
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_benchmark_stats.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** running cryptographic operations.

#### A2b: Synthetic local six-operation benchmark

**Files:** Modify `src/sparc/analysis/benchmark.py`; test `tests/unit/test_benchmark.py`

**Prerequisites:** A2a,C2.

**Interfaces:** Produce `run_local_benchmarks(sizes: tuple[int,...] = (64,1024,16384), warmups: int = 10, repetitions: int = 1000, cancel: Event | None = None) -> BenchmarkResult`

- [ ] **Fixed test oracle:** `test_encryption_nonces_unique_including_warmups` spies on actual AESGCM calls in a small run and asserts unique nonce for every encrypt. `test_benchmark_measures_six_operations`: requested successful counts for hash/sign/encrypt/decrypt/recompute-hash/verify. `test_timers_exclude_keygen_encoding_and_io`: injected clock/call ordering. `test_cancel_is_incomplete`
- [ ] **Luna implementation:** Synthetic keys generated outside timers; precompute C2 context/digest signing projection and serialized growing text envelope. Measure only primitive calls with perf_counter_ns; fresh nonce for warmup/measured encrypts, prepared valid ciphertext may repeat decrypt. ASCII workloads64/1024/16384,10warmups1000calls defaults; test injection may reduce counts only within1-1000 and0-10. Preserve failed rows outside success summaries. Include host/version/workload/units/definitions metadata
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_benchmark.py tests/unit/test_benchmark_stats.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** network goodput or live-key usage.

#### A2c: Isolated signature verification specimen

**Files:** Create `src/sparc/analysis/specimen.py`; test `tests/unit/test_signature_specimen.py`

**Prerequisites:** C2.

**Interfaces:** Produce `verify_specimen(public_key: bytes, signed_bytes: bytes, signature: bytes) -> bool`; `make_specimen() -> tuple[bytes,bytes,bytes]` returns synthetic raw public key/context/signature, never private key

- [ ] **Fixed test oracle:** `test_specimen_rejects_edit`: valid true, modified signed_bytes false, changed signature false, malformed public key/signature false. `test_specimen_contains_no_live_keys`: unrelated generated key, no service access
- [ ] **Luna implementation:** Use cryptography Ed25519 synthetic identity and C2 domain/projection demonstration, label valid/edited outcomes. Library validation exceptions become false for specimen checks; live protocol still fails closed separately
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_signature_specimen.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** editing live chat or exposing private keys.

#### A2d: Atomic raw/summary CSV exports

**Files:** Create `src/sparc/analysis/export.py`; test `tests/unit/test_analysis_export.py`

**Prerequisites:** A1,A2a-A2b.

**Interfaces:** Produce `export_lab(result: LabResult, directory: Path) -> tuple[Path,Path]` for trials/summary csv and `export_benchmark(result: BenchmarkResult, destination: Path) -> None`

- [ ] **Fixed test oracle:** `test_csv_reconstructs_results_without_live_secrets`: recompute mode/metric count/mean/popstd and timing mean/median/p95 from raw rows, units/metadata present, only labeled synthetic lab key fields allowed. `test_failed_export_preserves_previous_files`: failure before publish preserves old destinations. `test_canceled_export_marked_incomplete`
- [ ] **Luna implementation:** CSV deterministic columns from result schema; repeated run metadata includes runID,UTC,platform,versions,workload,complete/units/definitions. Store trial original/modified operands and values; benchmark no keys. Stage all lab outputs before replacing, no completed label for partial results. Destination errors leave in-memory results retryable
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_analysis_export.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** CLI, GUI, unexpected extra formats.

#### A2e: Analysis CLI wiring

**Files:** Create `src/sparc/analysis/__main__.py`; test `tests/integration/test_analysis_cli.py`

**Prerequisites:** A2c-A2d.

**Interfaces:** Produce `python -m sparc.analysis sensitivity --seed 42 --output DIRECTORY` and `python -m sparc.analysis benchmark --output FILE.csv`; command entry `main(argv: list[str] | None = None) -> int`

- [ ] **Fixed test oracle:** `test_sensitivity_cli_exports_expected_counts`:6400/12800 default with labeled synthetic operands. `test_benchmark_cli_preserves_metadata_and_counts`: default workload10/1000 and sixoperations; small unit test may stub runner but actual smoke unmocked. `test_bad_cli_input_nonzero_and_no_completed_output`
- [ ] **Luna implementation:** Argparse delegates exact runners/exports, domain errors actionable and nonzero. Controller runs both default commands after tests and independently reconstructs summaries; measured output only. No sockets/GUI/TShark imported by standalone analysis CLI
- [ ] **Controller red/green:** `python -m pytest tests/integration/test_analysis_cli.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** performing controller commands inside Luna task or claiming predicted speed.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_benchmark_stats.py tests/unit/test_benchmark.py tests/unit/test_signature_specimen.py tests/unit/test_analysis_export.py tests/integration/test_analysis_cli.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: measure and export local cryptographic performance`.

### A3: Network/resource performance and Analysis tab

#### A3a: Verified receipt network runner

**Files:** Create `src/sparc/analysis/network.py`; test `tests/integration/test_network_benchmark.py`

**Prerequisites:** C5-C6,A2a.

**Interfaces:** Produce `run_network_benchmark(service: PeerService, sizes: tuple[int,...] = (64,1024,16384), warmups: int = 10, repetitions: int = 100, cancel: Event | None = None, evidence_mode: str = "unspecified") -> BenchmarkResult`; consumes publicsend_text/run_id, wait_for_receipt and state

- [ ] **Fixed test oracle:** `test_network_benchmark_uses_verified_audited_receipts`: pairfixture64bytes/2warmups/3measured, confirmed_count3/plainbytes192, distinct ids, all5 deliveries durable in logs; goodput=192*1e9/(lastfinish-first start). `test_disconnect_marks_benchmark_incomplete`: partial status, no full-run goodput. `test_character_rate_counts_codepoints`
- [ ] **Luna implementation:** Sequential fresh runID benchmark envelopes via unchanged live service; start/finish from confirmed receipts includes cryptography/audit/pacing. Warmups excluded; per-row actual frame bytes and characters. Preserve failed/unconfirmed rows, completed_count distinct from requested; goodput None for incomplete workload. Defaults3sizes10warmups100measured; test overrides bounded. Do not disable auditing or rate limits
- [ ] **Controller red/green:** `python -m pytest tests/integration/test_network_benchmark.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** one-way latency or inferred Ethernet overhead.

#### A3b: Bounded one-second resource sampler

**Files:** Create `src/sparc/analysis/resources.py`; test `tests/unit/test_resources.py`

**Prerequisites:** A1a.

**Interfaces:** Produce `sample_resources(pid: int, stop: Event, interval_s: float = 1) -> ResourceResult`; consume the final `ResourceResult` schema above, including its bounded-window flag

- [ ] **Fixed test oracle:** `test_resource_peak_is_observed_sample_peak`: fakeprocessknown RSS sequence, max sample equals reported peak; CPU prime occurs before measured interval. `test_stop_wakes_sampler`: Event.wait cancels. `test_samples_bound_3600_and_window_label`: at most3600 retained, window_truncated True after bound
- [ ] **Luna implementation:** psutil Process cpu_percent/rss at1s intervals; rolling deque of 3,600 and monotonic timestamps. Report interval and the maximum RSS among retained samples; if the window rolls, label the retained-window peak and window_truncated flag, never an exact instantaneous maximum. Handle process exit as finite canceled/ended run with data already collected
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_resources.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** privileged system sampling or unbounded history.

#### A3c: Analysis tab controls, bounded jobs and result tables

**Files:** Create `src/sparc/gui/analysis_view.py`; test `tests/gui/test_analysis_view.py`

**Prerequisites:** C7,A1-A2,A3a-A3b.

**Interfaces:** Produce `AnalysisTab(parent: ttk.Notebook, service: PeerService).handle_event(event: ServiceEvent) -> None`, `.close() -> None`; `register_analysis(app: SparcApp, service: PeerService) -> None`; consume C7 JobController unchanged

- [ ] **Fixed test oracle:** `test_analysis_close_cancels_job_and_ignores_late_result`: no widget access after close. `test_network_disabled_until_connected`. `test_single_trial_displays_operands_formulas_and_observed_values`: correct mode/bit bounds, labels50% expectation vs observed. `test_only_one_job_and_cancel_is_not_complete`. `test_specimen_shows_valid_and_edited_rejection`
- [ ] **Luna implementation:** Reuse bounded JobController queue of 64; single trial/batch/local/network/resource actions one job at a time, progress/cancel, tables, CSV save dialog. Synthetic operands only; signing specimen separate from live record. Register fourth tab lazily, no result worker calls Tk. Core operation events routed to metrics table in A3d
- [ ] **Controller red/green:** `python -m pytest tests/gui/test_analysis_view.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** new job executor/concurrency design or packet tools.

#### A3d: Operation metrics export, registration and evidence

**Files:** Create `src/sparc/analysis/operation_metrics.py`; modify `src/sparc/gui/analysis_view.py`, `src/sparc/gui/app.py`, `docs/progress-check-demo.md`, `docs/progress-check-evidence.md`; test `tests/unit/test_operation_metrics.py`

**Prerequisites:** A3c,C5g,C6.

**Interfaces:** Produce `OperationMetrics(capacity: int = 1000).add(event: ServiceEvent) -> None`, `.result() -> BenchmarkResult`; registration calls existing `register_analysis(app, service)`

- [ ] **Fixed test oracle:** `test_operation_spans_are_separate_and_bounded`: max1000 raw events, operation label/elapsed/success/encoded bytes/public context preserved; failures excluded from success averages. `test_audit_overhead_and_handshake_approval_label`: log bytes/audit ns separate from frame bytes, handshake labels include/exclude approval. `test_export_can_reconstruct_each_operation`
- [ ] **Luna implementation:** Consume existing events for handshake, peer-loss detection, reconnect, audit append/verification; no new competing timers or secret fields. Export rawrows + policy limits and sample window metadata. Docs add baseline/network/flood resource capture and five-goal efficiency mapping. Controller runs default network workload on labeled simulation or physical devices with one-second samples and visually checks fourth tab; unavailable physical checks remain unverified
- [ ] **Controller red/green:** `python -m pytest tests/unit/test_operation_metrics.py tests/gui/test_analysis_view.py tests/integration/test_network_benchmark.py -q`. Initial missing-behavior failure, then all stated tests PASS; use the master plan's shared cycle.

**Exclusions:** fake physical evidence or packet-overhead estimation.

**Sol 6.1 milestone gate:** Controller runs `python -m pytest tests/unit/test_resources.py tests/unit/test_operation_metrics.py tests/integration/test_network_benchmark.py tests/gui/test_analysis_view.py -q`; Sol reviews the contracts, failure paths and accumulated diff before dependent units proceed. Conditional controller commit: `feat: add network performance and analysis interface`.

## Completion boundary

Laboratory/local CLI works without sockets or packet tools. A3 adds the fourth GUI tab. The controller records separate primitive, round-trip/goodput, audit/handshake/recovery and resource evidence; Sol checks formulas and interpretation.
