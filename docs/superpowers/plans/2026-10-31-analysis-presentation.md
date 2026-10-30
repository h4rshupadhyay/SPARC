# Analysis presentation implementation plan

> **For agentic workers:** Use superpowers:executing-plans, preserving the recorded solo preference. Tasks use checkbox tracking.

**Goal:** Make the approved information-security requirements demonstrable through the existing GUI with correctly scoped graphs and reliable exports.

**Architecture:** Add bounded message/public-artifact domain modules; connect them to the current job/results lifecycle. Extend sensitivity and graph data models without changing live messaging cryptography.

**Tech Stack:** Existing Python 3.10+, Tkinter/ttk, cryptography, PyCryptodome, pytest; no new dependencies.

**Spec:** [approved audit implementation design](../specs/2026-10-31-analysis-presentation-design.md).

## Global constraints

Use the existing isolated progress-check worktree. Preserve unrelated files,
native appearance, runtime protocol and seeded/CLI compatibility. Public exports
exclude private keys. Messages are bounded to 16,384 UTF-8 bytes; custom AES keys
are 32 bytes and sensitivity blocks 16 bytes. Local workloads use 64–16,384 bytes,
up to 9 distinct sizes; network limits remain unchanged.

## Review focus

Unicode byte lengths; malformed/oversized/tampered JSON; stale results after
errors or edited specimens; cancellation and late jobs; compact layouts with
long digests/labels and dense conditional data.

### Task 1: Custom message and AES sensitivity domain

Files: add `analysis/message.py`; modify `analysis/sensitivity.py`, `analysis/models.py`;
tests `unit/test_message_lab.py`, `unit/test_sensitivity_trial.py`.
Interfaces: `run_message_trial(text, key=None) -> MessageTrial`;
`custom_sensitivity_trial(key, block, mode, bit_index) -> Trial`.
- [x] Add tests for exact Unicode recovery/digest/signature, timings, private-key exclusion, invalid sizes and custom one-bit operands; run meaningful RED.
- [x] Implement with real AESGCM/SHA-256/Ed25519 and isolated single-block AES.
- [x] Run domain tests GREEN and affected existing sensitivity/specimen tests.

### Task 2: Specimen timing and public artifacts

Files: add `analysis/artifacts.py`; modify `analysis/specimen.py`;
tests `unit/test_analysis_artifacts.py`, `unit/test_signature_specimen.py`.
Interfaces: immutable `SignatureResult`; `verify_timed_specimen(...) -> (bool,int)`;
`save_artifact(result,path)`; `load_signature_artifact(path) -> SignatureResult`.
- [x] Test generation/verification timing preservation, JSON public fields, bounded/malformed load, reverify edited bytes, atomic output preservation; run RED.
- [x] Implement typed public serialization, version/schema bounds and timing helpers.
- [x] Run artifact/specimen/message tests GREEN.

### Task 3: GUI custom inputs, correct result/export association

Files: add `gui/message_lab.py`; modify `gui/analysis_view.py`;
tests `gui/test_analysis_presentation.py` and affected GUI tests.
- [x] Reproduce stale specimen export and absent custom input/verification timing with native GUI tests; run RED.
- [x] Integrate the message form/results, seeded/custom sensitivity options,
  specimen save/load/timings, current-result JSON/CSV dispatch and clear states.
- [x] Run GUI analysis and domain tests GREEN; retain compatibility for existing callback callers.

### Task 4: Honest performance/sensitivity graph data

Files: modify `analysis/benchmark.py`, `analysis/plots.py`; tests `unit/test_analysis_plots.py`, `unit/test_benchmark.py`.
- [x] Test more local sizes, signature operations/s, numeric annotations, timing distribution and conditional frequencies; run RED.
- [x] Implement transformations with explicit algorithm/operand/scope definitions;
  no fabricated measurements or inferential confidence claims.
- [x] Run plot/statistics/benchmark/CLI tests GREEN.

### Task 5: Readable native graph and experiment layout

Files: modify `gui/plot_view.py`, `gui/analysis_view.py`; tests `gui/test_analysis_presentation.py`.
- [x] Test visible legends/scope/primary actions, custom errors and table scrolling at 800×640; run RED.
- [x] Separate fixed essential legends/scope from scrollable chart/provenance;
  render empirical spread and optional conditional views, direct actions and
  concise specimen/message results while retaining the theme.
- [x] Run all GUI analysis tests GREEN and numerical/export checks.

### Task 6: PCAP performance presentation

Files: modify `traffic/summary.py`, `gui/traffic_view.py` only as needed; add
focused traffic-rate tests and GUI integration coverage.
- [x] Test fixed capture-time bins, byte conservation, empty/nonpositive-time cases and distinct rate labels; run RED.
- [x] Add an honestly labeled capture-time rate view with source provenance.
- [x] Run traffic unit/integration/GUI checks GREEN.

### Task 7: Final integration and evidence

- [x] Run full pytest suite with display and real synthetic decoder, dependency
  check, current-result exports and native custom message/sensitivity/specimen,
  performance and PCAP smoke. Inspect compact/wide screenshots in one batch;
  fix demonstrated defects, confirm once.
- [x] Review the complete task diff solo, record any limits/rulings, update
  README/evidence and this plan; commit only owned changes locally.
