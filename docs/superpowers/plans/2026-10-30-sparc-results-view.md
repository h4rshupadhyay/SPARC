# SPARC Results View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Execute solo as requested by the user.

**Goal:** Make measured graphical analysis immediately visible, readable and interpretable after each run.

**Architecture:** Extend the pure plot model and shared drawing/export layer, then place independent performance and avalanche views in a native Results workspace. Keep experiment runners and measurement definitions intact.

**Tech Stack:** Python >=3.10, tkinter/ttk, existing Canvas/SVG, pytest.

**Spec:** docs/superpowers/specs/2026-10-30-sparc-results-view-design.md

## Global Constraints

- Python >=3.10; no new dependencies or protocol/security changes.
- Preserve unrelated traffic files and documentation.
- Execute solo; do not spawn agents.
- Graphs must reflect measured data and never infer missing observations.

## Review Focus

- Canceled/empty runs must retain missing measurements without fabricated distributions (Task 1).
- Single workloads and uneven payloads must have finite, numeric axis geometry (Task 1).
- Export metadata must escape text and omit keys/raw synthetic operands (Task 1).
- Switching categories must retain their own latest results and contextual labels (Task 2).
- Error, cancel, export and close must not select a stale result as a new successful run (Task 2).

### Task 1: Measured charts and export context

**Files:** src/sparc/analysis/plots.py; tests/unit/test_analysis_plots.py.

**Interfaces:** Consume BenchmarkResult, LabResult, Trial unchanged. Extend Series with connected/ranges, Plot with axis bounds, scale, notes and context. Preserve benchmark_plots, sensitivity_plots, drawing, plot_height and plots_svg entry points.

- [ ] Write failing tests for mean/p95 and missing values; logarithmic spacing; hand-checked distributions and per-output-bit frequencies; empty/single-trial behavior; escaped contextual exports.
- [ ] Run `.venv/bin/python -m pytest tests/unit/test_analysis_plots.py -q`; confirm expected failures.
- [ ] Implement the data and shared vector drawing, including readable labels and metadata in SVG.
- [ ] Run the same command; expect all passing, then commit only this task's files.

### Task 2: Results workspace and native verification

**Files:** src/sparc/gui/analysis_view.py; src/sparc/gui/plot_view.py; tests/gui/test_analysis_view.py; docs/image-transfer-and-analysis-evidence.md.

**Interfaces:** Consume the Task 1 plotting entry points. AnalysisTab owns workspace and results notebooks, selecting graph tabs on completed result delivery. PlotView owns independent latest-result context, chart selector and SVG export.

- [ ] Write failing real-Tk tests for immediate graph visibility, switching retained results, context-specific operation controls, export preservation and bounded rendering at 800x640.
- [ ] Run `.venv/bin/python -m pytest tests/gui/test_analysis_view.py -q`; confirm new behavior fails.
- [ ] Implement native navigation, compact details and scrollable responsive charts; preserve result/export/cancel/close semantics.
- [ ] Run unit and GUI analysis tests; expect all passing. Inspect native ordinary/wide windows in one batch, fix defects and confirm once.
- [ ] Run `.venv/bin/python -m pytest -q`, report all failures against the established traffic baseline. Self-review the diff under the user's solo instruction; record evidence and commit only owned files.
