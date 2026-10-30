# Analysis results view evidence

Date: 2026-10-30, Asia/Kolkata. Workspace: `.worktrees/sparc-progress-check`.

The user approved the preceding graphical-analysis audit recommendation. Implementation and review are solo. No protocol changes, dependency additions, merge or push.

## Behavior

- Analysis now has Experiments and Results views. Completed benchmarks reveal Results → Performance; sensitivity results reveal Results → Avalanche. Other reports use Details or Operation metrics.
- Each graph category keeps its latest measured run. Changing categories, generating a signature specimen or failing a later experiment does not relabel or erase the retained run. The status footer reports errors separately. CSV export still refers to the latest detail report; each graph's SVG export refers to that graph category.
- A chart selector displays one panel at a time; SVG export includes every panel in the selected category. Operation filters appear only for local cryptographic results. Idle progress controls are hidden.
- Duration plots show mean and dashed p95 series. Payload positions use a numeric logarithmic axis. Goodput remains distinct from local primitive throughput.
- Sensitivity overview plots show means with min/max ranges, separately labelled model expectations and the 100% coursework byte target. Batch views also include normalized 5-percentage-point histograms and change frequency for all 128 output bits. Single trials do not claim a distribution. Empty or unmeasured data stay unavailable.
- Public run context and sample counts are included on screen and in SVG: benchmark run ID/UTC/environment, warmups/repetitions/evidence mode; sensitivity seed/cases/trial counts. Keys and raw operands are excluded from graph metadata. Arbitrarily large supported seeds use the existing safe decimal formatter.

## Verification

- Before changes: 28 plot/unit and main Analysis GUI tests passed.
- RED: five plot-data/export tests failed for the missing behavior, then passed. Additional histogram-bar and large-seed regressions were each observed failing before their fixes.
- RED: three real-Tk navigation, category/export and network-control tests failed before the Results workspace existed.
- Focused gate: 40 passed in 8.98 s across `test_analysis_plots.py`, `test_analysis_view.py`, `test_analysis_charts.py`, and `test_analysis_results.py`.
- Current native screenshots and actual local benchmark / two-case sensitivity run exports are retained under `.demo/results-view-evidence/`. Checked 800×640 and 1200×1000. Final measured native text bounds showed no horizontal clipping on the five captured charts. Chart content and axes appear immediately; smaller windows scroll vertically for legends and provenance. A font-metric correction handles this desktop's extra font scaling.
- Keyboard Page Up / Page Down bindings are provided for the focused graph canvas. Screen-reader accessibility and other operating systems were not verified.

## Full suite and review

`.venv/bin/python -m pytest -q`: **1129 passed, 11 failed, 10 skipped in 174.49 s**. No new analysis failures. The 11 failures match the previously established unrelated traffic baseline; their source files were not modified:

- `test_sqlite_index.py::test_public_import_hash_is_bounded_and_cancellable`
- `test_traffic_exports.py::test_export_uses_exact_unfiltered_argv_and_file_streams`
- `test_traffic_exports.py::test_valid_pdml_and_empty_document_publish_actual_packet_count` (2 cases)
- `test_traffic_exports.py::test_invalid_pdml_preserves_selected_output_and_cleans_staging` (2 cases)
- `test_traffic_exports.py::test_nonzero_child_error_is_safe_and_preserves_output`
- `test_traffic_exports.py::test_pre_cancel_does_not_mutate_source_or_selected_output`
- `test_traffic_exports.py::test_source_destination_alias_is_rejected_before_process` (3 cases)

Solo review covered missing/partial runs, operation filtering, per-category retention, chart/export provenance, numeric axes, histogram normalization, output-bit indexing, large seeds, Tk closure and CSV ownership. The full suite is not green; this branch has not been merged or pushed.
