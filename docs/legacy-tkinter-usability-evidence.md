# Legacy Tkinter usability evidence

Date: 2026-10-10. Branch: `feat/legacy-tkinter-usability`, based on `main` at
`8e5378e`. The user chose the original Tkinter UI and requested changes only
where functionality or visibility suffers, especially macOS scroll speed and
Linux scrollbar thickness. The separate CustomTkinter experiment is set aside.

The legacy notebook, controls, fonts, native theme, and service behavior are
preserved. Connection and Analysis now preserve wheel/trackpad gesture magnitude
and use a stable, DPI-aware line increment. Page scrolling works over ordinary
child controls; native Text, Listbox, Treeview, Combobox and Spinbox behavior
remains available. Zero-delta events do not move the page, and small Windows-style
deltas accumulate. Linux scrollbar handles are at least 20 pixels thick and scale
with Tk's DPI setting. Audit now exposes a scrollbar for long reports. Connection
focus scrolling leaves enough margin to keep keyboard-focused controls visible.

## Verification

Environment: Linux, Python 3.10.12, Tcl/Tk 8.6.12, X11 virtual display `:2`.
Dependencies and tests run from this worktree's own `.venv`.

- Baseline: `env DISPLAY=:2 .venv/bin/python -m pytest tests/gui -q` —
  **85 passed**, two existing Tk `Variable.__del__` warnings.
- Four symptom regressions were observed failing before their fixes: gesture
  magnitude discarded; wheel over an Analysis label did not move the page;
  Connection scrollbar measured 15 pixels wide; Audit had no visible scrollbar.
  The same four checks passed after the fixes.
- Aqua events are replayed on actual Linux widgets. Restoring the old sign-only
  conversion made the Aqua magnitude regression fail; restoring the correction
  made it pass. This checks event arithmetic and routing, not native trackpad feel.
- The existing supported-size/high-DPI Connection focus test exposed two pixels
  of clipping after line increments were introduced. It passed after adding an
  increment-sized reveal margin.
- Helper tests cover gesture direction/magnitude, small-delta accumulation, zero
  movement, embedded native list/text/table scrolling, repeated dynamic-control
  binding, and vertical/horizontal handle geometry under four Linux themes.
- Initial full suite: `env DISPLAY=:2 .venv/bin/python -m pytest -q` —
  **901 passed, 9 skipped in 177.73 seconds**. The skips are native Windows gates.
- Independent source review identified retained Tcl class-binding callbacks after
  page destruction. A new collection regression was observed failing; the fix
  removes both class scripts and registered callbacks on canvas destruction.

- Corrected affected gate: `env DISPLAY=:2 .venv/bin/python -m pytest
  tests/gui/test_scrolling.py tests/gui/test_connection_view.py
  tests/gui/test_analysis_view.py tests/gui/test_audit_view.py tests/gui/test_app.py
  tests/gui/test_chat_view.py -q` — **97 passed in 14.46 seconds**, exit 0.
- Corrected full suite: `env DISPLAY=:2 .venv/bin/python -m pytest -q` —
  **902 passed, 9 skipped in 173.31 seconds**, exit 0, no warning summary.
- Final helper check, including native widget wheel events appropriate to their
  Tk windowing system: `env DISPLAY=:2 .venv/bin/python -m pytest
  tests/gui/test_scrolling.py -q` — **15 passed in 0.48 seconds**, exit 0.
- Independent scoped re-review: callback retention **addressed**, no new material
  regression. Independent probes confirmed class scripts and callback commands
  disappear, canvas/scroller/root objects are collected, and another canvas's
  callbacks remain intact. Source and staged whitespace checks exited 0.

The full-suite gate covers existing backend behavior rather than adding a new
security audit. The re-review sets aside unchanged usability behavior because
it is covered by the original review; native hardware feel remains pending.

## Visual evidence

Capture command: `env DISPLAY=:2 .venv/bin/python
.demo/tkinter-usability/capture.py` — exit 0, eight screenshots. This ignored
one-off evidence harness uses the existing GUI test fixtures and Pillow; it is
not a runtime dependency or a new app launcher.

The real legacy app widgets were captured using fictional test services,
documentation-only IP addresses and dummy public metadata. No real identity,
network session, audit chain or measurement was used. Capture tooling is separate
from runtime code. All eight images were inspected together: layout is preserved,
scroll handles are visible, and the composer and persistent Analysis footer fit
at both supported sizes. Long page content remains scrollable.

| View | 960 × 760 | 800 × 640 |
| --- | --- | --- |
| Connection | [Normal](evidence/legacy-tkinter-usability/connection-normal.png) | [Compact](evidence/legacy-tkinter-usability/connection-compact.png) |
| Chat | [Normal](evidence/legacy-tkinter-usability/chat-normal.png) | [Compact](evidence/legacy-tkinter-usability/chat-compact.png) |
| Audit | [Normal](evidence/legacy-tkinter-usability/audit-normal.png) | [Compact](evidence/legacy-tkinter-usability/audit-compact.png) |
| Analysis | [Normal](evidence/legacy-tkinter-usability/analysis-normal.png) | [Compact](evidence/legacy-tkinter-usability/analysis-compact.png) |

The reviewer independently dragged real scrollbar thumbs successfully in all
four Linux themes and both orientations at Tk scaling 1.8; thickness measured
27–31 pixels. Native macOS trackpad speed, momentum and smoothness remain
unverified. Native Windows hardware was not exercised. There is no new theme or
DPI switching UI; handles are sized against the active settings at construction.
Backend changes and a new security audit are outside this UI-only follow-up;
existing backend behavior is covered by the full regression suite.
