# SPARC Dark Appearance Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans inline. The user's established solo preference is preserved.

**Goal:** A readable dark desktop interface with larger, coherent typography.

**Architecture:** Extend root-owned appearance.py, consume its palette in chart
rendering and install the theme before identity startup. Preserve data and
service boundaries; adjust only layouts that fail with the new font metrics.

**Tech Stack:** Existing Python3.10+, Tk/ttk, pytest; no new dependencies.

**Spec:** [Dark appearance design](../specs/2026-10-31-sparc-dark-appearance-design.md).

## Global Constraints

Solo work in the existing isolated branch. Preserve unrelated files. No new
dependencies, font downloads, protocol/security/export semantic changes.
Root-owned measured fonts; compact800×640 and ordinary1200×900 viewports.
Dark charts on screen, existing light-background standalone SVG output.

## Review Focus

- Native default dropdown/disabled/scrollbar states must not introduce white surfaces or unreadable text.
- Larger fonts must leave navigation/actions reachable in the smallest supported window.
- Startup identity dialog must be themed before SparcApp exists.
- Dark chart series and text must remain visible without changing values or exported drawing data.
- Closing another peer must not invalidate root-owned fonts.

### Task1: Shared dark theme and larger fonts

**Files:** appearance.py; tests/gui/test_dark_appearance.py.
**Interfaces:** Preserve install(widget), Appearance and text_options; add a
private screen chart-color mapping consumed by Task2.

- [x] Add behavioral native tests for dark field/surface luminance, readable text/selection/disabled contrast, body metrics>=26px, technical font separation, shared lifetime and dropdown/scrollbar treatment.
- [x] Run new tests, observe failures on the current light theme and22px body.
- [x] Implement shared palette/styles and installed font fallback selection.
- [x] Run theme and existing font/navigation/layout checks; fix demonstrated layout failures.

### Task2: Dark chart/startup coverage and responsive layout

**Files:** plot_view.py; identity_unlock.py; minimal layout fixes in affected
views only; tests/gui/test_dark_appearance.py and affected existing GUI tests.
**Interfaces:** Consume Task1 Appearance/palette; preserve drawing model,
SVG output, identity unlock API, result navigation and all service calls.

- [x] Add failing chart contrast and early identity-theme checks.
- [x] Apply dark canvas/color mapping and install appearance before startup dialog construction.
- [x] Run all GUI tests plus existing analysis model tests. Observe and fix actual larger-font clipping with meaningful geometry assertions.
- [x] Capture/inspect all five tabs and charts at compact/wide sizes using fictional or synthetic data; preserve current peer sessions.
- [x] Review inline, run full regression and record evidence/README notes. Commit only task-owned files, keep branch/worktree; no merge/push.


## Verification follow-up

The first final suite exposed a pre-existing intermittent decoder EOF/exit race,
not a UI failure. A bounded correction and its deterministic regressions are
tracked separately in [decoder evidence](../../traffic-decoder-exit-evidence.md).
The complete suite is refreshed on the combined frozen source before commit.
