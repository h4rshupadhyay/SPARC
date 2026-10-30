# SPARC UI Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Execute solo as requested.

**Goal:** Make Chat clear on arrival and provide coherent, readable native navigation across SPARC.

**Architecture:** Share root-owned appearance and disclosure components, refine existing views, and keep service calls and event handling intact. Flatten Analysis navigation while retaining its measured plot/export modules.

**Tech Stack:** Python >=3.10, tkinter/ttk, existing Pillow, pytest. No new dependencies.

**Spec:** docs/superpowers/specs/2026-10-30-sparc-ui-refinement-design.md

## Global Constraints

- Solo; preserve unrelated traffic work and existing audit/scope evidence.
- No protocol, cryptographic or trust-policy changes.
- Preserve Unicode, drafts, image acceptance/saving, public inspector evidence and shutdown behavior.

## Review Focus

- Optional inspector must reveal real selected evidence without altering drafts or send semantics (Task 1).
- Typography must remain stable across multiple windows and keyboard focus must remain visible (Task 1).
- Approval always presents complete immutable fingerprints; scrolling retains reachable controls (Task 2).
- Refreshing audit head must not falsely imply verification or overwrite the captured report (Task 2).
- Flat Analysis routing, background errors and exports must retain correct category provenance (Task 3).

### Task 1: Shared appearance and Chat composition

**Files:** src/sparc/gui/appearance.py (new); app.py; chat.py; conversation.py; image_chat.py; tests/gui/test_ui_refinement.py (new); tests/gui/test_chat_view.py.

**Interfaces:** `appearance.install(widget)` returns root-owned fonts/palette; `Disclosure(parent, text)` exposes `body` and `toggle`. Chat retains existing event/inspection APIs and adds an explicit inspector toggle.

- [x] Add failing real-Tk tests for the empty conversation, inspector disclosure with selected evidence and preserved draft, attachment beside Send, shared font ownership.
- [x] Run `.venv/bin/python -m pytest tests/gui/test_ui_refinement.py -q`; observe expected failures.
- [x] Implement shared appearance and native Chat layout, preserving all transfer/evidence behavior.
- [x] Run Chat/image/app/refinement tests; expect all passing. Commit only owned files.

### Task 2: Connection and Audit hierarchy

**Files:** connection.py; audit_view.py; tests/gui/test_ui_status.py; tests/gui/test_audit_view.py.

**Interfaces:** Consume appearance and Disclosure. Preserve fingerprint approval fields, scroll-to-focus, audit JobController and verification reports.

- [x] Add failing tests for peer-first ordering and unverified Audit with expandable complete raw head.
- [x] Run new tests; observe expected failures.
- [x] Reorder Connection sections, lead Audit with verification state/action, disclose raw head and keep report scope stable.
- [x] Run connection/audit/refinement tests; expect all passing. Commit owned files.

### Task 3: Analysis navigation and complete verification

**Files:** analysis_view.py; plot_view.py; plots.py if measured geometry requires it; tests/gui/test_analysis_results.py; tests/gui/test_analysis_navigation.py; tests/gui/test_chat_images.py; docs/native-ui-refinement-evidence.md.

**Interfaces:** ResultsView uses the Analysis workspace notebook directly; `show/select/close` retain their behavior. PlotView and exports retain category-specific data and provenance. Experiment selector only changes visible configuration frames.

- [x] Add failing tests for one row of Analysis sections and selecting the desired experiment without losing values; adapt obsolete nested-tab assertions.
- [x] Run the new tests; observe expected failures.
- [x] Flatten navigation, add the experiment selector and harmonize graph text/layout with shared appearance.
- [x] Run GUI and analysis plot tests. Inspect native empty/populated Chat, image offer and audit/connection/analysis states at minimum/ordinary/wide sizes in one batch; fix defects and confirm once.
- [x] Run full pytest and record inherited traffic failures separately. Self-review under the user's solo instruction, commit owned changes and refresh the connected two-peer demo.
