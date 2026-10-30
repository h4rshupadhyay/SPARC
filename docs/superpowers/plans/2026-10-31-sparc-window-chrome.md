# Integrated window chrome implementation

Execute inline, preserving the user's established solo preference and existing
isolated branch. Leave unrelated files and open demo sessions intact.

- [x] Add behavioral tests for integrated navigation, lifecycle close routing,
   moving/resizing, native window state, and startup dialog chrome. Run red.
- [x] Implement a small window-chrome controller and platform decoration helper;
   integrate with the application and startup prompt. Run focused GUI checks.
- [x] Inspect full-window native screenshots at compact and wide sizes, verify
   window state and cleanup, then run the regression suite. Record evidence
   and commit only task-owned files locally; do not push or merge.

Design: [Integrated SPARC window chrome](../specs/2026-10-31-sparc-window-chrome-design.md).

Verification: [Native window chrome evidence](../../window-chrome-evidence.md).
