# Pragmatic maintainability cleanup

> Execute inline with superpowers:executing-plans; preserve the established solo preference.

**Goal:** Remove proven stale implementation and simplify ownership/layout
code while preserving the current interface and supported compatibility.

**Architecture:** Retain existing modules. Put root-owned styles in
appearance.py; keep window setup, header construction, bindings and native
decoration setup in focused methods of WindowChrome. Consolidate exceptional
startup cleanup and guarantee ordered shutdown with contextlib.ExitStack.

**Tech stack:** Existing Python3.10+, Tk and pytest; no new dependencies.

The source scan covers all65 application modules. Keep public exports,
type-only imports, supported identity migration, bounded handshake approval
and documented standalone analysis helpers. Remove only private functions
with no callers and their orphaned native declarations/imports. Preserve
unrelated pending files, local environments and open demo sessions.

- [x] Remove obsolete POSIX path-only symlink scan and Windows path-only
  ownership/security-query helpers; retain active fd/handle validation.
  Remove unused imports and ImageChat's unused composer layout fallback.
  Verify existing storage, image and export tests.
- [x] Add a failing shutdown regression for tab/service exceptions. Refactor
  startup cleanup and ordered shutdown in app.py; run lifecycle/CLI checks.
- [x] Move chrome styles into appearance.install; divide the long chrome
  constructor into focused setup methods, simplify decoration state, and
  remove the pass-through Analysis child iterator. Run existing GUI checks.
- [x] Review the complete diff inline, run native GUI smoke and full suite,
  record results here, and commit task-owned files locally.

## Review and verification

The removed private storage functions had no source or test callers. Active
POSIX fd checks and Windows handle checks remain. The two path-based Win32
security declarations were also unused. Import scanning retains annotation
imports, public reexports and standalone documented functions; the identity
credential reexport is now explicit. The final65-module/source-and-test scan
reports no unreferenced function or unused-import candidates. This static
scan is supporting evidence, not a proof about dynamic external callers.

The two new shutdown cases failed before correction: a tab exception left
all later owners open, and a service exception left the root open. ExitStack
now closes every owner in display order, then service and root, while
propagating cleanup errors. Existing startup exception handling is retained
in one helper, with an added check that a cleanup error cannot replace the
original setup error. A fallback-header check covers absent native adapters.

Focused storage/image/export/theme/lifecycle checks:59passed in12.23s.
Final lifecycle/header/CLI gate:20passed in4.26s. Native two-peer smoke passed
verified text, byte-equal image transfer, audit verification, local/sensitivity
plots and real TShark analysis. The inspected chat preview retains the same
layout; all13captures and measurement bounds are retained in the ignored
`.demo/maintainability-cleanup-evidence/` directory.

Final frozen-source regression: **1213passed /9native Windows-only skips in
198.92seconds**, exit0, no warning summary. Command:

```sh
env DISPLAY=:1 SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark .venv/bin/python -m pytest -q
```

Log: `.demo/maintainability-cleanup-evidence/full-regression.log`. The native
startup preview also passed safe cancellation after rendering the unchanged
header and form. Whitespace checks passed. Native Windows and macOS remain
unavailable on this Linux X11 host. Inline final review has no blocking
findings. Existing demo sessions, unrelated pending docs and local
environment/user artifacts are preserved.
