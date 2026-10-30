# Integrated window chrome evidence

The user requested a SPARC-owned header like VS Code, Obsidian or Chrome,
without a generic operating-system title row. Implementation is in the
existing isolated `feat/sparc-progress-check` branch, starting at `db22a30`.
Work and review were performed inline, preserving the user's solo preference.

## Behavior

SPARC branding, all five tabs and minimize/maximize/close share one dark row.
There is no additional application title row. The compact800×640 layout keeps
every tab and action reachable. Drag the branding or unused navigation space
to move the window; double-click those areas to maximize/restore. Thin edge
and corner handles resize within the configured bounds. Close dispatches the
current WM_DELETE_WINDOW callback, retaining existing service shutdown and
identity cancellation. Tabs keep their own pointer and keyboard behavior.

The identity prompt has a close-only application header. The main root stays
hidden until identity startup and tab construction finish, avoiding an empty
decorated window behind the prompt. No service, storage, security, analysis
or export semantics changed. No packages or font downloads were added.

Native adapters preserve window-manager ownership where supported: X11 Motif
decoration hints, Win32 caption styles and Tk's macOS noTitleBar style. A Tk
override fallback is available when an adapter is unavailable. Native adapters
and fallback behavior require physical validation on Windows and macOS; the
verified platform here is Tk8.6.12 on the GNOME X11 desktop.

References: [Tk window management](https://www.tcl-lang.com/man/tcl8.6/TkCmd/wm.htm),
[Tk macOS window styles](https://raw.githubusercontent.com/tcltk/tk/main/macosx/README)
and [Qt's XCB decoration hints](https://github.com/qt/qtbase/blob/dev/src/plugins/platforms/xcb/qxcbwindow.cpp).

## Verification

New tests initially failed because the chrome module did not exist. Native
checks then exposed stale frame extents when decoration hints were applied
after Map. Setting the hints on the hidden Tk wrapper before its first map
preserves the requested800×640 dimensions. Actual outer-window inspection
confirmed that the OS title bar was removed. Native test assertions also
inspect `_MOTIF_WM_HINTS` and frame extents.

This GNOME/Tk combination reports Tk state as normal while WM_STATE is Iconic,
including for an ordinary decorated Tk control window. The minimize check
therefore observes actual window-manager state, then verifies restoration.
Native maximize/restore retains WM ownership. No periodic state polling or
background GUI worker was introduced.

Eight new native tests passed in3.59seconds: compact navigation, current close
callback/cleanup, dragging and minimum-size anchoring, native states, modal
header, tab drag isolation, negative coordinates and real chat expansion after
resizing. An earlier combined chrome/app/identity run passed14 in5.62seconds.

Final frozen-source regression:

```sh
env DISPLAY=:1 SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark .venv/bin/python -m pytest -q
```

Result: **1209passed /9native Windows-only skips in205.87seconds**, exit0,
with no warning summary. The log is
`.demo/window-chrome-evidence/full-regression.log`. Whitespace and task-owned
documentation-link checks also passed. Unrelated pending documentation and
local user artifacts were preserved. No blocking inline-review findings remain.

## Native previews

Ignored artifacts in `.demo/window-chrome-evidence/` retain the two-peer smoke
script,13screens, charts and `inspection.json`. The smoke passed actual
mutually approved localhost connections, bidirectional verified text, image
acceptance with byte equality, audit verification, local/sensitivity analysis
and real TShark fixture analysis. It covered800×640,1200×900/1000 and2600×1400.
Chart labels had zero horizontal clipping. All13screens were visually
inspected; screenshot capture waits for asynchronous native resizing to settle.

`startup_preview.py` covers the initial prompt and close cancellation without
creating an identity. `open_peers.py` provides additional disposable demo
windows; old sessions and their drafts are left intact.
