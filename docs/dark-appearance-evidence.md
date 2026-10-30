# Dark desktop appearance evidence

The user requested a dark UI, larger fonts, freedom to change the typeface,
and inspiration from established software beyond chat. Work was performed
solo in the existing `feat/sparc-progress-check` worktree from `9fa4f64`.
Unrelated pending documentation and local user artifacts were preserved.

## Appearance

The shared native theme now uses charcoal workspace surfaces, recessed dark
fields, raised controls, neutral text and blue active/focus cues. The visual
direction draws from [VS Code themes](https://code.visualstudio.com/docs/configure/themes)
and [Obsidian's interface typography](https://obsidian.md/help/settings).
It covers all five tabs, text/technical evidence, tables, dropdowns, scrollbars,
selected/disabled states, charts and the initial identity dialog.

On the verified Linux machine, installed Fira Sans and Fira Mono were selected.
Measured body line height is27px, supporting text22px, headings32px, titles39px,
navigation25px and technical text25px. The previous body target was22px.
Installed Inter/native/Noto fallbacks are used on other systems; no font
downloads or new dependencies were added. This changes the default typeface;
it does not add a font settings panel.

On-screen chart colors are adapted to the dark surface while their data,
drawing geometry, units and standalone light-background SVG output remain
unchanged. The identity theme is installed before the application shell exists.
OS title bars and system file dialogs may follow the operating system theme.

## Tests and corrections

Initial native checks failed in three expected places: light text fields,
white charts and an unthemed startup dialog. After implementation, 16 focused
checks passed and one measured-font assertion failed because rounding produced
25px instead of the intended26px minimum. Font sizing now verifies the measured
lower bound rather than relying only on the requested Tk size.

The first broad GUI/chart run reported130passed/5failed in40.30s. The larger
font clipped a compact Chat inspector timing line; that failed test left its
window open and caused four subsequent identity timer assertions. An isolated
identity handoff passed. Compact composer/padding adjustments then passed the
timing, identity and appearance checks:11passed in2.79s.

Native screenshots exposed inherited light clam tab highlights and wrapped
long paths crowding the Traffic table. Two additional behavioral tests failed
before correction. Explicit native state maps remove the pale highlights and
unequal selected-tab padding. Readonly horizontally navigable path fields keep
full paths available without consuming multiple vertical lines. A precise
third-row bounding-box check caught another one-pixel clipping edge; a small
spacing reduction corrected it. The final four appearance/geometry checks
passed in0.67s. Earlier combined theme/traffic/timing verification passed11 in6.64s.

Contrast checks verify dark surfaces, text/selection readability, disabled
button legibility and visible chart text/series. Existing checks retain
root-owned font lifetime when another peer window closes. No test was relaxed
to accept clipping or pending identity callbacks.

The first complete run passed1196tests and skipped9platform-specific cases,
but exposed an existing intermittent malformed-capture success (195.09s).
The isolated rerun passed. Deterministic regressions reproduced the decoder
EOF/exit-status race before a narrow correction; see
[decoder exit evidence](traffic-decoder-exit-evidence.md). The affected
decoder/CLI gate passed41tests in6.59s and bounded exit/cancel checks passed4
in0.28s. Final frozen-source verification:

```sh
env DISPLAY=:1 SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark .venv/bin/python -m pytest -q --tb=short
```

Result: **1201passed /9native Windows-only skips in194.32seconds**, exit0,
with no warning summary. Product source was unchanged during this run. The
complete log is `.demo/dark-appearance-evidence/final-regression.log`.
Whitespace and local documentation-link checks passed. No important findings
or deferred minors remain in this scope.

## Native visual and interaction evidence

Retained ignored artifacts are in `.demo/dark-appearance-evidence/`:

- `native_smoke.py` and13screens cover actual connected localhost peers,
  bidirectional verified text, image approval and byte-equal recovery,
  captured-prefix audit verification, measured local/sensitivity plots and
  actual synthetic-fixture offline analysis.
- Compact800×640, ordinary1200×900/1000 and wide2600×1400 captures were inspected.
  Performance/avalanche chart text bounds had zero horizontal clipping.
- `startup_preview.py` and `14-identity-startup.png` cover the initial dark
  dialog without creating an identity. `fonts.json` records measured type.
- `inspection.json`, `smoke.log`, light-background `performance.svg` and
  `avalanche.svg` retain observed results and their scope.

All14screens were inspected. Controls remain reachable, evidence remains
scrollable, and compact Traffic results show at least three complete data rows.
Chat uses a two-line composer in compact windows and three lines in taller
windows; resizing preserves its content. Full source/tool paths remain
selectable and copyable in readonly fields.

Review was inline, without an independent reviewer, following the user's solo
preference. Protocol, trust, audit semantics and analysis/export calculations
were untouched. The separate decoder completion correction is documented
explicitly above. These are Linux native GUI results, not native macOS or
physical-device validation.


Two disposable connected dark-UI demo peers were left open for review
(PID160148); the existing sessions were preserved. `ui-peer-session.json`
records connected states and completed local/sensitivity results. The preview
uses the verified appearance source; normal next launch also includes the
separately verified decoder completion correction.
