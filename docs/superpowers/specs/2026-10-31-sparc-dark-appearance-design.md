# SPARC dark desktop appearance

The user requested a dark UI, larger fonts, permission to change the typeface,
and inspiration from established software beyond chat applications. This is
a bounded appearance change in the existing native Tk application. Work stays
solo in the existing worktree and preserves all unrelated pending edits.

## Direction and approaches

Use the existing shared appearance layer. A palette-only change leaves the
small typography and white chart/startup surfaces; replacing Tk would expand
packaging and interaction scope. A shared dark native theme with measured
larger fonts addresses the request directly. These detailed visual choices
are the builder's choices within the user's requested appearance change.

Take inspiration from [VS Code themes](https://code.visualstudio.com/docs/configure/themes)
and [Obsidian appearance and font settings](https://obsidian.md/help/settings):
charcoal workspace, distinct recessed fields and raised controls, readable
neutral text, subtle panel borders, blue active/focus treatment and restrained
status colors. Keep the present five-tab workflow and all evidence controls.

## Typography and constraints

Choose an installed sans-serif face, preferring Inter or Fira Sans, with native
and Noto Sans fallbacks. Use a separate installed monospace face for technical
evidence. Measure fonts at the Tk root: body line height26px (previously22),
supporting text22px, headings31px, titles38px and monospace24px. Navigation
may use24px to retain compact-window reachability. No downloaded fonts or new
dependencies; the selected face may differ by platform.

Apply the scheme to all tabs, text/edit fields, menus/dropdowns, scrollbars,
selected/disabled/focused states, charts and the initial identity dialog.
Keep readable text/selection contrast. Adapt layout where larger text would
clip controls at800×640; scrolling remains available. Root-owned font lifetime
and shared appearance across peer windows remain intact.

Charts use the existing drawing geometry/data and a dark on-screen palette.
SVG exports retain their existing light background for standalone documents.
Identity and pairing state, crypto, networking, audit semantics, exports and
worker ownership are outside this appearance change. Native OS window chrome
and system file dialogs may follow the operating system's theme.

Verify native screenshots at800×640 and1200×900, plot labels/series contrast,
startup identity theme, focus/selection and multi-window lifetime. Run focused
GUI checks and the complete regression. No native macOS result is implied by
Linux rendering.
