# SPARC native UI refinement

The user approved improving Chat first, then consistent typography, spacing and navigation across the app. Work stays solo in the existing worktree. This refines native Tk/ttk; no new dependencies, protocol changes, trust decisions or crypto claims.

## Approach and constraints

Retain the existing native widgets and service/event boundaries. A separate web UI would change packaging and accessibility behavior; cosmetic recoloring alone would leave the empty panes and navigation problems. Use a shared native appearance layer and change layout at the existing view boundaries.

- Chat: visible conversation empty state, separate sender/status headings and message content, compact labelled composer, Attach image alongside Send, optional labelled security inspector. Explicit message selection reveals the inspector; background events update its content without opening it. Toggle preserves drafts and selection. Keep all plaintext/ciphertext/hash/signature/timing evidence and image safety/transfer controls.
- Appearance: one measured native body font and heading scale, restrained light surfaces, clear primary actions and focus/selection contrast. Own fonts at the Tk root so multiple peer windows have stable shared styling. Charts use the same body font, responsive width and appropriately measured wrapping rather than an isolated tiny font scale.
- Connection: current peer/connect controls and approval first, listener and interface details later. Full immutable fingerprints remain explicit before approval. Preserve scroll-to-focus and all public service calls.
- Audit: explicit unverified/verified/failed summary and an instructional empty state; verification action leads. Raw durable writer head stays available through a labelled disclosure and is never presented as a verification result. Refreshing head must not replace the captured-prefix verification summary.
- Analysis: one local navigation row for Experiments, Performance, Avalanche, Details and Operation metrics. Experiments has a selector for Performance, Avalanche, Signature specimen or Hash security, rather than displaying unrelated forms together. Completed runs still reveal their own result section; separate category retention and CSV/SVG ownership are unchanged.

Implementation choices above are the builder's choices within the approved critique scope. Native defaults and configurable content remain; do not replace security evidence with decorative badges. Verify at 800x640, ordinary two-peer window size and a wide/maximized viewport. No claim of full screen-reader accessibility or GUI completeness without evidence.
