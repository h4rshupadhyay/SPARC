# Inline image chat implementation

Execute inline in the existing isolated branch, preserving the solo preference
and unrelated files/open sessions. Design:
[inline image chat](../specs/2026-10-31-sparc-inline-images-design.md).

- [x] Add regression tests for automatic runtime receive/cleanup and explicit save;
  implement service-owned temporary receive storage and GUI receive/save jobs.
- [x] Add native file drop support through tkinterdnd2==0.7.0. Verify spaced
  paths, unsupported/multiple drops, preview and send, and cleanup bindings.
- [x] Replace plain history blocks with reusable directional bubbles. Reserve
  the inspector from startup; preserve explicit hide and user divider choice.
  Update tests whose old acceptance/auto-opening requirements were superseded.
- [x] Run focused GUI/transfer checks, actual two-peer/drop smoke and visual
  inspection, full regression and dependency checks; record evidence and commit
  only task-owned files locally.

Verification and solo review: [inline image chat evidence](../../inline-image-chat-evidence.md).
The continuation recovered the existing implementation and verifies its final
behavior; earlier test-first results are not reconstructed from memory.
