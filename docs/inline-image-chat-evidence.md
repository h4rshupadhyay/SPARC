# Inline image chat evidence — 2026-10-31

The existing `feat/sparc-progress-check` worktree now receives incoming images
automatically into service-owned private temporary storage. Verified images
appear inline and can be saved independently, including after disconnection.
Runtime files survive reconnects and are removed when the service closes;
saved copies preserve all original bytes. Retention remains bounded.

Local images can be dropped into the composer or conversation and then sent
with **Send image**. Text drafts are preserved. Multiple-file drops are rejected;
unsupported files report an error. Native drop bindings are released on close.
The pinned dependency is `tkinterdnd2==0.7.0`.

Incoming gray and outgoing blue bubbles reuse their widgets while retaining
semantic text and keyboard selection in the native history. The security pane
is reserved from startup; selection preserves a manually moved divider and an
explicit hide choice. The existing authenticated offer/chunk/verification
protocol is retained.

## Verification

The continuation recovered the implementation and prior artifacts from the
worktree, then ran these checks against the final production source:

```sh
env DISPLAY=:1 SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark .venv/bin/python -m pytest -q --tb=short
```

Exit 0: **1,219 passed, 9 platform-specific skips in 219.72 seconds**, with no
warning summary. The log is `.demo/inline-images-evidence/full-regression-final.log`.

The existing drop and inspector tests were then strengthened to check unsupported
files, callback cleanup and a user-positioned divider. The focused final run was:

```sh
env DISPLAY=:1 .venv/bin/python -m pytest tests/gui/test_inline_images.py tests/gui/test_ui_refinement.py tests/gui/test_chat_images.py tests/unit/test_images.py tests/integration/test_image_transfer.py -q --tb=short
```

Exit 0: **31 passed in 12.69 seconds**. The log is
`.demo/inline-images-evidence/focused-final.log`. Coverage includes runtime-file
lifetime, real authenticated loopback transfer, saved-byte equality, canceled
save preservation, verified-only previews, text-draft preservation, bounded
history/thumbnails, scroll/focus behavior and inspector visibility.

`.venv/bin/python -m pip check` reported **No broken requirements found**.
`git diff --check` exited 0.

## Native two-peer and pointer evidence

```sh
env DISPLAY=:1 .venv/bin/python .demo/inline-images-evidence/native_smoke.py
```

The final isolated run exited 0. It used two real authenticated localhost peers,
synthetic text and a generated PNG. Native Xdnd gestures dropped the image into
the composer and over an embedded message bubble. The receiver automatically
completed delivery while its attachment-job controller was occupied. Explicit
Save image produced an exact byte-for-byte copy. The smoke also exercised audit
verification, Analysis measurements and synthetic capture analysis.

The log is `.demo/inline-images-evidence/native-smoke-final.log`; structured
observations are in `inspection.json` alongside it. Compact 800×640 and wide
1200×1000 captures were inspected, including `03-image-received-800.png`,
`04-image-inspector-1200.png`, and `15-drop-preview.png`. The save action,
attachment controls, bubble directions and inspector were reachable. The wide
chart check also used 2600×1400 and reported no clipped chart text.

Early :2 regression attempts were interrupted because that display was absent.
Early pointer attempts timed out before the drag reached its target. Instrumented
events confirmed the compositor source needed to become visible before the
synthetic gesture; the driver now calls `wait_visibility()` before computing
coordinates. The uninstrumented final run passed. These attempts are retained
as diagnostics and are not reported as successful checks.

## Review and limits

The review was performed solo, preserving the plan's recorded preference. It
checked the final diff and surrounding transfer/service, background-job and Tk
widget lifecycles against the approved specification. No critical or important
finding remained. This is an author review, not an independent reviewer gate.

One minor visual issue is deferred: the successful Save image confirmation uses
the existing red status-label style. It does not affect saving or byte integrity.

Evidence is Linux/X11 with synthetic files and localhost peers. Native macOS
drag-and-drop and physical-device/LAN behavior were not validated. No production
changes were needed during the continuation review. Unrelated F1/T1/master-plan
edits and local lab, checkpoint and style artifacts are excluded from this task's
commit. The branch and worktree are retained locally.
