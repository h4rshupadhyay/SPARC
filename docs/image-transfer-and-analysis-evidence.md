# Image transfer and graphical analysis evidence

Date: 2026-10-30 (Asia/Kolkata).
Workspace: `.worktrees/sparc-progress-check`, branch `feat/sparc-progress-check`.
Execution and final code review were solo, as requested. No merge or push.

## Implemented behavior

- Chat supports Attach image / Send image, an original preview and digest,
  inline Accept and save / Reject / Cancel transfer controls, and recovered
  previews after authenticated, hash-checked publication. Text drafts and
  concurrent text messages are preserved.
- PNG/JPEG/GIF/WebP images retain their original file bytes. File, pixel,
  queue, chunk-window, history, ciphertext-sample, and thumbnail bounds follow
  the approved design. Existing destinations are never overwritten.
- The inspector shows latest-chunk ciphertext/signature/nonce/tag, local
  cryptographic times, full-file digest, file hashing including I/O, transfer
  duration, and verified goodput when available. A displayed missing primitive
  time remains unavailable; it is not replaced with a whole-file/I/O duration.
- The sender requires a signed final receiver result to report verified
  delivery. Publication followed by lost confirmation or durability/audit
  failure retains published bytes and does not claim verified delivery.
- Analysis plots local primitive duration/throughput, network receipt
  duration/goodput, and sensitivity observations/expectations. Canvas and SVG
  consume the same plot data and geometry. Missing values remain gaps and
  incomplete runs retain their label.
- Byte change is explicitly the character-level proxy. The 100% coursework
  target is separate from the 99.609375% byte-model expectation; bit and hex
  expectations are 50% and 93.75%. Observations are never forced to a target.

## Verification

Commands run from the worktree with `.venv/bin/python`.

| Gate | Actual result |
| --- | --- |
| Strict file protocols, records, message/audit compatibility | 143 passed in 0.31 s |
| Supported image decoding and protocol tests | 49 passed in 0.24 s |
| Transfers, writer, real loopback peers, heartbeat, availability, send | 72 passed in 72.62 s |
| Chat image/text/app gate before final review | 24 passed in 8.83 s |
| Plot models, Analysis GUI, and CSV compatibility | 35 passed in 11.52 s |
| Review corrections: Chat/image/Analysis GUI | 49 passed in 20.92 s |
| Native-layout regressions after visual correction | 2 passed in 0.71 s |
| Dependency consistency | `python -m pip check`: no broken requirements |
| Whitespace | `git diff --check`: passed |

The final corrected frozen-source run finished with **1121 passed, 11 inherited
traffic failures, 9 Windows-only skips, and 1 warning in 206.11 s**. All new
feature tests passed; the failure names match the pre-feature baseline below.
The earlier peer-pairing setup error did not recur.

The warning is an intermittent `tkinter.Variable.__del__` cleanup warning:
`RuntimeError: main thread is not in main loop`, reported while a later capture
integration test ran. The initial assessment also observed this warning. Its
retained-variable source is unresolved; no warning-free whole-suite claim is
made. Functional native GUI and lifecycle assertions passed.

### Inherited traffic failures

The first complete run produced **1116 passed, 11 failed, 9 Windows-only
skipped in 196.91 s**. All 11 failures concern the previously unfinished traffic
milestone: one bounded/cancellable source-hash test in `test_sqlite_index.py`
and ten cases in `test_traffic_exports.py` whose PDML implementation is absent.

To verify attribution, exported tracked source at pre-feature commit `d35c899`
to a temporary directory, added the two unchanged, pre-existing untracked
traffic modules (`sqlite_index.py`, `summary.py`), and ran those two test files
with pytest's `pythonpath` set to that source snapshot. The same **11 failed,
29 passed in 0.46 s**. The current checkout, original traffic files, and paused
traffic ledger were not changed by that baseline check.

The final suite command uses the available real decoder:

```sh
SPARC_TEST_TSHARK="$PWD/.tools/tshark/usr/bin/tshark" \
  .venv/bin/python -m pytest -q --tb=short
```

The worktree's entire suite is not claimed green while inherited failures
remain. Traffic work is preserved for its existing milestone.

## Actual native GUI exercise

An isolated script created two actual PeerService instances with encrypted
temporary identity stores, explicitly approved their fingerprints, created
native Chat windows, and sent a synthetic PNG through the real signed/GCM
record path. It invoked the receiver's actual **Accept and save** button with
a selected temporary destination, continued text chat, waited for verified
states on both peers, and asserted source/received byte equality.

The final synthetic transfer contained **376,250 bytes**. Original and recovered
thumbnails appeared in their corresponding conversations. Captured both peers
at 1000×850 and the receiver at 800×640, then exercised close during a second
image preparation. Compact windows retain vertical scrolling and an adjustable
history/inspector divider; the entire attachment need not fit in one viewport.

Ran actual local benchmarks (40 repetitions, 2 warmups), displayed the resulting
graphs, and exported performance and sensitivity SVGs. The script printed:

```text
PASS: real peer image transfer via Chat acceptance, concurrent text, exact bytes,
thumbnails, 1000x850 and 800x640, measured charts/SVG; 4 screenshots.
```

Final captures and SVGs are retained locally in
`.demo/image-analysis-evidence/`: `chat-sender.png`, `chat-receiver.png`,
`chat-compact.png`, `performance-graphs.png`, `performance-graphs.svg`, and
`sensitivity-graphs.svg`. All four captures were opened and visually checked.
The screenshot correction batch improved preview space and separated chart
labels for the actual system font metrics. Temporary peer identities and
transferred files were removed after the exercise; no private stores are
included in the retained evidence.

## Solo review and decisions

The review checked the feature diff against the approved design and plan,
including cancellation/publication races, bounded queues, exact-session
ownership, no-overwrite publication, signed completion evidence, thumbnail
eviction, keyboard selection/focus, failed-result charts, units, and SVG output.

Confirmed defects were reproduced before correction:

- Sender's short-chunk inspection initially included tag bytes; corrected
  ciphertext slicing and added a real-codec regression.
- A non-string media hint leaked TypeError; strict validation now produces a
  domain error.
- Rebuilding history initially registered callbacks per row on every refresh;
  one coordinate/tag click binding now keeps callbacks bounded.
- Selected older images did not reload evicted previews; selection now requests
  the selected image within the same sixteen-thumbnail budget.
- Progress refreshes destroyed keyboard focus on Cancel; focus now follows the
  corresponding recreated control, or returns to history when it disappears.
- Failed analysis runs retained stale charts; failures now clear the chart.
- Large native fonts exposed cramped history and overlapping tick/axis labels;
  font-aware pane sizing, horizontal units, and explicit workload categories
  resolved those issues. Existing timing visibility remains regression tested.

Rulings carried during execution:

1. Explicit solo execution also applies to final review. This was author
   self-review, with no independent reviewer; that limits review independence.
2. The user's implementation approval authorized continuous execution of the
   plan after design approval; no additional approval round was introduced.
3. The old Listbox-specific test assertion was updated to check the same two
   distinct text messages in the approved mixed-content conversation surface.
4. Renamed the GUI chart test file to avoid pytest's unit/GUI basename import
   collision; test coverage and product behavior were unchanged.
5. Workload values are discrete, explicitly labeled categories so closely spaced
   sizes do not collide. Do not interpret their horizontal separation as a
   continuous linear payload-size scale.
6. Existing traffic failures remain outside this feature's implementation scope,
   with baseline evidence above. They prevent a whole-worktree green claim.

Deferred minor: the intermittent Tk variable cleanup warning above remains;
its source needs a separate targeted lifecycle investigation. No outstanding
critical/important findings in the reviewed feature scope.
Linux loopback and native Tk evidence does not establish native macOS,
Linux↔Mac LAN behavior, physical-device performance, or completion of the
separate traffic-analysis milestone.
