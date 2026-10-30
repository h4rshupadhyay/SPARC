# Analysis presentation verification — 2026-10-31

The approved requirements and graph audits were implemented on
`feat/sparc-progress-check`, based on `ccc99ec`, in the existing isolated worktree.
The implementation extends the native Tk application without changing the live
wire protocol. The historical [requirements audit](audits/2026-10-31-analysis/README.md)
and [graph review](audits/2026-10-31-analysis/graph-review.md) describe the earlier
build; their screenshots are not the current interface.

## Suggested presentation sequence

1. **Message lab:** enter a custom message, analyze it, and show the six timing
   rows (scroll vertically), original/recovered text, matching digests,
   ciphertext and public signature in Details. Save JSON. Unicode size is in
   UTF-8 bytes; the signature covers those exact bytes.
2. **Diffusion / confusion:** use an exact 16-byte custom block and 32-byte lab
   key. Flip a plaintext bit for diffusion, then a key bit for key sensitivity.
   Show changed/total counts and references. Run a seeded batch for the
   distribution and conditional heatmaps, whose denominator is cases per input bit.
3. **Performance:** choose nine sizes, warmups and repetitions. Show
   encryption/decryption mean/p95, effective plaintext throughput and timing
   distributions. Switch to Sign/verify for microseconds and operations/s.
   Fixed legends and scope remain visible; SVG retains full provenance.
4. **Hash security:** run each full SHA-256 search: preimage, second-preimage
   and collision. The console contains definitions, attempts, outcome and any
   target/witness digests. No match in a finite run is inconclusive about
   cryptographic resistance. Message digest equality is a separate result.
5. **Signature specimen:** generate, verify, edit signed bytes/signature and
   observe rejection. Save/load JSON demonstrates stored public evidence and
   fresh verification. Edited data loses its earlier signing measurement;
   imported signing times are self-reported by the artifact.
6. **Traffic Analysis:** analyze a saved PCAP, show aggregate captured bytes/s,
   then Capture rate for nominal time-bin rates. Return to Summary for controls.
   Manual bind/peer IP and ports remain in Connection.

## Graph semantics

| View | Meaning and scope |
| --- | --- |
| Local duration | Primitive calls, including timer overhead; excludes key creation, encoding and I/O. AES-GCM processes a signed envelope; SHA-256 hashes original plaintext. |
| Effective plaintext throughput | Original plaintext bytes / successful primitive time; not processed-envelope throughput. |
| Signature operations/s | Inverse mean duration over the protocol's nearly constant-size signed context; not message-byte signing speed. |
| Timing distribution | Inclusive interpolated Q1/Q3, median and observed min/max from successful samples; whiskers are not confidence limits. |
| Single-trial sensitivity | Changed/total counts and percentages, with separately labeled bit, byte, coursework and hex references. |
| Histogram | Each mode normalized independently; five-percentage-point bins and a 50% reference. |
| Conditional heatmap | Each flipped input bit/output bit pair, denominators in cases; missing cells remain unmeasured. Pooled frequencies do not establish this criterion. |
| PCAP bins | Captured frame bytes / nominal bin width, with partial edges, adaptive coarsening, origin and source provenance disclosed; not plaintext goodput. |

The workload axis is logarithmic; measurements are never forced into a desired
curve. Avalanche observations do not prove Shannon confusion or AES security.
The 100% coursework character proxy target differs from the 99.609375% byte
model. Binary ciphertext has no natural Unicode-character interpretation.

## Native smoke and review

Real Tk jobs and temporary synthetic identities were exercised on Linux at
**800×640** and **1200×900**. Checks covered exact Unicode recovery, digest and
signature validity, six timings, JSON contents/private-key exclusion, custom
sensitivity operands, signature editing and save/load re-verification.

The benchmark produced **5,400 samples**: nine sizes × six operations × 100
measured repetitions, with two excluded warmups per operation/workload. A
five-case sensitivity batch retained **1,920 trials** and both conditional
matrices. All three SHA-256 searches ran with 1,000-candidate budgets. Real
TShark decoded five synthetic packets and **262 captured bytes**, conserved
exactly by the time bins. There were **zero Tk callback errors**.

The batched visual review found a squeezed message console, crowded workload
ticks and insufficient PCAP graph space. These were corrected and confirmed in
one follow-up round. Later timing-unit/scope copy changes are covered by GUI
tests. See the [contact sheet](audits/2026-10-31-analysis/implemented/contact-sheet.png),
[message console](audits/2026-10-31-analysis/implemented/02-message-result.png),
[PCAP graph](audits/2026-10-31-analysis/implemented/16-traffic-rate.png), and
[numeric smoke record](audits/2026-10-31-analysis/implemented/smoke.json).

Solo diff review reproduced and corrected hex formatting inside the hash timer,
public-key loading inside specimen verification timing, and JSON escaping of
the maximum control-character message exceeding the original artifact limit.
Regression tests cover these boundaries. Message/trial exports are capped at
512 KiB; signature imports at 256 KiB with a 64 KiB signed-input limit,
duplicate-field rejection and fresh validity checks. Malformed signature fields
have no primitive verification measurement.

## Validation and remaining limits

The full regression command, with `DISPLAY=:1` and `SPARC_TEST_TSHARK` pointing
to the real decoder, completed with **1,272 passed, 9 skipped in 219.31 s**.
The skips require Windows semantics. After the final artifact-size/encoding
metadata corrections, all **54 focused domain and GUI tests passed in 4.72 s**,
including the new maximum-message export regression. These focused checks cover
message input, artifacts, graph statistics, presentation forms and capture bins.

`python -m pip check` reported no broken requirements; `git diff --check` was clean.
The first run exposed a chat-image mapping failure that passed in isolation and
with its entire test module. The Traffic compact-layout regression was
reproduced and fixed without weakening its existing visibility assertions.

Physical LAN performance and Windows/macOS native appearance were not tested by
this change. The GUI covers the requested demonstration workflows; an exact
“50% GUI” mark requires the assessor's definition of that percentage. Finite
hash searches and avalanche samples make no cryptographic proof claims.
