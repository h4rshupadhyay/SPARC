# Analysis tab audit for the information security project

**Historical audit of `ccc99ec`.** The recommended changes were subsequently
implemented; see [current workflow and verification](../../analysis-presentation-evidence.md).

Audited 2026-10-31, on `feat/sparc-progress-check` at `ccc99ec`, in
`/home/harsh/SPARC/.worktrees/sparc-progress-check`. This evaluates the current
build against the supplied requirements, ignoring the rough notes' pending
labels. It does not describe the older root checkout on `main`.

**Verdict: the cryptographic analysis foundation is substantially implemented,
but the tab is not yet a complete, self-contained demonstration of every
requirement.** The main gaps are custom input, a clear single-message hash and
encryption/decryption workflow, and specimen verification/export behavior.
Graphical analysis, diffusion experiments, signing time and three hash searches
already exist; they should not be scheduled as entirely new features.

This was an audit. Application code was not changed. Native screenshots, actual
experiment output, an exported-file reproduction, source inspection and existing
tests supplied the evidence.

The follow-up [graph suitability review](graph-review.md) checks chart choices,
statistics, units and what the plotted data can support, including fresh
captures and independent numerical verification.

## Requirements coverage

| Requirement | Current status | Evidence and qualification |
| --- | --- | --- |
| At least 50% GUI | Strong GUI coverage; exact rubric unverified | Core analysis operations run through native forms/buttons/results/charts. A percentage needs a defined denominator; source-code line counts would not establish it. |
| AES-256 encryption/decryption | Implemented; demonstration is fragmented | Local benchmark measures AES-256-GCM encrypt/decrypt. Chat performs real round trips. Analysis has no custom-text encrypt → ciphertext → recovered-text demonstration. |
| Diffusion, plaintext change | Implemented | Single plaintext-bit flips, exact bit/byte/hex differences, batch summaries and graphs. |
| Confusion/key sensitivity | Implemented as a key-avalanche illustration | Key-bit flips use a 256-bit key and a 50% output-bit model reference. This illustrates key sensitivity; it is not a proof of Shannon confusion. |
| Avalanche effect | Implemented | Single trials, 50-case batches, distributions and output-bit frequency plots. |
| 50% bit and 100% character targets | Present with appropriate distinctions | GUI separates the 50% bit model, 99.609375% byte model and 100% coursework target. Bytes are explicitly a character-level proxy. |
| Custom input for a single trial | Missing | Only Seed, Case, Mode and Bit index are accepted. The operands are generated internally. |
| Encrypt/decrypt time and speed graphs | Implemented | Mean/p95 duration and throughput plots, three allowed payload sizes, SVG export. |
| Hash digest displayed | Partial in Analysis; present in Chat | The security search shows a target or witness digest when one exists. There is no general custom-message SHA-256 calculator in Analysis. Chat's inspector displays actual message digests. |
| Hash time for one message | Present in Chat and benchmark samples; missing as a custom Analysis workflow | Local benchmark measures SHA-256 timing; live Chat shows per-message hashing time. Hash-search elapsed time measures the entire search, not one hash. |
| Preimage, second-preimage and collision resistance | Implemented as bounded experiments | All three full SHA-256 searches ran with 100,000 candidates. The GUI correctly says no match is not proof of resistance. |
| Hash matches in a console box | Partially satisfied; terminology needs clarification | Search definitions/outcomes/witnesses render in Details' text box. Actual sender/receiver digest equality renders as `Hash: match` in Chat's inspector. A normal collision-search run has no witness to display. |
| Signature displayed/stored | Partial for the Analysis specimen | Public key, signed bytes and signature are visible/editable. Live protocol evidence is stored in audit records. The specimen has no dedicated save/load path, and Save CSV can export the wrong result. |
| Signature generation and verification times | Both implemented in benchmarks; specimen verification time absent | Sign/verify graphs and raw timings exist. Specimen generation reports signing-only time; Verify specimen returns a boolean and clears the timing table. |
| PCAP performance, bytes/characters per second | Implemented in separate workflows | Traffic Analysis reports captured bytes/s. Analysis's connected-peer benchmark reports verified application bytes/s and characters/s. These are different measurements. |
| Manual IP configuration | Implemented in Connection | Bind IPv4, peer IPv4 and ports are editable. No need to duplicate networking settings in Analysis. |

## Findings to resolve before the presentation

### 1. High — Save CSV can export an older experiment after a signature specimen

Reproduction: run a local benchmark → Generate specimen → Verify specimen →
Details → Save CSV. The screen describes a verified specimen, but the file is
the earlier benchmark: **1,800 timing samples and 18 summaries**, marked
`test_type=local_cryptographic`, with no signature column.

See [export proof](specimen-export-proof.json),
[actual exported CSV](specimen-save-result.csv), and screenshots 06–09.
In `analysis_view.py:760` and `:782`, specimen result branches return before
`self._last_result = value` at `:821`. `_save_csv` at `:996` uses that retained
older result. This is a data/result association bug, not just unclear copy.

Required outcome: the visible result and its export must refer to the same
experiment. A specimen should have an explicit public artifact export or the
unrelated CSV action should be unavailable.

### 2. High — Custom single-trial input is absent

Screenshot 10 shows the complete sensitivity form. A presenter cannot enter
their own plaintext or key, or demonstrate an examiner-supplied message.
`_run_trial` at `analysis_view.py:554` passes only seed/case/mode/bit index;
`sensitivity.py:64` generates both operands internally.

Required outcome: accept custom lab input with an explicit encoding, validated
AES key/block sizes or a clearly explained message-to-block policy, and show
original/modified inputs alongside their outputs. Preserve the reproducible
seeded experiment as a separate option. AES-256 has a 256-bit key and a
128-bit block; those are different lengths. [NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).

### 3. High for this rubric — There is no unified single-message demonstration

The Analysis performance form accepts sizes rather than message text. Its
benchmark discards the actual hash/ciphertext outputs and returns measurements.
Hash security accepts a property, seed and budget rather than a message. The
signature generator uses fixed synthetic specimen text.

Consequently, a live demonstration of **this input → encrypted data → recovered
input → SHA-256 digest/time → signature/sign time → verification/time** requires
switching to Chat and using a connected peer. That functionality is partly
present elsewhere, but the Analysis tab alone cannot satisfy the intended
custom-input presentation.

Required outcome: make those values discoverable together for a chosen lab
message, with copy/export and clear units. Keep primitive benchmarks and live
network measurements visibly distinct.

### 4. Medium — Specimen verification drops the useful timing presentation

Screenshots 06–08 show a generation-time row, followed by an empty table after
Verify specimen. The validity result works, including rejection of edited data,
but no verification duration is returned or displayed for that specimen.
`specimen.py:52` returns only `bool`; `analysis_view.py:782` clears the table.

This does **not** mean verification timing is entirely unimplemented: the local
Sign/verify benchmark already measures and graphs it. The missing behavior is
the single-specimen result and an exportable link between signature, input,
validity and its two timings.

### 5. Medium — “Unavailable” conflates several normal states

The audit reproduced three distinct cases:

- Before generating a specimen: `Signature generation: unavailable` means not
  measured yet (screenshot 05).
- A collision search with no collision: `Target / matching digest: unavailable`
  means no matching witness exists, and a collision search has no fixed target
  (screenshot 17).
- Operation metrics: unavailable frame bytes for an audit/handshake observation
  means the event did not supply that field (screenshots 23/23a).

Outgoing Chat also has no receiver-side recomputed digest in its local
inspection, so `Hash: unavailable` there is not evidence of failed hashing.
On an actual incoming message the audit observed equal digests and **Hash:
match** (screenshot 22b).

Required outcome: distinguish **Not run yet**, **No collision found within
100,000 attempts**, **Not applicable**, and **Not reported by this event**. Keep
failures and genuine missing measurements separate. `_display` at
`analysis_view.py:877` currently maps every `None` to the same word.

### 6. Medium — The compact layout hides important presentation controls/context

At 800×640, the initial performance form puts its run buttons below the visible
fold (01); the hash form similarly pushes Run hash search below the fold (16).
Graphs remain usable, but the compact duration view requires scrolling to see
its legends, sample counts and provenance (03). Even the 1200×900 duration view
requires chart scrolling for all legend/context rows (02).

The operation-metrics table exposes six rows while leaving substantial blank
space below, and has a horizontal scrollbar but no visible vertical scrollbar
(23/23a). Wheel/keyboard scrolling can reveal later rows; its affordance is weak
for a live presentation. The generic Details table also occupies a large blank
area for three-row results and for a boolean verification result.

Required outcome: prioritize the selected experiment's primary action and its
essential interpretation. Give result tables appropriate height and visible
scroll affordances. Show human-readable microseconds in presentation views;
retain raw nanoseconds in exports.

### 7. Medium — Labels and scientific scope need a presentation explanation

Diffusion/confusion are reached through **Avalanche → Mode plaintext/key**,
although those are explicit rubric terms. A first-time viewer has to infer the
mapping until reading the graph or Details. The performance chart also omits
the algorithm name from its title; AES-256-GCM, SHA-256 and Ed25519 are clearer
presentation labels than “local cryptographic duration.”

The benchmark uses only **64, 1,024 and 16,384** plaintext bytes. These are valid
measurements, but three points do not establish a general scaling law. The
x-axis is logarithmic; line shape must not be interpreted as a linear-size
relationship. Preserve actual measured timings rather than requiring a curve
to look non-proportional.

The benchmark's byte throughput uses plaintext bytes, while AES-GCM processes a
serialized signed envelope and Ed25519 signs a near-constant-sized context.
Those definitions exist in source/export metadata; surface them during the
demo so signature throughput is not presented as raw bulk-signing speed.

## Captured walkthrough

All screenshots below were generated during this audit from the unmodified
application, with synthetic inputs. The complete set is in `screenshots/`.

### Step 1 — Local performance: works, with compact-layout limitations

Run local benchmark: three payload sizes, two warmups, 100 measured repetitions
per operation/size. Encryption/decryption, hash and sign/verify charts all
rendered. Duration means and p95 are separate; the SVG drawing model includes
measurement provenance. The initial compact form and chart context need scrolling.

![Step 1: initial compact form](screenshots/01-performance-start-800.png)
![Step 1: measured AES duration](screenshots/02-encryption-duration-1200.png)
![Step 1: signature generation and verification graph](screenshots/04a-signature-performance.png)

### Step 2 — Signature specimen: generation/verification work; saving is incorrect

Generation displayed a real Ed25519 signing duration and editable public data.
Original signatures verified; the generated demonstration reported rejection of
edited bytes/signatures. Manual Verify specimen displayed validity but no
verification duration. Save CSV reproduced finding 1.

![Step 2: generated signature fields](screenshots/07-signature-populated-form.png)
![Step 2: verification result without a timing row](screenshots/08-signature-verification-details.png)

### Step 3 — Single sensitivity trials: works for seeded inputs only

Plaintext-bit and key-bit runs both rendered graphs and exact differences.
For seed 42, case 0, plaintext bit 0, the result was **61/128 bits
(47.65625%)**, **15/16 bytes (93.75%)**, and **27/32 hex positions (84.375%)**.
There is no custom-input control.

![Step 3: single-trial controls](screenshots/10-avalanche-form.png)
![Step 3: exact differences and definitions](screenshots/12-diffusion-single-details.png)

### Step 4 — Fifty-case batch and graphs: works

The run completed **19,200 trials**: 6,400 plaintext-bit flips and 12,800
key-bit flips. Mean changed bits were **49.8575%** and **50.0338%**, respectively.
Mean changed bytes were **99.6133%** and **99.6392%**. These are observed results,
not hardcoded target values.

![Step 4: output-bit change frequencies](screenshots/14-avalanche-batch-frequency.png)
![Step 4: byte changes and the separate coursework target](screenshots/15-character-diffusion.png)

### Step 5 — Three SHA-256 searches: works within the stated bound

Collision, preimage and second-preimage runs each exhausted a budget of 100,000
full SHA-256 candidate hashes without a match. The GUI correctly describes this
as a bounded observation. Definitions, outcomes and available digests appear in
the Details text box. Collision's unavailable witness is the wording problem
in finding 5, not a failed hash computation.

![Step 5: collision result and its console text](screenshots/17-hash-collision.png)
![Step 5: second-preimage target/input digest](screenshots/19-hash-second_preimage.png)

### Step 6 — Manual IP and connected-peer performance: works outside/alongside Analysis

Connection exposes editable IPv4/port fields. Two temporary authenticated
localhost peers connected with explicit approvals. The GUI network benchmark
completed three repetitions per size and recorded verified bytes/s and
characters/s. These small runs establish the workflow, not a definitive network
performance result.

![Step 6: verified peer-receipt timings](screenshots/21-network-performance.png)

### Step 7 — Actual message hash/signature and metrics: works, but fragmented

A real custom text message showed its sender hash/sign/encrypt times in Chat.
An incoming message showed the actual sender and recomputed receiver digests,
their equality result, signature and receiver timings. Analysis operation
metrics remained a separate event table, rather than a message-level digest or
signature console.

![Step 7: actual matching message hashes](screenshots/22b-receiver-hash-match.png)
![Step 7: operation-metrics layout and unavailable values](screenshots/23-operation-metrics.png)

### Step 8 — PCAP analysis: works in Traffic Analysis

Actual TShark decoding of the deterministic five-packet fixture produced
**262 captured bytes / 4 seconds = 65.5 captured bytes/s**. The GUI explicitly
says application plaintext goodput is not measured here. SQLite and XML export
actions are discoverable; export correctness was not rerun in this audit.

![Step 8: decoded PCAP measurements](screenshots/24-pcap-performance.png)

## How to explain the cryptographic results accurately

**AES key size and block size.** AES-256 means a 256-bit key, while the AES
block remains 128 bits. The isolated sensitivity experiment therefore compares
128 output bits, even when it flips one of 256 key bits.
[NIST FIPS 197](https://csrc.nist.gov/pubs/fips/197/final).

**Targets are expectations, not mandatory outcomes for each trial.** Under an
idealized independent-output model, each bit differs with probability 1/2,
each byte with probability `1 - 1/256 = 99.609375%`, and each hex position with
probability `1 - 1/16 = 93.75%`. These percentages are a model calculation, not
a separate AES certification requirement. Keep 100% as the explicitly labeled
coursework character target, rather than marking a valid AES trial as broken
when a byte happens to remain equal. Binary ciphertext bytes and rendered hex
characters are different measurements.

**The avalanche experiment tests the AES block primitive.** It deliberately
uses isolated single-block AES with synthetic keys. Live messaging and local
message benchmarks use AES-GCM. GCM uses counter-mode encryption and an
authentication tag, so its message ciphertext must not be judged by applying
the isolated block's plaintext-bit avalanche rule to the entire message.
[NIST SP 800-38D, sections 6.5 and 7.1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

**Hash-search completion is not a security verdict.** NIST distinguishes
collision resistance, preimage resistance and second-preimage resistance.
Its table gives SHA-256 collision strength as 128 bits and preimage strength as
256 bits; second-preimage strength has a message-length qualification.
The program's 100,000-candidate experiment illustrates those search problems;
it cannot establish those strengths empirically.
[NIST hash-function definitions and security strengths](https://csrc.nist.gov/projects/hash-functions).

## Verification and limits

Fresh targeted checks:

```sh
env DISPLAY=:1 .venv/bin/python -m pytest tests/gui/test_analysis_view.py tests/gui/test_analysis_charts.py tests/gui/test_analysis_results.py tests/gui/test_analysis_navigation.py tests/unit/test_sensitivity_trial.py tests/unit/test_sensitivity_metrics.py tests/unit/test_sensitivity.py tests/unit/test_benchmark.py tests/unit/test_signature_specimen.py tests/unit/test_hash_security.py tests/unit/test_analysis_plots.py -q --tb=short
```

**145 passed in 17.15 seconds.** Existing tests passing does not invalidate the
requirements gaps or the exported-file reproduction. No regression fixes were
made as part of this audit.

The final native capture run exited 0 with no recorded Tk callback errors.
Its driver and logs are under `.demo/analysis-requirements-audit/`.
[Structured observations](observations.json), [export proof](specimen-export-proof.json),
and the two SVG artifacts preserve measurement evidence. All sensitive lab
identities were temporary; screenshots show public synthetic data and local
connection information.

Visual checks covered 800×640 and 1200×900 on Linux/X11. Native macOS, physical
LAN conditions, screen-reader behavior, complete keyboard-only navigation and
formal contrast conformance were not validated. Large text, labeled native
controls, tables alongside charts and solid/dashed series are useful strengths;
small-viewport scrolling and graph-context visibility remain accessibility
risks. No WCAG compliance claim is made.

## Recommended next work

1. Correct the visible-result/export association and define a public specimen
   save/load artifact.
2. Add the custom-message single-trial workflow, exposing input/output,
   recovered plaintext, digest, signature and individual timings together.
3. Preserve specimen generation timing when verifying and report its
   verification duration alongside validity.
4. Clarify unavailable/empty states and distinguish digest equality from
   collision/preimage search outcomes in the console.
5. Make the rubric's Diffusion, Key sensitivity/Confusion, Hash and Signature
   tasks easy to find, with primary actions and essential graph context visible
   at the presentation's target window size.

The existing AES plots, sensitivity engine, three bounded hash searches,
cryptographic benchmarks and PCAP importer can support these changes. They do
not need to be rebuilt to address the identified gaps.
