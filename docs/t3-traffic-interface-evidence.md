# Offline traffic interface verification

The paused Traffic Analysis work was resumed in the existing
`feat/sparc-progress-check` worktree after the completed image/results/native-UI
changes. The newer recorded user preference for solo work supersedes the
historical model dispatch policy. Implementation and review were performed
inline; there was no independent reviewer. Main and existing demo sessions
were preserved; no merge or push was performed.

## Delivered behavior

`python -m sparc.traffic analyze` builds one index/summary pass, optionally
exports unfiltered PDML, then publishes an unsigned JSON report last. It
prevalidates source/output and output/output aliases, checks source hashes
between operations, preserves Decimal text and lists independently completed
artifacts when a later operation fails. Post-replacement durability uncertainty
retains the candidate and names the unconfirmed artifact.

The fifth Traffic Analysis tab discovers dependencies only when an action
starts. It reuses JobController's queue of 64 and one worker, with immutable
snapshots and main-thread rendering. Cancel waits for worker settlement using
a done event and a scalar terminal outcome; canceled callbacks cannot replace
prior completed data. Failed exports retain same-source results; new source,
tool or filter selections invalidate them. XML is visibly unfiltered.

The existing capture adapter now uses a local public FileCapture subclass
whose destructor does not initiate another cleanup operation. The supervisor
remains the sole owner of `close_async`. A malformed decoder can make PyShark's
cleanup raise; this still reports `capture_cleanup_failed`, without retrying
cleanup against an already-closed event loop from a finalizer. No stronger
process-termination guarantee is claimed.

## Tests and review

Tests-first CLI gate: 12 expected failures for the absent command. Initial
implementation passed all 12, but a real malformed capture exposed the PyShark
finalizer warning. A dedicated adapter test failed before the ownership
correction; adapter/CLI verification then passed 26 tests in 4.09 seconds
without warnings. Additional JSON serialization, file-sync, replacement and
KeyboardInterrupt fault checks passed in the 16-test CLI gate (3.23 seconds).

Tests-first GUI gate: five expected failures for the absent tab. Initial native
verification passed five in 5.32 seconds. Expanded traffic/app/startup checks
passed 14 in 5.61 seconds, covering lazy dependency loading, once-only
registration, canceled dialogs, late results, unconfirmed cleanup, retained
results, generation changes and main-thread rendering.

Solo final review checked source agreement, publication and cancellation
ordering, bounded XML element ownership, worker/Tk separation, version and
measurement provenance, and five-goal/13-criterion documentation. It reproduced
a directory-close retry after a descriptor might already have been released,
and an outer index-stage setup leak after a permission fault. Failing
regressions preceded both corrections. The writer and shared publication
helper relinquish descriptor ownership before closing; failed setup closes
its owned descriptor and removes its stage. The affected index/export/CLI gate
passed **70 tests in 3.00 seconds**.

The first combined regression passed **1,186 tests, 9 platform skips in
200.31 seconds**, with no warning summary, before these final review corrections.
The final source regression passed **1,193 tests, 9 native Windows-only skips
in 197.42 seconds**, exit 0, with no warning summary:

```sh
env DISPLAY=:1 SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark .venv/bin/python -m pytest -q --tb=short
```

The full output is retained in `.demo/t3-final-regression.log`. Product source
was frozen for the run; subsequent changes only record its result. The nine
skips do not establish Windows compatibility, which remains outside current
requirements. `pip check` found no broken requirements; Git whitespace and
workflow/evidence local-link checks passed. No open important findings or
deferred minors remain for this scoped traffic implementation.

## Actual native and command evidence

Retained ignored artifacts live under `.demo/t3-evidence/`. The actual command
was:

```sh
.venv/bin/python -m sparc.traffic analyze tests/fixtures/traffic-small.pcap --report .demo/t3-evidence/report.json --sqlite .demo/t3-evidence/index.sqlite --xml .demo/t3-evidence/details.xml --tshark .tools/tshark/usr/bin/tshark
```

It exited 0. Independent checks in `agreement.json` confirm the unchanged
source hash, five SQLite/PDML packets, 262 captured bytes, Decimal `65.5`
captured bytes/s, ARP SQL NULLs and `PRAGMA integrity_check = ok`. Actual
versions and both conversion timing/size records are retained in the JSON
report. The source is the independent five-frame synthetic fixture, SHA-256
`bce1ddb3889550c41193e4cec7486f40547518c3f9840ca6fb1ba58332219505`.

`native_smoke.py` ran actual GUI analysis and exports with TShark. Inspected
screenshots `01-analysis-800.png` (800×640) and
`02-filtered-summary-unfiltered-export-1200.png` (1200×900) show reachable
controls and scrollable results. The filtered index has two packets, 108 bytes
and `108` captured bytes/s; an unfiltered XML export retains that analyzed
summary. `gui-checks.json` records these assertions and the unchanged source
hash. Existing peer windows were left intact.

These are Linux native-GUI and synthetic-fixture decoder results. Genuine
secure/baseline PCAPNG conversion, native macOS tool/GUI behavior, physical
Linux–Mac communication, and measured attack detection/recovery outcomes
remain pending. The five-goal and 13-criterion evidence map preserves these
limits. No simulated fixture or mock is presented as physical capture evidence.
