# Implementation status

This ledger tracks the task interfaces in `interfaces.json`. Evidence is recorded
only after the owning task's checks have run; commit references are added when
commits exist.

## Milestones

| Milestone | Tasks | Status |
| --- | --- | --- |
| C1 Shared types, encoding, identity and trust | C1a-C1d | verified |
| C2 Protocol and cryptography | C2a-C2f | verified |
| C3 Handshake | C3a-C3d | verified |
| C4 Audit | C4a-C4d | verified |
| C5 Peer service | C5a-C5g | verified |
| C6 Availability | C6a-C6d | verified |
| C7 GUI | C7a-C7e | verified |
| C8 Demonstration and baseline | C8a-C8c | verified |
| A1 Sensitivity analysis | A1a-A1c | verified |
| A2 Local benchmarks and exports | A2a-A2e | verified |
| A3 Network and resource analysis | A3a-A3d | verified |
| F1 Private identity key encryption at rest | F1 | pending (after A3, before T1) |
| T1 Capture normalization | T1a-T1d | pending |
| T2 Traffic indexing and exports | T2a-T2d | pending |
| T3 Traffic CLI and GUI | T3a-T3c | pending |

## Task ledger

| Task | Status | Test evidence | Commit ref |
| --- | --- | --- | --- |
| C1a | verified | pytest tests/unit/test_models.py -q: 4 passed; editable requirements install succeeded | 38d4d58 |
| C1b | verified | pytest encoding/models: 32 passed, no warnings | 38d4d58 |
| C1c | verified | pytest tests/unit -q: 42 passed; invalid-fixture serialization corrected without weakening checks | 38d4d58 |
| C1d | verified | unit/integration suite: 67 passed; review regressions fixed; --check and pip check successful | 38d4d58 |
| C2a | verified | framing/models/encoding: 42 passed; invalid fixture corrected, bounds retained | 317b919 |
| C2b | verified | messages/framing/encoding: 66 passed; signed fixture corrected | 317b919 |
| C2c | verified | crypto/messages/encoding: 84 passed | 317b919 |
| C2d | verified | finished/crypto/messages/framing: 77 passed | 317b919 |
| C2e | verified | outbound/finished/crypto/messages/framing: 81 passed | 317b919 |
| C2f | verified | full unit/integration suite: 172 passed; Sol review and hash timing regression fix passed | 317b919 |
| C3a | verified | handshake/records/finished/trust: 77 passed | 2f2e713 |
| C3b | verified | initiator/helpers/hello/framing: 41 passed; Sol role-boundary ruling approved | 2f2e713 |
| C3c | verified | responder/initiator/hello/finished: 54 passed, no warnings | 2f2e713 |
| C3d | verified | full unit/integration suite: 219 passed; phase regression fixed, Sol review passed | 2f2e713 |
| C4a | verified | audit format/records/encoding: 97 passed; evidence-binding regressions passed | a8ec46c |
| C4b | verified | audit verify/format/encoding: 98 passed | a8ec46c |
| C4c | verified | audit/identity/trust suite: 115 passed | a8ec46c |
| C4d | verified | full unit/integration suite: 330 passed; Sol review passed after report-count fix | a8ec46c |
| C5a | verified | full suite: 339 passed; idle-writer wake regression fixed | af7a5a1 |
| C5b | verified | full suite: 348 passed; bounded receipt and expiry oracles passed | af7a5a1 |
| C5c | verified | full suite: 356 passed; listener and trust snapshot oracles passed | af7a5a1 |
| C5d | verified | 37 pairing/listener/trust and 56 handshake/writer tests passed; audit endpoint serialization corrected | af7a5a1 |
| C5e | verified | send/writer/receipt suite: 29 passed; stale-owner receipt invalidation regression fixed | af7a5a1 |
| C5f | verified | receive/model/record/writer/send suite: 57 passed; signed peer evidence verified | af7a5a1 |
| C5g | verified | full suite: 404 passed; Sol review corrections and scoped gate passed | af7a5a1 |
| C6a | verified | Missing-module RED; rolling source/global/capacity tests: 3 passed | 9c7c8eb |
| C6b | verified | Focused 7 passed; 44 affected tests passed; audit-failure active-channel regression fixed | 9c7c8eb |
| C6c | verified | Heartbeat, pacing maintenance, writer and rate-limit suite: 28 passed | 9c7c8eb |
| C6d | verified | Full suite: 453 passed; audit-failure and full-queue regressions pass; Sol spec/security gate passed | 9c7c8eb |
| C7a | verified | Full C7 gate: 540 passed in 95.55s without warnings; finite bounded jobs and late-result shutdown covered | 0a6c0d4 |
| C7b | verified | Full C7 gate: 540 passed; Connection state, approval, forget and reachability regressions pass | 0a6c0d4 |
| C7c | verified | Full C7 gate: 540 passed; delivery reconciliation, bounded in-memory history, inspector and close cleanup pass | 0a6c0d4 |
| C7d | verified | Full C7 gate: 540 passed; stable-prefix snapshots, cancellation and checkpoint publication pass | 0a6c0d4 |
| C7e | verified | Full C7 gate: 540 passed; lazy CLI launch, actionable Tk setup and platform guide pass | 0a6c0d4 |
| C8a | verified | Independent-process simulation; fresh core gate 526 passed in 95.93s; Sol fixes/re-review passed; actual retained evidence under .demo/c8-evidence | d1189c3 |
| C8b | verified | Separate lab-only baseline; simulation/baseline focused 40 passed in 7.20s; secure runtime remains isolated | d1189c3 |
| C8c | verified | All five goals and thirteen criteria mapped; copy-only audit/tamper example executed; links and bounded demo recipes checked | d1189c3 |
| A1a | verified | A1 gate 62 passed; Sol review large-seed fix verified RED to GREEN | 1cc050a |
| A1b | verified | A1 gate 62 passed; Sol review large-seed fix verified RED to GREEN | 1cc050a |
| A1c | verified | A1 gate 62 passed; Sol review large-seed fix verified RED to GREEN | 1cc050a |
| A2a | verified | A2 focused gate: 47 passed in 2.11s; default CLI raw-summary reconstruction passed; Sol milestone review passed | 0d3ed50 |
| A2b | verified | A2 focused gate: 47 passed in 2.11s; default CLI raw-summary reconstruction passed; Sol milestone review passed | 0d3ed50 |
| A2c | verified | A2 focused gate: 47 passed in 2.11s; default CLI raw-summary reconstruction passed; Sol milestone review passed | 0d3ed50 |
| A2d | verified | A2 focused gate: 47 passed in 2.11s; default CLI raw-summary reconstruction passed; Sol milestone review passed | 0d3ed50 |
| A2e | verified | A2 focused gate: 47 passed in 2.11s; default CLI raw-summary reconstruction passed; Sol milestone review passed | 0d3ed50 |
| A3a | verified | A3 post-correction all-GUI/network/resource/metrics/export gate: 101 passed in 22.18s; actual Tk/default loopback evidence and Sol review passed | uncommitted |
| A3b | verified | A3 post-correction all-GUI/network/resource/metrics/export gate: 101 passed in 22.18s; actual Tk/default loopback evidence and Sol review passed | uncommitted |
| A3c | verified | A3 post-correction all-GUI/network/resource/metrics/export gate: 101 passed in 22.18s; actual Tk/default loopback evidence and Sol review passed | uncommitted |
| A3d | verified | A3 post-correction all-GUI/network/resource/metrics/export gate: 101 passed in 22.18s; actual Tk/default loopback evidence and Sol review passed | uncommitted |
| F1 | pending | Pending | pending |
| T1a | pending | Pending | pending |
| T1b | pending | Pending | pending |
| T1c | pending | Pending | pending |
| T1d | pending | Pending | pending |
| T2a | pending | Pending | pending |
| T2b | pending | Pending | pending |
| T2c | pending | Pending | pending |
| T2d | pending | Pending | pending |
| T3a | pending | Pending | pending |
| T3b | pending | Pending | pending |
| T3c | pending | Pending | pending |

## Additional security task

- [ ] **F1: Encrypt persistent private identity keys at rest.** Requested on 2026-10-09; schedule after A3 tasks and their validation are complete, before starting T1. Execution order: A3 → F1 → T1 → T2 → T3. Replace the Base64-only private-key storage in `identity.json` with encrypted storage. The unlock mechanism and Linux/Windows behavior remain pending a Sol design decision; do not store an unprotected decryption secret alongside the encrypted key. Preserve the existing public key/fingerprint and audit verification when migrating version-1 identities, retain restrictive file permissions, and ensure wrong credentials, corruption, and migration failures never replace the identity. Include CLI/GUI unlock cancellation and regression coverage.
  - [ ] Before coding, Sol fixes the unlock mechanism, encrypted format, migration and failure contracts, plus exact lettered task interfaces, allowed files, and test assertions. F1 remains an additional pending milestone; these contracts and its lettered task breakdown must be fixed before execution.
  - [ ] Luna writes only the prescribed tests; the controller runs each meaningful RED check and records the actual command and result. The same Luna then implements each bounded task; the controller runs GREEN plus affected identity, trust, audit, handshake, CLI, and GUI checks, recording actual commands and results per unit.
  - [ ] Before T1 starts, Sol performs an independent F1 security/integration milestone review. The controller commits F1 only after its gates pass and records the resulting ref here.
  Status: pending; implementation, tests, and milestone review have not started. Record actual evidence after execution.

## Unresolved decisions

C1-C6 Sol spec/quality reviews passed. C7 controller gate: 540 passed in 95.55s without warnings; focused layout checks: 3 passed in 0.79s. Sol's C7 re-review passed. Controller also completed a real single-process localhost GUI smoke with bidirectional Unicode/newline messages, audit operations, resizing, and close during work; direct-window captures confirmed approval controls, audit actions/head wrapping, and chat security details were reachable. This evidence covers the local GUI path only; Windows and physical-device behavior remain unverified and belong to later validation. C7 committed as `0a6c0d4`.

C8 controller gate: 526 unit/integration tests passed in 95.93s without warnings on the corrected runtime. Simulation/baseline focus: 40 passed in 7.20s. Sol scoped re-review passed after terminal-state barrier and nonzero child-exit corrections. Actual local independent-process report and separately retained public audit evidence are under `.demo/c8-evidence/`; copy-only tail-removal/signature-tamper checks passed. Physical devices, Windows, packet captures, and analysis measurements remain unverified/pending.

A1: reproducible public AES laboratory verified; 62 sensitivity tests passed. Sol reviewed formulas, baseline-once, cancellation and schema; arbitrary-size seed regression fixed with local decimal chunks. A2a statistics: 15 passed. A2/A3 remain in progress/pending; no new physical-device evidence.

A2 resumed on 2026-10-09: 47 focused tests passed in 2.11s. Huge decimal CLI seed regression fixed with local bounded parsing (RED: 2 failed/45 passed; GREEN: 47 passed). Real default sensitivity and local benchmark commands completed; independent reconstruction verified 19,200 lab trials (6,400 plaintext/12,800 key), 18,000 local timings, and all 24 summaries. Ignored artifacts: `.demo/a2-evidence/lab/`, `local-benchmark.csv`, `reconstruction.json`. Sol milestone spec/quality review passed with no findings (`.superpowers/a2-review.md`). These are synthetic local measurements; physical-device evidence remains pending.

A2 committed as `0d3ed50`. Fresh unit/integration regression gate: 650 passed in 101.38s (local sockets required sandbox escalation). A3a network receipt and A3b bounded sampler focused gates pass; Analysis GUI and A3 milestone review remain pending.

A3 measured loopback run: `.demo/a3-evidence/b43fafc2b06c45cc900a5207780c80ee/` contains 300 measured verified receipts plus 30 warmups, all three default sizes, CSV reconstruction checks, four one-second CPU/RSS samples, and independently verified retained signed audit logs/checkpoints. Evidence mode is **two services in one Linux process**; it is not a physical-device or independent-process claim. Sol found cancellation during summary aggregation could retain earlier goodput; regression reproduced and fix passed the 20-test network/resource focus. GUI and remaining A3 work/review pending.

A3 completed: post-correction gate `python -m pytest tests/gui tests/unit/test_operation_metrics.py tests/unit/test_resources.py tests/integration/test_network_benchmark.py tests/unit/test_analysis_export.py -q`: 101 passed in 22.18s. Earlier full unit/integration/GUI gate: 728 passed in 121.28s, before the final bounded metadata/layout/redraw corrections. Actual native Tk smoke passed default sensitivity/local runs and exports, valid/edited signature specimen, resource Finish/Cancel, explicit audit metric export, resizing and close. Native captures are `.demo/a3-evidence/gui/*.png`; `operations.csv` contains an actual scoped audit-verification row and policy metadata. Sol independent final A3 review passed (`.superpowers/a3-review.md`), including all correction dispositions. Controller-retained checkpoint copies outside peer stores anchor the benchmark log verification. Windows/physical-device checks, measured loss/recovery and traffic conversion remain unavailable/pending; no broader performance claim is made.
