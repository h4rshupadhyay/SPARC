# Progress-check evidence and report outline

Use explicit evidence labels in a report: **automated test**, **Linux local
GUI**, **independent-process simulation**, **external physical-device run**, or
**pending**. Tests establish behavior under their stated conditions. They do
not substitute for an actual Windows-to-Linux session, packet capture, or
workload measurement. Current retained simulation files are ignored local
artifacts under `.demo/c8-evidence/`, not committed evidence for another
machine.

## Five security goals

| Goal | Concrete evidence | Current status and limit |
| --- | --- | --- |
| Confidentiality | `tests/unit/test_records.py`, `tests/integration/test_handshake_sockets.py`; simulation run at `.demo/c8-evidence/simulation.json` | Automated record protection and local socket behavior are covered. The external secure-versus-baseline capture is pending; public handshake, endpoint, size, and timing metadata remain visible. |
| Integrity | `tests/unit/test_records.py`, `tests/integration/test_peer_service.py`, `tests/integration/test_simulation.py` | Tamper/replay rejection and observed message/receipt evidence have automated coverage; the simulation records actual transfer verification. |
| Authentication | `tests/integration/test_handshake_sockets.py`, `tests/integration/test_service_pairing.py`, `tests/gui/test_connection_view.py`, `tests/integration/test_simulation.py` | Signed handshake and trust decisions are covered in tests and independent-process simulation. Manual fingerprint comparison on two physical devices remains pending. |
| Accountability | `tests/unit/test_audit_verify.py`, `tests/unit/test_audit_checkpoint.py`, `tests/integration/test_simulation.py`; `.demo/c8-evidence/{alice,bob}/public-key.hex`, `audit.jsonl`, `retained-checkpoint.json`, and `.demo/c8-evidence/audit-evidence.json` | The controller independently verified both retained logs (seven records each). A tail-removal copy fails with its retained checkpoint; an unanchored prefix cannot prove that a tail was not removed. These are local ignored artifacts. |
| Availability | `tests/integration/test_record_pacing.py`, `tests/integration/test_availability.py`, `tests/integration/test_heartbeat.py`, `tests/integration/test_service_shutdown.py`; finite local captures under `.demo/a3-evidence/resources-1bf14715c72f41f2b11a2deacae219cd/` | Bounded policies, loss/reconnect behavior, and shutdown cases have named automated coverage. The retained captures record an idle listener and one finite 50-connection invalid-handshake exercise with one-second CPU/RSS samples. They do not measure declared-loss or recovery latency and do not establish protection against arbitrary network denial of service. |

## Thirteen acceptance criteria

| # | Acceptance criterion | Existing evidence and current status |
| --- | --- | --- |
| 1 | Install dependencies and start the same Tk application on Windows and Linux. | Linux diagnostic/GUI checks: `tests/integration/test_check_cli.py`, `tests/integration/test_gui_cli.py`, and `tests/gui/test_app.py`; `python -m sparc --check --data-dir PATH`. Windows installation and actual Windows startup are **pending**. |
| 2 | Configure IP/port, connect, approve a fingerprint once, and recognize it on reconnect. | `tests/gui/test_connection_view.py`, `tests/integration/test_service_pairing.py`, `tests/integration/test_simulation.py`; the simulation uses actual comparison decisions. Two physical devices are **pending**. |
| 3 | Exchange Unicode text in both directions and show confirmed delivery. | `tests/integration/test_peer_service.py`, `tests/integration/test_handshake_sockets.py`, `tests/integration/test_simulation.py`; includes newline/Unicode behavior and observed delivery evidence. |
| 4 | Use AES-256-GCM with fresh session keys and nonreused directional nonces. | `tests/unit/test_crypto.py`, `tests/unit/test_records.py`, `tests/integration/test_handshake_sockets.py`, `tests/integration/test_availability.py`. These are implementation tests, not a physical packet-capture claim. |
| 5 | Display SHA-256 values, signatures, and validation outcomes in the GUI. | `tests/gui/test_chat_view.py`, `tests/gui/test_audit_view.py`, `tests/integration/test_peer_service.py`; Linux GUI behavior only. |
| 6 | Reject tampering, signature failures, replay, and changed peer identities. | `tests/unit/test_records.py`, `tests/integration/test_handshake_sockets.py`, `tests/integration/test_service_pairing.py`; covers altered records and identity decisions in automated cases. |
| 7 | Verify signed audit chains and detect changes; demonstrate checkpoint-relative deletion using an independently retained checkpoint. | `tests/unit/test_audit_verify.py`, `tests/unit/test_audit_checkpoint.py`; `.demo/c8-evidence/audit-evidence.json` reports independent verification and tail-removal rejection with retained checkpoints. Keep checkpoint copies separate from log copies. |
| 8 | Exercise heartbeat, rate limits, bounded reconnect, and measured availability outcomes. | Bounded behavior tests: `tests/integration/test_record_pacing.py`, `tests/integration/test_heartbeat.py`, `tests/integration/test_availability.py`. Measurement outcomes are **pending**; test pass status alone is not a measured availability result. |
| 9 | Report sensitivity experiments with operands, formulas, observed data, and aggregate results. | A1/A2 automated checks and actual synthetic-local CLI artifacts: `.demo/a2-evidence/lab/` contains 6,400 plaintext and 12,800 key flips. Raw CSV reconstruction agrees with all six mode/metric summaries. These are synthetic operands, not live session data. |
| 10 | Separate and export local, network, audit, resource, and conversion performance results. | A2 local primitive benchmark/export: `.demo/a2-evidence/local-benchmark.csv` contains 18,000 successful timings with independently reconstructed summaries. The A3 loopback run at `.demo/a3-evidence/b43fafc2b06c45cc900a5207780c80ee/` used two peer services in one process and contains 300 verified receipt rows (100 each at 64, 1,024, and 16,384 bytes), 10 warmups per size (30 total), and four resource samples. Raw receipt rows are in `network.csv`; the controller independently checked reconstruction and records it in `reconstruction.json`. Finite resource exercise artifacts are under `.demo/a3-evidence/resources-1bf14715c72f41f2b11a2deacae219cd/`. These are local simulation measurements; physical-device and conversion measurements remain pending. |
| 11 | Provide external Wireshark evidence for secure traffic and a separate plaintext baseline; reconcile XML, SQLite, and automated summaries with source capture. | Baseline CLI behavior: `tests/integration/test_plaintext_baseline.py`; secure CLI contract: `tests/integration/test_simulation.py`. Capture steps are in [the demo guide](progress-check-demo.md). Actual PCAP/PCAPNG, PDML, SQLite, and PyShark outputs are **pending Traffic Analysis (T1–T3)**. |
| 12 | Use two physical devices or explicitly identified independent-process simulation and justify evidence for all five goals. | `.demo/c8-simulation.json` and `.demo/c8-evidence/simulation.json` document two independent local processes, distinct identities/directories/ports, actual peer comparisons, verified transfers, and normal cleanup. This is simulation evidence; physical cross-platform evidence is **pending**. Goal-by-goal limits are in the table above. |
| 13 | Ensure shutdown, canceled work, and failed connections leave no hanging GUI operations. | `tests/integration/test_service_shutdown.py`, `tests/gui/test_app.py`, and `tests/integration/test_simulation.py` cover bounded cleanup paths. Windows GUI lifecycle remains **pending**. |

## Reproducible report fields

For every run, record the evidence label, date/time and timezone, OS, Python
and dependency versions, test command or GUI steps, endpoint/port, payload
size, sample count, result, artifact path, and known limits. Keep automated
test output, local GUI observations, simulation artifacts, and physical-device
artifacts distinguishable.

When later Analysis work is available, report local sender/receiver operation
timings separately: hashing/signing/encryption and decryption/hash/signature
verification. These are local `perf_counter_ns` intervals; do not subtract
timestamps from different processes or devices. A receipt's `finished -
started` duration is meaningful only within the process that produced those
monotonic timestamps. Report confirmed UTF-8 text bytes over the measured
interval as application goodput, separately from cryptographic throughput and
Wireshark captured-byte rate.

For controlled loss and bounded workload runs, record workload parameters,
rejection counts, one-second CPU/RSS samples and peak observed RSS, time from
last valid activity to declared loss, reconnect attempts and completion time,
fresh-session identity evidence, outcome, and confirmed goodput. Label the
specific test conditions; do not generalize them to arbitrary floods. The
retained A3 finite local exercise includes resource samples for an idle listener
and a bounded invalid-connection workload. It does not record measured
detection or recovery times, fresh-session recovery evidence, or goodput for an
attack workload; those results remain unavailable.

For future capture conversion, retain the source capture and its SHA-256;
record Wireshark/TShark/PyShark versions, filters, packet counts, included
captured bytes, conversion elapsed time, output sizes, completion status, and
cross-check results. PDML export, SQLite import, traffic summaries, and
conversion-efficiency measurements remain pending. Captured-byte rate is not
application goodput, and dissector retransmission indicators are not proof of
an attack.

## Evidence handling and report order

Retain each public key, signed log, and signed checkpoint as separate files.
The private identity file (`identity.json`) and session keys are secret and
must never appear in exports or screenshots. A log plus its independently
retained signed checkpoint supports a tail-deletion check; the log alone cannot
prove that a suffix was not removed. Record the verification result and the
exact checkpoint used.

The [demo guide](progress-check-demo.md#retained-audit-evidence) contains a
copy-only verification recipe for an untouched log, a tail-removed copy, and a
modified-signature copy. Its [bounded availability section](progress-check-demo.md#bounded-availability-exercises)
lists the finite pacing, heartbeat, and reconnect test commands and describes a
separate manual receiver-stop/restart observation. These are reproducible
procedures, not completed measurements; retain actual outputs and timing data
before reporting measured outcomes.

Suggested report order: (1) scope and evidence labels; (2) environment and
setup; (3) pairing and bidirectional text result; (4) security-goal evidence;
(5) audit/checkpoint verification; (6) bounded availability behavior and
measured results when available; (7) Wireshark secure/baseline comparison and
conversion outputs when available; (8) criterion-by-criterion status and
limitations. Leave pending sections visibly pending rather than filling them
with estimates.

## Retained local analysis evidence

On 2026-10-09, the default sensitivity command and six-operation local benchmark command completed in the Linux worktree. Their ignored artifacts are under `.demo/a2-evidence/`; `reconstruction.json` records independent raw-row checks. The A2 focused gate passed 47 tests, including a huge-seed CLI regression, and the independent Sol milestone review passed. Local operation timers exclude key generation, encoding, nonce/AAD preparation, I/O, and audit work. The measured throughput uses plaintext workload bytes over summed primitive durations; it is separate from confirmed network goodput. No physical-device performance result is claimed.

The retained A3 loopback run uses two peer services in one process, the default three payload sizes, 10 warmups per size (30 total), and 100 measured sequential messages per size. All 300 receipt rows completed. `network.csv` contains the raw verified receipt rows; the controller independently checked summary reconstruction and records that check in `reconstruction.json`. `operations.json` contains collected service operation events, and `run.json` contains the grouped result. Its measured confirmed goodput is application payload bytes over the receipt interval, separate from primitive throughput and captured-frame rate. Resource samples are sparse (four points during this run). The separate finite resource exercise records an idle listener and 50 bounded invalid loopback connections; its workload-specific captures do not establish arbitrary-flood resistance or provide detection/recovery timing. Physical-device evidence remains pending.
