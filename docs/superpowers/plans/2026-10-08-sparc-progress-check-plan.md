# SPARC Text-Only Progress Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a Tkinter application that exchanges authenticated, encrypted text between two peers and demonstrates all five security goals with reproducible analysis.

**Architecture:** The secure peer service owns identities, the signed handshake, encrypted records, durable audit events, and bounded availability controls. Independent cryptographic-analysis and offline-traffic modules provide runnable tools and integrate into the GUI after the core works. Tkinter remains on the main thread and consumes bounded worker events.

**Tech Stack:** Python 3.10+, Tkinter/ttk, cryptography, PyCryptodome, psutil, PyShark/TShark, SQLite, pytest.

**Spec:** [Approved text-only specification](../specs/2026-10-08-sparc-progress-check-design.md). Media-transfer notes are deferred and are not implementation requirements.

**Execution policy:** User-selected on 2026-10-08: GPT-6.1 Sol (`gpt-6.1-sol`) for planning/reasoning, GPT-6 Luna (`gpt-6-luna`) for coding, direct tools for command execution. This explicit policy overrides the generic native/subagent recommendation in the standard header. This revision changes task granularity and ownership, not the approved project scope.

## Global Constraints

- Text only; Windows and Linux; two physical devices or explicitly labeled independent-process simulation.
- Manual IPv4 addresses/ports; default listening address `0.0.0.0`; default port 47655; GUI port range 1-65535.
- AES-256-GCM, X25519 plus HKDF-SHA256, persistent Ed25519 identities, full SHA-256 fingerprints; no trust-any production option.
- Implement the exact transcript, canonical JSON, signing projection, frame types, AAD, sequence/nonce construction, and validation rules in spec sections 4-5; do not substitute an alternative protocol.
- 16-KiB UTF-8 text limit; 8-KiB handshake JSON limit; 128-KiB frame limit; one connection/handshake; pending requests 100; GUI events 1,024; chat history 500.
- Handshake phase deadlines: 20/150/150/10 seconds; local approval 120 seconds; overall 300 seconds. Incomplete connected frames and delivery acknowledgments time out after 10 seconds; cancellation is polled within one second.
- Connections: 20/source/minute, 60/global/minute, at most 256 source buckets. Application records: 200/second/direction, burst 400, with matching sender pacing.
- Heartbeat after five seconds of outgoing inactivity; peer loss after fifteen seconds without valid incoming activity; original initiator retries at most three times after delays 1, 2, 4 seconds with fresh sessions. Authentication/audit failures and explicit stop cancel retries.
- Durable signed metadata audit before successful receipt acknowledgment. Never persist chat plaintext or export live private/session keys. Checkpoint-relative deletion evidence must use an independently retained checkpoint.
- AES laboratory: 50 base cases, 128 plaintext-bit flips and 256 key-bit flips per case; distinguish bits, bytes, and hex characters.
- Local benchmarks: 64/1,024/16,384-byte payloads, 10 warmups, 1,000 measured calls; network: 10 warmups, 100 sequential measured exchanges per size. Mean, median, nearest-rank p95; no invented results.
- External Wireshark capture; one offline pipeline; PyShark/TShark dependencies load only when needed. XML/SQLite/CSV outputs are atomically published and cannot overwrite input captures.

## Review Focus

1. Oversized UTF-8 text and lone surrogate characters: reject locally without crashing a worker or GUI. Core C2 owns the test.
2. Interrupted/corrupt identity, trust, audit, or checkpoint files: fail closed while preserving evidence. Core C1/C4 own the tests.
3. Approval or worker events arriving after cancel, reconnect, or window close: do not authorize another session or touch destroyed widgets. Core C5/C7 own the tests.
4. A remembered endpoint presenting another identity during automatic reconnect: stop retrying and require deliberate re-pairing. Core C3/C6 own the tests.
5. Captures with missing network layers or nonpositive timestamp intervals: preserve NULL fields and report unavailable rates. Traffic T1/T2 own the tests.

---

## Execution order and independently testable plans

| Order | Plan | Deliverable |
| --- | --- | --- |
| 1 | [Secure application: C1-C8](2026-10-08-sparc-secure-app-plan.md) | Runnable connection/chat/audit GUI and two-process simulation |
| 2 | [Cryptographic analysis: A1-A3](2026-10-08-sparc-crypto-analysis-plan.md) | Runnable laboratory/benchmark tool plus Analysis tab |
| 3 | [Offline traffic analysis: T1-T3](2026-10-08-sparc-traffic-analysis-plan.md) | Runnable PCAP analyzer/XML/SQLite exporter plus Traffic Analysis tab |
| 4 | Release checks below | Complete five-tab application and evidence guide |

The revised breakdown contains **60 executable tasks**: 37 core, 12 cryptographic-analysis and 11 traffic-analysis tasks. Original milestone labels remain stable for the acceptance mapping below.

The 14 labels C1-C8, A1-A3 and T1-T3 are milestone groups, not single coding assignments. Each linked plan splits its groups into lettered executable tasks, such as C1a and C1b. Execute those tasks in their stated prerequisite order. Analysis and traffic share package/contracts but have no dependency on each other's internals; their GUI integrations require C7. Default to one active coder to avoid shared-file conflicts.

## Model ownership and small-task workflow

| Work | Owner | Deliverable |
| --- | --- | --- |
| Requirements, algorithms, protocol/security decisions, concurrency design and failure diagnosis | GPT-6.1 Sol | Fixed contracts, branch conditions, test assertions and correction instructions |
| Implementation, prescribed tests, bounded fixes and code/documentation edits | GPT-6 Luna | A focused patch for the current lettered task and phase |
| Dependency installation, test execution, Git, file checks, benchmarks and smoke commands | Controller using tools directly | Actual command output, exit status and measured artifacts |
| Security/integration review and final acceptance review | GPT-6.1 Sol | Findings against the specification and fixed acceptance checks |

No separate model agent is created merely to run a command. The existing controller invokes command tools; choosing/invoking those tools still has ordinary orchestration overhead. Check Git availability and the current environment through those tools.

Each Luna task implements one responsibility, normally one or two implementation files and a focused test file. Larger existing files may be edited only in the explicitly named functions. Start a worker with `fork_turns="none"` and only its task packet, approved interfaces, relevant spec excerpt and necessary source snippets/paths. Reuse that Luna worker for related units within a milestone and for each unit's separately verified red/green phases, sending small sequential packets. Worker reuse never combines units' acceptance checks or skips security milestone gates. Keep one coder active by default. When accumulated context is large or unrelated, roll over to a fresh task-local worker with a compact ledger summary and the next packet; do not resend whole conversations, specs or plans. The user's reuse preference overrides the generic Superpowers fresh-agent-per-unit rule. There is no promise that a particular model will solve every task on its first attempt.

The reviewed task packet supplies routine prerequisite checks and test oracles without a new Sol call. Before dispatch, Sol resolves any missing schema, algorithm, state transition, ownership rule or test oracle. Security-sensitive tasks receive exact decision rules; Luna does not redesign the cryptography or asynchronous lifecycle. The shared contracts and constants remain authoritative. A change to a public interface returns to Sol and updates dependent tasks before coding continues.

For each lettered task:

- [ ] Sol confirms prerequisites, allowed files, exact consumed/produced interfaces, prescribed test assertions and the verification command. This may reuse the reviewed plan without a new model call when no reasoning is needed.
- [ ] Luna writes only the prescribed tests. The controller runs the focused test command and records the expected behavioral failure; syntax/import/environment failures must be distinguished from a meaningful failing test.
- [ ] Luna implements only that task. The controller runs its focused verification and affected earlier tests using tools directly.
- [ ] If the failure is a local coding mistake with a clear prescribed fix, return the diagnostic to Luna. If it exposes a missing contract, security choice or concurrency ambiguity, stop that task with `BLOCKED_CONTRACT` and have Sol supply the missing decision. Do not weaken assertions, bypass authentication, skip durability or silently change models to get a pass.
- [ ] Update the compact implementation ledger with patch scope, real command results and status in the same existing coding/controller exchange; do not create a model call solely for history bookkeeping. The milestone gate owns the commit and traceability record.

Sol reviews each completed milestone group before dependent groups begin, with particular attention to handshake authentication, nonce/sequence assignment, audit-before-ack ordering, pairing cancellation, GUI thread access, bounded memory and export publication. Reviews receive relevant diffs/snippets and test evidence, not all-source dumps. Sol calls are reserved for milestone gates, security/contract exceptions, reasoning-dependent diagnosis and final review; do not add routine precheck or per-unit review calls. The final review covers the complete implementation and all 13 acceptance criteria.

The controller batches independent read/check commands, and runs focused plus affected earlier tests per unit; milestone gates and release checks cover broader integration/full suites. Do not print all source files. Report token/cost savings only when tool-provided usage metrics exist; otherwise describe these overhead controls without fabricated counts or guaranteed savings.

For documentation-only tasks, use the supplied content/link checklist and existing relevant runtime regression checks. Do not add tests that merely mirror the documentation or manufacture a failing test when no runtime behavior changes.

### Luna dispatch contents

Each coding assignment includes these fields, copied from its lettered task:

```text
Task ID and one concrete outcome:
Prerequisites already verified:
Allowed files and named functions:
Consumed and produced interfaces:
Exact spec constants / relevant algorithm or state transitions:
Prescribed test names and assertions:
Phase: tests only OR implementation after controller's red check:
Out of scope:
Return: task ID / phase / status; changed paths and at most five summary bullets;
        relevant diff/snippet or failing-test diagnostic only;
        any BLOCKED_CONTRACT discrepancy (no full file/source/log dumps).
```

The controller supplies the relevant actual failing output for the implementation phase and runs the verification commands itself. Luna may inspect relevant source and edit the allowed files; it must not independently install dependencies, commit, change acceptance assertions or expand scope. A Sol review finding must be converted to the same bounded assignment before Luna fixes it.

## Repository and environment handling

Git was initialized on 2026-10-08 at the user's request. The SSH origin is `git@github.com:h4rshupadhyay/SPARC.git`; an SSH repository check succeeded and returned no remote refs. No commits or pushes have been made. The current session has unrestricted filesystem/network access and approval policy `never`; do not prescribe escalation or `sandbox_permissions`. At execution, apply the worktree skill's environment checks against this actual repository and use direct tools for Git operations.

Commit at the stated milestone gates through direct tools when the repository is writable. Stage only completed milestone paths, including their history/ledger updates, run `git diff --cached --check`, and use the stated commit subject with covered lettered task IDs in the body. Record unavailable commits honestly in the ledger. No installs, GUI launches, commits or pushes occur during planning.

At implementation create `.venv`; all commands below use its Python after activation, or the absolute `.venv/bin/python` path on Linux. In PowerShell use `.venv\Scripts\python.exe`. Install with `python -m pip install -r requirements-dev.txt`. C1 defines exact direct-dependency pins and package extras. Retain a tested dependency/version manifest in evidence. Capture tools are external OS packages, not pip packages.

## Lightweight version history and persistent progress

C1a creates `CHANGELOG.md` and `docs/implementation-status.md`; these are maintained during implementation, not populated with invented completed work during planning. Keep the existing 60 task IDs and milestone gates.

- `CHANGELOG.md` starts with `Unreleased`, using Added/Changed/Fixed/Security categories as applicable. Record significant user-visible changes and security changes; omit routine tiny edits. Move tested release entries into the release heading when the release checks pass.
- `pyproject.toml` is the single package-version source, initially `0.1.0.dev0`. Avoid duplicate hard-coded versions and bumps per tiny task. Set `0.1.0` only for the tested text-only release after the required checks; the wire protocol remains version 1.
- Git milestone commits identify the covered lettered task IDs. The compact ledger has one task/milestone row with status (`pending`, `in_progress`, `blocked`, `verified`), concise test evidence (command/result or evidence path), and commit/ref (`uncommitted` when applicable). Add only concise unresolved decisions with owner/next step; record the milestone commit ref after committing without requiring an extra bookkeeping commit or model call.
- A tested local release record in the ledger identifies the release version/tag, exact tested commit, required check results and artifact paths, with unavailable physical-device evidence/skips stated explicitly. Create local tag `v0.1.0` only after checks and the release commit; publishing/pushing is outside this planning revision.

## Release tasks

- [ ] Review the revised task breakdown before implementation. Model roles are already selected; do not ask the user to choose native/subagent execution again.
- [ ] Complete all lettered tasks within C1-C8, A1-A3, and T1-T3 under the Sol/Luna/direct-tools policy, recording failing-to-passing checks and milestone reviews.
- [ ] Run `python -m pytest tests/unit tests/integration -q`. Ordinary tests must pass; missing-TShark tests must pass, and actual TShark integration must be run after the tool is installed. Report tool-related skips explicitly.
- [ ] Run `python -m pytest tests/gui -m gui -q` with an available display, then visually inspect all five tabs, resizing, readable security details, cancellation, and close behavior. Do not infer visual quality from import success.
- [ ] Run `python scripts/simulate_peers.py --data-root .demo/simulation --report .demo/simulation.json`; require distinct peer identities, authenticated bidirectional Unicode messages, verified receipts, valid audit logs, and a report labeled simulation.
- [ ] Follow `docs/progress-check-demo.md` for Windows-to-Linux when both devices are available. If not, deliver the permitted simulation and leave the physical-device check explicitly unverified.
- [ ] Produce real laboratory/benchmark CSVs, signed audit/checkpoint evidence, and converted packet artifacts from recorded/synthetic captures; label fixtures, simulation, and physical-device measurements separately.
- [ ] Map all 13 spec acceptance criteria to evidence in `docs/progress-check-evidence.md`; no fabricated screenshots, PCAPs, timing values, or unperformed availability tests.
- [ ] Have GPT-6.1 Sol perform an independent final review against the approved spec and plans; send bounded coding corrections to Luna and run affected checks through direct tools.
- [ ] After required checks/review pass, finalize the text-only `0.1.0` changelog/version, rerun relevant package checks for that metadata change, create the release commit and local `v0.1.0` tag, and record its exact commit/checks/artifacts in `docs/implementation-status.md`. Keep unperformed physical-device checks explicit; no push is authorized by this planning work.

## Spec-to-plan coverage

| Spec requirement | Tasks |
| --- | --- |
| Identities, manual IP/port, pairing and handshake | C1, C3, C5, C7 |
| AES-GCM, signed text, hashes, delivery and replay rejection | C2, C3, C5 |
| Accountability, audit errors, checkpoints | C4, C5, C7 |
| Availability, shutdown, rate limits, reconnect | C5, C6, C7, C8 |
| Avalanche definitions, local/network timings, exports | A1, A2, A3 |
| Wireshark baseline, PCAP XML/SQLite, PyShark | C8, T1, T2, T3 |
| Two-device/simulation and all-goal evidence | C8, release checks |

All 13 acceptance criteria have concrete owners:

| Criterion | Verification owner |
| --- | --- |
| 1. Both platforms install/start | C1/C7 setup; physical-device release check |
| 2. Configure, pair, recognize | C1/C3/C5/C7 |
| 3. Bidirectional confirmed Unicode | C5/C8 |
| 4. AES-GCM, fresh keys/nonces | C2/C3 |
| 5. Display hashes/signatures/outcomes | C7/A3 |
| 6. Reject tampering/replay/changed identity | C2/C3/C6 |
| 7. Signed chain/checkpoint evidence | C4/C8 |
| 8. Measured availability controls | C6/C8/A3 |
| 9. Sensitivity operands/formulas/results | A1/A2/A3 |
| 10. Separate exportable performance metrics | A2/A3/T2/T3 |
| 11. Secure/baseline capture and agreeing exports | C8/T1/T2/T3 |
| 12. Two devices or labeled simulation | C8 and evidence release check |
| 13. Shutdown/cancellation without hangs | C5/C7/A3/T1/T2/T3 |

## Execution selection and review status

Use the user's selected **Sol reasoning / Luna coding / direct command tools** workflow. It replaces the previous native-execution recommendation. Initial agent dispatch uses the explicit model IDs above and fresh task-local context (`fork_turns="none"`); reuse workers and roll over with compact ledger context as described in the authoritative cycle. No coding agents are dispatched during this planning revision.

Plan self-review: history creation belongs to C1a, version/tag release gates remain separate from wire protocol version, and reused-worker red/green phases retain independent controller verification. Ownership/cycle rules are centralized here; current repository/permission status is synchronized with the spec. The breakdown retains 60 unique lettered tasks in 14 milestone groups; declared prerequisite IDs and local links resolve; shared interfaces, checkpoint dependencies and audit-before-confirmation ordering were checked; all 13 acceptance criteria remain assigned. All five Review Focus conditions retain test owners. Media remains deferred. This is a planning artifact, not executed software; documentation validation cannot substitute for runtime tests.

Dependency references checked on 2026-10-08: [cryptography 50.0.2](https://pypi.org/project/cryptography/), [PyCryptodome 3.24.0](https://pypi.org/project/pycryptodome/), [psutil 7.2.2](https://pypi.org/project/psutil/), [PyShark 0.6](https://pypi.org/project/pyshark/), [pytest 8.4.2](https://pypi.org/project/pytest/8.4.2/). Pins are verified release choices, not a promise of compatibility before installation/tests.
