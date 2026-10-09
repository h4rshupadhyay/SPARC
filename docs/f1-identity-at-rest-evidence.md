# F1 identity encryption at rest — verification evidence

The user **withdrew Windows compatibility on 2026-10-09** and selected a MacBook for the demo. The Windows gate is no longer required. F1 is committed as `5dcf5df` after Linux verification; The macOS compatibility patch has Linux regression coverage; physical Linux↔macOS demo validation remains separate follow-up work. Linux implementation and independent source review are complete: the fresh post-correction full suite passed **830 tests**, with **9 native Windows skips**, exit **0**, in **152.97 seconds**. Both final review findings are fixed and scoped Sol rereview passed. T1 work has not started.

## Scope and environment

The approved [design](superpowers/specs/2026-10-09-sparc-identity-at-rest-design.md) and [F1a–F1h plan](superpowers/plans/2026-10-09-sparc-identity-at-rest-plan.md) define the implementation and gates. The existing worktree is `.worktrees/sparc-progress-check`, branch `feat/sparc-progress-check`, pre-F1 HEAD `777dc75`; A3 baseline is `b53453b`. No intermediate F1 commits were made. Existing unrelated plan edits were preserved, and the main checkout was unchanged.

All commands below ran from that worktree using its `.venv/bin/python`: Python **3.10.12**, cryptography **50.0.2**, OpenSSL **4.0.3 (29 Sep 2026)**. The root checkout interpreter lacks cryptography; dependencies were unchanged.

The implementation adds bounded Argon2id/Fernet identity storage, exact-key legacy migration, private Linux/Windows storage adapters, explicit service credentials, masked responsive GUI startup, hidden terminal input, read-only public diagnostics and bounded private simulation credential IPC. Trust/audit formats, ongoing peer connection behavior, wire protocol and analysis timing policies retain their existing contracts.

## Controller gates

Each unit followed reused Luna tests → controller meaningful RED → same Luna implementation → controller GREEN → bounded Sol specification/quality review. Collection/fixture failures were corrected and were not counted as meaningful RED. Detailed commands and corrections remain in [implementation status](implementation-status.md).

| Unit | Recorded unit/controller result | Exit | Review |
| --- | --- | --- | --- |
| F1a codec | 28 passed in 1.11 s | 0 | Sol clear |
| F1b storage/races/native contracts | 20 passed, 9 native Windows skipped in 3.55 s | 0 | Sol binding/provenance corrections clear; native Windows behavior pending |
| F1c lifecycle/identity/trust/audit | 150 passed in 6.90 s | 0 | Sol handoff/path corrections clear |
| F1d service and affected callers | 139 passed in 103.85 s; actual GUI connection view: 32 passed in 6.55 s | 0 | Sol clear |
| F1e GUI startup | 44 passed, 1 F1f-owned diagnostic test deselected in 8.38 s; no GUI skips | 0 | Sol root-close correction clear |
| F1f console/check/GUI CLI/analysis CLI | 23 passed in 1.88 s; full GUI CLI file, no exclusions | 0 | Sol clear |
| F1g simulation | 43 passed in 8.78 s | 0 | Sol clear |
| F1h final correction affected gate | 133 passed, 9 native Windows skipped in 17.89 s | 0 | Scoped final Sol clear |
| F1h fresh Linux full suite | 830 passed, 9 native Windows skipped in 152.97 s | 0 | Independent milestone + scoped correction review clear for source |

The final F1f gate was `.venv/bin/python -m pytest tests/integration/test_check_cli.py tests/unit/test_identity_console.py tests/integration/test_gui_cli.py tests/integration/test_analysis_cli.py -q --tb=short`. The F1g gate was `.venv/bin/python -m pytest tests/unit/test_simulation_credentials.py tests/integration/test_simulation.py -q --tb=short`. The final Linux suite command is `.venv/bin/python -m pytest -q`.

## Actual Linux smoke evidence

Controller scripts in the ignored plan workspace used dedicated disposable stores and fresh random in-memory credentials. They emitted public success status only; no credential screenshots, recordings, files, argv or environment transport were used.

- **Visible Tk startup:** masked create/confirmation, existing encrypted unlock without rewriting identity, wrong-passphrase Retry, successful same-fingerprint legacy migration, service/worker/dialog cleanup; exit 0. The actual Tk F1e gate additionally covered Cancel during blocked KDF, dialog/root window close during migration, and no service construction on cancellation.
- **Controlling terminal:** actual Linux PTY hidden unlock/create/confirmation, Ctrl-C and EOF cancellation, no credential echo, and exact terminal-attribute restoration; exit 0.
- **Legacy continuity:** identical migrated key signatures and fingerprint, unchanged pre-start trust/audit/checkpoint bytes, old audit signatures valid, and a real loopback peer accepting its retained legacy-key pin after migration and after encrypted-store service restart; both services closed, exit 0.
- **Coordinator loss:** actual spawned child received private-pipe EOF before credential delivery, exited within the bounded wait, created no identity/service/listener, and left no surviving child; exit 0.

One actual production Argon2id derivation used **65536 KiB, 3 iterations, 4 lanes, 32-byte output and a fresh 16-byte salt**: **0.080031 seconds**. No weaker profile or fallback was used. This is one local startup measurement, not a benchmark or cross-platform performance claim.

## Platform scope and commit gate

No real Windows NTFS runner/display was available. The following were unverified and are now **outside required scope**, rather than passed:

- Pinned Python/cryptography/OpenSSL versions and actual ownership/protected DACL behavior, tighter-rights preservation, locking, reparse/ancestor rejection and replacement/durability behavior.
- Native hidden terminal input/restoration, GUI cancellation and exact-key legacy migration.
- Actual production-profile Argon2id measurement.
- `python -m pytest tests/integration/test_identity_windows.py tests/unit/test_identity_codec.py tests/unit/test_identity_migration.py tests/unit/test_identity_console.py tests/integration/test_check_cli.py tests/integration/test_simulation.py tests/gui/test_identity_unlock.py -q`, then `python -m pytest -q` on Windows.

Linux source/contract checks and native-test skips do not establish Windows correctness or release readiness. The user’s explicit platform change removes Windows results from F1 completion requirements. Recorded Linux results and independent source review satisfy the remaining verification gate; the F1 commit still precedes T1. The borrowed MacBook has not been tested here. The bounded macOS default-path, POSIX-permission and directory-sync follow-up below is implemented; native startup, encryption, terminal/Tk and LAN demo validation remain pending.

## Recorded rulings

1. Use the pinned worktree interpreter instead of the root interpreter, which lacks cryptography. Cost if wrong: environment-specific results require rerun.
2. Encode absent simulation confirmation as an empty string and map it to `None`; the existing canonical JSON contract rejects null. Cost if wrong: private IPC consumers need adaptation; public/report schemas are unchanged.
3. Defer the F1f-owned `--check` test from the GUI-only F1e gate. Cost if omitted later: a missed CLI regression. This gate was discharged by the full F1f GUI CLI file, without exclusions.

No review findings remain open or parked. Independent milestone review found an Important directory-sync durability classification issue and Minor missing passphrase guidance. The single correction wave addressed both, and scoped Sol rereview found no introduced critical, important or minor issue. No behavior was declined for judgment; Windows execution is no longer a required gate after the user’s platform change; native macOS execution remains unverified.

The regression injected real directory-descriptor `fsync` errors `EINVAL` and `ENOSYS`: RED was 2 failed in 0.45 s because startup continued. The fix propagates these errors into `identity_commit_uncertain`, keeps the published encrypted identity without rollback and prevents service initialization. GUI/terminal create/migrate prompts now explain long unique phrases and offline guessing resistance without changing validation. The corrected affected gate passed 133 tests with 9 native Windows skips in 17.89 s; actual visible Tk and controlling-PTY smokes passed again.

The pre-correction Linux full suite passed 828 tests with 9 native Windows skips in 153.37 s. The source changes and two regression cases justified the fresh final run: 830 passed, 9 native Windows skipped in 152.97 s, exit 0. No subsequent unchanged full-suite rerun was performed.

Final scope checks: `git diff --check` exited 0; untracked F1 files had no trailing whitespace. The changed-file inventory remains within the approved F1 production/test/evidence scope plus the three preserved pre-existing plan edits. The main checkout is clean. Before the platform change, work was held uncommitted by the Windows gate. That gate has now been withdrawn; the ignored plan workspace remains available for resumption and macOS demo follow-up.

## Platform follow-up

The selected physical demo is Linux↔macOS. The bounded follow-up adds `~/Library/Application Support/SPARC`, extends private POSIX modes and directory synchronization to macOS while preserving Linux behavior, and updates Tk/setup guidance. Actual Mac startup, hidden credentials/cancellation, encrypted identity persistence, KDF timing and LAN exchange must be exercised on the borrowed MacBook before the demo. The user confirmed Apple Silicon with macOS Sequoia; no native results are invented.

Borrowed demo machine: Apple Silicon MacBook running macOS Sequoia (user supplied). Native validation has not run. At F1 milestone closure, the production/test surface matched the reviewed, final-tested 830-pass tree. The macOS follow-up below adds separately verified changes.

Milestone commit: `5dcf5df` (`feat: encrypt persistent identity keys at rest`). Controller staged exactly 39 F1/source/test/evidence and platform-scope files, checked the staged diff (exit 0), then committed successfully. The three pre-existing plan edits stayed outside the commit. No merge, push, T1 work or native macOS validation occurred.

## macOS compatibility patch verification

The Darwin branches run against actual Linux files, file descriptors, mode bits and fsync calls selected by a platform monkeypatch. This proves the branch contracts, not native Sequoia/APFS behavior. The patch adds the macOS default, private 0700/0600 modes, 0644 nonprivate output, preserved external export-parent modes, ordinary file-then-directory sync and macOS Tk guidance. Every Darwin directory-sync error propagates; identity post-replace errors retain the encrypted candidate, return `identity_commit_uncertain` and prevent service initialization. Linux unsupported-errno behavior outside identity storage remains unchanged.

Controller meaningful RED: 13 failed/33 passed in 5.33s. A single test observation was corrected after tracing two legitimate preexisting directory-verification calls; production stayed frozen. Focused GREEN with launch/check regressions: **56 passed in 5.84s**, exit0. Fresh frozen-tree full command `.venv/bin/python -m pytest -q --tb=short`: **847 passed / 9 native Windows skipped in 158.65s**, exit0. Independent Sol scoped source/quality review: clear, no findings. `git diff --check` is checked before staging. No native Mac execution or hardware-cache/power-loss guarantee is claimed.
