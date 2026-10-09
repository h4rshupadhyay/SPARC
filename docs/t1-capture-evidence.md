# T1 offline capture evidence

T1a–T1d are verified by the corrected gate. Sol's scoped T1 rereview passed: both identified failure-path findings are closed, with no introduced actionable issues. The milestone was committed as `803c391`.

## Focused red and green runs

The normalization correction began with a meaningful failure and passed after implementation:

```text
.venv/bin/python -m pytest tests/unit/test_capture_normalization.py -q --tb=short
RED: exit 1, 12 failed / 60 passed (0.25 s)
GREEN: exit 0, 72 passed (0.13 s)
```

TShark discovery likewise failed before the implementation and passed with normalization coverage:

```text
.venv/bin/python -m pytest tests/unit/test_tshark_discovery.py -q --tb=short
RED: exit 1, 9 failed / 1 passed (0.19 s)
GREEN: normalization + discovery, exit 0, 82 passed (0.26 s)
```

The adapter API-absence check collected and failed as expected before implementation:

```text
.venv/bin/python -m pytest tests/unit/test_capture_adapter.py -q --tb=short
RED: exit 1, 11 failed (0.19 s)
```

The T1d fixture-artifact red run collected and reported the missing builder/PCAP/manifest from inside the tests:

```text
env SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark .venv/bin/python -m pytest tests/integration/test_capture_stream.py -m tshark -q --tb=short
RED: exit 1, 3 failed (0.05 s)
```

After independent review, the targeted regression command reproduced all five findings before the two bounded source corrections:

```text
.venv/bin/python -m pytest tests/unit/test_capture_adapter.py::test_unrequested_reader_cancel_never_becomes_eof tests/unit/test_tshark_discovery.py::test_discovery_filesystem_errors_are_safe_domain_errors -q --tb=short
RED: exit 1, 5 failed (0.40 s)
```

Unexpected reader cancellation/`StopCapture` could previously become normal EOF, and explicit/PATH discovery filesystem exceptions could escape as raw errors. The corrections map unexpected reader termination to `capture_parse_failed` and ordinary discovery `OSError`/`RuntimeError` to `tshark_missing`.

The final corrected gate used the controller-provided TShark 4.6.6 binary and passed without skips:

```text
env SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark .venv/bin/python -m pytest tests/unit/test_capture_normalization.py tests/unit/test_tshark_discovery.py tests/unit/test_capture_adapter.py tests/integration/test_capture_stream.py tests/integration/test_check_cli.py tests/integration/test_gui_cli.py -q --tb=short
GREEN: exit 0, 111 passed (3.61 s), no skips
```

This was the corrected focused T1 and CLI gate at the milestone checkpoint. Earlier broader runs were interrupted; the subsequent combined main full-suite pass is recorded below.

## Real decoder and fixture

PyShark 0.6 with TShark 4.6.6 decoded all five packets in the deterministic synthetic PCAP. Captured and wire lengths each total 262 bytes; the source file is 366 bytes. Source SHA-256 is `bce1ddb3889550c41193e4cec7486f40547518c3f9840ca6fb1ba58332219505`.

The decoder observed `highest_protocol` values `TCP`, `TCP`, `ENIP`, `ARP`, and `DATA`. These labels are decoder observations; manifest protocol values describe constructed transport. The fixture verifies frame lengths 54, 54, 46, 42, and 66; timestamps 1 through 5 seconds; addresses and ports; and absent ARP/TCP-only fields. It contains synthetic traffic only and supports no attack inference.

## Cleanup boundary

The adapter uses one producer-owned event loop, one reader and one supervisor-owned `close_async()` call. Its two-second consumer join bounds caller waiting; it does not guarantee native decoder or process termination. PyShark's display-filter version probe can block synchronously, and coroutine timeout handling depends on cooperative cancellation. A timed-out join or unconfirmed cleanup is reported as `capture_cleanup_failed`; it is not reported as successful EOF or confirmed process termination.

Native macOS execution remains pending. The Linux decoder result and POSIX adapter checks are not native Mac evidence.

## Combined main integration (2026-10-10)

On user request, committed T1 checkpoint `803c391` was merged with local main
`898ea94`, retaining the Tkinter scrolling and scrollbar fixes from `c8393e7`.
Only the implementation-status documentation conflicted; both milestones'
evidence was preserved. T1 source, fixtures and tests match `803c391`; the GUI
source and tests match `898ea94`. Unfinished T2/T3 work and local lab/identity/audit
artifacts remain in the traffic worktree and are excluded from this integration.

The pre-merge main suite passed: **902 passed / 9 native Windows skips in
171.36 seconds**. The combined source was then verified with:

```sh
env DISPLAY=:2 PYTHONPATH=/home/harsh/SPARC/src SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark /home/harsh/SPARC/.worktrees/sparc-progress-check/.venv/bin/python -m pytest -q --tb=short
```

Result: exit 0, **1003 passed / 9 native Windows skips in 172.78 seconds**,
with no warning summary. This includes the real TShark 4.6.6 synthetic-capture
decoder checks and the native Linux Tk regression suite. Native macOS hardware
behavior remains unverified. T1 is usable through its Python API without T2/T3;
traffic storage, summaries, exports and CLI/GUI entry points remain pending.
