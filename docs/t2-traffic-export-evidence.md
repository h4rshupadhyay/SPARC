# Offline index and PDML verification

T2 resumed on 2026-10-30 in the existing `feat/sparc-progress-check`
worktree at `6f4ea5a`. The latest user preference recorded in the UI work
ledger is solo execution, so this milestone was implemented and reviewed
inline. There was no independent reviewer. Existing unrelated documentation
edits, demo sessions, identities, checkpoints and lab outputs were preserved.

The previously paused T2a/T2b index and summary implementation was retained.
The fresh baseline reproduced the source hashing defect: two 1 MiB reads
after cancellation was requested by the first read. The corrected hash reads
at most 64 KiB and polls cancellation before and after every read. The index
and unfiltered PDML exporter share source hashing, version observation and
final publication helpers.

The exporter owns its subprocess and staging files, uses structured arguments,
checks incremental XML through EOF, counts direct PDML packet children and
removes completed XML elements. Existing outputs survive errors before
replacement. Durability failures after replacement retain the candidate and
report publication uncertainty. Analysis-only jobs remove their temporary
index before returning a result.

## Verification

The tests-first failure run produced 20 failures: 19 missing-export cases and
the reproduced hashing regression. The first implementation run passed 168
tests with one fixture error: a 31-byte XML literal was incorrectly expected
to contain 30 bytes. Correcting that arithmetic yielded 169 passing accumulated
capture/index/summary/export tests, with no skips.

Analysis-only tests then failed in four cases because `analyze_capture` was
absent; the real filtered and unfiltered export agreement cases already passed.
Inline review reproduced two additional errors with failing tests: a leaked
index file descriptor after fsync failure, and output-close uncertainty
classified as an ordinary XML error. Both were corrected before the final gate:

```sh
env SPARC_TEST_TSHARK=/home/harsh/SPARC/.worktrees/sparc-progress-check/.tools/tshark/usr/bin/tshark .venv/bin/python -m pytest tests/unit/test_sqlite_index.py tests/unit/test_traffic_summary.py tests/unit/test_traffic_exports.py tests/integration/test_capture_exports.py -q --tb=short
```

Result: **76 passed in 1.92 seconds**, exit 0, no skips or warning summary.
This is a scoped milestone gate; the final combined regression follows T3.

Actual TShark 4.6.6 and PyShark 0.6 decoded the independent synthetic fixture.
SQLite and PDML both contain five packets; the index contains 262 captured
bytes over four seconds, giving Decimal `65.5` captured bytes/s. Known fields,
SQL NULLs, XML structure, SQLite integrity and unchanged source hash/mode were
checked. With `tcp.port == 47655`, the index contains two packets and 108
captured bytes over one second; the separate PDML still contains five packets.
Source file size is 366 bytes and SHA-256 is
`bce1ddb3889550c41193e4cec7486f40547518c3f9840ca6fb1ba58332219505`.

These are Linux synthetic-fixture results. They do not establish native macOS
behavior, physical-device capture agreement, loss, latency or attack resistance.
Public facades leave evidence provenance `unspecified`; the fixture is
identified as synthetic in this evidence record.
