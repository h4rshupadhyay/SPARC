# Progress-check demo

This guide describes the current text-only demonstration. Mark evidence by
where it came from: **automated test**, **Linux local GUI**, **independent
process simulation**, or **external physical-device run**. The last category
has not been completed. A simulation does not establish Windows-to-Linux
behavior.

## Run the GUI on one machine

Create a fresh virtual environment and install the development requirements.
Use the commands for your shell from the [README](../README.md). Check startup
before opening the window:

```sh
python -m sparc --check --data-dir ./.demo/alice
python -m sparc --data-dir ./.demo/alice
```

For two local GUI instances, launch a second window with a different data
directory and listener port, such as `.demo/bob` on `47657`; both processes
cannot bind the same local address and port. Exchange the reachable local
addresses and ports, compare the full fingerprints through an independent
channel, and approve the first contact on both sides. Send a distinctive
synthetic Unicode message containing a line break, then inspect the delivery
status and audit view. Do not use real credentials or sensitive text in a lab
capture.

Linux local GUI checks have been performed. Windows installation, Windows GUI
operation, and an actual Windows-to-Linux exchange are still unverified.

## Independent-process simulation

The simulation starts two independent peer processes, each with its own
identity, data directory, and ephemeral listener port. It uses actual local
TCP sockets and does not exercise Tkinter. Run a fresh copy with:

```sh
python scripts/simulate_peers.py --data-root ./.demo/new-simulation --report ./.demo/new-simulation-report.json
```

The current controller smoke report is
`.demo/c8-simulation.json`. It records two peer process IDs, distinct
fingerprints, data directories and ports, two actual fingerprint comparisons,
two verified transfers, two seven-record audit verifications, normal cleanup,
and an elapsed coordinator interval of 1,118,448,998 ns. These are local
simulation observations, not physical-device or performance claims. The
simulation's default listener ports are ephemeral; a Wireshark filter for
`47655` alone will not capture that run. Use the reported endpoints when
capturing it, or use the GUI demo with fixed ports.

## Secure traffic and separate plaintext baseline

For a fixed-port capture, start SPARC with a listener on TCP port `47655` and
capture the active interface in Wireshark. On a single host, give the second
GUI process a different port and add that port to the filter. For two devices,
both may listen on `47655` on their respective addresses.

Use capture filter:

```text
tcp port 47655
```

Use display filter:

```text
tcp.port == 47655
```

Capture both directions, establish the connection, approve fingerprints, and
send a known synthetic string. Use **Follow → TCP Stream** to inspect the
reassembled conversation. TCP segmentation means an individual packet is not
necessarily one application message. Public handshake material, IP/port
metadata, lengths, and timing remain observable. The secure application
records should not expose the message as plaintext.

The comparison tool is a separate synthetic lab program and prints the
mandatory label **LAB ONLY: plaintext baseline**. In terminal A:

```sh
python scripts/plaintext_baseline.py listen --ip 127.0.0.1 --port 47656
```

In terminal B:

```sh
python scripts/plaintext_baseline.py send --ip 127.0.0.1 --port 47656 --text "LAB ONLY synthetic plaintext: café 雪"
```

Capture separately with capture filter `tcp port 47656` or display filter
`tcp.port == 47656`, then follow that TCP stream. The synthetic text is
readable. This program has no import path into secure runtime and no secure
CLI plaintext switch. Never send sensitive content through it.

For simultaneous Wireshark capture of both fixed-port demos, use capture filter
`tcp port 47655 or tcp port 47656` and display filter
`tcp.port == 47655 || tcp.port == 47656`. Inspect the secure and baseline
streams separately. A capture of a simulation with ephemeral ports instead
requires those actual reported endpoint ports.

## Retained audit evidence

The controller retained public evidence under `.demo/c8-evidence/`:

- `simulation.json` and `audit-evidence.json` summarize the run and independent
  verification.
- `alice/public-key.hex`, `alice/audit.jsonl`, and
  `alice/retained-checkpoint.json`, with corresponding `bob/` files, are
  public verification inputs.

The controller's audit-evidence result reports valid independent verification.
Removing the final audit record from a copy fails verification when checked
against its separately retained checkpoint; verifying the prefix without that
checkpoint cannot establish that a tail was not deleted. These are local,
ignored controller artifacts, not committed or portable capture files. Keep
the original signed checkpoint and public key separate from the log copy when
repeating this check. Do not copy identity or session private keys into the
bundle.

The following Python here-document copies only public evidence to a fresh
directory, verifies the untouched copy against its retained checkpoint, then
checks that both a removed tail and a modified signature fail. It never reads
or copies `identity.json`. Run it from the repository root with the installed
SPARC environment:

```sh
python - <<'PY'
from pathlib import Path
from shutil import copyfile
from sparc.audit import verify_log

source = Path(".demo/c8-evidence/alice")
work = Path(".demo/audit-copy-check")
work.mkdir(parents=True, exist_ok=True)
public_bytes = bytes.fromhex((source / "public-key.hex").read_text(encoding="ascii").strip())
original = work / "audit.original.jsonl"
checkpoint = work / "retained-checkpoint.json"
copyfile(source / "audit.jsonl", original)
copyfile(source / "retained-checkpoint.json", checkpoint)

good = verify_log(original, public_bytes, checkpoint)
print("original:", good)
assert good.valid and good.checkpoint_checked and good.verified_records == 7

lines = original.read_bytes().splitlines(keepends=True)
assert len(lines) == 7
tail_removed = work / "audit.tail-removed.jsonl"
tail_removed.write_bytes(b"".join(lines[:-1]))
removed = verify_log(tail_removed, public_bytes, checkpoint)
print("tail removed with independent checkpoint:", removed)
assert not removed.valid

tampered = work / "audit.modified-signature.jsonl"
record = lines[0]
needle = b'"signature":"'
start = record.index(needle) + len(needle)
replacement = b"B" if record[start:start + 1] != b"B" else b"C"
tampered.write_bytes(record[:start] + replacement + record[start + 1:] + b"".join(lines[1:]))
changed = verify_log(tampered, public_bytes, checkpoint)
print("modified record signature:", changed)
assert not changed.valid
PY
```

This preserves the source files and checkpoint. The examples demonstrate
verification on copies; they are not a substitute for retaining the checkpoint
independently in an actual evidence handoff.

## Bounded availability exercises

Run only the finite automated integration cases below in the repository's
development environment. They use controlled local test peers and bounded
fixtures; do not aim them at a public or shared network.

```sh
python -m pytest tests/integration/test_record_pacing.py -q
python -m pytest tests/integration/test_heartbeat.py -q
python -m pytest tests/integration/test_availability.py -q
```

These cover configured record pacing and receive-burst rejection,
connection-attempt limits, liveness timeout, fresh-session reconnect, no
automatic resend, and a finite retry budget. For a manual abrupt-loss/restart
observation, use two disposable local GUI data directories and a short
synthetic message: start both peers, pair, send once, then quit the receiver
while connected. Observe the initiator's state and retry outcome; restart the
receiver using its same disposable data directory and observe whether a new
authenticated session can be established. Only the original initiator retries
automatically (up to three attempts with 1, 2, and 4 second delays); the
responder waits for a connection. An unconfirmed message is not automatically
resent. A person may deliberately resend after reconnection. Record the actual
event/result and timing source; do not infer measured values from configured
retry delays. The tests inject controlled loss and do not constitute this
manual GUI observation. No measured detection time, recovery time, resource
use, or goodput is supplied by this recipe.

For an external physical-device session, record each device's OS, Python and
dependency versions, interface, endpoint, chosen port, capture file digest,
and whether pairing was new or remembered. Keep physical-device evidence
separate from simulation results. The Wireshark capture and packet-conversion
deliverables remain future work; no PCAP, PDML, SQLite, or PyShark result is
claimed here.

## Standalone synthetic analysis

Run the laboratory and local benchmark without a connected peer:

```bash
python -m sparc.analysis sensitivity --seed 42 --output .demo/lab
python -m sparc.analysis benchmark --output .demo/local-benchmark.csv
```

The default laboratory exports 19,200 trials: 6,400 plaintext flips and 12,800 key flips across 50 synthetic cases. The benchmark exports 18,000 measured primitive calls after 10 warmups per operation/workload. Each CSV includes completion state, run metadata and definitions. Retain raw rows with summaries; recompute means, medians, nearest-rank p95 and population standard deviation before incorporating results into a report. Synthetic laboratory keys are public operands; benchmark CSVs contain no keys. Canceled or failed runs must remain labeled incomplete. These measurements are local primitive timings and do not establish network goodput or physical cross-platform performance.

## Analysis tab operation metrics

The fourth GUI tab keeps the latest 1,000 public operation events in a bounded
window. Select **Export metrics CSV…** to save the raw retained rows and
reconstructable duration summaries. The CSV metadata names the retained-window
policy, truncation state, units, and measurement definitions. Failures remain
raw rows and are excluded from successful duration summaries. Encoded audit
bytes and protected-frame bytes are separate when the service supplies both.
This queue is best-effort: dropped service events cannot be recovered later.

**Verify audit metric** runs the existing committed-prefix verifier through the
tab's one cancellable job. Its row uses the verifier's reported duration and
verified-record count; it adds no timer and does not choose a checkpoint or
claim to verify later appends. An invalid report remains a failed measurement.
Canceled or errored verification produces no timing row. Reconnect recovery
uses the service's retry-chain duration in its public context and retains the
wrapper duration as provenance; the reconnect-attempt event is an outcome
diagnostic, not a measured attempt duration.

The retained loopback capture at
`.demo/a3-evidence/b43fafc2b06c45cc900a5207780c80ee/` contains 300 completed
receipts across the default three sizes, with 10 warmups per size (30 total),
from two peer services running in one process, and four resource samples. The
raw verified receipt rows are in `network.csv`; the controller independently
checked reconstruction of the summaries, with the reconstruction record at
`reconstruction.json`. `operations.json` contains collected service operation
events. The separate finite resource exercise at
`.demo/a3-evidence/resources-1bf14715c72f41f2b11a2deacae219cd/` records an idle
listener and a bounded 50-connection invalid-handshake workload. Neither
artifact supplies physical-device results, attack-workload goodput, measured
detection/recovery timing, or an arbitrary-denial-of-service claim.
