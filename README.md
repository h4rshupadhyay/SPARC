# SPARC

SPARC is a secure peer-to-peer text communication and analysis lab built with
Python and Tkinter. It combines authenticated IPv4/TCP messaging, encrypted
local identities, signed audit records, and reproducible analysis tools.

## Current features

- **Connection:** manual listener and peer configuration, first-contact
  fingerprint approval, remembered-peer trust, and bounded reconnection.
- **Chat:** Unicode and multiline text protected with AES-256-GCM and Ed25519
  signatures, authenticated X25519 session establishment, verified delivery
  receipts, replay checks, and public record inspection.
- **Audit:** signed hash-chain logs, retained checkpoints, and cancellable
  verification. Detecting a deleted log tail requires an independently retained
  checkpoint.
- **Analysis:** synthetic AES sensitivity trials, local cryptographic
  benchmarks, verified-receipt network measurements, CPU/RSS sampling,
  signature specimens, operation metrics, and CSV exports.

Traffic Analysis is in progress. Capture normalization, traffic indexing, and
the traffic CLI/GUI are not yet completed features. See the
[implementation ledger](docs/implementation-status.md) for task-level status.

## Install and run

Run these commands from the repository root. Python 3.10 or newer and a working
Tk installation are required for the desktop app.

### Linux

On Debian or Ubuntu, install Tk if it is missing:

```sh
sudo apt install python3-tk
```

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m sparc --check --data-dir ./lab/alice
python -m sparc --data-dir ./lab/alice
```

### macOS

Use the official python.org CPython installer with bundled Tcl/Tk, then create
the environment with that interpreter:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m tkinter
python -m sparc --check --data-dir ./lab/alice
python -m sparc --data-dir ./lab/alice
```

Close the Tk test window before launching SPARC. macOS storage and startup
support are implemented; native Apple Silicon/macOS Sequoia validation and the
Linux–Mac LAN demo remain pending. Windows compatibility is outside the
current required demo scope and is unverified.

The development requirements install analysis, traffic, and test dependencies.
TShark is not required for secure chat, the startup diagnostic, or the current
Analysis tools.

### Identity and data directories

On first launch, create and confirm a long, unique passphrase of at least 15
characters. Later launches prompt to unlock the same identity. Persistent
Ed25519 private keys are encrypted using Argon2id-derived keys and Fernet;
legacy unencrypted identities are migrated while preserving their key,
fingerprint, remembered-peer pins, and existing audit verification.

Keep the passphrase safe: SPARC does not store it alongside the encrypted key.
Use a separate data directory for each local instance and keep those directories
private. Never include `identity.json` or passphrases in an evidence bundle.
Canceling the unlock prevents networking from starting.

`--check` is a read-only, GUI-free dependency and public identity diagnostic. It
does not create, unlock, or migrate an identity. It labels displayed fingerprints
as unverified stored metadata and does not verify the private key.

Without `--data-dir`, SPARC uses `$XDG_CONFIG_HOME/sparc` (when set to an absolute
path) or `~/.config/sparc` on Linux, and `~/Library/Application Support/SPARC` on
macOS.

## Pair two peers

1. Launch each instance with its own data directory and unlock its identity.
2. In **Connection**, start a listener on one peer and connect from the other
   using its reachable IPv4 address and port. Two listeners on one machine need
   different ports, such as `47655` and `47657`.
3. Compare the full fingerprints through an independent channel and approve
   first contact on both sides.
4. Send text in **Chat**, inspect the verified delivery result, and use **Audit**
   to verify the local log against a retained checkpoint.

An unconfirmed message is not automatically resent after reconnection. See the
[demo guide](docs/progress-check-demo.md) for the full procedure and availability
exercises.

## Standalone analysis

Run synthetic sensitivity trials and local benchmarks without a connected peer
or GUI:

```sh
python -m sparc.analysis sensitivity --seed 42 --output .demo/lab
python -m sparc.analysis benchmark --output .demo/local-benchmark.csv
```

Retain raw CSV rows with their summaries and completion labels. Synthetic
operands and local primitive timings do not establish physical-device network
performance. Network benchmarks and resource sampling are available in the
**Analysis** tab; network runs require a connected, authenticated peer.

## Demonstrations and evidence

- [Progress-check demo and capture procedure](docs/progress-check-demo.md)
- [Evidence map, measurement fields, and acceptance checklist](docs/progress-check-evidence.md)
- [Identity encryption and platform verification evidence](docs/f1-identity-at-rest-evidence.md)
- [Implementation status](docs/implementation-status.md)

Run the independent-process loopback demonstration from an interactive terminal:

```sh
python scripts/simulate_peers.py --data-root .demo/new-simulation --report .demo/new-simulation-report.json
```

The terminal prompts for each peer's identity credentials without echoing them.
Use disposable data directories and synthetic text for captures.

The simulation is explicitly a pair of independent local processes, not a
physical-device or cross-platform result. Linux local GUI checks, analysis
measurements, and encrypted-identity verification are recorded in the linked
guides; native macOS and physical-device results remain pending. The plaintext
comparison is a separate **LAB ONLY** tool for synthetic text; secure SPARC has
no plaintext fallback.

## Development checks

With the development requirements installed:

```sh
python -m pytest -q
```

GUI tests require a working display and Tk. Platform-specific tests may skip on
other operating systems; skips do not establish native platform compatibility.
