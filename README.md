# SPARC

SPARC is a secure peer-to-peer text/image communication and analysis lab built with
Python and Tkinter. It combines authenticated IPv4/TCP messaging, encrypted
local identities, signed audit records, and reproducible analysis tools.

## Current features

- **Connection:** manual listener and peer configuration, first-contact
  fingerprint approval, remembered-peer trust, refreshable local IP addresses,
  and bounded reconnection.
- **Chat:** Unicode text and inline image attachments protected with AES-256-GCM and Ed25519
  signatures, authenticated X25519 session establishment, verified delivery
  receipts, replay checks, public record inspection, receiver approval, and
  byte-for-byte verified image files.
- **Audit:** signed hash-chain logs, retained checkpoints, and cancellable
  verification. Detecting a deleted log tail requires an independently retained
  checkpoint.
- **Analysis:** synthetic AES sensitivity trials, local cryptographic
  benchmarks, verified-receipt network measurements, CPU/RSS sampling,
  timed signature specimens, collision/preimage/second-preimage hashing
  experiments, operation metrics, performance/sensitivity graphs, CSV exports,
  and standalone SVG graph exports.

- **Traffic Analysis:** offline saved-capture summaries, transactional SQLite
  indexes, validated unfiltered PDML XML, conversion measurements, and a CLI
  with JSON reports. Optional TShark/PyShark dependencies are checked when an
  offline action starts. Linux synthetic-fixture agreement is verified;
  physical secure/baseline captures and native macOS validation remain pending.

## Install and run

The desktop uses a dark charcoal theme with larger shared typography across
all five tabs, charts and the identity dialog. It selects an installed
sans-serif face (Fira Sans on the verified Linux machine) and a separate
monospace face for technical evidence. Fonts have native fallbacks and require
no download. SVG charts retain a light background for standalone documents.
See [appearance evidence](docs/dark-appearance-evidence.md) for verification.

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

After switching networks, use **Refresh IPs** in **Connection** to update the
device address list and **Copy endpoint** actions. Refreshing preserves your
listener and peer settings; restart a listener bound to a specific old IP if
that address is no longer available.

An unconfirmed message is not automatically resent after reconnection. See the
[demo guide](docs/progress-check-demo.md) for the full procedure and availability
exercises.

The **Chat** message inspector shows local signature timings near the top:
generation on outgoing messages and verification on incoming messages, in
microseconds. Missing timings are labeled unavailable. These are local
operation durations; sender timings are not transmitted to the receiver.

### Send images in Chat

Update **both peers** with `python -m pip install -r requirements-dev.txt`.
The image preview dependency is Pillow 12.3.0, compatible with Python 3.10.
Older SPARC peers do not understand image-transfer records.

In **Chat**, choose **Attach image** or drop a local image into the conversation
or message box, inspect the preview, then choose **Send image**. Native file
dropping uses tkinterdnd2 0.7.0. PNG, JPEG, GIF, and WebP files up to 100 MiB are
supported; previews are limited to 20 million pixels and show the first frame.
Your text draft stays intact and text chat remains available during transfer.

Images arrive automatically in the connected peer's conversation. Received
images use private temporary storage for the running peer and survive reconnects;
the latest 100 received images are retained and removed when the peer closes.
Choose **Save image** to keep a permanent copy, including after disconnecting.
The preview appears only after authenticated transfer and whole-file hash/size
checks. All original bytes are preserved, including animated frames; previews
do not transcode files. Incoming and outgoing messages use distinct bubbles.
Security details occupy a reserved pane from startup; the checkbox hides it,
and selecting another message respects that choice.

Select an image entry to inspect its hash, latest chunk's signature, bounded
Base64 ciphertext, authentication tag, and local encryption/decryption timings.
Progress counts stored/confirmed bytes. **Verified** on the sender requires the
receiver's signed final result. **Unconfirmed** means that confirmation was not
obtained; the receiver may already have saved the file. Cancel or disconnect
removes owned partial files, and a retry starts a new transfer.

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

In **Analysis → Hashing security analysis**, choose collision, preimage, or
second-preimage resistance, a seed, and an attempt limit.
All searches compare complete 256-bit SHA-256 digests. Results show attempts,
elapsed time, and any matching synthetic inputs
with their full digests. **Cancel** retains incomplete hashing results;
**Save CSV…** exports the result and its scope. No match is expected in these
finite searches; it does not establish SHA-256 security. Definitions
follow [NIST's hash-function guidance](https://csrc.nist.gov/Projects/hash-functions).

**Generate specimen** also displays Ed25519 signature generation time, excluding
key generation and encoding. Local benchmark signature rows display
microseconds; CSV timing fields retain nanoseconds.

**Analysis → Graphs** plots the latest benchmark's mean operation duration and
throughput against payload size. Select encryption/decryption, hashing,
signing/verification, or all operations. Network runs show verified receipt
duration and network goodput separately. Missing measurements appear as gaps;
incomplete runs retain their label. **Export graphs SVG…** saves the visible
graphs with their labels, units, and completion state.

Sensitivity trials plot observed values alongside model expectations: 50% bit
change, 99.609375% byte change, and 93.75% lowercase hex-character change.
**Byte change (character-level proxy)** uses raw ciphertext bytes; the course's
100% character-level target is displayed separately. Neither that target nor
the model expectations are forced pass/fail outcomes or proof of security.

## Demonstrations and evidence

Analyze a saved PCAP/PCAPNG without opening the GUI:

```sh
python -m sparc.traffic analyze capture.pcapng --report report.json --sqlite index.sqlite --xml details.xml --tshark /path/to/tshark
```

In the fifth **Traffic Analysis** tab, use **Open Capture**, optionally choose
the TShark executable, then **Analyze**, **Export SQLite**, or **Export XML**.
The optional display filter applies to the index and summary; XML always
describes the full unfiltered source. Captured frame bytes/s is separate from
application plaintext goodput; conversion packets/s measures processing speed.
Source/output aliases and duplicate CLI output paths are rejected. Failed or
canceled jobs preserve prior outputs before publication; a later CLI failure
lists artifacts already completed. Publication uncertainty keeps the candidate
and reports failure. See [setup](docs/setup.md#offline-traffic-analysis) and the
[offline workflow](docs/progress-check-demo.md#offline-capture-analysis-and-exports).

- [Progress-check demo and capture procedure](docs/progress-check-demo.md)
- [Evidence map, measurement fields, and acceptance checklist](docs/progress-check-evidence.md)
- [Identity encryption and platform verification evidence](docs/f1-identity-at-rest-evidence.md)
- [Image transfer and graphical analysis evidence](docs/image-transfer-and-analysis-evidence.md)
- [Traffic index and PDML evidence](docs/t2-traffic-export-evidence.md)
- [Traffic CLI and native interface evidence](docs/t3-traffic-interface-evidence.md)
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
