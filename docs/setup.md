# SPARC setup

SPARC provides Connection, Chat, Audit, Analysis, and Traffic Analysis tabs.
Chat supports text and approved image attachments over authenticated IPv4/TCP.
Analysis supplies synthetic experiments and performance measurements; Traffic
Analysis processes externally saved captures. Current required demo platforms
are Linux and macOS; Windows compatibility was withdrawn on 2026-10-09 and
the historical Windows recipe below is unverified.

## Linux

On Debian or Ubuntu, install the Tk runtime before creating the virtual environment:

```sh
sudo apt update
sudo apt install python3-tk python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m sparc --check
```

The project pins its runtime and development dependencies in `pyproject.toml`. Start a device with its own data directory:

```sh
python -m sparc --data-dir "$HOME/.local/share/sparc/device-a"
```

## macOS

For Apple Silicon and macOS Sequoia, use Python 3.10 or newer from the official [python.org macOS universal2 installer](https://docs.python.org/3/using/mac.html). Use its normal GIL-enabled interpreter; the installer includes native Tcl/Tk support. Create and activate the environment with that same interpreter:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m tkinter
python -m sparc --check
python -m sparc
```

`python -m tkinter` should open its check window. Run it with the same Python interpreter and environment used to launch SPARC. The default identity directory is `~/Library/Application Support/SPARC`; explicit paths still override it. For two local devices, quote paths with spaces:

```sh
python -m sparc --data-dir "$HOME/Library/Application Support/SPARC/device-a"
python -m sparc --data-dir "$HOME/Library/Application Support/SPARC/device-b"
```

SPARC applies ordinary POSIX private-mode hardening to its store, identity, lock, and temporary files. If the filesystem reports an error while synchronizing the identity directory after publication, SPARC fails closed and keeps the already-published encrypted identity; it does not roll back or start the service. Use the normal local user data directory. Arbitrary external or remote filesystems have not been validated. The native macOS installation, Tk window, identity creation and reload, and Linux-to-Mac LAN chat remain unverified until exercised on an actual Mac. Python's [Tkinter documentation](https://docs.python.org/3/library/tkinter.html) describes `python -m tkinter` as the installation check; Apple's [file-system guidance](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively) documents the Application Support location.

## Windows

Install Python 3.10 or newer using the official CPython installer and include the Tcl/Tk support. Open PowerShell in the project directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m sparc --check
python -m sparc --data-dir "$env:LOCALAPPDATA\SPARC\device-a"
```

If PowerShell blocks virtual-environment activation, use `.\.venv\Scripts\python.exe -m pip ...` and `.\.venv\Scripts\python.exe -m sparc ...` directly. If startup reports that Tk is unavailable, install or modify CPython to include Tcl/Tk, then recreate the environment if needed.

## Connect two devices

1. Put both devices on the same trusted private LAN, not a guest Wi-Fi network. Some access points enable client isolation, which blocks devices on the same Wi-Fi from reaching one another; disable that setting or use a network that permits peer connections. Start SPARC on each with a different data directory. Keep those directories separate; each one stores that device's identity, trust records, and audit log.
2. On the listening device, choose its reachable LAN IPv4 address as the bind interface and a port. The default is TCP port `47655`; use a different available port when needed. Do not use `127.0.0.1` or `0.0.0.0` as the address you give the other device: those are loopback and all-interface bind addresses, not a remote destination. Allow incoming TCP connections to the chosen port on the local firewall, limited to the private network.
3. Give the connecting device the listener's literal IPv4 address and port. SPARC does not discover peers automatically.
4. Compare the full identity fingerprints through a separate trusted channel before approving the pairing request. Approve only the fingerprint you intended to connect to. SPARC has no trust-any mode.
5. Use Chat for Unicode text and multiple lines. The Audit tab reports the committed writer head separately from verification of the captured audit prefix.

For two instances on one computer, use different data directories and different listening ports. On Windows, a second example directory is `$env:LOCALAPPDATA\SPARC\device-b`; on Linux, use `$HOME/.local/share/sparc/device-b`.

`python -m sparc --check` prints local package versions and the public identity fingerprint without opening the GUI. Tk is required only for normal desktop launch. PyShark, TShark, and the optional analysis dependencies are not needed for the current Connection, Chat, and Audit tabs.

## Offline traffic analysis

Install the optional Python adapter in the environment used to launch SPARC:

```sh
python -m pip install -e '.[traffic]'
```

PyShark invokes a separate TShark executable. On Debian/Ubuntu, install it with
`sudo apt install tshark`. For macOS, install Wireshark and choose its bundled
`/Applications/Wireshark.app/Contents/MacOS/tshark`, or use a standalone TShark
already installed on the machine. Verify the actual executable with
`tshark --version` (or its quoted full path). Use **Choose TShark** in the
Traffic Analysis tab or `--tshark /path/to/tshark` on the offline CLI if it is
not on PATH. Paths containing spaces must be quoted in terminal commands.
Missing tools affect the offline action; ordinary chat and `--check` remain
available. Native macOS tool and capture checks have not been performed.

Save PCAP/PCAPNG externally in Wireshark. SPARC does not request live capture
privileges, change capture permissions, or modify the source capture. Use
separate filenames for the source, JSON report, SQLite index and PDML export.
See the [offline workflow](progress-check-demo.md#offline-capture-analysis-and-exports)
for filtering, source hashes, integrity checks and measurement definitions.
