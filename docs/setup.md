# SPARC setup

SPARC's current desktop app provides Connection, Chat, and Audit tabs for text-only peer communication. It connects directly to a manually entered IPv4 address and TCP port on the same LAN. The analysis tab and file transfer are not part of this setup.

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
