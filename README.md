# SPARC

SPARC is a text-only secure communication lab. The current Tkinter app has
**Connection**, **Chat**, and **Audit** tabs. It supports manually configured
IPv4/TCP connections, first-contact fingerprint approval, Unicode text, message
inspection, and signed local audit verification. Analysis and Traffic Analysis
are future milestones; they are not presented as completed features.

## Install and run

Python 3.10 or newer is required. On Linux:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m sparc --check --data-dir ./lab/alice
python -m sparc --data-dir ./lab/alice
```

On Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python -m sparc --check --data-dir .\lab\alice
python -m sparc --data-dir .\lab\alice
```

Use a separate data directory for each local instance. Keep those directories
private: they contain identity material. Never include `identity.json` in an
evidence bundle. The `--check` command is a GUI-free dependency and identity
diagnostic. Linux local GUI checks and independent-process simulation have been
run; an actual Windows installation and Windows-to-Linux session remain
unverified.

## Demonstrations and evidence

- [Progress-check demo and capture procedure](docs/progress-check-demo.md)
- [Evidence map, measurement fields, and acceptance checklist](docs/progress-check-evidence.md)

The simulation is explicitly a pair of independent local processes, not a
physical-device or cross-platform result. The plaintext comparison is a
separate **LAB ONLY** tool for synthetic text; secure SPARC has no plaintext
fallback. Current evidence status and limitations are recorded in the linked
guides.
