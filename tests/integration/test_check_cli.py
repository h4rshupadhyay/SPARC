import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys


_IMPORT_GUARD = r'''
import builtins
import runpy
import sys

original_import = builtins.__import__
blocked = ("tkinter", "pyshark", "sparc.gui", "sparc.traffic")
def guarded_import(name, *args, **kwargs):
    if any(name == item or name.startswith(item + ".") for item in blocked):
        raise AssertionError("unexpected optional import: " + name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
try:
    runpy.run_module("sparc", run_name="__main__")
except SystemExit as result:
    if result.code not in (None, 0):
        raise
for item in blocked:
    assert not any(name == item or name.startswith(item + ".") for name in sys.modules)
'''


def test_check_needs_no_tk_or_packet_tools_and_keeps_fingerprint_private(tmp_path):
    project_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    source_path = str(project_root / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, environment.get("PYTHONPATH", "")) if part
    )
    command = [sys.executable, "-c", _IMPORT_GUARD, "--check", "--data-dir", str(tmp_path)]

    outputs = []
    for _ in range(2):
        result = subprocess.run(
            command,
            cwd=project_root,
            env=environment,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        outputs.append(result.stdout)

    assert "0.1.0.dev0" in outputs[0]
    assert outputs[0] == outputs[1]
    match = re.search(r"(?i)(?:public\s+)?fingerprint\s*[:=]\s*([0-9a-f]{64})", outputs[0])
    assert match is not None

    identity = json.loads((tmp_path / "identity.json").read_text(encoding="utf-8"))
    private_base64 = identity["private_key"]
    public_raw = base64.b64decode(identity["public_key"], validate=True)
    import hashlib

    assert match.group(1) == hashlib.sha256(public_raw).hexdigest()
    assert private_base64 not in outputs[0]
