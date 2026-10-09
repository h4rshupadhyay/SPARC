"""Read-only public identity diagnostics must not unlock or mutate stores."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from sparc.identity import load_identity
from sparc.__main__ import main


_IMPORT_GUARD = r'''
import builtins
import runpy
import sys

original_import = builtins.__import__
blocked = ("tkinter", "pyshark", "sparc.gui", "sparc.traffic", "sparc.peer")
def guarded_import(name, *args, **kwargs):
    if any(name == item or name.startswith(item + ".") for item in blocked):
        raise AssertionError("unexpected optional/service import: " + name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import

import sparc.identity as identity
import sparc.identity_codec as codec
def forbidden(*args, **kwargs):
    raise AssertionError("diagnostics attempted private identity work")
identity._legacy_identity = forbidden
identity._unlock_store = forbidden
identity.load_identity = forbidden
codec._derive_key = forbidden
codec.decode_identity = forbidden

try:
    runpy.run_module("sparc", run_name="__main__")
except SystemExit as result:
    if result.code not in (None, 0):
        raise
for item in blocked:
    assert not any(name == item or name.startswith(item + ".") for name in sys.modules)
'''


def _subprocess_check(data_dir: Path):
    project_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    source_path = str(project_root / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, environment.get("PYTHONPATH", "")) if part
    )
    return subprocess.run(
        [sys.executable, "-c", _IMPORT_GUARD, "--check", "--data-dir", str(data_dir)],
        cwd=project_root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )


def _snapshot(directory: Path):
    if not directory.exists():
        return None
    return {
        path.relative_to(directory).as_posix():
        (path.read_bytes(), path.stat().st_mode & 0o777)
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    } | {"<directory-mode>": directory.stat().st_mode & 0o777}


def test_check_absent_is_read_only_and_does_not_create_directory(tmp_path):
    absent_dir = tmp_path / "absent"
    result = _subprocess_check(absent_dir)

    assert result.returncode == 0, result.stderr
    assert "0.1.0.dev0" in result.stdout
    assert "Public fingerprint: unavailable (identity absent)" in result.stdout
    assert not absent_dir.exists()


def test_check_encrypted_store_reports_unverified_metadata_without_mutation(
    tmp_path, credential_provider
):
    data_dir = tmp_path / "encrypted"
    identity = load_identity(data_dir, credential_provider=credential_provider)
    before = _snapshot(data_dir)

    result = _subprocess_check(data_dir)

    assert result.returncode == 0, result.stderr
    label = f"Public fingerprint (unverified stored metadata): {identity.fingerprint}"
    assert label in result.stdout
    assert "encrypted; locked; private key not verified" in result.stdout.lower()
    assert _snapshot(data_dir) == before
    document = json.loads((data_dir / "identity.json").read_text(encoding="utf-8"))
    assert document["encrypted_private_key"] not in result.stdout


def test_check_legacy_mismatched_public_metadata_stays_unverified(
    tmp_path, legacy_identity_store, capsys
):
    data_dir = tmp_path / "legacy-mismatch"
    legacy_identity_store(data_dir)
    identity_path = data_dir / "identity.json"
    document = json.loads(identity_path.read_text(encoding="utf-8"))
    mismatched_public = b"\x01" * 32
    document["public_key"] = base64.b64encode(mismatched_public).decode("ascii")
    identity_path.write_text(json.dumps(document), encoding="utf-8")
    before = _snapshot(data_dir)
    expected = hashlib.sha256(mismatched_public).hexdigest()

    result = main(["--check", "--data-dir", str(data_dir)])

    assert result == 0
    output = capsys.readouterr().out
    assert f"Public fingerprint (unverified stored metadata): {expected}" in output
    assert "legacy" in output.lower()
    assert "not verified" in output.lower()
    assert _snapshot(data_dir) == before


def test_check_corrupt_envelope_errors_without_mutation(tmp_path, credential_provider, capsys):
    data_dir = tmp_path / "corrupt"
    load_identity(data_dir, credential_provider=credential_provider)
    identity_path = data_dir / "identity.json"
    document = json.loads(identity_path.read_text(encoding="utf-8"))
    document["encrypted_private_key"] = "!" * 32
    identity_path.write_text(json.dumps(document), encoding="utf-8")
    before = _snapshot(data_dir)

    result = main(["--check", "--data-dir", str(data_dir)])
    captured = capsys.readouterr()

    assert result == 1
    assert "check failed" in captured.err.lower()
    assert _snapshot(data_dir) == before
