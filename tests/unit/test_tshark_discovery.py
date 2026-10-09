"""Discovery contract for the optional TShark executable."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap

import pytest


def _capture_module():
    import sparc.traffic.capture as capture

    return capture


def _fake_executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    return path


def _assert_tshark_missing(call):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as caught:
        call()
    assert caught.value.code == "tshark_missing"
    assert "tshark" in caught.value.message.lower()
    assert caught.value.message.strip()


def test_valid_explicit_executable_wins_without_path_lookup(tmp_path, monkeypatch):
    executable = _fake_executable(tmp_path / "TShark ; (capture) tool")
    marker = tmp_path / "launched"
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
    executable.chmod(0o755)

    capture = _capture_module()

    def unexpected_lookup(_name):
        pytest.fail("PATH lookup must not run when an explicit executable is valid")

    monkeypatch.setattr(shutil, "which", unexpected_lookup)
    assert capture.find_tshark(executable) == executable.resolve()
    assert not marker.exists()


@pytest.mark.parametrize("invalid_kind", ["missing", "directory", "not_executable"])
def test_invalid_explicit_executable_fails_without_path_fallback(tmp_path, monkeypatch, invalid_kind):
    valid_path_tool = _fake_executable(tmp_path / "path tool")
    if invalid_kind == "missing":
        explicit = tmp_path / "missing tool"
    elif invalid_kind == "directory":
        explicit = tmp_path / "directory tool"
        explicit.mkdir()
    else:
        explicit = tmp_path / "not executable"
        explicit.write_text("content")
        explicit.chmod(0o644)

    capture = _capture_module()
    monkeypatch.setattr(shutil, "which", lambda _name: str(valid_path_tool))
    _assert_tshark_missing(lambda: capture.find_tshark(explicit))


def test_valid_path_executable_returns_resolved_path(tmp_path, monkeypatch):
    executable = _fake_executable(tmp_path / "tshark tool")
    marker = tmp_path / "launched"
    executable.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
    executable.chmod(0o755)
    capture = _capture_module()
    monkeypatch.setattr(shutil, "which", lambda name: str(executable) if name == "tshark" else None)

    assert capture.find_tshark() == executable.resolve()
    assert not marker.exists()


@pytest.mark.parametrize("which_result", [None, "missing", "directory", "not_executable"])
def test_invalid_path_lookup_result_is_actionable_error(tmp_path, monkeypatch, which_result):
    if which_result == "missing":
        result = str(tmp_path / "missing tool")
    elif which_result == "directory":
        path = tmp_path / "directory tool"
        path.mkdir()
        result = str(path)
    elif which_result == "not_executable":
        path = tmp_path / "not executable"
        path.write_text("content")
        path.chmod(0o644)
        result = str(path)
    else:
        result = None

    capture = _capture_module()
    monkeypatch.setattr(shutil, "which", lambda _name: result)
    _assert_tshark_missing(capture.find_tshark)


def test_cli_check_does_not_need_pyshark_or_tshark(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    script = textwrap.dedent(
        """
        import builtins
        import runpy
        import sys

        original_import = builtins.__import__
        def guarded_import(name, *args, **kwargs):
            if name == "pyshark" or name.startswith("pyshark."):
                raise AssertionError("PyShark import attempted during --check")
            return original_import(name, *args, **kwargs)

        builtins.__import__ = guarded_import
        sys.argv = ["sparc", "--check", "--data-dir", sys.argv[1]]
        try:
            runpy.run_module("sparc", run_name="__main__")
        except SystemExit as exc:
            assert exc.code in (None, 0)
        assert not any(name == "pyshark" or name.startswith("pyshark.") for name in sys.modules)
        """
    )
    env = os.environ.copy()
    env["PATH"] = ""
    result = subprocess.run(
        [sys.executable, "-c", script, str(data_dir)],
        cwd=Path(__file__).resolve().parents[2],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("failure_site", ["explicit_is_file", "path_is_file", "which"])
def test_discovery_filesystem_errors_are_safe_domain_errors(tmp_path, monkeypatch, failure_site):
    capture = _capture_module()
    secret = "private-discovery-sentinel"
    candidate = tmp_path / secret / "tshark"
    real_is_file = Path.is_file
    which_calls = []

    def failing_is_file(path):
        if path == candidate:
            raise PermissionError(secret)
        return real_is_file(path)

    def controlled_which(name):
        which_calls.append(name)
        if failure_site == "which":
            raise OSError(secret)
        return str(candidate)

    def unexpected_launch(*args, **kwargs):
        pytest.fail("TShark discovery must never launch the executable")

    monkeypatch.setattr(Path, "is_file", failing_is_file)
    monkeypatch.setattr(shutil, "which", controlled_which)
    monkeypatch.setattr(subprocess, "Popen", unexpected_launch)
    monkeypatch.setattr(subprocess, "run", unexpected_launch)
    monkeypatch.setattr(subprocess, "check_output", unexpected_launch)

    explicit = candidate if failure_site == "explicit_is_file" else None
    from sparc.models import SparcError

    with pytest.raises(SparcError) as caught:
        capture.find_tshark(explicit)
    assert caught.value.code == "tshark_missing"
    assert "TShark" in caught.value.message
    assert "required" in caught.value.message.lower()
    assert secret not in caught.value.message
    assert str(candidate) not in caught.value.message
    if failure_site == "explicit_is_file":
        assert which_calls == []
    else:
        assert which_calls == ["tshark"]
