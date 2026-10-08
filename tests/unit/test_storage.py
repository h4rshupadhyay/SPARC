"""Focused tests for private versus selected-export parent permissions."""

import os
import sys

import pytest


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux owner modes are platform-specific")
def test_atomic_write_default_keeps_private_parent_and_file_modes(tmp_path):
    from sparc.storage import atomic_write

    parent = tmp_path / "private-store"
    destination = parent / "state.json"
    atomic_write(destination, b"private state")

    assert destination.read_bytes() == b"private state"
    assert parent.stat().st_mode & 0o777 == 0o700
    assert destination.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux owner modes are platform-specific")
def test_atomic_write_external_mode_preserves_existing_parent_and_private_file(tmp_path):
    from sparc.storage import atomic_write

    parent = tmp_path / "chosen-export-directory"
    parent.mkdir(mode=0o750)
    os.chmod(parent, 0o750)
    destination = parent / "checkpoint.json"
    destination.write_bytes(b"old export")

    atomic_write(destination, b"new checkpoint", secure_parent=False)

    assert destination.read_bytes() == b"new checkpoint"
    assert parent.stat().st_mode & 0o777 == 0o750
    assert destination.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux owner modes are platform-specific")
def test_atomic_write_external_mode_allows_a_new_private_parent(tmp_path):
    from sparc.storage import atomic_write

    parent = tmp_path / "new" / "export-directory"
    destination = parent / "checkpoint.json"
    atomic_write(destination, b"checkpoint", secure_parent=False)

    assert destination.read_bytes() == b"checkpoint"
    assert parent.stat().st_mode & 0o777 == 0o700
    assert destination.stat().st_mode & 0o777 == 0o600


def test_atomic_write_replace_failure_preserves_previous_destination(tmp_path, monkeypatch):
    import sparc.storage as storage

    destination = tmp_path / "state.json"
    destination.write_bytes(b"old")
    original_replace = storage.os.replace

    def fail_before_replace(source, target):
        if target == destination:
            raise OSError("injected replace failure")
        return original_replace(source, target)

    monkeypatch.setattr(storage.os, "replace", fail_before_replace)
    with pytest.raises(OSError):
        storage.atomic_write(destination, b"new")

    assert destination.read_bytes() == b"old"
    assert not list(tmp_path.glob(".state.json.*.tmp"))
