"""Focused tests for private versus selected-export parent permissions."""

import errno
import os
import stat
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


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are required")
def test_darwin_atomic_write_private_and_nonprivate_modes(tmp_path, monkeypatch):
    import sparc.storage as storage

    monkeypatch.setattr(storage.sys, "platform", "darwin")
    parent = tmp_path / "existing-parent"
    parent.mkdir(mode=0o755)
    os.chmod(parent, 0o755)
    private_path = parent / "private.json"
    storage.atomic_write(private_path, b"private on Darwin")

    assert private_path.read_bytes() == b"private on Darwin"
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600

    nonprivate_path = parent / "export.json"
    storage.atomic_write(nonprivate_path, b"public export", private=False)
    assert nonprivate_path.read_bytes() == b"public export"
    assert stat.S_IMODE(nonprivate_path.stat().st_mode) == 0o644


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are required")
def test_darwin_atomic_write_external_parent_modes(tmp_path, monkeypatch):
    import sparc.storage as storage

    monkeypatch.setattr(storage.sys, "platform", "darwin")
    external_parent = tmp_path / "selected-external"
    external_parent.mkdir(mode=0o750)
    os.chmod(external_parent, 0o750)
    private_path = external_parent / "private.json"
    storage.atomic_write(private_path, b"private external data", secure_parent=False)

    assert private_path.read_bytes() == b"private external data"
    assert stat.S_IMODE(external_parent.stat().st_mode) == 0o750
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600

    new_parent = tmp_path / "new" / "external-leaf"
    new_path = new_parent / "private.json"
    storage.atomic_write(new_path, b"new private leaf", secure_parent=False)
    assert new_path.read_bytes() == b"new private leaf"
    assert stat.S_IMODE(new_parent.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are required")
def test_darwin_secure_private_store_restricts_parent_and_existing_file(
    tmp_path, monkeypatch
):
    import sparc.storage as storage

    monkeypatch.setattr(storage.sys, "platform", "darwin")
    store = tmp_path / "store"
    store.mkdir(mode=0o755)
    os.chmod(store, 0o755)
    identity = store / "identity.json"
    identity.write_bytes(b"encrypted identity")
    os.chmod(identity, 0o644)

    storage.secure_private_store(identity)

    assert stat.S_IMODE(store.stat().st_mode) == 0o700
    assert stat.S_IMODE(identity.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX file descriptors are required")
def test_darwin_atomic_write_syncs_real_file_then_parent(tmp_path, monkeypatch):
    import sparc.storage as storage

    monkeypatch.setattr(storage.sys, "platform", "darwin")
    parent = tmp_path / "sync-order"
    parent.mkdir(mode=0o700)
    destination = parent / "state.json"
    expected = b"new destination bytes"
    real_fsync = os.fsync
    directory_descriptors = []
    sync_order = []
    observed_directory = []

    def record_fsync(descriptor):
        info = os.fstat(descriptor)
        if stat.S_ISREG(info.st_mode):
            sync_order.append("file")
        elif stat.S_ISDIR(info.st_mode):
            sync_order.append("directory")
            directory_descriptors.append(descriptor)
            observed_directory.append((info.st_dev, info.st_ino))
            assert destination.read_bytes() == expected
            parent_info = parent.stat()
            assert (info.st_dev, info.st_ino) == (parent_info.st_dev, parent_info.st_ino)
        else:
            pytest.fail("atomic write fsynced an unexpected descriptor type")
        return real_fsync(descriptor)

    monkeypatch.setattr(storage.os, "fsync", record_fsync)
    storage.atomic_write(destination, expected)

    assert destination.read_bytes() == expected
    assert sync_order == ["file", "directory"]
    assert observed_directory
    assert len(directory_descriptors) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(directory_descriptors[0])
    assert closed.value.errno == errno.EBADF


@pytest.mark.skipif(os.name != "posix", reason="POSIX file descriptors are required")
@pytest.mark.parametrize(
    "failure_errno",
    [errno.EINVAL, errno.ENOTSUP, errno.ENOSYS, errno.EIO],
)
def test_darwin_atomic_directory_sync_failure_is_not_silently_successful(
    tmp_path, monkeypatch, failure_errno
):
    import sparc.storage as storage

    monkeypatch.setattr(storage.sys, "platform", "darwin")
    parent = tmp_path / f"failed-directory-sync-{failure_errno}"
    parent.mkdir(mode=0o700)
    destination = parent / "state.json"
    expected = b"published bytes before directory-sync error"
    real_fsync = os.fsync
    directory_fds = []

    def fail_directory_fsync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            directory_fds.append(descriptor)
            raise OSError(failure_errno, "injected Darwin directory sync failure")
        return real_fsync(descriptor)

    monkeypatch.setattr(storage.os, "fsync", fail_directory_fsync)
    with pytest.raises(OSError) as raised:
        storage.atomic_write(destination, expected)

    assert raised.value.errno == failure_errno
    assert destination.read_bytes() == expected
    assert not list(parent.glob(".state.json.*.tmp"))
    assert len(directory_fds) == 1
    with pytest.raises(OSError) as closed:
        os.fstat(directory_fds[0])
    assert closed.value.errno == errno.EBADF


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
