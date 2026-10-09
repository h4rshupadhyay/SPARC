"""F1b bounded identity reads, private storage and publication contracts."""

from __future__ import annotations

import hashlib
import errno
import os
from pathlib import Path
import secrets
import stat
import threading
import time

import pytest


def _storage():
    from importlib import import_module

    try:
        module = import_module("sparc.identity_storage")
    except ModuleNotFoundError as error:
        if error.name != "sparc.identity_storage":
            raise
        pytest.fail("the F1b identity storage API must be implemented")
    required = (
        "read_identity_file",
        "read_private_identity_file",
        "publish_identity",
        "identity_lock",
    )
    missing = [name for name in required if not hasattr(module, name)]
    assert not missing, f"identity storage is missing its prescribed API: {missing}"
    return module


def _candidate():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sparc.identity_codec import encode_identity
    from sparc.models import Identity

    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    identity = Identity(private_key, public_bytes, hashlib.sha256(public_bytes).hexdigest())
    return encode_identity(identity, secrets.token_hex(32).encode("ascii"))


def _expect_code(code, call):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as error:
        call()
    assert error.value.code == code
    return error.value


def _expect_error(call):
    from sparc.models import SparcError

    with pytest.raises(SparcError) as error:
        call()
    return error.value


def _owned_temps(directory: Path, target: Path):
    return [item for item in directory.iterdir() if item != target and item.name != ".identity.lock"]


def test_read_is_bounded_read_only_and_rejects_links(tmp_path, monkeypatch):
    storage = _storage()
    directory = tmp_path / "store"
    directory.mkdir()
    path = directory / "identity.json"
    assert storage.read_identity_file(path) is None
    exact_bound = b"x" * 4096
    path.write_bytes(exact_bound)
    os.chmod(directory, 0o750)
    os.chmod(path, 0o640)
    before_modes = (stat.S_IMODE(directory.stat().st_mode), stat.S_IMODE(path.stat().st_mode))

    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_bytes", lambda _path: pytest.fail("unbounded Path.read_bytes used"))
        assert storage.read_identity_file(path) == exact_bound

    assert (stat.S_IMODE(directory.stat().st_mode), stat.S_IMODE(path.stat().st_mode)) == before_modes
    path.write_bytes(b"y" * 4097)
    _expect_error(lambda: storage.read_identity_file(path))

    target = directory / "target.json"
    target.write_bytes(b"linked bytes")
    os.chmod(target, 0o640)
    link = directory / "link.json"
    try:
        link.symlink_to(target)
        dangling = directory / "dangling.json"
        dangling.symlink_to(directory / "does-not-exist.json")
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symbolic links are unavailable in this environment: {error}")
    target_before = target.read_bytes()
    target_mode = stat.S_IMODE(target.stat().st_mode)
    _expect_error(lambda: storage.read_identity_file(link))
    _expect_error(lambda: storage.read_identity_file(dangling))
    assert target.read_bytes() == target_before
    assert stat.S_IMODE(target.stat().st_mode) == target_mode
    assert link.is_symlink() and dangling.is_symlink()

    if hasattr(os, "mkfifo"):
        fifo = directory / "identity-fifo"
        os.mkfifo(fifo)
        _expect_error(lambda: storage.read_identity_file(fifo))


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are verified on Linux")
def test_private_modes_and_permission_failure(tmp_path, monkeypatch):
    storage = _storage()
    candidate = _candidate()
    directory = tmp_path / "private-store"
    path = directory / "identity.json"
    directory.mkdir(mode=0o755)
    os.chmod(directory, 0o755)

    storage.publish_identity(path, expected=None, candidate=candidate)
    assert path.read_bytes() == candidate
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    lock_path = directory / ".identity.lock"
    assert lock_path.is_file()
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600
    assert storage.read_private_identity_file(path) == candidate

    failed_dir = tmp_path / "permission-failure"
    failed_path = failed_dir / "identity.json"
    failed_dir.mkdir(mode=0o755)
    os.chmod(failed_dir, 0o755)
    real_chmod, real_fchmod = os.chmod, os.fchmod
    chmod_attempts = []

    def fail_chmod(target, mode, *args, **kwargs):
        if Path(target) == failed_dir:
            chmod_attempts.append((target, mode))
            raise PermissionError("injected directory permission failure")
        return real_chmod(target, mode, *args, **kwargs)

    def fail_fchmod(fd, mode):
        chmod_attempts.append((fd, mode))
        raise PermissionError("injected private mode failure")

    monkeypatch.setattr(os, "chmod", fail_chmod)
    monkeypatch.setattr(os, "fchmod", fail_fchmod)
    _expect_code(
        "data_permissions_failed",
        lambda: storage.publish_identity(failed_path, expected=None, candidate=candidate),
    )
    assert chmod_attempts
    assert not failed_path.exists()
    assert not (failed_dir / ".identity.lock").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner checks use uid metadata")
def test_private_store_rejects_linked_lock_ancestors_and_unowned_directory(
    tmp_path, monkeypatch
):
    storage = _storage()
    candidate = _candidate()

    linked_store = tmp_path / "linked-store"
    linked_store.mkdir(mode=0o700)
    os.chmod(linked_store, 0o700)
    lock_target = linked_store / "lock-target"
    lock_target.write_bytes(b"keep lock target")
    os.chmod(lock_target, 0o640)
    lock_link = linked_store / ".identity.lock"
    try:
        lock_link.symlink_to(lock_target)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"symbolic links are unavailable in this environment: {error}")
    lock_before = lock_target.read_bytes()
    lock_mode = stat.S_IMODE(lock_target.stat().st_mode)
    linked_path = linked_store / "identity.json"
    _expect_code(
        "data_permissions_failed",
        lambda: storage.publish_identity(linked_path, expected=None, candidate=candidate),
    )
    assert lock_link.is_symlink()
    assert lock_target.read_bytes() == lock_before
    assert stat.S_IMODE(lock_target.stat().st_mode) == lock_mode
    assert not linked_path.exists()

    real_root = tmp_path / "real-root"
    real_store = real_root / "sparc"
    real_store.mkdir(parents=True, mode=0o755)
    os.chmod(real_root, 0o755)
    os.chmod(real_store, 0o755)
    sentinel = real_store / "sentinel"
    sentinel.write_bytes(b"ancestor target remains untouched")
    os.chmod(sentinel, 0o640)
    ancestor_link = tmp_path / "ancestor-link"
    ancestor_link.symlink_to(real_root, target_is_directory=True)
    sentinel_before = sentinel.read_bytes()
    sentinel_mode = stat.S_IMODE(sentinel.stat().st_mode)
    ancestor_path = ancestor_link / "sparc" / "identity.json"
    _expect_code(
        "data_permissions_failed",
        lambda: storage.publish_identity(ancestor_path, expected=None, candidate=candidate),
    )
    assert sentinel.read_bytes() == sentinel_before
    assert stat.S_IMODE(sentinel.stat().st_mode) == sentinel_mode
    assert not (real_store / "identity.json").exists()
    assert not (real_store / ".identity.lock").exists()

    unowned_store = tmp_path / "unowned-store"
    unowned_store.mkdir(mode=0o755)
    os.chmod(unowned_store, 0o755)
    path = unowned_store / "identity.json"
    real_getuid = os.getuid
    real_geteuid = getattr(os, "geteuid", None)
    fake_chmods = []
    real_chmod = os.chmod

    def different_owner():
        return real_getuid() + 1

    def fake_chmod(target, mode, *args, **kwargs):
        if Path(target) == unowned_store:
            fake_chmods.append((target, mode))
        return real_chmod(target, mode, *args, **kwargs)

    monkeypatch.setattr(os, "getuid", different_owner)
    if real_geteuid is not None:
        monkeypatch.setattr(os, "geteuid", different_owner)
    monkeypatch.setattr(os, "chmod", fake_chmod)
    _expect_code(
        "data_permissions_failed",
        lambda: storage.publish_identity(path, expected=None, candidate=candidate),
    )
    assert fake_chmods == []
    assert stat.S_IMODE(unowned_store.stat().st_mode) == 0o755
    assert not path.exists()
    assert not (unowned_store / ".identity.lock").exists()


def test_publication_preserves_original_before_commit(tmp_path, monkeypatch):
    storage = _storage()
    candidate = _candidate()
    directory = tmp_path / "store"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "identity.json"
    original = b"old identity bytes"
    path.write_bytes(original)

    replaced = []

    def fail_replace(source, destination):
        replaced.append((Path(source), Path(destination), Path(source).read_bytes()))
        raise OSError("injected replace failure")

    monkeypatch.setattr(storage, "_replace", fail_replace)
    _expect_code(
        "identity_write_failed",
        lambda: storage.publish_identity(path, expected=original, candidate=candidate),
    )
    assert path.read_bytes() == original
    assert len(replaced) == 1
    assert replaced[0][1] == path
    assert replaced[0][2] == candidate
    assert not replaced[0][0].exists()
    assert _owned_temps(directory, path) == []
    assert (directory / ".identity.lock").exists()

    mismatch_candidate = _candidate()
    replace_calls = []
    monkeypatch.setattr(storage, "_replace", lambda *args: replace_calls.append(args))
    _expect_code(
        "identity_changed",
        lambda: storage.publish_identity(path, expected=b"stale snapshot", candidate=mismatch_candidate),
    )
    assert path.read_bytes() == original
    assert replace_calls == []


def test_post_replace_error_is_uncertain_not_rollback(tmp_path, monkeypatch):
    storage = _storage()
    candidate = _candidate()
    directory = tmp_path / "store"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "identity.json"
    original = b"v1 snapshot"
    path.write_bytes(original)

    def fail_sync(_directory):
        raise OSError("injected directory sync failure")

    monkeypatch.setattr(storage, "_sync_directory", fail_sync)
    _expect_code(
        "identity_commit_uncertain",
        lambda: storage.publish_identity(path, expected=original, candidate=candidate),
    )
    assert path.read_bytes() == candidate
    assert _owned_temps(directory, path) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptor durability contract")
@pytest.mark.parametrize("platform", ["linux", "darwin"])
@pytest.mark.parametrize(
    "failure_errno", [errno.EINVAL, errno.ENOTSUP, errno.ENOSYS, errno.EIO]
)
def test_swallowed_directory_fsync_error_is_uncertain_and_stops_service_startup(
    tmp_path, monkeypatch, credential_provider, platform, failure_errno
):
    storage = _storage()
    service_module = __import__("sparc.peer.service", fromlist=["PeerService"])
    from sparc.identity_codec import inspect_document
    from sparc.models import SparcError

    monkeypatch.setattr(storage.sys, "platform", platform)
    data_dir = tmp_path / f"sync-failure-{platform}-{failure_errno}"
    identity_path = data_dir / "identity.json"
    sync_failures = []
    initialization_attempts = []
    real_fsync = os.fsync

    def fail_directory_fsync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            sync_failures.append(descriptor)
            raise OSError(failure_errno, "injected unsupported directory synchronization")
        return real_fsync(descriptor)

    def record_service_initialization(self, data_dir, limits, identity):
        initialization_attempts.append((data_dir, limits, identity))
        return None

    monkeypatch.setattr(storage.os, "fsync", fail_directory_fsync)
    monkeypatch.setattr(service_module.PeerService, "_initialize", record_service_initialization)

    caught = None
    try:
        service_module.PeerService(data_dir, credential_provider=credential_provider)
    except SparcError as error:
        caught = error

    assert sync_failures
    assert caught is not None, "service startup continued after directory fsync failure"
    assert caught.code == "identity_commit_uncertain"
    assert initialization_attempts == []
    published = identity_path.read_bytes()
    assert published
    assert inspect_document(published).status == "encrypted_locked"
    assert _owned_temps(data_dir, identity_path) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptor sync is required")
def test_darwin_identity_publication_syncs_pinned_directory(tmp_path, monkeypatch):
    storage = _storage()
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    candidate = _candidate()
    directory = tmp_path / "darwin-pinned-store"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "identity.json"
    real_fsync = os.fsync
    real_dup = os.dup
    duplicate_sources = []
    pinned_directory_ids = []
    sync_descriptors = []
    sync_order = []
    real_verify = storage._posix_verify_directory

    def capture_verified_directory(path, *, create):
        descriptor = real_verify(path, create=create)
        info = os.fstat(descriptor)
        pinned_directory_ids.append((info.st_dev, info.st_ino))
        return descriptor

    def capture_dup(descriptor):
        duplicate = real_dup(descriptor)
        duplicate_sources.append((descriptor, duplicate))
        return duplicate

    def record_fsync(descriptor):
        info = os.fstat(descriptor)
        if stat.S_ISREG(info.st_mode):
            sync_order.append("file")
        elif stat.S_ISDIR(info.st_mode):
            sync_order.append("directory")
            sync_descriptors.append(descriptor)
            active_pinned_directory = storage._publication_directory_fd.get()
            assert active_pinned_directory is not None
            assert next(
                source
                for source, duplicate in reversed(duplicate_sources)
                if duplicate == descriptor
            ) == active_pinned_directory
            assert path.read_bytes() == candidate
            directory_info = directory.stat()
            assert (info.st_dev, info.st_ino) == (
                directory_info.st_dev,
                directory_info.st_ino,
            )
        else:
            pytest.fail("identity publication fsynced an unexpected descriptor type")
        return real_fsync(descriptor)

    monkeypatch.setattr(storage, "_posix_verify_directory", capture_verified_directory)
    monkeypatch.setattr(storage.os, "dup", capture_dup)
    monkeypatch.setattr(storage.os, "fsync", record_fsync)
    storage.publish_identity(path, expected=None, candidate=candidate)

    assert sync_order == ["file", "directory"]
    assert duplicate_sources
    assert sync_descriptors
    assert path.read_bytes() == candidate
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((directory / ".identity.lock").stat().st_mode) == 0o600
    assert duplicate_sources
    directory_identity = (directory.stat().st_dev, directory.stat().st_ino)
    assert pinned_directory_ids
    assert all(identity == directory_identity for identity in pinned_directory_ids)
    for descriptor in sync_descriptors:
        with pytest.raises(OSError) as closed:
            os.fstat(descriptor)
        assert closed.value.errno == errno.EBADF


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptor sync is required")
def test_darwin_identity_file_sync_failure_preserves_original(tmp_path, monkeypatch):
    storage = _storage()
    monkeypatch.setattr(storage.sys, "platform", "darwin")
    candidate = _candidate()
    directory = tmp_path / "darwin-file-sync-failure"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "identity.json"
    original = b"existing identity snapshot"
    path.write_bytes(original)
    os.chmod(path, 0o600)
    real_fsync = os.fsync
    fsynced_types = []

    def fail_regular_file_fsync(descriptor):
        info = os.fstat(descriptor)
        if stat.S_ISREG(info.st_mode):
            fsynced_types.append("file")
            raise OSError(errno.EIO, "injected temporary-file sync failure")
        fsynced_types.append("directory")
        return real_fsync(descriptor)

    monkeypatch.setattr(storage.os, "fsync", fail_regular_file_fsync)
    _expect_code(
        "identity_write_failed",
        lambda: storage.publish_identity(path, expected=original, candidate=candidate),
    )

    assert fsynced_types == ["file"]
    assert path.read_bytes() == original
    assert _owned_temps(directory, path) == []


@pytest.mark.skipif(os.name != "posix", reason="directory descriptor swap check uses POSIX links")
def test_publication_rejects_data_directory_swap_before_replace(tmp_path, monkeypatch):
    storage = _storage()
    candidate = _candidate()
    directory = tmp_path / "store"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "identity.json"
    original = b"original store identity bytes"
    path.write_bytes(original)
    os.chmod(path, 0o600)

    linked_target = tmp_path / "linked-target"
    linked_target.mkdir(mode=0o755)
    os.chmod(linked_target, 0o755)
    target_path = linked_target / "identity.json"
    target_original = b"target identity bytes"
    target_path.write_bytes(target_original)
    os.chmod(target_path, 0o640)
    target_dir_mode = stat.S_IMODE(linked_target.stat().st_mode)
    target_file_mode = stat.S_IMODE(target_path.stat().st_mode)

    moved_directory = tmp_path / "original-store-after-swap"
    real_replace = storage._replace

    def swap_then_replace(source, destination):
        directory.rename(moved_directory)
        directory.symlink_to(linked_target, target_is_directory=True)
        real_replace(source, destination)

    monkeypatch.setattr(storage, "_replace", swap_then_replace)
    _expect_code(
        "data_permissions_failed",
        lambda: storage.publish_identity(path, expected=original, candidate=candidate)
    )

    assert (moved_directory / "identity.json").read_bytes() == original
    assert target_path.read_bytes() == target_original
    assert stat.S_IMODE(linked_target.stat().st_mode) == target_dir_mode
    assert stat.S_IMODE(target_path.stat().st_mode) == target_file_mode
    assert directory.is_symlink()
    assert _owned_temps(moved_directory, moved_directory / "identity.json") == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors are required")
def test_lock_and_publication_share_the_same_directory_object(tmp_path, monkeypatch):
    storage = _storage()
    candidate = _candidate()
    parent = tmp_path / "parent"
    directory = parent / "store"
    directory.mkdir(parents=True, mode=0o700)
    os.chmod(parent, 0o700)
    os.chmod(directory, 0o700)
    path = directory / "identity.json"
    original = b"original identity"
    path.write_bytes(original)
    os.chmod(path, 0o600)

    replacement = tmp_path / "replacement-store"
    replacement.mkdir(mode=0o755)
    os.chmod(replacement, 0o755)
    replacement_path = replacement / "identity.json"
    target_bytes = b"replacement target"
    replacement_path.write_bytes(target_bytes)
    os.chmod(replacement_path, 0o640)
    replacement_mode = stat.S_IMODE(replacement.stat().st_mode)
    target_mode = stat.S_IMODE(replacement_path.stat().st_mode)
    displaced = parent / "displaced-original-store"
    real_verify = storage._posix_verify_directory
    verify_calls = 0

    def swap_after_publication_directory_was_opened(target, *, create):
        nonlocal verify_calls
        descriptor = real_verify(target, create=create)
        verify_calls += 1
        if verify_calls == 2:
            directory.rename(displaced)
            replacement.rename(directory)
        return descriptor

    monkeypatch.setattr(storage, "_posix_verify_directory", swap_after_publication_directory_was_opened)
    try:
        _expect_code(
            "data_permissions_failed",
            lambda: storage.publish_identity(path, expected=original, candidate=candidate),
        )
    finally:
        if directory.exists():
            directory.rename(replacement)
        displaced.rename(directory)

    assert (directory / "identity.json").read_bytes() == original
    assert replacement_path.read_bytes() == target_bytes
    assert stat.S_IMODE(replacement.stat().st_mode) == replacement_mode
    assert stat.S_IMODE(replacement_path.stat().st_mode) == target_mode
    assert not (replacement / ".identity.lock").exists()
    assert _owned_temps(replacement, replacement_path) == []
    assert not (directory / ".identity.lock").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors are required")
def test_ancestor_swap_between_inspection_and_open_does_not_mutate_target(tmp_path, monkeypatch):
    storage = _storage()
    candidate = _candidate()
    ancestor = tmp_path / "ancestor"
    directory = ancestor / "store"
    directory.mkdir(parents=True, mode=0o755)
    os.chmod(ancestor, 0o755)
    os.chmod(directory, 0o755)
    moved_ancestor = tmp_path / "moved-ancestor"
    external = tmp_path / "external"
    external.mkdir(mode=0o755)
    target_directory = external / "store"
    target_directory.mkdir(mode=0o755)
    os.chmod(target_directory, 0o755)
    sentinel = target_directory / "sentinel"
    sentinel.write_bytes(b"external bytes stay untouched")
    os.chmod(sentinel, 0o640)
    target_mode = stat.S_IMODE(target_directory.stat().st_mode)
    sentinel_mode = stat.S_IMODE(sentinel.stat().st_mode)
    real_open = os.open
    swapped = False

    def swap_ancestor_before_full_path_open(file, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and Path(os.fspath(file)).name == directory.name:
            swapped = True
            ancestor.rename(moved_ancestor)
            ancestor.symlink_to(external, target_is_directory=True)
        return real_open(file, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_ancestor_before_full_path_open)
    try:
        _expect_code(
            "data_permissions_failed",
            lambda: storage.publish_identity(directory / "identity.json", expected=None, candidate=candidate),
        )
    finally:
        if ancestor.is_symlink():
            ancestor.unlink()
        moved_ancestor.rename(ancestor)

    assert swapped
    assert sentinel.read_bytes() == b"external bytes stay untouched"
    assert stat.S_IMODE(target_directory.stat().st_mode) == target_mode
    assert stat.S_IMODE(sentinel.stat().st_mode) == sentinel_mode
    assert not (target_directory / "identity.json").exists()
    assert not (target_directory / ".identity.lock").exists()
    assert {item.name for item in target_directory.iterdir()} == {"sentinel"}


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory descriptors are required")
def test_public_read_rejects_ancestor_swap_without_reading_alternate_identity(
    tmp_path, monkeypatch
):
    storage = _storage()
    ancestor = tmp_path / "ancestor"
    directory = ancestor / "store"
    directory.mkdir(parents=True, mode=0o755)
    os.chmod(ancestor, 0o755)
    os.chmod(directory, 0o755)
    identity_path = directory / "identity.json"
    identity_path.write_bytes(b"original public identity")
    external = tmp_path / "external"
    external.mkdir(mode=0o755)
    target_directory = external / "store"
    target_directory.mkdir(mode=0o755)
    target_path = target_directory / "identity.json"
    target_path.write_bytes(b"alternate identity must not be read")
    os.chmod(target_path, 0o640)
    target_mode = stat.S_IMODE(target_path.stat().st_mode)
    moved_ancestor = tmp_path / "moved-ancestor"
    real_lstat = Path.lstat
    swapped = False

    def swap_before_binding_check(path):
        nonlocal swapped
        if not swapped and Path(path) in {directory, identity_path}:
            swapped = True
            ancestor.rename(moved_ancestor)
            ancestor.symlink_to(external, target_is_directory=True)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", swap_before_binding_check)
    try:
        _expect_error(lambda: storage.read_identity_file(identity_path))
    finally:
        if ancestor.is_symlink():
            ancestor.unlink()
        moved_ancestor.rename(ancestor)

    assert swapped
    assert target_path.read_bytes() == b"alternate identity must not be read"
    assert stat.S_IMODE(target_path.stat().st_mode) == target_mode
    assert not (target_directory / ".identity.lock").exists()
    assert {item.name for item in target_directory.iterdir()} == {"identity.json"}


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock semantics are checked here")
def test_cancel_and_lock_timeout(tmp_path):
    storage = _storage()
    directory = tmp_path / "store"
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "identity.json"
    entered = threading.Event()
    release = threading.Event()
    errors = []

    def holder():
        try:
            with storage.identity_lock(path):
                entered.set()
                release.wait(4)
        except BaseException as error:  # collect worker failures for assertion in parent
            errors.append(error)

    thread = threading.Thread(target=holder, daemon=True)
    thread.start()
    assert entered.wait(2)
    try:
        _expect_code(
            "identity_unlock_cancelled",
            lambda: storage.identity_lock(path, cancelled=lambda: True).__enter__(),
        )
        started = time.monotonic()
        _expect_code(
            "identity_busy",
            lambda: storage.identity_lock(path).__enter__(),
        )
        elapsed = time.monotonic() - started
        assert elapsed < 2.5
    finally:
        release.set()
        thread.join(timeout=2)
    assert not thread.is_alive()
    assert errors == []
