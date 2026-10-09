"""Private, bounded persistence for encrypted identity documents."""

from __future__ import annotations

from contextlib import contextmanager
import errno
from contextvars import ContextVar
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import time
from typing import Iterator

from .identity_codec import inspect_document
from .models import SparcError

_MAX_IDENTITY_BYTES = 4096
_LOCK_NAME = ".identity.lock"
_LOCK_SECONDS = 2.0
_POLL_SECONDS = 0.05
_publication_directory_fd: ContextVar[int | None] = ContextVar("identity_publication_directory_fd", default=None)


def _error(code: str, message: str) -> SparcError:
    return SparcError(code, message)


def _cancelled(cancelled) -> bool:
    if cancelled is None:
        return False
    try:
        return bool(cancelled())
    except Exception as exc:
        raise _error("identity_unlock_cancelled", "Identity operation was canceled") from exc


def _ensure_bytes(raw: bytes, label: str) -> None:
    if not isinstance(raw, bytes):
        raise TypeError(f"{label} must be bytes")


def _absolute_path(path: Path) -> Path:
    result = Path(os.path.abspath(os.fspath(path)))
    if ".." in Path(path).parts:
        raise _error("data_permissions_failed", "Identity storage path contains an unsafe component")
    return result


def _posix_reject_link_components(path: Path) -> Path:
    absolute = _absolute_path(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise _error("data_permissions_failed", "Identity storage path contains a symbolic link")
    return absolute


def _posix_verify_directory(path: Path, *, create: bool) -> int:
    """Open each path component relative to a retained no-follow directory fd."""
    absolute = _absolute_path(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute.anchor, flags)
    except OSError as exc:
        raise _error("data_permissions_failed", "Could not open identity path root") from exc
    try:
        for part in absolute.parts[1:]:
            try:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise _error("data_permissions_failed", "Identity storage path contains an unsafe component")
            child = os.open(part, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                os.close(child)
                raise _error("data_permissions_failed", "Identity path component changed during inspection")
            os.close(descriptor)
            descriptor = child

        info = os.fstat(descriptor)
        try:
            path_info = absolute.lstat()
        except OSError as exc:
            raise _error("data_permissions_failed", "Identity directory changed during inspection") from exc
        if stat.S_ISLNK(path_info.st_mode) or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino):
            raise _error("data_permissions_failed", "Identity directory changed during inspection")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise _error("data_permissions_failed", "Identity directory is not owned by the current user")
        if stat.S_IMODE(info.st_mode) != 0o700:
            try:
                os.fchmod(descriptor, 0o700)
            except OSError as exc:
                raise _error("data_permissions_failed", "Could not secure private identity directory") from exc
        secured = os.fstat(descriptor)
        if stat.S_IMODE(secured.st_mode) != 0o700:
            raise _error("data_permissions_failed", "Private identity directory permissions were not applied")
        return descriptor
    except BaseException as exc:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if isinstance(exc, FileNotFoundError):
            raise _error("data_permissions_failed", "Identity storage directory is absent") from exc
        if isinstance(exc, OSError) and not isinstance(exc, SparcError):
            raise _error("data_permissions_failed", "Could not safely open identity directory") from exc
        raise


def _fd_read_bounded(descriptor: int) -> bytes:
    chunks: list[bytes] = []
    remaining = _MAX_IDENTITY_BYTES + 1
    while remaining:
        chunk = os.read(descriptor, min(remaining, 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    result = b"".join(chunks)
    if len(result) > _MAX_IDENTITY_BYTES:
        raise _error("invalid_identity", "Identity file exceeds the supported size limit")
    return result


def _posix_open_read_directory(path: Path) -> int | None:
    """Open a public-read parent component by component without mutation."""
    absolute = _absolute_path(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute.anchor, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise _error("invalid_identity", "Could not safely open identity directory") from exc
    try:
        for part in absolute.parts[1:]:
            try:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                os.close(descriptor)
                return None
            except OSError as exc:
                raise _error("invalid_identity", "Identity directory changed during inspection") from exc
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise _error("invalid_identity", "Identity directory contains an unsafe component")
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise _error("invalid_identity", "Could not safely open identity directory") from exc
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                os.close(child)
                raise _error("invalid_identity", "Identity directory changed during inspection")
            os.close(descriptor)
            descriptor = child
        opened = os.fstat(descriptor)
        try:
            current = absolute.lstat()
        except OSError as exc:
            raise _error("invalid_identity", "Identity directory changed during inspection") from exc
        if stat.S_ISLNK(current.st_mode) or (opened.st_dev, opened.st_ino) != (
            current.st_dev, current.st_ino
        ):
            raise _error("invalid_identity", "Identity directory changed during inspection")
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _posix_open_regular(path: Path, *, dir_fd: int | None = None, writable: bool = False) -> int | None:
    flags = (os.O_RDWR if writable else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise _error("invalid_identity", "Identity file must not be a symbolic link") from exc
        raise
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise _error("invalid_identity", "Identity path is not a regular file")
        if info.st_nlink != 1:
            raise _error("invalid_identity", "Identity file must not have additional hard links")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise _error("data_permissions_failed", "Identity file is not owned by the current user")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _posix_read(path: Path, *, private: bool, cancelled=None) -> bytes | None:
    absolute = _absolute_path(path)
    if private:
        directory_fd = _posix_verify_directory(absolute.parent, create=True)
        try:
            with identity_lock(absolute, cancelled=cancelled, _directory_fd=directory_fd):
                descriptor = _posix_open_regular(Path(absolute.name), dir_fd=directory_fd, writable=True)
                if descriptor is None:
                    return None
                try:
                    os.fchmod(descriptor, 0o600)
                    os.lseek(descriptor, 0, os.SEEK_SET)
                    return _fd_read_bounded(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            os.close(directory_fd)

    directory_fd = _posix_open_read_directory(absolute.parent)
    if directory_fd is None:
        return None
    try:
        descriptor = _posix_open_regular(Path(absolute.name), dir_fd=directory_fd)
        if descriptor is None:
            return None
        try:
            return _fd_read_bounded(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def _windows_adapter():
    if not sys.platform.startswith("win"):
        return None
    from . import _windows_identity_storage

    return _windows_identity_storage


def read_identity_file(path: Path) -> bytes | None:
    """Read at most 4097 bytes without following an identity-file link."""
    absolute = Path(path)
    adapter = _windows_adapter()
    if adapter is not None:
        try:
            with adapter.open_directory_chain(absolute.parent, private=False):
                with adapter.open_regular_file(absolute) as stream:
                    value = stream.read(_MAX_IDENTITY_BYTES + 1)
        except FileNotFoundError:
            return None
        except SparcError:
            raise
        except OSError as exc:
            raise _error("invalid_identity", "Could not safely read identity file") from exc
        if len(value) > _MAX_IDENTITY_BYTES:
            raise _error("invalid_identity", "Identity file exceeds the supported size limit")
        return value
    return _posix_read(absolute, private=False)


def _secure_private_directory(directory: Path) -> None:
    adapter = _windows_adapter()
    if adapter is not None:
        try:
            adapter.prepare_private_directory(directory)
        except SparcError:
            raise
        except OSError as exc:
            raise _error("data_permissions_failed", "Could not secure private identity directory") from exc
        return
    descriptor = _posix_verify_directory(directory, create=True)
    os.close(descriptor)


def read_private_identity_file(path: Path, *, cancelled=None) -> bytes | None:
    """Secure the identity store and read its file while holding the identity lock."""
    absolute = _absolute_path(path)
    _secure_private_directory(absolute.parent)
    adapter = _windows_adapter()
    if adapter is not None:
        with identity_lock(absolute, cancelled=cancelled):
            try:
                adapter.secure_identity_file(absolute)
                with adapter.open_regular_file(absolute) as stream:
                    value = stream.read(_MAX_IDENTITY_BYTES + 1)
            except FileNotFoundError:
                return None
            if len(value) > _MAX_IDENTITY_BYTES:
                raise _error("invalid_identity", "Identity file exceeds the supported size limit")
            return value
    return _posix_read(absolute, private=True, cancelled=cancelled)


@contextmanager
def identity_lock(path: Path, *, cancelled=None, _directory_fd: int | None = None) -> Iterator[None]:
    """Acquire the reusable identity lock with a bounded, cancellable wait."""
    absolute = _absolute_path(path)
    directory = absolute.parent
    adapter = _windows_adapter()
    if adapter is not None:
        _secure_private_directory(directory)
        with adapter.identity_file_lock(directory / _LOCK_NAME, cancelled=cancelled):
            yield
        return

    directory_fd = (
        os.dup(_directory_fd)
        if _directory_fd is not None
        else _posix_verify_directory(directory, create=True)
    )
    descriptor = None
    acquired = False
    try:
        if _directory_fd is not None:
            try:
                path_info = directory.lstat()
                opened_info = os.fstat(directory_fd)
            except OSError as exc:
                raise _error("data_permissions_failed", "Identity directory changed before locking") from exc
            if (path_info.st_dev, path_info.st_ino) != (opened_info.st_dev, opened_info.st_ino):
                raise _error("data_permissions_failed", "Identity directory changed before locking")
        try:
            descriptor = os.open(
                _LOCK_NAME,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                0o600,
                dir_fd=directory_fd,
            )
            info = os.fstat(descriptor)
            lock_info = os.stat(_LOCK_NAME, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_ISLNK(lock_info.st_mode):
                raise _error("data_permissions_failed", "Identity lock is not a regular file")
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise _error("data_permissions_failed", "Identity lock is not owned by the current user")
            if (info.st_dev, info.st_ino) != (lock_info.st_dev, lock_info.st_ino):
                raise _error("data_permissions_failed", "Identity lock changed during inspection")
            os.fchmod(descriptor, 0o600)
        except FileExistsError as exc:
            raise _error("data_permissions_failed", "Identity lock is not a usable regular file") from exc
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise _error("data_permissions_failed", "Identity lock must not be a symbolic link") from exc
            raise _error("data_permissions_failed", "Could not open private identity lock") from exc

        try:
            import fcntl
        except ImportError as exc:
            raise _error("data_permissions_failed", "Identity locking is unavailable") from exc
        deadline = time.monotonic() + _LOCK_SECONDS
        while True:
            if _cancelled(cancelled):
                raise _error("identity_unlock_cancelled", "Identity operation was canceled")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _error("identity_busy", "Identity storage is busy; try again")
                time.sleep(min(_POLL_SECONDS, remaining))
            except OSError as exc:
                raise _error("data_permissions_failed", "Could not acquire identity lock") from exc
        yield
    finally:
        if acquired and descriptor is not None:
            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _replace(source: Path, destination: Path) -> None:
    descriptor = _publication_directory_fd.get()
    if descriptor is None:
        os.replace(source, destination)
        return
    info = os.fstat(descriptor)
    try:
        current = destination.parent.lstat()
    except OSError as exc:
        raise _error("data_permissions_failed", "Identity directory changed before publication") from exc
    if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
        raise _error("data_permissions_failed", "Identity directory changed before publication")
    os.replace(source.name, destination.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)


def _sync_directory(directory: Path) -> None:
    if not sys.platform.startswith("linux"):
        return
    pinned = _publication_directory_fd.get()
    if pinned is not None:
        info = os.fstat(pinned)
        try:
            current = directory.lstat()
        except OSError as exc:
            raise _error("data_permissions_failed", "Identity directory changed after publication") from exc
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise _error("data_permissions_failed", "Identity directory changed after publication")
        descriptor = os.dup(pinned)
    else:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _unlink_owned(path: Path, identity: tuple[int, int] | None) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
        if (current.st_dev, current.st_ino) == identity:
            path.unlink()
    except OSError:
        pass


def _unlink_owned_at(name: str, identity: tuple[int, int] | None, directory_fd: int) -> None:
    if identity is None:
        return
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == identity:
            os.unlink(name, dir_fd=directory_fd)
    except OSError:
        pass


def _read_under_lock(path: Path, directory_fd: int) -> bytes | None:
    descriptor = _posix_open_regular(Path(path.name), dir_fd=directory_fd, writable=True)
    if descriptor is None:
        return None
    try:
        os.fchmod(descriptor, 0o600)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return _fd_read_bounded(descriptor)
    finally:
        os.close(descriptor)


def _validate_candidate(candidate: bytes) -> None:
    _ensure_bytes(candidate, "candidate")
    if len(candidate) > _MAX_IDENTITY_BYTES:
        raise _error("invalid_identity", "Identity document exceeds the supported size limit")
    info = inspect_document(candidate)
    if getattr(info, "status", None) != "encrypted_locked":
        raise _error("invalid_identity", "Only encrypted version-2 identities may be published")


def publish_identity(
    path: Path,
    expected: bytes | None,
    candidate: bytes,
    *,
    cancelled=None,
) -> None:
    """Publish an encrypted candidate with compare-and-replace semantics."""
    _validate_candidate(candidate)
    if expected is not None:
        _ensure_bytes(expected, "expected")
        if len(expected) > _MAX_IDENTITY_BYTES:
            raise _error("invalid_identity", "Expected identity exceeds the supported size limit")
    absolute = _absolute_path(path)
    directory = absolute.parent
    _secure_private_directory(directory)
    adapter = _windows_adapter()
    if adapter is not None:
        with identity_lock(absolute, cancelled=cancelled):
            adapter.secure_identity_file(absolute, allow_missing=True)
            current = read_identity_file(absolute)
            if current != expected:
                raise _error("identity_changed", "Identity changed while it was being updated")
            if current == candidate:
                return
            if _cancelled(cancelled):
                raise _error("identity_unlock_cancelled", "Identity operation was canceled")
            committed = False
            temp_path: Path | None = None
            temp_identity: tuple[int, int] | None = None
            try:
                temp_path = adapter.write_encrypted_temporary(directory, absolute.name, candidate)
                temp_info = temp_path.lstat()
                temp_identity = (temp_info.st_dev, temp_info.st_ino)
                if _cancelled(cancelled):
                    raise _error("identity_unlock_cancelled", "Identity operation was canceled")
                if read_identity_file(absolute) != expected:
                    raise _error("identity_changed", "Identity changed while it was being updated")
                _replace(temp_path, absolute)
                committed = True
                adapter.sync_directory(directory)
                if read_identity_file(absolute) != candidate:
                    raise OSError("published identity did not read back exactly")
            except BaseException as exc:
                if not committed and expected != candidate:
                    try:
                        committed = read_identity_file(absolute) == candidate
                    except BaseException:
                        pass
                if committed:
                    raise _error("identity_commit_uncertain", "Identity was published but durability could not be confirmed") from exc
                if isinstance(exc, SparcError):
                    raise
                raise _error("identity_write_failed", "Could not safely publish encrypted identity") from exc
            finally:
                if not committed and temp_path is not None:
                    _unlink_owned(temp_path, temp_identity)
        return

    directory_fd = _posix_verify_directory(directory, create=True)
    temporary_path: Path | None = None
    temporary_identity: tuple[int, int] | None = None
    committed = False
    try:
        with identity_lock(absolute, cancelled=cancelled, _directory_fd=directory_fd):
            current = _read_under_lock(absolute, directory_fd)
            if current != expected:
                raise _error("identity_changed", "Identity changed while it was being updated")
            if current == candidate:
                return
            if _cancelled(cancelled):
                raise _error("identity_unlock_cancelled", "Identity operation was canceled")
            publication_token = _publication_directory_fd.set(directory_fd)
            try:
                temp_name = f".{absolute.name}.{secrets.token_hex(6)}.tmp"
                descriptor = os.open(
                    temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                    0o600, dir_fd=directory_fd,
                )
                temporary_path = directory / temp_name
                temp_info = os.fstat(descriptor)
                temporary_identity = (temp_info.st_dev, temp_info.st_ino)
                try:
                    os.fchmod(descriptor, 0o600)
                    with os.fdopen(descriptor, "wb") as stream:
                        descriptor = -1
                        stream.write(candidate)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                if _cancelled(cancelled):
                    raise _error("identity_unlock_cancelled", "Identity operation was canceled")
                if _read_under_lock(absolute, directory_fd) != expected:
                    raise _error("identity_changed", "Identity changed while it was being updated")
                _replace(temporary_path, absolute)
                committed = True
                temporary_path = None
                _sync_directory(directory)
                readback = _read_under_lock(absolute, directory_fd)
                if readback != candidate:
                    raise OSError("published identity did not read back exactly")
            except BaseException as exc:
                if not committed and expected != candidate:
                    try:
                        committed = _read_under_lock(absolute, directory_fd) == candidate
                    except BaseException:
                        pass
                if committed:
                    raise _error(
                        "identity_commit_uncertain",
                        "Identity was published but durability could not be confirmed",
                    ) from exc
                if isinstance(exc, SparcError):
                    raise
                raise _error("identity_write_failed", "Could not safely publish encrypted identity") from exc
            finally:
                _publication_directory_fd.reset(publication_token)
    finally:
        if temporary_path is not None:
            _unlink_owned_at(temporary_path.name, temporary_identity, directory_fd)
        os.close(directory_fd)
