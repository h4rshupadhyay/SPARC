"""Filesystem helpers for private SPARC data."""

import errno
import os
from pathlib import Path
import sys
import tempfile

from .models import SparcError


def resolve_data_dir(override: Path | None) -> Path:
    """Resolve the platform's SPARC data directory, honoring explicit overrides."""
    if override is not None:
        return Path(override)

    if sys.platform.startswith("win"):
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise SparcError(
                "data_dir_unavailable",
                "LOCALAPPDATA is not set; choose a data directory explicitly",
            )
        return Path(local_app_data) / "SPARC"

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "SPARC"

    if sys.platform.startswith("linux"):
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config_home:
            xdg_path = Path(xdg_config_home)
            if xdg_path.is_absolute():
                return xdg_path / "sparc"
        return Path.home() / ".config" / "sparc"

    raise SparcError("data_dir_unavailable", "No default SPARC data directory for this platform")


def secure_private_store(path: Path) -> None:
    """Create the store directory and restrict existing POSIX identity/trust files."""
    store_path = Path(path)
    parent = store_path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if sys.platform.startswith("linux") or sys.platform == "darwin":
            os.chmod(parent, 0o700)
            if store_path.exists():
                os.chmod(store_path, 0o600)
    except OSError as exc:
        raise SparcError(
            "data_permissions_failed",
            f"Could not secure SPARC data permissions at {store_path}; check directory ownership and permissions",
        ) from exc


def _sync_parent_directory(parent: Path) -> None:
    linux = sys.platform.startswith("linux")
    darwin = sys.platform == "darwin"
    if not (linux or darwin):
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        directory_fd = os.open(parent, flags)
    except OSError as exc:
        if linux and exc.errno in (
            errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS
        ):
            return
        raise
    try:
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            if not linux or exc.errno not in (
                errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS
            ):
                raise
    finally:
        os.close(directory_fd)


def atomic_write(
    path: Path,
    data: bytes,
    private: bool = True,
    *,
    secure_parent: bool = True,
) -> None:
    """Atomically replace a file using a flushed same-directory temporary file."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if type(secure_parent) is not bool:
        raise TypeError("secure_parent must be a boolean")

    destination = Path(path)
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_posix = sys.platform.startswith("linux") or sys.platform == "darwin"
    if private_posix and secure_parent:
        os.chmod(parent, 0o700)

    descriptor = -1
    temporary_path: str | None = None
    try:
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=parent
        )
        if private_posix:
            os.fchmod(descriptor, 0o600 if private else 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        _sync_parent_directory(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
