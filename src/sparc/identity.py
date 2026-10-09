"""Persistent local Ed25519 identity management."""

import base64
import binascii
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import stat
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .encoding import canonical, parse_object
from .models import Endpoint, Identity, SparcError
from . import identity_codec as _identity_codec
from . import identity_storage as _identity_storage
from .identity_codec import (
    CancelPredicate,
    CredentialProvider,
    IdentityCredentials,
    IdentityInfo,
    IdentityUnlockRequest,
)
from .storage import atomic_write, secure_private_store


_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}\Z")


def _raw_private_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _raw_public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _decode_key(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise SparcError("invalid_identity", f"Identity {field} must be a Base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SparcError("invalid_identity", f"Identity {field} is not valid Base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise SparcError("invalid_identity", f"Identity {field} is not canonical Base64")
    if len(decoded) != 32:
        raise SparcError("invalid_identity", f"Identity {field} must encode exactly 32 bytes")
    return decoded


_HISTORY_FILES = (
    "trusted_peers.json",
    "audit.jsonl",
    "audit-checkpoint.json",
    "simulation-checkpoint.json",
)
_UNLOCK_ISSUER = object()


class _UnlockedStore:
    """Private, redacted, single-use credential handoff."""

    __slots__ = (
        "_data_dir", "_path", "_snapshot", "_identity", "_issuer", "_consumed", "_guard"
    )

    def __init__(self, data_dir, path, snapshot, identity, *, _issuer_token=None):
        if _issuer_token is not _UNLOCK_ISSUER:
            raise SparcError("invalid_identity", "Unlocked identity handles can only be issued internally")
        self._data_dir = data_dir
        self._path = path
        self._snapshot = snapshot
        self._identity = identity
        self._issuer = _UNLOCK_ISSUER
        self._consumed = False
        self._guard = threading.Lock()

    def __repr__(self):
        return "<UnlockedStore>"


def _absolute_data_dir(data_dir: Path) -> Path:
    # abspath makes a stable handoff path without resolving symlink ancestors.
    supplied = Path(data_dir)
    if ".." in supplied.parts:
        raise SparcError("data_permissions_failed", "Identity storage path contains an unsafe component")
    return Path(os.path.abspath(os.fspath(supplied)))


def _check_cancelled(cancelled: CancelPredicate | None) -> None:
    _identity_codec._check_cancelled(cancelled)


def _request_credentials(
    provider: CredentialProvider | None,
    purpose: str,
    data_dir: Path,
    fingerprint: str | None,
    cancelled: CancelPredicate | None,
) -> bytes:
    _check_cancelled(cancelled)
    if provider is None:
        raise SparcError("identity_credentials_required", "Identity credentials are required")
    try:
        supplied = provider(IdentityUnlockRequest(purpose, data_dir, fingerprint))
    except SparcError:
        raise
    except Exception as exc:
        raise SparcError("identity_unlock_cancelled", "Identity operation was canceled") from exc
    _check_cancelled(cancelled)
    if supplied is None:
        raise SparcError("identity_unlock_cancelled", "Identity operation was canceled")
    return _identity_codec.validate_credentials(supplied, purpose)


def inspect_identity(data_dir: Path) -> IdentityInfo:
    """Read and validate only bounded public identity metadata."""
    directory = _absolute_data_dir(data_dir)
    raw = _identity_storage.read_identity_file(directory / "identity.json")
    if raw is None:
        return IdentityInfo("absent", None, None, False)
    return _identity_codec.inspect_document(raw)


def _legacy_identity(raw: bytes) -> Identity:
    try:
        document = parse_object(raw)
    except SparcError as exc:
        raise SparcError("invalid_identity", "Identity store is corrupt") from exc
    if set(document) != {"version", "private_key", "public_key"}:
        raise SparcError("invalid_identity", "Identity store has unexpected fields")
    if type(document["version"]) is not int or document["version"] != 1:
        raise SparcError("invalid_identity", "Identity store version is unsupported")
    private_bytes = _decode_key(document["private_key"], "private_key")
    public_bytes = _decode_key(document["public_key"], "public_key")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    except (TypeError, ValueError) as exc:
        raise SparcError("invalid_identity", "Identity private key is invalid") from exc
    if _raw_public_bytes(private_key) != public_bytes:
        raise SparcError("invalid_identity", "Identity public key does not match its private key")
    return Identity(private_key, public_bytes, hashlib.sha256(public_bytes).hexdigest())


def _has_retained_history(directory: Path) -> bool:
    for name in _HISTORY_FILES:
        try:
            (directory / name).lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SparcError("data_permissions_failed", "Could not inspect identity history") from exc
        return True
    return False


def _same_identity(left: Identity, right: Identity) -> bool:
    return (
        left.public_bytes == right.public_bytes
        and left.fingerprint == right.fingerprint
        and _raw_private_bytes(left.private_key) == _raw_private_bytes(right.private_key)
    )


def _unlock_store(
    data_dir: Path,
    *,
    credential_provider: CredentialProvider | None = None,
    cancelled: CancelPredicate | None = None,
) -> _UnlockedStore:
    directory = _absolute_data_dir(data_dir)
    path = directory / "identity.json"
    _check_cancelled(cancelled)

    # Initial inspection is read-only. Validate legacy consistency before ever
    # asking for credentials, and retain the exact bytes across the prompt.
    initial = _identity_storage.read_identity_file(path)
    if initial is None:
        if _has_retained_history(directory):
            raise SparcError("identity_missing", "Identity is missing while retained history exists")
        purpose = "create"
        legacy = None
        info = IdentityInfo("absent", None, None, False)
    else:
        info = _identity_codec.inspect_document(initial)
        legacy = _legacy_identity(initial) if info.status == "legacy_unencrypted" else None
        purpose = "migrate" if legacy is not None else "unlock"

    phrase = _request_credentials(
        credential_provider, purpose, directory, info.fingerprint, cancelled
    )
    _check_cancelled(cancelled)

    if initial is None:
        private_key = Ed25519PrivateKey.generate()
        public_bytes = _raw_public_bytes(private_key)
        identity = Identity(private_key, public_bytes, hashlib.sha256(public_bytes).hexdigest())
        expected = None
    elif legacy is not None:
        identity = legacy
        expected = initial
    else:
        # Permission tightening and the private read happen only after the
        # credential has been supplied and validated.
        current = _identity_storage.read_private_identity_file(path, cancelled=cancelled)
        if current != initial:
            raise SparcError("identity_changed", "Identity changed while credentials were requested")
        identity = _identity_codec.decode_identity(current, phrase, cancelled=cancelled)
        return _UnlockedStore(directory, path, current, identity, _issuer_token=_UNLOCK_ISSUER)

    candidate = _identity_codec.encode_identity(identity, phrase, cancelled=cancelled)
    decoded = _identity_codec.decode_identity(candidate, phrase, cancelled=cancelled)
    if not _same_identity(identity, decoded):
        raise SparcError("invalid_identity", "Encrypted identity self-check failed")
    _check_cancelled(cancelled)
    _identity_storage.publish_identity(path, expected, candidate, cancelled=cancelled)
    # Publication cannot be rolled back. A cancellation now retains the same
    # encrypted key and prevents callers from starting a service.
    _check_cancelled(cancelled)
    committed = _identity_storage.read_private_identity_file(path, cancelled=cancelled)
    if committed != candidate:
        raise SparcError("identity_changed", "Identity changed after publication")
    return _UnlockedStore(directory, path, committed, decoded, _issuer_token=_UNLOCK_ISSUER)


def _consume_unlocked_store(
    handle: _UnlockedStore,
    *,
    cancelled: CancelPredicate | None = None,
) -> tuple[Path, Identity]:
    if type(handle) is not _UnlockedStore or getattr(handle, "_issuer", None) is not _UNLOCK_ISSUER:
        raise SparcError("invalid_identity", "Unlocked identity handle is invalid")
    _check_cancelled(cancelled)
    with handle._guard:
        if handle._consumed:
            raise SparcError("invalid_identity", "Unlocked identity handle has already been consumed")
        _check_cancelled(cancelled)
        if os.name == "posix":
            directory_fd = _identity_storage._posix_verify_directory(
                handle._data_dir, create=False
            )
            try:
                with _identity_storage.identity_lock(
                    handle._path, cancelled=cancelled, _directory_fd=directory_fd
                ):
                    _check_cancelled(cancelled)
                    _verify_handle_directory_binding(handle._data_dir, directory_fd)
                    current = _identity_storage._read_under_lock(handle._path, directory_fd)
                    _verify_handle_directory_binding(handle._data_dir, directory_fd)
                    if current != handle._snapshot:
                        raise SparcError("identity_changed", "Identity changed after it was unlocked")
            finally:
                os.close(directory_fd)
        else:
            with _identity_storage.identity_lock(handle._path, cancelled=cancelled):
                _check_cancelled(cancelled)
                current = _identity_storage.read_identity_file(handle._path)
                if current != handle._snapshot:
                    raise SparcError("identity_changed", "Identity changed after it was unlocked")
        handle._consumed = True
        return handle._data_dir, handle._identity


def _verify_handle_directory_binding(directory: Path, directory_fd: int) -> None:
    try:
        opened = os.fstat(directory_fd)
        current = directory.lstat()
    except OSError as exc:
        raise SparcError("data_permissions_failed", "Identity directory changed during handoff") from exc
    if not stat.S_ISDIR(current.st_mode) or (opened.st_dev, opened.st_ino) != (
        current.st_dev, current.st_ino
    ):
        raise SparcError("data_permissions_failed", "Identity directory changed during handoff")


def load_identity(
    data_dir: Path,
    *,
    credential_provider: CredentialProvider | None = None,
    cancelled: CancelPredicate | None = None,
) -> Identity:
    """Load, create, or migrate the local identity using explicit credentials."""
    handle = _unlock_store(
        data_dir, credential_provider=credential_provider, cancelled=cancelled
    )
    return handle._identity


def _validate_public_key(public_key: bytes) -> tuple[bytes, str]:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise SparcError("invalid_public_key", "Peer public key must be exactly 32 bytes")
    return public_key, hashlib.sha256(public_key).hexdigest()


def _validate_endpoint(endpoint) -> tuple[str, int]:
    from .models import Endpoint

    if not isinstance(endpoint, Endpoint):
        raise SparcError("invalid_endpoint", "Peer endpoint must be an Endpoint")
    if not isinstance(endpoint.ip, str):
        raise SparcError("invalid_endpoint", "Endpoint IP must be a literal IPv4 address")
    try:
        address = ipaddress.IPv4Address(endpoint.ip)
    except ipaddress.AddressValueError as exc:
        raise SparcError("invalid_endpoint", "Endpoint IP must be a literal IPv4 address") from exc
    if str(address) != endpoint.ip:
        raise SparcError("invalid_endpoint", "Endpoint IP must use canonical IPv4 notation")
    if type(endpoint.port) is not int or not 1 <= endpoint.port <= 65535:
        raise SparcError("invalid_endpoint", "Endpoint port must be an integer from 1 to 65535")
    return endpoint.ip, endpoint.port


def _decode_peer_key(value: object) -> bytes:
    return _decode_key(value, "peer public_key")


def _load_trust_file(path: Path) -> dict[str, dict]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SparcError("trust_read_failed", "Could not read the trusted peers store") from exc
    try:
        document = parse_object(raw)
    except SparcError as exc:
        raise SparcError("invalid_trust_store", "Trusted peers store is corrupt") from exc
    if set(document) != {"version", "peers"}:
        raise SparcError("invalid_trust_store", "Trusted peers store has unexpected fields")
    if type(document["version"]) is not int or document["version"] != 1:
        raise SparcError("invalid_trust_store", "Trusted peers store version is unsupported")
    peers = document["peers"]
    if not isinstance(peers, dict):
        raise SparcError("invalid_trust_store", "Trusted peers must be stored in an object")

    for fingerprint, entry in peers.items():
        if not isinstance(fingerprint, str) or _FINGERPRINT_RE.fullmatch(fingerprint) is None:
            raise SparcError("invalid_trust_store", "Trusted peer fingerprint is invalid")
        if not isinstance(entry, dict) or set(entry) != {"public_key", "label", "ip", "port"}:
            raise SparcError("invalid_trust_store", "Trusted peer entry has unexpected fields")
        public_key = _decode_peer_key(entry["public_key"])
        if hashlib.sha256(public_key).hexdigest() != fingerprint:
            raise SparcError("invalid_trust_store", "Trusted peer key does not match its fingerprint")
        if not isinstance(entry["label"], str):
            raise SparcError("invalid_trust_store", "Trusted peer label must be a string")
        try:
            ip = ipaddress.IPv4Address(entry["ip"])
        except (ipaddress.AddressValueError, TypeError) as exc:
            raise SparcError("invalid_trust_store", "Trusted peer IP must be literal IPv4") from exc
        if str(ip) != entry["ip"]:
            raise SparcError("invalid_trust_store", "Trusted peer IP must use canonical IPv4 notation")
        if type(entry["port"]) is not int or not 1 <= entry["port"] <= 65535:
            raise SparcError("invalid_trust_store", "Trusted peer port is invalid")
    return peers


class TrustStore:
    """Explicitly pinned peer identities with endpoint-change protection."""

    def __init__(self, data_dir: Path) -> None:
        self.path = Path(data_dir) / "trusted_peers.json"
        secure_private_store(self.path)
        self._lock = threading.RLock()
        self._blocked = False
        if self.path.exists():
            self._peers = _load_trust_file(self.path)
        else:
            self._peers: dict[str, dict] = {}

    def _ensure_available(self) -> None:
        if self._blocked:
            raise SparcError(
                "trust_write_failed",
                "Trusted peers state is blocked after a write failure; create a fresh TrustStore to reload the on-disk state",
            )

    def check(self, public_key: bytes, endpoint) -> str:
        with self._lock:
            self._ensure_available()
            _public_key, fingerprint = _validate_public_key(public_key)
            ip, port = _validate_endpoint(endpoint)
            for known_fingerprint, entry in self._peers.items():
                if entry["ip"] == ip and entry["port"] == port and known_fingerprint != fingerprint:
                    return "changed"
            if fingerprint in self._peers:
                return "known"
            return "unknown"

    def snapshot(self) -> list[dict]:
        """Return sorted public peer records without exposing trust-store state."""
        with self._lock:
            self._ensure_available()
            return [
                {
                    "fingerprint": fingerprint,
                    "label": entry["label"],
                    "endpoint": Endpoint(entry["ip"], entry["port"]),
                }
                for fingerprint, entry in sorted(self._peers.items())
            ]

    def _write_peers(self, peers: dict[str, dict]) -> None:
        document = {"version": 1, "peers": peers}
        try:
            atomic_write(self.path, canonical(document), private=True)
        except Exception as exc:
            self._blocked = True
            raise SparcError("trust_write_failed", "Could not update trusted peers store") from exc

    def pin(self, public_key: bytes, endpoint, label: str = "") -> None:
        with self._lock:
            self._ensure_available()
            _public_key, fingerprint = _validate_public_key(public_key)
            ip, port = _validate_endpoint(endpoint)
            if not isinstance(label, str):
                raise SparcError("invalid_label", "Peer label must be a string")
            for known_fingerprint, entry in self._peers.items():
                if (
                    known_fingerprint != fingerprint
                    and entry["ip"] == ip
                    and entry["port"] == port
                ):
                    raise SparcError("endpoint_already_pinned", "Endpoint is pinned to a different peer key")

            updated = {key: dict(value) for key, value in self._peers.items()}
            updated[fingerprint] = {
                "public_key": base64.b64encode(public_key).decode("ascii"),
                "label": label,
                "ip": ip,
                "port": port,
            }
            self._write_peers(updated)
            self._peers = updated

    def forget(self, fingerprint: str) -> None:
        with self._lock:
            self._ensure_available()
            if not isinstance(fingerprint, str) or _FINGERPRINT_RE.fullmatch(fingerprint) is None:
                raise SparcError("invalid_fingerprint", "Fingerprint must be lowercase 64-character hexadecimal")
            if fingerprint not in self._peers:
                return
            updated = {key: dict(value) for key, value in self._peers.items() if key != fingerprint}
            self._write_peers(updated)
            self._peers = updated
