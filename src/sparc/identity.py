"""Persistent local Ed25519 identity management."""

import base64
import binascii
import hashlib
import ipaddress
from pathlib import Path
import re
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .encoding import canonical, parse_object
from .models import Identity, SparcError
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


def _load_existing(path: Path) -> Identity:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SparcError("identity_read_failed", "Could not read the identity store") from exc
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
    return Identity(
        private_key=private_key,
        public_bytes=public_bytes,
        fingerprint=hashlib.sha256(public_bytes).hexdigest(),
    )


def _create_identity(path: Path) -> Identity:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = _raw_private_bytes(private_key)
    public_bytes = _raw_public_bytes(private_key)
    document = {
        "version": 1,
        "private_key": base64.b64encode(private_bytes).decode("ascii"),
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
    }
    try:
        atomic_write(path, canonical(document), private=True)
    except OSError as exc:
        raise SparcError("identity_write_failed", "Could not create the identity store") from exc
    return Identity(
        private_key=private_key,
        public_bytes=public_bytes,
        fingerprint=hashlib.sha256(public_bytes).hexdigest(),
    )


def load_identity(data_dir: Path) -> Identity:
    """Load an existing identity or create a new one when its store is absent."""
    path = Path(data_dir) / "identity.json"
    secure_private_store(path)
    if path.exists():
        return _load_existing(path)
    return _create_identity(path)


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
