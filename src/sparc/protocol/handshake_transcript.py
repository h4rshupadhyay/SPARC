"""Pure construction, validation, and trust decisions for handshake messages."""

import base64
import hashlib
import os
import socket
import threading
import time
from collections.abc import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ..encoding import canonical
from ..identity import TrustStore
from ..models import Identity, Limits, SparcError
from .messages import decode_base64
from .handshake_types import PeerCandidate


HANDSHAKE_RESPONDER_DOMAIN = b"SPARC-v1 handshake responder\x00"
HANDSHAKE_INITIATOR_DOMAIN = b"SPARC-v1 handshake initiator\x00"
_HELLO_FIELDS = frozenset(
    {"kind", "protocol", "version", "identity_key", "ephemeral_key", "random"}
)


def _schema(message: str) -> SparcError:
    return SparcError("invalid_schema", message)


def _validate_hello_kind(payload: dict, kind: str, signed: bool) -> None:
    if not isinstance(payload, dict):
        raise _schema("Handshake hello must be an object")
    expected = _HELLO_FIELDS | ({"signature"} if signed else set())
    if payload.keys() != expected:
        raise _schema("Handshake hello fields do not match the required schema")
    if payload.get("kind") != kind or payload.get("protocol") != "SPARC":
        raise _schema("Handshake kind or protocol is unsupported")
    version = payload.get("version")
    if type(version) is not int:
        raise _schema("Handshake version must be an integer")
    if version != 1:
        raise SparcError("unsupported_version", "Handshake version is unsupported")
    for field in ("identity_key", "ephemeral_key", "random"):
        decode_base64(payload[field], 32)
    if signed:
        decode_base64(payload["signature"], 64)


def make_hello(identity: Identity, kind: str):
    """Create an unsigned hello and a fresh X25519 private key."""
    if not isinstance(identity, Identity):
        raise _schema("Handshake identity is invalid")
    if kind not in ("client_hello", "server_hello"):
        raise _schema("Handshake hello kind is unsupported")
    if not isinstance(identity.public_bytes, bytes) or len(identity.public_bytes) != 32:
        raise _schema("Handshake identity key must contain 32 bytes")

    ephemeral = X25519PrivateKey.generate()
    raw_ephemeral = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    payload = {
        "kind": kind,
        "protocol": "SPARC",
        "version": 1,
        "identity_key": base64.b64encode(identity.public_bytes).decode("ascii"),
        "ephemeral_key": base64.b64encode(raw_ephemeral).decode("ascii"),
        "random": base64.b64encode(os.urandom(32)).decode("ascii"),
    }
    return payload, ephemeral


def validate_hello(payload: dict, signed: bool) -> None:
    """Validate an exact client or server hello schema and its binary fields."""
    if type(signed) is not bool:
        raise _schema("Signed-mode selector must be a boolean")
    kind = payload.get("kind") if isinstance(payload, dict) else None
    if kind not in ("client_hello", "server_hello"):
        raise _schema("Handshake hello kind is unsupported")
    if signed and kind != "server_hello":
        raise _schema("Only server hello may carry a signature")
    _validate_hello_kind(payload, kind, signed)


def transcript(client: dict, server_unsigned: dict) -> bytes:
    """Canonical transcript of the exact unsigned client and server hellos."""
    _validate_hello_kind(client, "client_hello", False)
    _validate_hello_kind(server_unsigned, "server_hello", False)
    return canonical({"client_hello": client, "server_hello": server_unsigned})


def _validate_client_auth(payload: dict) -> None:
    """Validate the exact client authentication message shape."""
    if not isinstance(payload, dict) or payload.keys() != {"kind", "signature"}:
        raise _schema("Client authentication fields do not match the required schema")
    if payload.get("kind") != "client_auth":
        raise _schema("Client authentication kind is unsupported")
    decode_base64(payload["signature"], 64)


def approve_candidate(
    candidate: PeerCandidate, trust: TrustStore, approve
) -> bool:
    """Check a candidate and ask only for unknown, unpinned identities."""
    if not isinstance(candidate, PeerCandidate) or not isinstance(trust, TrustStore):
        raise _schema("Peer candidate or trust store is invalid")
    if (
        not isinstance(candidate.public_key, bytes)
        or len(candidate.public_key) != 32
        or candidate.fingerprint != hashlib.sha256(candidate.public_key).hexdigest()
    ):
        raise _schema("Peer candidate identity is inconsistent")

    status = trust.check(candidate.public_key, candidate.endpoint)
    if status == "changed":
        raise SparcError("changed_identity", "Peer identity changed at a trusted endpoint")
    if status == "known":
        return False
    try:
        decision = approve(candidate)
    except Exception as exc:
        raise SparcError("pairing_rejected", "Peer approval failed") from exc
    if type(decision) is not bool:
        raise _schema("Peer approval must return a boolean")
    if decision is not True:
        raise SparcError("pairing_rejected", "Peer identity was not approved")
    return True


def _check_deadline(cancel: threading.Event, deadline: float) -> None:
    """Raise promptly when cancellation or a monotonic deadline wins."""
    if cancel.is_set():
        raise SparcError("canceled", "Handshake was canceled")
    if time.monotonic() >= deadline:
        raise SparcError("handshake_timeout", "Handshake deadline expired")


def _bounded_approval(
    candidate: PeerCandidate,
    approve: Callable[[PeerCandidate], bool],
    cancel: threading.Event,
    limits: Limits,
    overall_deadline: float,
) -> bool:
    """Call a synchronous approval function on a daemon thread with bounds."""
    if not isinstance(candidate, PeerCandidate) or not callable(approve):
        raise SparcError("invalid_schema", "Peer approval request is invalid")
    if not isinstance(cancel, threading.Event) or not isinstance(limits, Limits):
        raise SparcError("invalid_schema", "Peer approval controls are invalid")
    started = time.monotonic()
    if cancel.is_set():
        raise SparcError("canceled", "Peer approval was canceled")
    if started >= overall_deadline:
        raise SparcError("handshake_timeout", "Handshake deadline expired during approval")
    approval_deadline = started + limits.pairing_timeout_seconds
    effective_deadline = min(approval_deadline, overall_deadline)
    result: list[object] = []
    finished = threading.Event()

    def decide() -> None:
        try:
            result.append((True, approve(candidate)))
        except Exception:
            result.append((False, None))
        finally:
            finished.set()

    threading.Thread(target=decide, name="sparc-peer-approval", daemon=True).start()
    poll = min(1.0, float(limits.cancel_poll_seconds))
    while True:
        if cancel.is_set():
            raise SparcError("canceled", "Peer approval was canceled")
        now = time.monotonic()
        if now >= effective_deadline:
            if effective_deadline == overall_deadline:
                raise SparcError("handshake_timeout", "Handshake deadline expired during approval")
            cancel.set()
            raise SparcError("pairing_timeout", "Peer approval timed out")
        if finished.is_set():
            # Cancellation/deadline checks precede result acceptance, including
            # the race where the callback completed just before this check.
            if cancel.is_set():
                raise SparcError("canceled", "Peer approval was canceled")
            now = time.monotonic()
            if now >= effective_deadline:
                if effective_deadline == overall_deadline:
                    raise SparcError("handshake_timeout", "Handshake deadline expired during approval")
                cancel.set()
                raise SparcError("pairing_timeout", "Peer approval timed out")
            succeeded, decision = result[0]
            if not succeeded:
                raise SparcError("pairing_rejected", "Peer approval callback failed")
            if type(decision) is not bool:
                raise SparcError("invalid_schema", "Peer approval must return a boolean")
            if decision is not True:
                raise SparcError("pairing_rejected", "Peer identity was not approved")
            return True
        finished.wait(min(poll, max(0.0, effective_deadline - now)))


def _send_frame(
    sock: socket.socket,
    frame: bytes,
    cancel: threading.Event,
    limits: Limits,
    deadline: float,
) -> None:
    """Send one prepared frame with cancellation and deadline polling."""
    if not isinstance(frame, bytes) or not isinstance(limits, Limits):
        raise SparcError("invalid_schema", "Prepared frame or limits are invalid")
    try:
        previous_timeout = sock.gettimeout()
    except OSError as exc:
        raise SparcError("tcp_loss", "Socket is unavailable for frame writing") from exc
    view = memoryview(frame)
    sent = 0
    poll = min(1.0, float(limits.cancel_poll_seconds))
    try:
        while sent < len(view):
            _check_deadline(cancel, deadline)
            remaining = deadline - time.monotonic()
            try:
                sock.settimeout(max(0.001, min(poll, remaining)))
            except OSError as exc:
                raise SparcError("tcp_loss", "Socket failed while setting a frame write timeout") from exc
            try:
                count = sock.send(view[sent:])
            except (socket.timeout, TimeoutError):
                continue
            except OSError as exc:
                raise SparcError("tcp_loss", "Socket failed while writing a frame") from exc
            if type(count) is not int or count <= 0:
                raise SparcError("tcp_loss", "Socket closed while writing a frame")
            sent += count
    finally:
        try:
            sock.settimeout(previous_timeout)
        except OSError:
            pass
