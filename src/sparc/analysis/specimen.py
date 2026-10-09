"""Isolated Ed25519 signature-verification specimen using synthetic data."""

import hashlib
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..crypto import message_context
from ..protocol.messages import signing_projection


_SPECIMEN_TEXT = "SPARC synthetic signature specimen"
_SESSION_LABEL = b"SPARC synthetic signature specimen session v1"


def make_specimen() -> tuple[bytes, bytes, bytes]:
    """Return a fresh synthetic public key, signed C2 context, and signature."""
    public_key, signed_context, signature, _sign_ns = make_timed_specimen()
    return public_key, signed_context, signature


def make_timed_specimen() -> tuple[bytes, bytes, bytes, int]:
    """Return a specimen with signing-only time; exclude keygen and encoding."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    text_bytes = _SPECIMEN_TEXT.encode("ascii")
    payload = {
        "kind": "benchmark",
        "run_id": uuid.uuid4().hex,
        "message_id": uuid.uuid4().hex,
        "text": _SPECIMEN_TEXT,
        "byte_count": len(text_bytes),
        "sha256": hashlib.sha256(text_bytes).hexdigest(),
    }
    projection = signing_projection(payload)
    session_id = hashlib.sha256(_SESSION_LABEL).digest()
    signed_context = message_context(session_id, 0, 0, projection)
    started = time.perf_counter_ns()
    signature = private_key.sign(signed_context)
    sign_ns = time.perf_counter_ns() - started
    return public_key, signed_context, signature, sign_ns


def verify_specimen(public_key: bytes, signed_bytes: bytes, signature: bytes) -> bool:
    """Verify a specimen signature, returning false for malformed or edited data."""
    if type(public_key) is not bytes or len(public_key) != 32:
        return False
    if type(signed_bytes) is not bytes:
        return False
    if type(signature) is not bytes or len(signature) != 64:
        return False

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, signed_bytes)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True
